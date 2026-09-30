"""End-to-end analysis pipeline: PCAP -> sessions -> rules -> ML -> risk -> posture -> drift -> stored analysis."""
from __future__ import annotations
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .. import config, storage
from ..core.cert_analyzer import get_trust_store
from ..core.pcap_reader import read_tcp_packets
from ..core.session_builder import build_session
from ..core.tcp_reassembly import build_flows
from . import baseline as baseline_mod
from . import drift as drift_mod
from .ml_anomaly import run_ml
from .risk_engine import compute_posture, score_session
from .rule_catalog import RULES, SEV_ORDER, SEV_RANK
from .rules import aggregate_findings, evaluate_session, prioritise, remediation_plan


def _iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None


def _ml_findings(sessions: list[dict], totals: dict) -> list[dict]:
    meta = RULES["ML-001"]
    out = []
    for ep in sorted({s["endpoint"] for s in sessions}):
        an = [s for s in sessions if s["endpoint"] == ep and (s["ml"] or {}).get("anomalous")]
        if not an:
            continue
        top = sorted(an, key=lambda s: -s["ml"]["score"])
        sev = "HIGH" if top[0]["ml"]["score"] >= 0.75 else "MEDIUM"
        out.append({"finding_id": None, "rule_id": "ML-001", "variant": "", "title": meta["title"], "severity": sev, "category": "anomaly", "source": "ml",
                    "endpoint": ep, "server_name": next((s["server_name"] for s in an if s["server_name"]), None), "protocol": an[0]["protocol"],
                    "description": meta["description"], "detail": f"{len(an)} anomalous session(s); top score {top[0]['ml']['score']:.2f} - " + "; ".join(top[0]["ml"]["reasons"][:2]),
                    "why_it_matters": meta["why_it_matters"], "affected_sessions": len(an), "total_sessions": totals[ep], "exposure_ratio": round(len(an) / totals[ep], 4),
                    "session_ids": [s["session_id"] for s in top[:100]],
                    "evidence": [{"session_id": s["session_id"], "tcp_stream": s["tcp_stream"], "client": s["client"], "server": s["server"], "handshake_message": "session features",
                                  "field": "ml_anomaly_score", "value": s["ml"]["score"], "reasons": s["ml"]["reasons"]} for s in top[:5]],
                    "remediation": meta["remediation"], "config_hints": {}, "effort": meta["effort"], "references": [],
                    "first_seen": min(s["timing"]["start_ts"] for s in an), "last_seen": max(s["timing"]["start_ts"] for s in an)})
    return out


def relink(sessions: list[dict], findings: list[dict]) -> None:
    """Point each session's finding refs at the (re-ranked) aggregated finding ids."""
    idx = {(f["rule_id"], f["endpoint"], f["variant"]): f["finding_id"] for f in findings}
    for s in sessions:
        for r in s["findings"]:
            r["finding_id"] = idx.get((r["rule_id"], s["endpoint"], r["variant"]))


def recompute_drift(doc: dict) -> dict:
    """Re-run baseline comparison on a stored analysis (e.g. after a baseline was created/updated)."""
    from .common import inflate_certs
    inflate_certs(doc)
    sessions = doc["sessions"]
    totals = Counter(s["endpoint"] for s in sessions)
    profiles = baseline_mod.endpoint_profiles(sessions)
    first_ts = min((s["timing"]["start_ts"] for s in sessions), default=time.time())
    drift = drift_mod.detect_all(sessions, profiles, doc["posture"], first_ts)
    findings = [f for f in doc["findings"] if f["category"] != "drift"]
    findings += [drift_mod.to_finding(d, totals.get(d["endpoint"], 0)) for d in drift["items"]]
    prioritise(findings)
    relink(sessions, findings)
    doc["drift"], doc["findings"], doc["remediation_plan"] = drift, findings, remediation_plan(findings)
    sev = {k: 0 for k in reversed(SEV_ORDER)}
    for f in findings:
        sev[f["severity"]] += 1
    doc["summary"].update(findings=len(findings), findings_by_severity=sev, drift_items=len(drift["items"]), drift_status=drift["status"],
                          drift_score=drift["drift_score"], findings_by_category=dict(Counter(f["category"] for f in findings)))
    doc["certificates"] = _dedupe_certs(sessions) or doc["certificates"]
    doc["report_summary"] = _lightweight(doc)
    storage.save_analysis(doc, doc["report_summary"])
    return doc


def _dedupe_certs(sessions: list[dict]) -> dict:
    """Move full certificate dicts into a shared registry; sessions keep fingerprints only."""
    reg: dict = {}
    for s in sessions:
        ch = s.get("chain")
        if ch and ch.get("certificates"):
            fps = []
            for c in ch["certificates"]:
                reg.setdefault(c["fingerprint_sha256"], c)
                fps.append(c["fingerprint_sha256"])
            ch["fingerprints"] = fps
            del ch["certificates"]
    return reg


def analyze_pcap(path: Path, *, filename: str, sha256: str, size: int, batch_id: str | None = None, compare_baseline: bool = True,
                 create_baseline: bool = False, analyst: str | None = None) -> dict:
    t0 = time.time()
    packets, stats = read_tcp_packets(path)
    flows = build_flows(packets)
    trust = get_trust_store()
    sessions, ignored, ignored_tls = [], 0, 0
    for f in flows:
        s = build_session(f, trust)
        if s:
            sessions.append(s)
        else:
            ignored += 1
    sessions.sort(key=lambda s: s["tcp_stream"])
    totals = Counter(s["endpoint"] for s in sessions)

    for s in sessions:
        s["_hits"] = evaluate_session(s)
    ml_info = run_ml(sessions) if sessions else {"engine": "IsolationForest", "models": {}}
    findings = aggregate_findings(sessions, totals) + _ml_findings(sessions, totals)
    prioritise(findings)                                        # assigns finding ids
    for s in sessions:
        s["findings"] = [{"finding_id": None, "rule_id": h["rule_id"], "variant": h["variant"],
                          "title": RULES[h["rule_id"]]["title"] + (f" - {h['variant']}" if h["variant"] else ""), "severity": h["severity"],
                          "detail": h["detail"]} for h in s.pop("_hits")]
        s["risk"] = score_session(s)
    relink(sessions, findings)
    posture = compute_posture(sessions, findings)
    profiles = baseline_mod.endpoint_profiles(sessions)
    first_ts = min((s["timing"]["start_ts"] for s in sessions), default=stats.first_ts)
    drift = {"baseline_compared": False, "items": [], "drift_score": 0, "status": "NOT_REQUESTED", "endpoints": {}, "notes": []}
    if compare_baseline and sessions:
        drift = drift_mod.detect_all(sessions, profiles, posture, first_ts or time.time())
        findings += [drift_mod.to_finding(d, totals.get(d["endpoint"], 0)) for d in drift["items"]]
        prioritise(findings)
        relink(sessions, findings)
    certs = _dedupe_certs(sessions)

    aid = f"A-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    sev_counts = {k: 0 for k in reversed(SEV_ORDER)}
    for f in findings:
        sev_counts[f["severity"]] += 1
    by_proto_sev: dict = {}
    for f in findings:
        if f["protocol"]:
            by_proto_sev.setdefault(f["protocol"], {k: 0 for k in reversed(SEV_ORDER)})[f["severity"]] += 1
    neg = [s["tls"]["negotiated"] for s in sessions if s["tls"] and s["tls"]["negotiated"]]
    anomalies = [{"session_id": s["session_id"], "tcp_stream": s["tcp_stream"], "endpoint": s["endpoint"], "score": s["ml"]["score"], "reasons": s["ml"]["reasons"],
                  "top_features": s["ml"]["top_features"], "model": s["ml"]["model"]} for s in sessions if (s["ml"] or {}).get("anomalous")]
    anomalies.sort(key=lambda a: -a["score"])
    summary = {
        "sessions": len(sessions), "endpoints": len(profiles), "findings": len(findings), "findings_by_severity": sev_counts,
        "findings_by_protocol": by_proto_sev, "findings_by_category": dict(Counter(f["category"] for f in findings)),
        "sessions_by_protocol": dict(Counter(s["protocol"] for s in sessions)), "sessions_by_transport": dict(Counter(s["transport"]["mode"] for s in sessions)),
        "sessions_by_risk": dict(Counter(s["risk"]["level"] for s in sessions)),
        "tls_versions": dict(Counter(n["version"] for n in neg)), "cipher_suites": dict(Counter(n["cipher_suite"] for n in neg)),
        "key_exchange": dict(Counter(n["kex"] for n in neg)), "cipher_grades": dict(Counter(n["grade"] for n in neg)),
        "forward_secrecy_ratio": round(sum(1 for n in neg if n["forward_secrecy"]) / len(neg), 3) if neg else None,
        "plaintext_sessions": sum(1 for s in sessions if not s["transport"]["encrypted"]),
        "credential_exposures": sum(1 for s in sessions if s["dialog"]["auth"]["credentials_exposed"] and not s["transport"]["encrypted"]),
        "anomalous_sessions": len(anomalies), "drift_items": len(drift["items"]), "drift_status": drift["status"], "drift_score": drift["drift_score"],
        "certificates_seen": len(certs),
        "message_layer": {"pgp_sessions": sum(1 for s in sessions if s["message_security"]["pgp"]["detected"]),
                          "smime_sessions": sum(1 for s in sessions if s["message_security"]["smime"]["detected"]),
                          "plaintext_with_message_protection": sum(1 for s in sessions if s["message_security"]["layer"] != "none" and not s["transport"]["encrypted"])},
    }
    doc = {
        "analysis_id": aid, "created_at": datetime.now(timezone.utc).isoformat(), "batch_id": batch_id, "analyst": analyst,
        "tool": {"name": config.APP_NAME, "version": config.APP_VERSION},
        "source": {"filename": filename, "sha256": sha256, "size_bytes": size, "format": stats.file_format, "packets_total": stats.total_packets,
                   "packets_tcp": stats.tcp_packets, "tcp_streams": len(flows), "first_ts": stats.first_ts, "last_ts": stats.last_ts,
                   "capture_start": _iso(stats.first_ts), "capture_end": _iso(stats.last_ts)},
        "parsing": {"email_sessions": len(sessions), "ignored_tcp_streams": ignored, "warnings": stats.warnings + [w for s in sessions for w in s["warnings"]][:20],
                    "elapsed_seconds": round(time.time() - t0, 3), "trust_store": trust.sources},
        "summary": summary, "posture": posture, "endpoints": list(profiles.values()), "findings": findings,
        "remediation_plan": remediation_plan(findings), "anomalies": anomalies, "ml": ml_info, "drift": drift, "certificates": certs, "sessions": sessions,
    }
    doc["report_summary"] = _lightweight(doc)
    storage.save_analysis(doc, doc["report_summary"])
    if create_baseline:
        doc["baseline_creation"] = baseline_mod.create_from_analysis(doc)
        doc["report_summary"]["baseline_created"] = True
        storage.save_analysis(doc, doc["report_summary"])
    return doc


def _lightweight(doc: dict) -> dict:
    """Small sidecar used for listings and dashboards (avoids loading full analyses)."""
    s = doc["summary"]
    ep_rows = []
    for ep in doc["endpoints"]:
        p = doc["posture"]["endpoints"].get(ep["endpoint"], {})
        ep_rows.append({"endpoint": ep["endpoint"], "server_name": ep["server_name"], "protocol": ep["protocol"], "sessions": ep["session_count"],
                        "score": p.get("score"), "grade": p.get("grade"), "subscores": p.get("subscores"), "tls_versions": ep["tls_versions"],
                        "forward_secrecy_ratio": p.get("forward_secrecy_ratio"), "modern_tls_ratio": p.get("modern_tls_ratio")})
    certs = []
    for fp, c in doc["certificates"].items():
        certs.append({"fingerprint": fp, "cn": c["subject_cn"], "issuer": c["issuer_cn"], "not_after": c["not_after"], "days_remaining": c["days_remaining"],
                      "expired": c["expired"], "algorithm": f"{c['public_key']['algorithm']}-{c['public_key']['size']}"})
    return {
        "analysis_id": doc["analysis_id"], "created_at": doc["created_at"], "batch_id": doc["batch_id"], "filename": doc["source"]["filename"],
        "sha256": doc["source"]["sha256"], "capture_start": doc["source"]["capture_start"], "capture_end": doc["source"]["capture_end"],
        "sessions": s["sessions"], "posture": doc["posture"]["overall"], "endpoints": ep_rows, "findings_by_severity": s["findings_by_severity"],
        "findings_by_protocol": s["findings_by_protocol"], "findings_by_category": s["findings_by_category"], "sessions_by_protocol": s["sessions_by_protocol"],
        "sessions_by_transport": s["sessions_by_transport"], "sessions_by_risk": s["sessions_by_risk"], "tls_versions": s["tls_versions"],
        "cipher_suites": s["cipher_suites"], "key_exchange": s["key_exchange"], "anomalous_sessions": s["anomalous_sessions"], "drift_status": s["drift_status"],
        "drift_items": s["drift_items"], "drift_score": s["drift_score"], "plaintext_sessions": s["plaintext_sessions"],
        "credential_exposures": s["credential_exposures"], "forward_secrecy_ratio": s["forward_secrecy_ratio"], "certificates": certs,
        "top_findings": [{k: f[k] for k in ("finding_id", "title", "severity", "priority", "endpoint", "affected_sessions", "category")} for f in doc["findings"][:10]],
        "drift_top": [{k: d[k] for k in ("drift_id", "title", "severity", "endpoint", "affected_sessions")} for d in doc["drift"]["items"][:10]],
        "baseline_created": False,
    }
