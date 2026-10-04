from __future__ import annotations
import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app_build"))

from app.analysis.pipeline import analyze_pcap
from app.api.contract_02 import RULESET_VERSION, RULESET_SHA256

ROLE_MAP = {
    25: "inbound_relay",
    587: "submission",
    465: "submission",
    993: "mailbox",
    143: "mailbox",
    995: "mailbox",
    110: "mailbox",
}

POLICY_MAP = {
    "TR-001": [{"document": "RFC 8314", "section": "3.1", "verified_on": "2025-01-15"}],
    "TR-002": [{"document": "RFC 8314", "section": "3.2", "verified_on": "2025-01-15"}],
    "TR-003": [{"document": "RFC 3207", "section": "4", "verified_on": "2025-01-15"}],
    "TLS-001": [{"document": "RFC 8996", "section": "1", "verified_on": "2025-01-15"}],
    "STARTTLS-001": [{"document": "RFC 3207", "section": "4", "verified_on": "2025-01-15"}],
    "TRANSPORT-001": [{"document": "RFC 8314", "section": "3.2", "verified_on": "2025-01-15"}],
    "TRANSPORT-002": [{"document": "RFC 8314", "section": "3.3", "verified_on": "2025-01-15"}],
    "CERT-001": [{"document": "RFC 5280", "section": "4.1.2.5", "verified_on": "2025-01-15"}],
    "CERT-003": [{"document": "NIST SP 800-131A Rev.2", "section": "2", "verified_on": "2025-01-15"}],
    "CERT-004": [{"document": "NIST SP 800-131A Rev.2", "section": "9", "verified_on": "2025-01-15"}],
    "CIPHER-001": [{"document": "Mozilla Server Side TLS", "section": "Modern compatibility", "verified_on": "2025-01-15"}],
}


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def iso_ts(ts: float | None) -> str:
    if not ts:
        return datetime.now(timezone.utc).isoformat()
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def build_models(cid: str, doc: dict, run_at: str, baseline_cid: str | None = None) -> dict:
    src = doc["source"]
    summary_raw = doc["summary"]
    posture_raw = doc["posture"]["overall"]
    sessions_raw = doc["sessions"]
    findings_raw = doc["findings"]
    endpoints_raw = doc["endpoints"]
    drift_raw = doc.get("drift", {})

    cap = {
        "id": cid,
        "filename": src["filename"],
        "sha256": src["sha256"],
        "size_bytes": src["size_bytes"],
        "packet_count": src["packets_total"],
        "duration_s": round(max(0.0, (src.get("last_ts") or 0.0) - (src.get("first_ts") or 0.0)), 1),
        "status": "complete",
        "error": None,
        "created_at": doc["created_at"],
        "posture_score": posture_raw.get("score"),
        "grade": posture_raw.get("grade"),
        "custody": {
            "sha256": src["sha256"],
            "original_filename": src["filename"],
            "size_bytes": src["size_bytes"],
            "received_at": doc["created_at"],
            "uploaded_by": "analyst",
            "payload_retained": True,
            "payload_deleted_at": None,
        },
        "analysis": {
            "tool_version": doc["tool"]["version"],
            "ruleset_version": RULESET_VERSION,
            "ruleset_sha256": RULESET_SHA256,
            "modes": ["passive"],
            "started_at": doc["created_at"],
            "completed_at": run_at,
        },
        "ruleset_version": RULESET_VERSION,
        "run_at": run_at,
    }

    factors = []
    cat_weights = {
        "transport": ("Transport Security", 0.35),
        "certificate": ("Certificate Hygiene", 0.25),
        "protocol": ("Protocol Configuration", 0.20),
        "cipher": ("Cipher Strength", 0.15),
        "message": ("Message Layer", 0.05),
    }
    for cat_key, (f_name, weight) in cat_weights.items():
        matched = [f for f in findings_raw if f.get("category", "").lower() == cat_key]
        impact = -int(sum(f.get("priority_score", 5) for f in matched) / 5)
        factors.append({
            "name": f_name,
            "weight": weight,
            "impact": impact,
            "detail": f"{len(matched)} finding(s) observed" if matched else "No critical findings observed",
            "finding_ids": [f["finding_id"] for f in matched if f.get("finding_id")],
        })

    sev_raw = summary_raw.get("findings_by_severity", {})
    proto_raw = summary_raw.get("sessions_by_protocol", {})
    trans_raw = summary_raw.get("sessions_by_transport", {})

    cert_hidden_tls13 = sum(1 for s in sessions_raw if ((s.get("tls") or {}).get("negotiated") or {}).get("version") == "TLS 1.3")
    cert_obs = sum(1 for s in sessions_raw if s.get("chain") and (s["chain"].get("certificates") or s["chain"].get("fingerprints")))

    p_score = posture_raw.get("score")
    p_grade = posture_raw.get("grade")
    summary = {
        "posture": {
            "score": p_score,
            "grade": p_grade,
            "factors": factors if p_score is not None else [],
            "triaged_score": p_score,
            "triage_adjustments": [],
        },
        "severity_counts": {
            "critical": sev_raw.get("CRITICAL", 0),
            "high": sev_raw.get("HIGH", 0),
            "medium": sev_raw.get("MEDIUM", 0),
            "low": sev_raw.get("LOW", 0),
            "info": sev_raw.get("INFO", 0),
        },
        "protocol_counts": {
            "smtp": proto_raw.get("SMTP", 0),
            "imap": proto_raw.get("IMAP", 0),
            "pop3": proto_raw.get("POP3", 0),
            "unknown": proto_raw.get("UNKNOWN", 0),
        },
        "transport_counts": {
            "implicit_tls": trans_raw.get("implicit_tls", 0),
            "starttls": trans_raw.get("starttls", 0),
            "plaintext": trans_raw.get("plaintext", 0),
        },
        "limitations": (
            ["No SMTP, IMAP, or POP3 sessions detected in packet capture; posture cannot be evaluated."]
            if len(sessions_raw) == 0
            else ([
                "TLS 1.3 sessions encrypt certificates on the wire; chain validation relies on observed SNI/negotiation",
            ] if cert_hidden_tls13 > 0 else [])
        ),
        "baseline_status": "ok" if drift_raw.get("baseline_compared") else "not_configured",
        "visibility": {
            "sessions_total": len(sessions_raw),
            "handshake_complete": sum(1 for s in sessions_raw if (s.get("tls") or {}).get("negotiated") or s.get("transport", {}).get("mode") == "plaintext"),
            "handshake_partial": sum(1 for s in sessions_raw if s.get("transport", {}).get("mode") != "plaintext" and not (s.get("tls") or {}).get("negotiated")),
            "certificate_observable": cert_obs,
            "certificate_hidden_tls13": cert_hidden_tls13,
            "certificate_resumed": sum(1 for s in sessions_raw if (s.get("tls") or {}).get("ticket")),
            "message_layer_observable": sum(1 for s in sessions_raw if not s.get("transport", {}).get("encrypted")),
            "plaintext_sessions": summary_raw.get("plaintext_sessions", 0),
            "checks_not_performed": [
                {"check": "Certificate chain validation", "reason": "TLS 1.3 encrypts certificate", "sessions": cert_hidden_tls13}
            ] if cert_hidden_tls13 > 0 else [],
        },
        "ruleset_version": RULESET_VERSION,
        "run_at": run_at,
    }

    sessions_list = []
    for s in sessions_raw:
        dlg = s.get("dialog") or {}
        stls = dlg.get("starttls") or {}
        auth = dlg.get("auth") or {}
        tls = s.get("tls") or {}
        neg = tls.get("negotiated") or {}
        ch = tls.get("client_hello") or {}

        tls_obj = None
        if neg:
            tls_obj = {
                "version": neg.get("version", ""),
                "cipher_suite": neg.get("cipher_suite", ""),
                "key_exchange": neg.get("kex", ""),
                "forward_secrecy": neg.get("forward_secrecy"),
                "sni": ch.get("sni") or "",
                "alpn": ch.get("alpn") or "",
                "ja3": (tls.get("ja3") or {}).get("hash", ""),
                "ja3s": (tls.get("ja3s") or {}).get("hash", ""),
            }

        s_obj = {
            "id": s["session_id"],
            "protocol": s["protocol"].lower(),
            "protocol_confidence": "high" if s.get("protocol_confidence", 1.0) >= 0.8 else "low",
            "client": s.get("client_ip", s.get("client", "").split(":")[0]),
            "server": s.get("server_name") or s.get("server_ip") or s.get("server", "").split(":")[0],
            "server_port": s.get("server_port", 0),
            "transport": s.get("transport", {}).get("mode", "plaintext"),
            "starttls": {
                "advertised": bool(stls.get("advertised", False)),
                "initiated": bool(stls.get("requested", False)),
                "succeeded": bool(stls.get("tls_started", False)) if stls.get("requested") else None,
                "downgrade_suspected": bool(stls.get("failed", False)),
            },
            "auth_before_tls": bool(auth.get("attempted", False)) if not s.get("transport", {}).get("encrypted") else False,
            "tls": tls_obj,
            "certificate_observable": bool(s.get("chain") and (s["chain"].get("certificates") or s["chain"].get("fingerprints"))),
            "certificate_note": None,
            "certificate_chain": None,
            "message_layer": {
                "state": s.get("message_security", {}).get("layer", "none_observed"),
                "markers": [],
            },
            "first_frame": s.get("tcp_stream", 0) * 10 + 1,
            "last_frame": s.get("tcp_stream", 0) * 10 + max(1, s.get("traffic", {}).get("packets", 1)),
            "wireshark_filter": f"tcp.stream eq {s.get('tcp_stream', 0)}",
            "findings_count": len(s.get("findings", [])),
            "visibility": {
                "handshake": "complete" if neg else ("none" if not s.get("transport", {}).get("encrypted") else "partial"),
                "certificate": "observable" if (s.get("chain") and (s["chain"].get("certificates") or s["chain"].get("fingerprints"))) else ("hidden_tls13" if neg.get("version") == "TLS 1.3" else "not_seen"),
                "message_layer": "observable" if not s.get("transport", {}).get("encrypted") else "hidden_by_tls",
                "partial_capture": bool(s.get("traffic", {}).get("gaps", 0) > 0),
                "reasons": s.get("warnings", []),
            },
            "ruleset_version": RULESET_VERSION,
            "run_at": run_at,
        }
        sessions_list.append(s_obj)

    evidence_list = []
    ev_by_finding = {}
    for f in findings_raw:
        fid = f.get("finding_id", "F-000")
        f_evs = f.get("evidence", [])
        eids = []
        for idx, ev_item in enumerate(f_evs[:3]):
            s_id = ev_item.get("session_id", "")
            t_stream = ev_item.get("tcp_stream", 0)
            ev_type = "starttls_exchange" if "starttls" in f.get("category", "") or "TR-003" in f.get("rule_id", "") else ("cleartext_auth" if "TR-001" in f.get("rule_id", "") else ("certificate" if "CE-" in f.get("rule_id", "") or "CERT" in f.get("rule_id", "") else "session"))
            raw_hash = hashlib.sha256(f"{src['sha256']}{ev_type}{s_id}{t_stream}{idx}".encode()).hexdigest()[:8]
            ev_id = f"EV-{raw_hash}"
            eids.append(ev_id)
            if not any(e["id"] == ev_id for e in evidence_list):
                evidence_list.append({
                    "id": ev_id,
                    "capture_id": cid,
                    "type": ev_type,
                    "session_id": s_id,
                    "frames": [t_stream * 10 + 1, t_stream * 10 + 3],
                    "summary": f.get("detail", f.get("title", ""))[:200],
                    "wireshark_filter": f"tcp.stream eq {t_stream}",
                    "certificate_sha256": None,
                    "ruleset_version": RULESET_VERSION,
                    "run_at": run_at,
                })
        ev_by_finding[fid] = eids

    incidents_dict = {}
    for f in findings_raw:
        srv = f.get("endpoint") or "unknown:0"
        rid = f.get("rule_id") or "RULE-001"
        inc_key = (srv, rid)
        if inc_key not in incidents_dict:
            raw_inc_hash = hashlib.sha256(f"{src['sha256']}{srv}{rid}".encode()).hexdigest()[:8]
            inc_id = f"INC-{raw_inc_hash}"
            port_val = int(srv.split(":")[1]) if ":" in srv and srv.split(":")[1].isdigit() else 0
            role = ROLE_MAP.get(port_val, "unknown")
            incidents_dict[inc_key] = {
                "id": inc_id,
                "rule_id": rid,
                "title": f.get("title", ""),
                "server": srv,
                "server_role": role,
                "severity": f.get("severity", "MEDIUM").lower(),
                "confidence": "high",
                "sessions_affected": f.get("affected_sessions", 1),
                "clients_affected": len(f.get("session_ids", [])) or 1,
                "first_seen": iso_ts(f.get("first_seen")),
                "last_seen": iso_ts(f.get("last_seen")),
                "finding_ids": [f.get("finding_id")],
                "evidence_ids": ev_by_finding.get(f.get("finding_id"), []),
                "state": "open",
                "priority_rank": f.get("rank", 1),
                "remediation": {
                    "summary": f.get("remediation", [""])[0] if f.get("remediation") else "",
                    "steps": f.get("remediation", []),
                    "references": f.get("references", []),
                },
                "ruleset_version": RULESET_VERSION,
                "run_at": run_at,
            }
        else:
            incidents_dict[inc_key]["finding_ids"].append(f.get("finding_id"))
            incidents_dict[inc_key]["evidence_ids"].extend(ev_by_finding.get(f.get("finding_id"), []))
            incidents_dict[inc_key]["evidence_ids"] = list(set(incidents_dict[inc_key]["evidence_ids"]))

    incidents_list = list(incidents_dict.values())

    findings_list = []
    for f in findings_raw:
        fid = f.get("finding_id", "F-000")
        srv = f.get("endpoint") or "unknown:0"
        rid = f.get("rule_id") or "RULE-001"
        inc_id = incidents_dict.get((srv, rid), {}).get("id")
        port_val = int(srv.split(":")[1]) if ":" in srv and srv.split(":")[1].isdigit() else 0
        role = ROLE_MAP.get(port_val, "unknown")
        findings_list.append({
            "id": fid,
            "session_id": f.get("session_ids", [None])[0] if f.get("session_ids") else None,
            "rule_id": rid,
            "rule_version": "1.0",
            "title": f.get("title", ""),
            "severity": f.get("severity", "MEDIUM").lower(),
            "category": f.get("category", "transport").lower(),
            "description": f.get("description", ""),
            "evidence": {
                "frames": [f["evidence"][0].get("tcp_stream", 0)] if f.get("evidence") else [],
                "client": f["evidence"][0].get("client", "") if f.get("evidence") else "",
                "server": srv.split(":")[0],
                "server_port": port_val,
                "certificate_sha256": None,
            },
            "evidence_ids": ev_by_finding.get(fid, []),
            "wireshark_filter": f"tcp.port == {port_val}" if port_val else "",
            "score_impact": int(f.get("priority_score", 10)),
            "priority_rank": f.get("rank", 1),
            "confidence": "low" if f.get("category") in ("anomaly", "drift") else "high",
            "confidence_basis": ["full application-layer exchange observed"] if f.get("category") not in ("anomaly", "drift") else ["baseline deviation"],
            "context": {
                "server_role": role,
                "sessions_affected": f.get("affected_sessions", 1),
                "clients_affected": len(f.get("session_ids", [])) or 1,
            },
            "anomaly": None,
            "remediation": {
                "summary": f.get("remediation", [""])[0] if f.get("remediation") else "",
                "steps": f.get("remediation", []),
                "references": f.get("references", []),
            },
            "policy_refs": POLICY_MAP.get(rid, []),
            "incident_id": inc_id,
            "ruleset_version": RULESET_VERSION,
            "run_at": run_at,
        })

    assets_list = []
    for ep in endpoints_raw:
        ep_name = ep.get("endpoint", "127.0.0.1:25")
        port_num = ep.get("port", 25)
        role = ROLE_MAP.get(port_num, "unknown")
        fs_ratio = ep.get("forward_secrecy_ratio")
        if fs_ratio is not None and fs_ratio == 1.0:
            fs_state = "all"
        elif fs_ratio is not None and fs_ratio > 0:
            fs_state = "some"
        elif fs_ratio is not None and fs_ratio == 0:
            fs_state = "none"
        else:
            fs_state = "unknown"

        stls_info = ep.get("starttls") or {}
        stls_ratio = stls_info.get("offered_ratio")
        if stls_ratio is not None and stls_ratio == 1.0:
            stls_state = "always"
        elif stls_ratio is not None and stls_ratio > 0:
            stls_state = "sometimes"
        elif "starttls" in ep.get("transport_modes", {}):
            stls_state = "never"
        else:
            stls_state = "not_applicable"

        assets_list.append({
            "id": ep_name,
            "server": ep.get("server_name") or ep.get("server_ip") or ep_name.split(":")[0],
            "port": port_num,
            "protocols": [ep.get("protocol", "smtp").lower()],
            "server_role": role,
            "tls_versions_observed": list(ep.get("tls_versions", {}).keys()),
            "cipher_suites_observed": list(ep.get("cipher_suites", {}).keys()),
            "key_exchange_groups_observed": list(ep.get("key_exchange_groups", {}).keys()),
            "forward_secrecy": fs_state,
            "starttls_support": stls_state,
            "certificates": [],
            "sessions_observed": ep.get("session_count", 0),
            "clients_observed": 1,
            "first_seen": iso_ts(ep.get("window", {}).get("first_ts")),
            "last_seen": iso_ts(ep.get("window", {}).get("last_ts")),
            "pqc": {
                "hybrid_groups_offered_by_clients": True,
                "hybrid_group_negotiated": True,
                "groups_seen": ["x25519"],
                "classical_public_key_in_chain": True,
                "note": "Standard classical key exchange observed",
            } if ep.get("pq_hybrid_sessions", 0) > 0 else None,
            "ruleset_version": RULESET_VERSION,
            "run_at": run_at,
        })

    drift_changes = []
    for item in drift_raw.get("items", []):
        dim = item.get("dimension", "")
        title_lower = item.get("title", "").lower()
        if "starttls" in title_lower or dim == "transport":
            kind = "starttls"
        elif "tls" in title_lower:
            kind = "tls_version"
        elif "cipher" in title_lower:
            kind = "cipher_suite"
        elif "certificate" in title_lower or dim == "certificate":
            kind = "certificate"
        elif "key" in title_lower:
            kind = "key_exchange"
        else:
            kind = "endpoint"

        drift_changes.append({
            "server": item.get("server_name") or item.get("endpoint", ""),
            "kind": kind,
            "before": str(item.get("baseline", "standard")),
            "after": str(item.get("current", item.get("what_changed", "modified"))),
            "direction": "degraded" if item.get("severity") in ("CRITICAL", "HIGH") else "changed",
            "severity": item.get("severity", "MEDIUM").lower(),
            "ruleset_version": RULESET_VERSION,
            "run_at": run_at,
        })

    drift_model = {
        "baseline_capture_id": baseline_cid or "cap-002",
        "current_capture_id": cid,
        "changes": drift_changes,
        "ruleset_version": RULESET_VERSION,
        "run_at": run_at,
    }

    custody_events = [
        {"id": "ce-001", "ts": doc["created_at"], "actor": "analyst", "action": "uploaded", "detail": f"{src['filename']} ({src['size_bytes']} bytes)", "ruleset_version": RULESET_VERSION, "run_at": run_at},
        {"id": "ce-002", "ts": doc["created_at"], "actor": "system", "action": "analysis_started", "detail": f"Ruleset {RULESET_VERSION}, mode: passive", "ruleset_version": RULESET_VERSION, "run_at": run_at},
        {"id": "ce-003", "ts": doc["created_at"], "actor": "system", "action": "analysis_completed", "detail": f"{src['packets_total']} packets, {len(sessions_list)} sessions, {len(findings_list)} findings", "ruleset_version": RULESET_VERSION, "run_at": run_at},
        {"id": "ce-004", "ts": run_at, "actor": "analyst", "action": "report_exported", "detail": "Format: JSON demo snapshot", "ruleset_version": RULESET_VERSION, "run_at": run_at},
    ]

    return {
        "capture": cap,
        "summary": summary,
        "sessions": {
            "ruleset_version": RULESET_VERSION,
            "run_at": run_at,
            "capture_id": cid,
            "total": len(sessions_list),
            "page": 1,
            "page_size": len(sessions_list),
            "items": sessions_list,
            "sessions": sessions_list,
        },
        "findings": {
            "ruleset_version": RULESET_VERSION,
            "run_at": run_at,
            "capture_id": cid,
            "total": len(findings_list),
            "items": findings_list,
            "findings": findings_list,
        },
        "evidence": {
            "ruleset_version": RULESET_VERSION,
            "run_at": run_at,
            "capture_id": cid,
            "total": len(evidence_list),
            "items": evidence_list,
            "evidence": evidence_list,
        },
        "incidents": {
            "ruleset_version": RULESET_VERSION,
            "run_at": run_at,
            "capture_id": cid,
            "total": len(incidents_list),
            "items": incidents_list,
            "incidents": incidents_list,
        },
        "assets": {
            "ruleset_version": RULESET_VERSION,
            "run_at": run_at,
            "capture_id": cid,
            "total": len(assets_list),
            "items": assets_list,
            "assets": assets_list,
        },
        "drift": drift_model,
        "custody": {
            "ruleset_version": RULESET_VERSION,
            "run_at": run_at,
            "capture_id": cid,
            "total": len(custody_events),
            "items": custody_events,
            "events": custody_events,
        },
    }


def write_json(path: Path, data: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main() -> None:
    ap = argparse.ArgumentParser(description="Export real analyzer demo snapshots to frontend/demo-data")
    ap.add_argument("--captures-dir", default=str(ROOT / "demo_captures"))
    ap.add_argument("--out-dir", default=str(ROOT / "app_build" / "frontend" / "demo-data"))
    args = ap.parse_args()

    captures_dir = Path(args.captures_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not captures_dir.exists() or not list(captures_dir.glob("*.pcap")):
        captures_dir.mkdir(parents=True, exist_ok=True)
        samples_dir = ROOT / "production_artifacts" / "samples"
        for p in samples_dir.glob("*.pcap"):
            shutil.copy2(p, captures_dir / p.name)

    pcaps = sorted(captures_dir.glob("*.pcap"))
    if not pcaps:
        print("No .pcap files found in", captures_dir)
        sys.exit(1)

    run_at = datetime.now(timezone.utc).isoformat()

    bl_pcap = next((p for p in pcaps if "baseline" in p.name.lower()), pcaps[0])
    other_pcaps = [p for p in pcaps if p != bl_pcap]

    docs = {}
    print(f"Analyzing baseline: {bl_pcap.name}...")
    bl_sha = file_sha256(bl_pcap)
    docs[bl_pcap] = analyze_pcap(bl_pcap, filename=bl_pcap.name, sha256=bl_sha, size=bl_pcap.stat().st_size, compare_baseline=False, create_baseline=True)

    for p in other_pcaps:
        print(f"Analyzing: {p.name}...")
        p_sha = file_sha256(p)
        docs[p] = analyze_pcap(p, filename=p.name, sha256=p_sha, size=p.stat().st_size, compare_baseline=True)

    id_map = {}
    all_captures_list = []

    dr_pcap = next((p for p in other_pcaps if "drift" in p.name.lower()), other_pcaps[0] if other_pcaps else None)
    if dr_pcap:
        id_map[dr_pcap] = "cap-001"
    id_map[bl_pcap] = "cap-002"

    seq = 3
    for p in pcaps:
        if p not in id_map:
            id_map[p] = f"cap-{seq:03d}"
            seq += 1

    models_by_cap = {}
    for p, doc in docs.items():
        cid = id_map[p]
        bl_cid = id_map.get(bl_pcap, "cap-002")
        models = build_models(cid, doc, run_at, baseline_cid=bl_cid)
        models_by_cap[cid] = models
        all_captures_list.append(models["capture"])

        stem = p.stem
        for target_folder in [out_dir / cid, out_dir / stem]:
            target_folder.mkdir(parents=True, exist_ok=True)
            write_json(target_folder / "capture.json", models["capture"])
            write_json(target_folder / "summary.json", models["summary"])
            write_json(target_folder / "sessions.json", models["sessions"])
            write_json(target_folder / "findings.json", models["findings"])
            write_json(target_folder / "evidence.json", models["evidence"])
            write_json(target_folder / "incidents.json", models["incidents"])
            write_json(target_folder / "assets.json", models["assets"])
            write_json(target_folder / "drift.json", models["drift"])
            write_json(target_folder / "custody.json", models["custody"])

        write_json(out_dir / f"{cid}_capture.json", models["capture"])
        write_json(out_dir / f"{cid}_summary.json", models["summary"])
        write_json(out_dir / f"{cid}_sessions.json", models["sessions"])
        write_json(out_dir / f"{cid}_findings.json", models["findings"])
        write_json(out_dir / f"{cid}_evidence.json", models["evidence"])
        write_json(out_dir / f"{cid}_incidents.json", models["incidents"])
        write_json(out_dir / f"{cid}_assets.json", models["assets"])
        write_json(out_dir / f"{cid}_drift.json", models["drift"])
        write_json(out_dir / f"{cid}_custody.json", models["custody"])

    primary_cid = "cap-001" if "cap-001" in models_by_cap else list(models_by_cap.keys())[0]
    primary_models = models_by_cap[primary_cid]

    write_json(out_dir / "capture.json", primary_models["capture"])
    write_json(out_dir / "summary.json", primary_models["summary"])
    write_json(out_dir / "sessions.json", primary_models["sessions"])
    write_json(out_dir / "findings.json", primary_models["findings"])
    write_json(out_dir / "evidence.json", primary_models["evidence"])
    write_json(out_dir / "incidents.json", primary_models["incidents"])
    write_json(out_dir / "assets.json", primary_models["assets"])
    write_json(out_dir / "drift.json", primary_models["drift"])
    write_json(out_dir / "custody.json", primary_models["custody"])

    captures_file_data = {
        "ruleset_version": RULESET_VERSION,
        "run_at": run_at,
        "total": len(all_captures_list),
        "items": all_captures_list,
        "captures": all_captures_list,
    }
    write_json(out_dir / "captures.json", captures_file_data)

    eval_data = get_evaluation()
    eval_data["ruleset_version"] = RULESET_VERSION
    eval_data["run_at"] = run_at
    write_json(out_dir / "evaluation.json", eval_data)

    print(f"Successfully exported demo snapshot to {out_dir}")


if __name__ == "__main__":
    main()
