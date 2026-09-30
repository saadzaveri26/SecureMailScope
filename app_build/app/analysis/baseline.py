"""Cryptographic Baseline Profile: build, persist and (re)train the per-endpoint anomaly model."""
from __future__ import annotations
import hashlib
import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .. import config, storage
from .common import inflate_certs
from .ml_anomaly import AnomalyDetector, model_path


def build_profile(endpoint: str, ss: list[dict]) -> dict:
    tls = [s for s in ss if s["tls"] and s["tls"]["negotiated"]]
    neg = [s["tls"]["negotiated"] for s in tls]
    certs: dict = {}
    for s in ss:
        if s["chain"] and s["chain"]["certificates"]:
            c = s["chain"]["certificates"][0]
            e = certs.setdefault(c["fingerprint_sha256"], {
                "fingerprint": c["fingerprint_sha256"], "subject_cn": c["subject_cn"], "subject": c["subject"], "issuer": c["issuer"],
                "issuer_cn": c["issuer_cn"], "algorithm": c["public_key"]["algorithm"], "key_size": c["public_key"]["size"],
                "signature_algorithm": c["signature"]["algorithm"], "signature_hash": c["signature"]["hash"], "not_before": c["not_before"],
                "not_after": c["not_after"], "san": c["san"], "trusted": s["chain"]["trusted"], "sessions": 0})
            e["sessions"] += 1
    hs = sorted(s["tls"]["handshake_duration"] * 1000 for s in tls if s["tls"]["handshake_duration"])
    modes = Counter(s["transport"]["mode"] for s in ss)
    nego_sessions = [s for s in ss if s["transport"]["mode"] in ("plaintext", "starttls")]
    names = Counter(s["server_name"] for s in ss if s["server_name"])
    first = ss[0]
    return {
        "endpoint": endpoint, "server_ip": first["server_ip"], "port": first["server_port"], "protocol": first["protocol"],
        "server_name": names.most_common(1)[0][0] if names else None, "session_count": len(ss), "tls_session_count": len(tls),
        "transport_modes": dict(modes),
        "starttls": {"offered_sessions": sum(1 for s in nego_sessions if s["dialog"]["starttls"]["advertised"]),
                     "negotiating_sessions": len(nego_sessions),
                     "offered_ratio": round(sum(1 for s in nego_sessions if s["dialog"]["starttls"]["advertised"]) / len(nego_sessions), 3) if nego_sessions else None},
        "tls_versions": dict(Counter(n["version"] for n in neg)), "cipher_suites": dict(Counter(n["cipher_suite"] for n in neg)),
        "cipher_grades": dict(Counter(n["grade"] for n in neg)), "key_exchange": dict(Counter(n["kex"] for n in neg)),
        "key_exchange_groups": dict(Counter(n["group"] for n in neg if n.get("group"))),
        "forward_secrecy_ratio": round(sum(1 for n in neg if n["forward_secrecy"]) / len(neg), 3) if neg else None,
        "pq_hybrid_sessions": sum(1 for n in neg if n["pq_hybrid"]),
        "certificates": sorted(certs.values(), key=lambda c: -c["sessions"]),
        "certificate_visible_sessions": sum(1 for s in ss if s["chain"] and s["chain"]["certificates"]),
        "ja3s": dict(Counter(s["tls"]["server_hello"]["ja3s"] for s in tls if s["tls"]["server_hello"])),
        "handshake_ms": {"median": round(statistics.median(hs), 2) if hs else None, "p95": round(hs[int(0.95 * (len(hs) - 1))], 2) if hs else None, "samples": len(hs)},
        "message_security": {"pgp_sessions": sum(1 for s in ss if s["message_security"]["pgp"]["detected"]),
                             "smime_sessions": sum(1 for s in ss if s["message_security"]["smime"]["detected"])},
        "window": {"first_ts": min(s["timing"]["start_ts"] for s in ss), "last_ts": max(s["timing"]["end_ts"] for s in ss)},
    }


def endpoint_profiles(sessions: list[dict]) -> dict[str, dict]:
    by = defaultdict(list)
    for s in sessions:
        by[s["endpoint"]].append(s)
    return {ep: build_profile(ep, ss) for ep, ss in by.items()}


def create_from_analysis(doc: dict, endpoints: list[str] | None = None, notes: str = "") -> dict:
    sessions = inflate_certs(doc)["sessions"]
    eps = endpoints or sorted({s["endpoint"] for s in sessions})
    created, warnings = [], []
    for ep in eps:
        ss = [s for s in sessions if s["endpoint"] == ep]
        if not ss:
            warnings.append(f"{ep}: no sessions in analysis")
            continue
        profile = build_profile(ep, ss)
        posture = doc["posture"]["endpoints"].get(ep, {})
        bad = [f for f in doc["findings"] if f["endpoint"] == ep and f["severity"] in ("CRITICAL", "HIGH") and f["category"] != "drift"]
        if bad:
            warnings.append(f"{ep}: baseline captured with {len(bad)} CRITICAL/HIGH finding(s); the baseline encodes those weaknesses as 'normal'")
        model_info = None
        if len(ss) >= config.ML_MIN_SESSIONS:
            det = AnomalyDetector().fit(ss)
            det.save(model_path(ep))
            model_info = {"type": "IsolationForest", "trained_sessions": len(ss)}
        body = {"baseline_id": f"B-{doc['analysis_id']}-{storage.safe_name(ep)}", "endpoint": ep,
                "created_at": datetime.now(timezone.utc).isoformat(), "source": {"analysis_id": doc["analysis_id"], **{k: doc["source"].get(k) for k in ("filename", "sha256")}},
                "notes": notes, "profile": profile, "posture": {"score": posture.get("score"), "grade": posture.get("grade")},
                "model": model_info}
        body["integrity_sha256"] = hashlib.sha256(json.dumps(profile, sort_keys=True, default=str).encode()).hexdigest()
        storage.save_baseline(body)
        created.append({"endpoint": ep, "version": body["version"], "sessions": len(ss), "model": model_info})
    return {"created": created, "warnings": warnings}
