"""Shared report data assembly (chain-of-custody, executive summary, top-risk session cards)."""
from __future__ import annotations
from datetime import datetime, timezone

from .. import config
from ..analysis.common import inflate_certs
from ..analysis.risk_engine import explain_session

SEV_COLORS = {"CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#2563eb", "INFO": "#64748b", "MINIMAL": "#16a34a"}


def executive_summary(doc: dict) -> list[str]:
    s, p = doc["summary"], doc["posture"]["overall"]
    sev = s["findings_by_severity"]
    out = [f"{s['sessions']} email sessions across {s['endpoints']} service endpoint(s) were reconstructed from {doc['source']['filename']} "
           f"({doc['source']['packets_total']} packets, {doc['source']['tcp_streams']} TCP streams). "
           f"The overall cryptographic security posture is {p['score']}/100 (grade {p['grade']})."]
    out.append(f"{sum(sev.values()) - sev['INFO']} actionable finding(s): {sev['CRITICAL']} critical, {sev['HIGH']} high, {sev['MEDIUM']} medium, {sev['LOW']} low "
               f"({sev['INFO']} informational).")
    if s["plaintext_sessions"]:
        out.append(f"{s['plaintext_sessions']} session(s) carried mail without any transport encryption; {s['credential_exposures']} exposed mailbox credentials in cleartext.")
    if s["tls_versions"]:
        dep = sum(v for k, v in s["tls_versions"].items() if k in ("SSLv3", "TLS 1.0", "TLS 1.1"))
        if dep:
            out.append(f"{dep} TLS session(s) negotiated a deprecated protocol version (< TLS 1.2).")
    if s["anomalous_sessions"]:
        out.append(f"The ML engine flagged {s['anomalous_sessions']} anomalous session(s) ({doc['ml']['engine']}).")
    d = doc["drift"]
    if d["baseline_compared"]:
        out.append(f"Baseline comparison: {d['status'].replace('_', ' ').lower()} - {len(d['items'])} drift item(s), drift score {d['drift_score']}/100.")
    top = [f for f in doc["findings"] if f["severity"] in ("CRITICAL", "HIGH")][:3]
    if top:
        out.append("Highest-priority issues: " + "; ".join(f"{f['title']} ({f['endpoint']})" for f in top) + ".")
    return out


def build_context(doc: dict, top_sessions: int = 10) -> dict:
    inflate_certs(doc)
    ranked = sorted(doc["sessions"], key=lambda x: -x["risk"]["score"])
    cards = [explain_session(x) for x in ranked[:top_sessions] if x["risk"]["score"] >= 10]
    now = datetime.now(timezone.utc).isoformat()
    return {"generated_at": now, "tool": f"{config.APP_NAME} {config.APP_VERSION}", "exec": executive_summary(doc), "cards": cards,
            "custody": {"analysis_id": doc["analysis_id"], "filename": doc["source"]["filename"], "sha256": doc["source"]["sha256"],
                        "size_bytes": doc["source"]["size_bytes"], "capture_start": doc["source"]["capture_start"], "capture_end": doc["source"]["capture_end"],
                        "analysed_at": doc["created_at"], "analyst": doc.get("analyst")},
            "limitations": [
                "Analysis is passive: TLS 1.3 encrypts the server certificate, so chain validation is only possible for TLS <= 1.2 handshakes (or resumed-free full handshakes).",
                "Encrypted mail content cannot be inspected; PGP/S-MIME detection applies to plaintext streams only.",
                "Trust evaluation uses the Mozilla CA bundle plus any enterprise CAs in production_artifacts/trust_store; revocation (OCSP/CRL) is not checked offline.",
                "ML anomaly scores are statistical indicators, not proof of attack; always correlate with rule findings and change records.",
                "Drift results are only as good as the baseline: a baseline captured during an insecure period encodes that insecurity as normal."]}
