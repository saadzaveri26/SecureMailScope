from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException

from .. import storage
from .deps import require_key

router = APIRouter(prefix="/dashboard", tags=["dashboard"], dependencies=[Depends(require_key)])


def _when(s: dict) -> str:
    return s.get("capture_start") or s["created_at"]


def _share(d: dict, key: str) -> float | None:
    tot = sum(d.values())
    return round(d.get(key, 0) / tot, 3) if tot else None


@router.get("/overview", summary="Aggregated data for the dashboard: severity, protocol, trend, top findings, drift, cert expiry")
def overview(analysis_id: str | None = None):
    sums = storage.list_summaries()
    if not sums:
        return {"empty": True}
    if analysis_id:
        try:
            cur = storage.load_summary(analysis_id)
        except KeyError:
            raise HTTPException(404, "analysis not found")
    else:
        cur = max(sums, key=_when)
    hist = sorted(sums, key=_when)
    trend = [{"analysis_id": s["analysis_id"], "label": s["filename"], "captured_at": _when(s), "posture_score": s["posture"]["score"], "grade": s["posture"]["grade"],
              "sessions": s["sessions"], "findings_by_severity": s["findings_by_severity"], "drift_score": s["drift_score"], "anomalous_sessions": s["anomalous_sessions"],
              "plaintext_sessions": s["plaintext_sessions"], "credential_exposures": s["credential_exposures"], "tls13_share": _share(s["tls_versions"], "TLS 1.3"),
              "forward_secrecy_ratio": s["forward_secrecy_ratio"]} for s in hist]
    return {
        "empty": False, "current": {"analysis_id": cur["analysis_id"], "filename": cur["filename"], "captured_at": _when(cur), "posture": cur["posture"], "sessions": cur["sessions"]},
        "totals": {"analyses": len(sums), "sessions": sum(s["sessions"] for s in sums), "findings": sum(sum(s["findings_by_severity"].values()) for s in sums)},
        "findings_by_severity": cur["findings_by_severity"], "findings_by_protocol": cur["findings_by_protocol"], "findings_by_category": cur["findings_by_category"],
        "sessions_by_protocol": cur["sessions_by_protocol"], "sessions_by_transport": cur["sessions_by_transport"], "sessions_by_risk": cur["sessions_by_risk"],
        "tls_versions": cur["tls_versions"], "cipher_suites": cur["cipher_suites"], "key_exchange": cur["key_exchange"],
        "endpoints": cur["endpoints"], "top_findings": cur["top_findings"], "drift": {"status": cur["drift_status"], "score": cur["drift_score"], "top": cur["drift_top"]},
        "certificate_expiry": sorted(cur["certificates"], key=lambda c: c["days_remaining"]), "anomalous_sessions": cur["anomalous_sessions"], "trend": trend}


@router.get("/trend", summary="Time series for one endpoint across all analyses")
def trend(endpoint: str):
    out = []
    for s in sorted(storage.list_summaries(), key=_when):
        for e in s["endpoints"]:
            if e["endpoint"] == endpoint:
                out.append({"analysis_id": s["analysis_id"], "captured_at": _when(s), "score": e["score"], "grade": e["grade"], "sessions": e["sessions"],
                            "tls13_share": _share(e["tls_versions"], "TLS 1.3"), "modern_tls_ratio": e["modern_tls_ratio"], "forward_secrecy_ratio": e["forward_secrecy_ratio"],
                            "subscores": e["subscores"]})
    return {"endpoint": endpoint, "points": out}
