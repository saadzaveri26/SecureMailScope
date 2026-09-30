from __future__ import annotations
import json
from .common import build_context


def render(doc: dict, include_sessions: bool = True) -> str:
    ctx = build_context(doc)
    out = {"report_metadata": {"generated_at": ctx["generated_at"], "tool": ctx["tool"], "chain_of_custody": ctx["custody"], "limitations": ctx["limitations"]},
           "executive_summary": ctx["exec"], "summary": doc["summary"], "posture": doc["posture"], "findings": doc["findings"],
           "remediation_plan": doc["remediation_plan"], "drift": doc["drift"], "anomalies": doc["anomalies"], "endpoints": doc["endpoints"],
           "certificates": doc["certificates"], "top_risk_sessions": ctx["cards"], "ml": doc["ml"], "parsing": doc["parsing"]}
    if include_sessions:
        out["sessions"] = doc["sessions"]
    return json.dumps(out, indent=2, default=str)
