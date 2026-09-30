"""Explainable risk engine: per-session risk, endpoint/overall posture scoring, session explanation cards."""
from __future__ import annotations
from collections import Counter, defaultdict

from .rule_catalog import RULES, SEV_RANK, SEV_ORDER

SEV_W = {"CRITICAL": 0.90, "HIGH": 0.60, "MEDIUM": 0.30, "LOW": 0.10, "INFO": 0.0}
SEV_PTS = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 8, "LOW": 3, "INFO": 0}
LEVELS = [(85, "CRITICAL"), (55, "HIGH"), (30, "MEDIUM"), (10, "LOW"), (0, "MINIMAL")]
CATEGORIES = ["transport", "protocol", "cipher", "certificate", "message", "anomaly"]


def level_for(score: float) -> str:
    return next(name for th, name in LEVELS if score >= th)


def grade_for(score: float) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"


def score_session(s: dict) -> dict:
    p = 1.0
    for f in s["findings"]:
        p *= 1 - SEV_W[f["severity"]]
    rule_risk = 1 - p
    m = s.get("ml") or {}
    ml = m.get("score", 0.0) if m.get("available") and m.get("anomalous") else 0.0
    ml_risk = 0.5 * ml
    total = 1 - (1 - rule_risk) * (1 - ml_risk)
    score = round(100 * total)
    return {"score": score, "level": level_for(score), "rule_risk": round(100 * rule_risk), "ml_contribution": round(100 * (total - rule_risk))}


def compute_posture(sessions: list[dict], findings: list[dict]) -> dict:
    by_ep = defaultdict(list)
    for s in sessions:
        by_ep[s["endpoint"]].append(s)
    eps = {}
    for ep, ss in by_ep.items():
        fs = [f for f in findings if f["endpoint"] == ep and f["category"] != "drift" and f["severity"] != "INFO"]
        cat_pen = Counter()
        for f in fs:
            cat_pen[f["category"]] += SEV_PTS[f["severity"]] * (0.5 + 0.5 * f["exposure_ratio"])
        total_pen = min(100.0, sum(cat_pen.values()))
        score = round(100 - total_pen)
        n = len(ss)
        tls = [x for x in ss if x["tls"] and x["tls"]["negotiated"]]
        eps[ep] = {
            "score": score, "grade": grade_for(score), "sessions": n,
            "subscores": {c: max(0, round(100 - min(100, cat_pen.get(c, 0)))) for c in CATEGORIES},
            "encrypted_ratio": round(sum(1 for x in ss if x["transport"]["encrypted"]) / n, 3),
            "forward_secrecy_ratio": round(sum(1 for x in tls if x["tls"]["negotiated"]["forward_secrecy"]) / len(tls), 3) if tls else None,
            "modern_tls_ratio": round(sum(1 for x in tls if x["tls"]["negotiated"]["version_id"] >= 0x0303) / len(tls), 3) if tls else None,
            "pq_hybrid_ratio": round(sum(1 for x in tls if x["tls"]["negotiated"]["pq_hybrid"]) / len(tls), 3) if tls else None,
            "anomalous_sessions": sum(1 for x in ss if (x.get("ml") or {}).get("anomalous")),
            "message_layer": {"pgp_sessions": sum(1 for x in ss if x["message_security"]["pgp"]["detected"]),
                              "smime_sessions": sum(1 for x in ss if x["message_security"]["smime"]["detected"])},
        }
    total_sessions = sum(e["sessions"] for e in eps.values()) or 1
    overall = round(sum(e["score"] * e["sessions"] for e in eps.values()) / total_sessions) if eps else 100
    worst = min(eps.items(), key=lambda kv: kv[1]["score"])[0] if eps else None
    return {"overall": {"score": overall, "grade": grade_for(overall), "worst_endpoint": worst,
                        "sessions": sum(e["sessions"] for e in eps.values())}, "endpoints": eps}


# ---------------------------------------------------------------- explainability card
def _row(label, value, status):
    return {"label": label, "value": value, "status": status}


def explain_session(s: dict) -> dict:
    tls, ch = s["tls"], s["chain"]
    neg = tls["negotiated"] if tls else None
    leaf = ch["certificates"][0] if ch and ch["certificates"] else None
    rows = []
    m = s["transport"]["mode"]
    rows.append(_row("Transport", {"implicit_tls": "Implicit TLS", "starttls": "STARTTLS", "plaintext": "Plaintext"}[m],
                     "ok" if m != "plaintext" else "fail"))
    if neg:
        v = neg["version"]
        rows.append(_row("TLS Version", v, "ok" if neg["version_id"] >= 0x0303 else "fail"))
        rows.append(_row("Cipher Suite", neg["cipher_suite"].replace("TLS_", ""),
                         {"strong": "ok", "acceptable": "info", "weak": "warn", "insecure": "fail"}.get(neg["grade"], "info")))
        rows.append(_row("Key Exchange", f"{neg['kex']}" + (f" ({neg['group']})" if neg.get("group") else ""),
                         "ok" if neg["forward_secrecy"] else "warn"))
    elif tls:
        rows.append(_row("TLS Version", "handshake incomplete", "warn"))
    if leaf:
        bad = leaf["expired"] or leaf["signature"]["weak"] or leaf["public_key"]["size"] < 2048 and leaf["public_key"]["algorithm"] == "RSA"
        st = "Valid" if not bad and (ch["trusted"] or ch["self_signed_leaf"] is False) else "Issues"
        if leaf["expired"]: st = "Expired"
        elif ch["self_signed_leaf"] and not ch["trusted"]: st = "Self-signed"
        elif ch["trusted"] is False: st = "Untrusted issuer"
        rows.append(_row("Certificate", f"{st} ({leaf['public_key']['algorithm']}-{leaf['public_key']['size']}, {leaf['signature']['hash'].upper()})",
                         "ok" if st == "Valid" else "fail" if bad or st in ("Expired",) else "warn"))
    elif tls:
        rows.append(_row("Certificate", "not visible (encrypted / resumed)", "info"))
    ml = s.get("ml") or {}
    if ml.get("available"):
        rows.append(_row("ML Anomaly Score", f"{ml['score']:.2f}", "warn" if ml["anomalous"] else "ok"))
    if s["message_security"]["layer"] != "none":
        rows.append(_row("Message Layer", s["message_security"]["layer"].upper(), "ok"))
    fs = sorted(s["findings"], key=lambda f: -SEV_RANK[f["severity"]])
    why = [f"{f['title']}" + (f": {f['detail']}" if f["detail"] else "") for f in fs if f["severity"] != "INFO"][:6]
    why += [f"ML: {r}" for r in ml.get("reasons", [])[:3]]
    rec, seen = [], set()
    for f in fs:
        if f["severity"] == "INFO":
            continue
        for step in RULES[f["rule_id"]]["remediation"][:1]:
            if step not in seen:
                seen.add(step); rec.append(step)
    risk = s["risk"]
    return {"session_id": s["session_id"], "tcp_stream": s["tcp_stream"], "title": f"SESSION #{s['tcp_stream']}",
            "protocol": s["protocol"], "client": s["client"], "server": s["server"], "server_name": s["server_name"],
            "risk_level": risk["level"], "risk_score": risk["score"], "rows": rows,
            "why": why or ["No cryptographic weaknesses detected"],
            "recommendation": " ".join(rec[:3]) if rec else "No action required.",
            "findings": [{"finding_ref": f["rule_id"], "title": f["title"], "severity": f["severity"]} for f in fs],
            "ml": {"score": ml.get("score"), "anomalous": ml.get("anomalous"), "reasons": ml.get("reasons", []), "model": ml.get("model")}}
