"""Cryptographic Drift Detection: compares the current capture against a stored baseline profile.

Every drift item answers: what changed / where / how many sessions / why it matters / what to investigate."""
from __future__ import annotations
import math
from datetime import datetime, timezone

from .. import storage
from ..config import CERT_EXPIRY_WARN_DAYS
from .rule_catalog import SEV_RANK

VERSION_ORDER = ["SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]
DEPRECATED = {"SSLv3": "CRITICAL", "TLS 1.0": "HIGH", "TLS 1.1": "HIGH"}
GRADE_SEV = {"insecure": "CRITICAL", "weak": "HIGH", "acceptable": "LOW", "strong": "INFO"}
DR_IDS = {"tls_version": "DR-TLS", "cipher_suite": "DR-CIPHER", "key_exchange": "DR-KEX", "forward_secrecy": "DR-PFS", "certificate": "DR-CERT",
          "transport": "DR-TRANSPORT", "fingerprint": "DR-JA3S", "behavior": "DR-LATENCY"}
SEV_PTS = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 12, "LOW": 4, "INFO": 0}


def js_divergence(p: dict, q: dict) -> float:
    keys = set(p) | set(q)
    tp, tq = sum(p.values()) or 1, sum(q.values()) or 1
    P = [p.get(k, 0) / tp for k in keys]
    Q = [q.get(k, 0) / tq for k in keys]
    M = [(a + b) / 2 for a, b in zip(P, Q)]
    kl = lambda a, b: sum(x * math.log2(x / y) for x, y in zip(a, b) if x > 0)  # noqa: E731
    return round(0.5 * kl(P, M) + 0.5 * kl(Q, M), 4)


def _vs(vs) -> str:
    return " / ".join(sorted(vs, key=lambda v: VERSION_ORDER.index(v) if v in VERSION_ORDER else 9)) or "none"


def _ev(s, msg, field, value):
    return {"tcp_stream": s["tcp_stream"], "session_id": s["session_id"], "client": s["client"], "server": s["server"],
            "handshake_message": msg, "field": field, "value": value}


def _item(dim, title, sev, ep, name, **kw):
    return {"drift_id": None, "dimension": dim, "title": title, "severity": sev, "endpoint": ep, "server_name": name,
            "baseline": kw.get("baseline"), "current": kw.get("current"), "what_changed": kw.get("what", title),
            "affected_sessions": kw.get("affected", 0), "affected_ratio": kw.get("ratio", 0.0), "evidence": kw.get("evidence", []),
            "session_ids": kw.get("session_ids", []), "why_it_matters": kw.get("why", ""), "recommendation": kw.get("rec", ""),
            "previous": kw.get("previous"), "observed": kw.get("observed"), "category": "drift"}


def compare_endpoint(base: dict, cur: dict, sessions: list[dict], ref_ts: float) -> tuple[list[dict], dict]:
    ep, name, n = cur["endpoint"], cur["server_name"] or base.get("server_name"), max(len(sessions), 1)
    items: list[dict] = []
    tls_s = [s for s in sessions if s["tls"] and s["tls"]["negotiated"]]

    def sess_with(pred):
        return [s for s in sessions if pred(s)]

    # ---- TLS version drift
    bv, cv = set(base["tls_versions"]), set(cur["tls_versions"])
    for v in sorted(cv - bv, key=lambda x: VERSION_ORDER.index(x) if x in VERSION_ORDER else 9):
        aff = sess_with(lambda s, v=v: s["tls"] and s["tls"]["negotiated"] and s["tls"]["negotiated"]["version"] == v)
        if v in DEPRECATED:
            sev, title = DEPRECATED[v], f"{v} traffic detected"
            why = f"{v} is deprecated (RFC 8996) and vulnerable to downgrade and padding-oracle attacks; it was absent from the baseline."
            rec = f"Investigate the server/client configuration responsible for negotiating {v}; disable it on the server and upgrade the legacy client."
        elif v == "TLS 1.3":
            sev, title = "INFO", "TLS 1.3 adoption detected"
            why, rec = "Positive change: stronger protocol now in use.", "Update the baseline once the change is confirmed intentional."
        else:
            sev, title = "LOW", f"{v} sessions newly observed"
            why, rec = f"Baseline traffic was {_vs(bv)} only.", "Confirm a client fleet change or a TLS 1.3 regression."
        items.append(_item("tls_version", title, sev, ep, name, baseline=f"{_vs(bv)}{' only' if len(bv) else ''}", current=_vs(cv),
                           affected=len(aff), ratio=round(len(aff) / n, 4), session_ids=[s["session_id"] for s in aff[:50]],
                           evidence=[_ev(s, "ServerHello", "negotiated_version", v) for s in aff[:5]], why=why, rec=rec,
                           what=f"{v} newly negotiated"))
    if "TLS 1.3" in bv and cur["tls_session_count"]:
        b_share = base["tls_versions"].get("TLS 1.3", 0) / max(sum(base["tls_versions"].values()), 1)
        c_share = cur["tls_versions"].get("TLS 1.3", 0) / max(sum(cur["tls_versions"].values()), 1)
        if b_share - c_share >= 0.10 and not (cv - bv):
            sev = "MEDIUM" if b_share - c_share >= 0.25 else "LOW"
            items.append(_item("tls_version", f"TLS 1.3 share dropped {b_share * 100:.0f}% -> {c_share * 100:.0f}%", sev, ep, name,
                               baseline=f"{b_share * 100:.0f}% TLS 1.3", current=f"{c_share * 100:.0f}% TLS 1.3",
                               why="Clients are negotiating older protocol versions than before (possible client change or downgrade pressure).",
                               rec="Check for new client software, middleboxes, or server settings that reduced TLS 1.3 usage."))

    # ---- cipher / key exchange / forward secrecy
    bc, cc = set(base["cipher_suites"]), set(cur["cipher_suites"])
    by_grade: dict = {}
    for suite in cc - bc:
        aff = sess_with(lambda s, suite=suite: s["tls"] and s["tls"]["negotiated"] and s["tls"]["negotiated"]["cipher_suite"] == suite)
        g = next((s["tls"]["negotiated"]["grade"] for s in aff), "unknown")
        by_grade.setdefault(g, []).append((suite, aff))
    for g, lst in by_grade.items():
        sev = GRADE_SEV.get(g, "LOW")
        aff = [s for _, a in lst for s in a]
        names = ", ".join(x for x, _ in lst)
        title = {"insecure": "Insecure cipher suite(s) newly negotiated", "weak": "Weak cipher suite(s) newly negotiated",
                 "strong": "New strong cipher suite(s) observed"}.get(g, "New cipher suite(s) observed")
        items.append(_item("cipher_suite", f"{title}: {names}", sev, ep, name, baseline=", ".join(sorted(bc)) or "none", current=", ".join(sorted(cc)),
                           affected=len(aff), ratio=round(len(aff) / n, 4), session_ids=[s["session_id"] for s in aff[:50]],
                           evidence=[_ev(s, "ServerHello", "cipher_suite", s["tls"]["negotiated"]["cipher_suite"]) for s in aff[:5]],
                           why="Cipher suites outside the baseline indicate a configuration change or a client forcing weaker algorithms." if sev != "INFO" else "Baseline expansion with strong crypto.",
                           rec="Restrict the server cipher list to AEAD+ECDHE suites and identify the client that selected this suite." if sev != "INFO" else "Update baseline if intended."))
    bfs, cfs = base.get("forward_secrecy_ratio"), cur.get("forward_secrecy_ratio")
    if bfs is not None and cfs is not None and bfs - cfs >= 0.10:
        aff = sess_with(lambda s: s["tls"] and s["tls"]["negotiated"] and not s["tls"]["negotiated"]["forward_secrecy"])
        items.append(_item("forward_secrecy", f"Forward-secrecy coverage dropped {bfs * 100:.0f}% -> {cfs * 100:.0f}%",
                           "HIGH" if bfs - cfs >= 0.2 else "MEDIUM", ep, name, baseline=f"{bfs * 100:.0f}% PFS", current=f"{cfs * 100:.0f}% PFS",
                           affected=len(aff), ratio=round(len(aff) / n, 4), session_ids=[s["session_id"] for s in aff[:50]],
                           evidence=[_ev(s, "ServerHello", "key_exchange", s["tls"]["negotiated"]["kex"]) for s in aff[:5]],
                           why="Sessions without ephemeral key exchange can be decrypted later if the server key leaks.",
                           rec="Remove static RSA key-exchange suites; require ECDHE/DHE."))
    bk, ck = set(base["key_exchange"]), set(cur["key_exchange"])
    if ck - bk and not (bfs is not None and cfs is not None and bfs - cfs >= 0.10):
        aff = sess_with(lambda s: s["tls"] and s["tls"]["negotiated"] and s["tls"]["negotiated"]["kex"] in (ck - bk))
        items.append(_item("key_exchange", f"New key-exchange mechanism(s): {', '.join(sorted(ck - bk))}", "LOW", ep, name,
                           baseline=", ".join(sorted(bk)), current=", ".join(sorted(ck)), affected=len(aff), ratio=round(len(aff) / n, 4),
                           session_ids=[s["session_id"] for s in aff[:50]],
                           evidence=[_ev(s, "ServerKeyExchange", "key_exchange", s["tls"]["negotiated"]["kex"]) for s in aff[:5]],
                           why="Key exchange profile differs from baseline.",
                           rec="Confirm the change is intentional."))

    # ---- certificate drift
    bcerts = {c["fingerprint"]: c for c in base["certificates"]}
    ccerts = {}
    for s in sessions:
        if s["chain"] and s["chain"]["certificates"]:
            c = s["chain"]["certificates"][0]
            ccerts.setdefault(c["fingerprint_sha256"], {"cert": c, "chain": s["chain"], "sessions": []})["sessions"].append(s)
    new_fps = set(ccerts) - set(bcerts)
    if bcerts and new_fps:
        prev = max(bcerts.values(), key=lambda c: c["sessions"])
        for fp in sorted(new_fps):
            e = ccerts[fp]
            c, ch, aff = e["cert"], e["chain"], e["sessions"]
            obs = []
            sev = "MEDIUM"
            if c["issuer"] != prev["issuer"]:
                obs.append(f"Issuer changed: {prev['issuer_cn'] or prev['issuer']} -> {c['issuer_cn'] or c['issuer']}"); sev = "HIGH"
            if (c["public_key"]["algorithm"], c["public_key"]["size"]) != (prev["algorithm"], prev["key_size"]):
                obs.append(f"Public key changed: {prev['algorithm']}-{prev['key_size']} -> {c['public_key']['algorithm']}-{c['public_key']['size']}")
                if c["public_key"]["algorithm"] == prev["algorithm"] and c["public_key"]["size"] < prev["key_size"]:
                    sev = "HIGH"
            if c["signature"]["weak"] and not prev.get("signature_hash", "") in ("md5", "sha1"):
                obs.append(f"Weaker signature hash: {c['signature']['hash']}"); sev = "HIGH"
            if c["subject"] != prev["subject"] or set(c["san"]) != set(prev["san"]):
                obs.append("Subject / SAN set changed")
                sev = sev if sev == "HIGH" else "MEDIUM"
            if ch["trusted"] is False and prev.get("trusted"):
                obs.append("New certificate does not chain to a trusted root (previous one did)"); sev = "HIGH"
            if c["self_signed"] and not prev["issuer"] == prev["subject"]:
                obs.append("New certificate is self-signed"); sev = "HIGH"
            try:
                prev_left = (datetime.fromisoformat(prev["not_after"]) - datetime.fromtimestamp(ref_ts, tz=timezone.utc)).days
            except Exception:  # noqa: BLE001
                prev_left = None
            renewal = (prev_left is not None and prev_left <= CERT_EXPIRY_WARN_DAYS)
            if not obs:
                obs.append("Same issuer, key and subject; only the fingerprint/validity window changed")
                sev = "LOW" if renewal else "MEDIUM"
                obs.append("Previous certificate was near/after expiry: likely routine renewal" if renewal else
                           "Previous certificate still had >30 days validity: unscheduled replacement")
            still_prev = prev["fingerprint"] in ccerts
            if still_prev:
                obs.append("Both old and new certificates are presented concurrently (load-balancer inconsistency or interception)")
                sev = "HIGH" if sev == "MEDIUM" else sev
            items.append(_item("certificate", "Certificate change detected", sev, ep, name,
                               baseline=f"{prev['fingerprint'][:23]}... ({prev['issuer_cn']}, {prev['algorithm']}-{prev['key_size']}, valid {prev['not_before'][:10]} -> {prev['not_after'][:10]})",
                               current=f"{fp[:23]}... ({c['issuer_cn']}, {c['public_key']['algorithm']}-{c['public_key']['size']}, valid {c['not_before'][:10]} -> {c['not_after'][:10]})",
                               affected=len(aff), ratio=round(len(aff) / n, 4), session_ids=[s["session_id"] for s in aff[:50]],
                               evidence=[_ev(s, "Certificate", "fingerprint_sha256", fp) for s in aff[:5]],
                               previous={"fingerprint": prev["fingerprint"], "issuer": prev["issuer_cn"]}, observed=obs,
                               what="; ".join(obs),
                               why="Unexpected certificate replacement or a new issuer can indicate TLS interception, an unauthorised CA, or an uncontrolled change.",
                               rec="Investigate certificate replacement: confirm the change ticket, issuer authorisation and that no interception device is in path."))

    # ---- transport / STARTTLS drift
    bm, cm = base["transport_modes"], cur["transport_modes"]
    b_st = base["starttls"]
    plain = sess_with(lambda s: s["transport"]["mode"] == "plaintext")
    if plain and not bm.get("plaintext"):
        stripped = [s for s in plain if not s["dialog"]["starttls"]["advertised"] or s["dialog"]["starttls"]["failed"]]
        if (b_st["offered_ratio"] or 0) >= 0.9 and stripped:
            items.append(_item("transport", "STARTTLS no longer offered / honoured - possible stripping", "CRITICAL", ep, name,
                               baseline=f"STARTTLS offered in {b_st['offered_ratio'] * 100:.0f}% of negotiating sessions", current=f"{len(stripped)} session(s) without a successful STARTTLS upgrade",
                               affected=len(stripped), ratio=round(len(stripped) / n, 4), session_ids=[s["session_id"] for s in stripped[:50]],
                               evidence=[_ev(s, "server capabilities", "starttls_advertised", s["dialog"]["starttls"]["advertised"]) for s in stripped[:5]],
                               why="The baseline server always supported encryption; its disappearance is the hallmark of a STARTTLS stripping/downgrade attack or a broken TLS configuration.",
                               rec="Check for on-path devices altering SMTP/IMAP/POP3 capabilities, verify server TLS config, and enforce MTA-STS/DANE."))
        else:
            items.append(_item("transport", "Unencrypted email sessions appeared", "HIGH", ep, name, baseline="0 plaintext sessions", current=f"{len(plain)} plaintext session(s)",
                               affected=len(plain), ratio=round(len(plain) / n, 4), session_ids=[s["session_id"] for s in plain[:50]],
                               evidence=[_ev(s, "session", "transport_mode", "plaintext") for s in plain[:5]],
                               why="The baseline had no cleartext traffic on this endpoint.", rec="Identify the clients sending cleartext and enforce TLS."))

    # ---- fingerprint + behaviour drift
    if not any(i["dimension"] in ("tls_version", "cipher_suite") for i in items):
        new_ja3s = set(cur["ja3s"]) - set(base["ja3s"])
        if base["ja3s"] and new_ja3s:
            items.append(_item("fingerprint", "Server TLS fingerprint (JA3S) changed", "LOW", ep, name, baseline=f"{len(base['ja3s'])} known JA3S", current=f"{len(new_ja3s)} new JA3S",
                               why="Server TLS stack behaviour changed (software upgrade or an inline device).", rec="Correlate with change records."))
    bh, ch_ = base["handshake_ms"]["median"], cur["handshake_ms"]["median"]
    if bh and ch_ and ch_ >= 3 * bh and ch_ - bh >= 20:
        items.append(_item("behavior", f"Handshake latency increased {ch_ / bh:.1f}x", "LOW", ep, name, baseline=f"median {bh} ms", current=f"median {ch_} ms",
                           why="Slower handshakes can indicate an inline inspection proxy or resource exhaustion.", rec="Check for TLS-intercepting devices and server load."))

    div = {"tls_version": js_divergence(base["tls_versions"], cur["tls_versions"]), "cipher_suite": js_divergence(base["cipher_suites"], cur["cipher_suites"]),
           "key_exchange": js_divergence(base["key_exchange"], cur["key_exchange"]), "transport_mode": js_divergence(bm, cm)}
    return items, div


def detect_all(sessions: list[dict], profiles: dict, posture: dict, ref_ts: float) -> dict:
    items, per_ep, notes = [], {}, []
    by_ep: dict = {}
    for s in sessions:
        by_ep.setdefault(s["endpoint"], []).append(s)
    have_any = False
    for ep, cur in profiles.items():
        b = storage.load_baseline(ep)
        if not b:
            per_ep[ep] = {"baseline": None, "status": "NO_BASELINE"}
            continue
        have_any = True
        its, div = compare_endpoint(b["profile"], cur, by_ep[ep], ref_ts)
        items += its
        cur_score = posture["endpoints"].get(ep, {}).get("score")
        base_score = (b.get("posture") or {}).get("score")
        delta = (cur_score - base_score) if (cur_score is not None and base_score is not None) else None
        per_ep[ep] = {"baseline": {"baseline_id": b["baseline_id"], "version": b.get("version"), "created_at": b["created_at"], "sessions": b["profile"]["session_count"]},
                      "divergence": div, "baseline_score": base_score, "current_score": cur_score, "delta": delta,
                      "status": "DEGRADED" if delta is not None and delta <= -10 else "IMPROVED" if delta is not None and delta >= 10 else "STABLE",
                      "items": len(its)}
    if have_any:
        for ep in profiles:
            if per_ep[ep]["status"] == "NO_BASELINE":
                notes.append(f"{ep}: no baseline (new endpoint relative to the stored baselines)")
        for b in storage.list_baselines():
            if b["endpoint"] not in profiles:
                notes.append(f"{b['endpoint']}: baselined endpoint not observed in this capture")
    items.sort(key=lambda i: -SEV_RANK[i["severity"]])
    for i, it in enumerate(items, 1):
        it["drift_id"] = f"D-{i:03d}"
    score = min(100, sum(SEV_PTS[i["severity"]] for i in items))
    return {"baseline_compared": have_any, "items": items, "drift_score": score,
            "status": "NO_BASELINE" if not have_any else ("DRIFT_DETECTED" if any(SEV_RANK[i["severity"]] >= 1 for i in items) else "NO_DRIFT"),
            "endpoints": per_ep, "notes": notes}


def to_finding(d: dict, total_sessions: int) -> dict:
    return {"finding_id": None, "rule_id": DR_IDS.get(d["dimension"], "DR-GEN"), "variant": "", "title": "Drift: " + d["title"], "severity": d["severity"],
            "category": "drift", "source": "drift", "endpoint": d["endpoint"], "server_name": d["server_name"], "protocol": None,
            "description": d["what_changed"], "detail": f"Baseline: {d['baseline']} | Current: {d['current']}", "why_it_matters": d["why_it_matters"],
            "affected_sessions": d["affected_sessions"], "total_sessions": total_sessions, "exposure_ratio": d["affected_ratio"],
            "session_ids": d["session_ids"], "evidence": d["evidence"], "remediation": [d["recommendation"]] if d["recommendation"] else [],
            "config_hints": {}, "effort": "medium", "references": [], "first_seen": None, "last_seen": None, "drift_id": d["drift_id"]}
