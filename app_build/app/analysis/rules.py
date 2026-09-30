"""Deterministic cryptographic rule engine + finding aggregation and prioritisation."""
from __future__ import annotations
from collections import defaultdict

from ..config import CERT_EXPIRY_WARN_DAYS, CERT_EXPIRY_CRIT_DAYS, CERT_MAX_VALIDITY_DAYS
from .rule_catalog import RULES, SEV_RANK

DEPRECATED = {"SSLv3": "CRITICAL", "TLS 1.0": "HIGH", "TLS 1.1": "HIGH"}
SEV_BASE = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 15, "INFO": 0}


def _ev(s, msg, field, value, **extra):
    return {"session_id": s["session_id"], "tcp_stream": s["tcp_stream"], "client": s["client"], "server": s["server"],
            "handshake_message": msg, "field": field, "value": value, **extra}


def evaluate_session(s: dict) -> list[dict]:
    hits: list[dict] = []

    def add(rid, detail, evidence, sev=None, variant=""):
        hits.append({"rule_id": rid, "variant": variant, "severity": sev or RULES[rid]["severity"], "detail": detail, "evidence": evidence})

    mode, d, proto = s["transport"]["mode"], s["dialog"], s["protocol"]
    st, au = d["starttls"], d["auth"]
    port = s["server_port"]
    tls, chain = s["tls"], s["chain"]

    # ---------------- transport
    if mode == "plaintext":
        if st["failed"]:
            cont = st["commands_after_starttls"] > 0 or au["attempted"]
            add("TR-003", f"{proto} server replied '{st['response']}' to STARTTLS; session continued in cleartext"
                + (" with authentication" if au["attempted"] else ""),
                _ev(s, "STARTTLS response", "response", st["response"]), sev="CRITICAL" if cont else "HIGH")
        if au["credentials_exposed"]:
            add("TR-001", f"{proto} {'/'.join(sorted(set(au['mechanisms'])))} credentials sent unencrypted"
                + (f" (user {au['username_hint']})" if au["username_hint"] else ""),
                _ev(s, "client command", "auth_mechanisms", sorted(set(au["mechanisms"]))))
        elif not st["failed"] and d["commands_count"] + (1 if d["banner"] else 0) > 0:
            sev = "MEDIUM" if (proto == "SMTP" and port == 25) else "HIGH"
            if st["advertised"]:
                add("TR-002", "STARTTLS advertised by server but never used by the client",
                    _ev(s, "server capabilities", "starttls_advertised", True), sev=sev, variant="STARTTLS offered but not used")
            else:
                add("TR-002", "server does not offer STARTTLS/TLS",
                    _ev(s, "server capabilities", "starttls_advertised", False), sev=sev, variant="STARTTLS not offered")
    if st["injection_suspected"]:
        add("TR-004", f"{st['commands_after_starttls']} plaintext command(s) followed STARTTLS before the handshake",
            _ev(s, "client commands", "commands_after_starttls", st["commands_after_starttls"]))
    if au["advertised_cleartext"] and mode != "implicit_tls":
        add("TR-005", f"server advertises {', '.join(au['advertised_cleartext'])} before TLS",
            _ev(s, "server capabilities", "auth_advertised", au["advertised_cleartext"]))

    # ---------------- TLS
    if tls:
        neg, ch, sh, kx = tls["negotiated"], tls["client_hello"], tls["server_hello"], tls["key_exchange"] or {}
        if neg:
            v = neg["version"]
            if v in DEPRECATED:
                add("TLS-001", f"negotiated {v}", _ev(s, "ServerHello", "negotiated_version", v), sev=DEPRECATED[v], variant=v)
            if sh and sh["downgrade_sentinel"]:
                add("TLS-003", f"downgrade sentinel for {sh['downgrade_sentinel']} in ServerHello.random", _ev(s, "ServerHello", "random_tail", sh["downgrade_sentinel"]))
            if sh and sh["compression"] != 0:
                add("TLS-006", f"compression method {sh['compression']}", _ev(s, "ServerHello", "compression", sh["compression"]))
            if neg["version_id"] <= 0x0303 and sh and not sh["secure_renegotiation"] and not (ch and ch["renegotiation_scsv"]):
                add("TLS-007", "no renegotiation_info in ServerHello", _ev(s, "ServerHello", "renegotiation_info", False))
            if neg["version_id"] == 0x0303 and sh and not sh["extended_master_secret"]:
                add("TLS-008", "no extended_master_secret in ServerHello", _ev(s, "ServerHello", "extended_master_secret", False))
            if sh and sh["heartbeat"]:
                add("TLS-009", "heartbeat extension in ServerHello", _ev(s, "ServerHello", "heartbeat", True))
            if neg["version_id"] == 0x0303 and ch and "TLS 1.3" in ch["versions_offered"] and not sh["downgrade_sentinel"]:
                add("TLS-010", "client offered TLS 1.3, server chose TLS 1.2", _ev(s, "ServerHello", "negotiated_version", v))
            # cipher
            g = neg["grade"]
            if g == "insecure":
                add("CS-001", f"{neg['cipher_suite']}: {'; '.join(neg['issues'][:2])}", _ev(s, "ServerHello", "cipher_suite", neg["cipher_suite"]))
            elif neg["encryption"] == "3DES":
                add("CS-002", neg["cipher_suite"], _ev(s, "ServerHello", "cipher_suite", neg["cipher_suite"]))
            elif neg["mode"] == "CBC" and neg["version_id"] < 0x0304:
                add("CS-003", neg["cipher_suite"], _ev(s, "ServerHello", "cipher_suite", neg["cipher_suite"]))
            if not neg["forward_secrecy"] and g != "unknown":
                add("CS-004", f"key exchange {neg['kex']} ({neg['cipher_suite']})", _ev(s, "ServerHello", "key_exchange", neg["kex"]))
            if kx.get("dh_bits") and kx["dh_bits"] < 2048:
                add("CS-006", f"DHE prime {kx['dh_bits']} bits", _ev(s, "ServerKeyExchange", "dh_bits", kx["dh_bits"]),
                    sev="HIGH" if kx["dh_bits"] <= 1024 else "MEDIUM")
            if kx.get("weak_group"):
                add("CS-007", f"group {kx.get('group')}", _ev(s, "ServerKeyExchange", "group", kx.get("group")))
            if kx.get("weak_signature"):
                add("CS-008", f"signature {kx.get('signature_algorithm')}", _ev(s, "ServerKeyExchange", "signature_algorithm", kx.get("signature_algorithm")))
            if not kx.get("pq_hybrid"):
                add("CS-009", "classical key exchange only", _ev(s, "ServerHello", "pq_hybrid", False))
        if ch:
            dep = [v for v in ch["versions_offered"] if v in DEPRECATED]
            if dep:
                add("TLS-004", f"offers {', '.join(dep)}", _ev(s, "ClientHello", "versions_offered", ch["versions_offered"]),
                    sev="MEDIUM" if "SSLv3" in dep else None)
            if ch["fallback_scsv"]:
                add("TLS-005", "TLS_FALLBACK_SCSV in ClientHello", _ev(s, "ClientHello", "fallback_scsv", True))
            if ch["offered_insecure"] or ch["offered_weak"]:
                bad = ch["offered_insecure"] + ch["offered_weak"]
                add("CS-005", f"{len(bad)} weak/insecure suites offered (e.g. {bad[0]})", _ev(s, "ClientHello", "offered_weak", bad[:5]),
                    sev="MEDIUM" if ch["offered_insecure"] else "LOW", variant="insecure suites offered" if ch["offered_insecure"] else "weak suites offered")
        fatal = [a for a in tls["alerts"] if a["level"] == "fatal"]
        if fatal or (not tls["completed"] and tls["server_hello"] is None and tls["client_hello"] is not None):
            add("TLS-002", ("fatal alert " + fatal[0]["description"] + f" from {fatal[0]['from']}") if fatal else "no ServerHello observed",
                _ev(s, "Alert", "alerts", tls["alerts"]))
        if neg and not tls["certificate_visible"] and not tls["resumed"] and neg["version_id"] == 0x0304:
            add("CE-016", "Certificate message encrypted (TLS 1.3)", _ev(s, "Certificate", "visible", False))

    # ---------------- certificates
    if chain and chain["certificates"]:
        leaf = chain["certificates"][0]
        ce = lambda m, f, v: _ev(s, m, f, v, fingerprint=leaf["fingerprint_sha256"])  # noqa: E731
        if leaf["expired"]:
            add("CE-001", f"expired {leaf['not_after'][:10]}", ce("Certificate", "not_after", leaf["not_after"]))
        elif leaf["not_yet_valid"]:
            add("CE-002", f"valid from {leaf['not_before'][:10]}", ce("Certificate", "not_before", leaf["not_before"]))
        elif leaf["days_remaining"] <= CERT_EXPIRY_WARN_DAYS:
            add("CE-003", f"{leaf['days_remaining']} day(s) remaining", ce("Certificate", "days_remaining", leaf["days_remaining"]),
                sev="HIGH" if leaf["days_remaining"] <= CERT_EXPIRY_CRIT_DAYS else None)
        if chain["self_signed_leaf"] and not chain["trusted"]:
            add("CE-004", f"CN={leaf['subject_cn']}", ce("Certificate", "self_signed", True))
        elif chain["trusted"] is False and not chain["self_signed_leaf"]:
            add("CE-005", f"issuer {leaf['issuer_cn']} not trusted", ce("Certificate", "issuer", leaf["issuer"]))
        if chain.get("ordered") is False:
            add("CE-007", "; ".join(chain["issues"]), ce("Certificate", "chain", chain["issues"]))
        if chain.get("intermediates_expired"):
            add("CE-015", f"intermediate #{chain['intermediates_expired'][0]} expired", ce("Certificate", "intermediates_expired", chain["intermediates_expired"]))
        k = leaf["public_key"]
        if k["algorithm"] == "RSA" and k["size"] < 2048:
            add("CE-008", f"RSA-{k['size']}", ce("Certificate", "public_key", f"RSA-{k['size']}"), sev="CRITICAL" if k["size"] < 1024 else "HIGH", variant=f"RSA-{k['size']}")
        if k["algorithm"] == "EC" and k["size"] < 224:
            add("CE-009", f"EC-{k['size']}", ce("Certificate", "public_key", f"EC-{k['size']}"))
        if k["algorithm"] == "DSA":
            add("CE-014", f"DSA-{k['size']}", ce("Certificate", "public_key", f"DSA-{k['size']}"))
        if leaf["signature"]["weak"]:
            add("CE-010", f"signed with {leaf['signature']['hash'].upper()}", ce("Certificate", "signature_hash", leaf["signature"]["hash"]),
                sev="CRITICAL" if leaf["signature"]["hash"] == "md5" else "HIGH", variant=leaf["signature"]["hash"].upper())
        if chain["hostname_match"] is False:
            add("CE-011", f"SNI '{chain['hostname_checked']}' not in SAN/CN", ce("Certificate", "san", leaf["san"] or [leaf["subject_cn"]]))
        if leaf["validity_days"] > CERT_MAX_VALIDITY_DAYS and not leaf["self_signed"]:
            add("CE-012", f"{leaf['validity_days']} days", ce("Certificate", "validity_days", leaf["validity_days"]))
        if not leaf["san"]:
            add("CE-013", "no SAN extension", ce("Certificate", "san", []))

    # ---------------- message layer
    ms = s["message_security"]
    if ms["layer"] != "none":
        add("MS-001", f"{ms['layer'].upper()} protected content detected", _ev(s, "message body", "layer", ms["layer"]))
        if mode == "plaintext":
            add("MS-002", "protected message carried over unencrypted transport", _ev(s, "message body", "transport", mode))
        if ms["pgp"]["no_integrity_protection"]:
            add("MS-004", f"{ms['pgp']['no_integrity_protection']} message(s) without MDC", _ev(s, "OpenPGP packet", "tag", 9))
        weak_cert = any(c["signature"]["weak"] or (c["public_key"]["algorithm"] == "RSA" and c["public_key"]["size"] < 2048) for c in ms["smime"]["signer_certificates"])
        if ms["smime"]["weak_hash"] or weak_cert:
            add("MS-003", "weak S/MIME signature hash or signer key", _ev(s, "S/MIME", "micalg", ms["smime"]["micalg"]))

    # de-duplicate (rule, variant) within a session keeping the highest severity
    best: dict = {}
    for h in hits:
        k = (h["rule_id"], h["variant"])
        if k not in best or SEV_RANK[h["severity"]] > SEV_RANK[best[k]["severity"]]:
            best[k] = h
    return list(best.values())


def aggregate_findings(sessions: list[dict], totals: dict[str, int]) -> list[dict]:
    """Group per-session hits into findings keyed by (rule, endpoint, variant)."""
    groups: dict = defaultdict(list)
    for s in sessions:
        for h in s["_hits"]:
            groups[(h["rule_id"], s["endpoint"], h["variant"])].append((s, h))
    findings = []
    for (rid, ep, variant), items in groups.items():
        meta = RULES[rid]
        sev = max((h["severity"] for _, h in items), key=lambda x: SEV_RANK[x])
        sess = [s for s, _ in items]
        total = totals.get(ep, len(sess))
        findings.append({
            "finding_id": None, "rule_id": rid, "variant": variant, "title": meta["title"] + (f" - {variant}" if variant else ""),
            "severity": sev, "category": meta["category"], "source": "rule", "endpoint": ep,
            "server_name": next((x["server_name"] for x in sess if x["server_name"]), None), "protocol": sess[0]["protocol"],
            "description": meta["description"], "detail": items[0][1]["detail"], "why_it_matters": meta["why_it_matters"],
            "affected_sessions": len(sess), "total_sessions": total, "exposure_ratio": round(len(sess) / max(total, 1), 4),
            "session_ids": [x["session_id"] for x in sess[:100]], "evidence": [h["evidence"] for _, h in items[:5]],
            "remediation": meta["remediation"], "config_hints": meta["config_hints"], "effort": meta["effort"],
            "references": meta["references"], "first_seen": min(x["timing"]["start_ts"] for x in sess),
            "last_seen": max(x["timing"]["start_ts"] for x in sess)})
    return findings


def prioritise(findings: list[dict]) -> list[dict]:
    """Threat prioritisation: severity base + exposure + context bonuses -> P1..P4, ranked."""
    for f in findings:
        score = SEV_BASE[f["severity"]] + 30 * f.get("exposure_ratio", 0)
        if f["rule_id"] in ("TR-001", "TR-003"):
            score += 15
        if f["category"] == "drift":
            score += 10
        if f["effort"] == "low" and f["severity"] not in ("INFO",):
            score += 3
        f["priority_score"] = round(score, 1)
        f["priority"] = "P1" if score >= 100 else "P2" if score >= 70 else "P3" if score >= 40 else "P4"
        f["quick_win"] = f["effort"] == "low" and SEV_RANK[f["severity"]] >= SEV_RANK["MEDIUM"]
    findings.sort(key=lambda f: (-f["priority_score"], -SEV_RANK[f["severity"]], f["title"]))
    for i, f in enumerate(findings, 1):
        f["rank"], f["finding_id"] = i, f"F-{i:03d}"
    return findings


def remediation_plan(findings: list[dict]) -> list[dict]:
    plan: dict = {}
    for f in findings:
        if f["severity"] == "INFO":
            continue
        for step in f["remediation"][:2]:
            e = plan.setdefault(step, {"action": step, "priority": f["priority"], "resolves": [], "finding_ids": [], "effort": f["effort"]})
            if f["rule_id"] not in e["resolves"]:
                e["resolves"].append(f["rule_id"]); e["finding_ids"].append(f["finding_id"])
    return list(plan.values())
