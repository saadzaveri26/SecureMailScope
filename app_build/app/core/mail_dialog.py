"""Plaintext SMTP / IMAP / POP3 dialog analysis: capabilities, STARTTLS negotiation, cleartext auth."""
from __future__ import annotations
import base64
import re

SOFTWARE = [("Postfix", r"postfix"), ("Exim", r"exim"), ("Sendmail", r"sendmail"), ("Microsoft Exchange", r"microsoft esmtp|exchange"),
            ("Dovecot", r"dovecot"), ("Courier", r"courier"), ("Cyrus", r"cyrus"), ("qmail", r"qmail"), ("OpenSMTPD", r"opensmtpd"),
            ("Haraka", r"haraka"), ("Zimbra", r"zimbra"), ("Gmail", r"gsmtp|gimap|gmail"), ("Zoho", r"zoho"), ("Office 365", r"outlook\.com|office365")]
CLEARTEXT_MECHS = {"PLAIN", "LOGIN", "XOAUTH2", "OAUTHBEARER"}
WEAK_MECHS = {"CRAM-MD5", "DIGEST-MD5", "NTLM", "APOP", "SCRAM-SHA-1"}


def _lines(data: bytes) -> list[str]:
    return [ln.rstrip(b"\r").decode("latin-1") for ln in data.split(b"\n") if ln.strip(b"\r")]


def _software(banner: str | None) -> str | None:
    if not banner:
        return None
    for name, pat in SOFTWARE:
        if re.search(pat, banner, re.I):
            return name
    return None


def _b64_user(tok: str) -> str | None:
    try:
        raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=False)
        parts = raw.split(b"\x00")
        u = (parts[1] if len(parts) >= 3 else parts[0]).decode("latin-1")
        return _mask(u) if u.isprintable() and u else None
    except Exception:  # noqa: BLE001
        return None


def _mask(u: str) -> str:
    return (u[:2] + "***") if len(u) > 2 else "***"


def _blank(protocol: str) -> dict:
    return {"protocol": protocol, "banner": None, "server_software": None, "commands_count": 0, "commands": [],
            "starttls": {"advertised": False, "requested": False, "accepted": None, "response": None, "tls_started": False,
                         "failed": False, "injection_suspected": False, "commands_after_starttls": 0},
            "auth": {"advertised_cleartext": [], "advertised": [], "attempted": False, "mechanisms": [], "credentials_exposed": False,
                     "weak_challenge_response": False, "success": None, "username_hint": None},
            "transactions": {"mail_from": 0, "rcpt_to": 0, "messages": 0, "retr": 0, "fetch": 0, "logindisabled": False}}


# ------------------------------------------------------------------ SMTP
def _smtp_client(data: bytes) -> tuple[list[str], list[bytes]]:
    cmds: list[str] = []
    bodies: list[bytes] = []
    i, n = 0, len(data)
    while i < n:
        j = data.find(b"\n", i)
        line, i = (data[i:], n) if j == -1 else (data[i:j], j + 1)
        s = line.rstrip(b"\r").decode("latin-1")
        cmds.append(s)
        up = s.upper()
        if up == "DATA":
            end = data.find(b"\r\n.\r\n", max(i - 2, 0))
            if end == -1:
                bodies.append(data[i:]); i = n
            else:
                bodies.append(data[i:end + 2]); i = end + 5
            cmds.append(".")
        elif up.startswith("BDAT "):
            try:
                size = int(s.split()[1])
            except (IndexError, ValueError):
                size = 0
            bodies.append(data[i:i + size]); i += size
    return cmds, bodies


def _smtp_replies(data: bytes) -> list[list[str]]:
    out, cur = [], []
    for ln in _lines(data):
        m = re.match(r"^(\d{3})([ -])", ln)
        if not m:
            continue
        cur.append(ln)
        if m.group(2) == " ":
            out.append(cur); cur = []
    if cur:
        out.append(cur)
    return out


def analyze_smtp(c2s: bytes, s2c: bytes, tls_started: bool) -> tuple[dict, list[bytes]]:
    d = _blank("SMTP")
    cmds, bodies = _smtp_client(c2s)
    replies = _smtp_replies(s2c)
    if replies and replies[0][0].startswith("220"):
        d["banner"] = replies[0][0][4:].strip()
    d["server_software"] = _software(d["banner"])
    st, au, tx = d["starttls"], d["auth"], d["transactions"]
    for r in replies:
        for ln in r:
            if re.match(r"^250[- ]STARTTLS\b", ln, re.I):
                st["advertised"] = True
            m = re.match(r"^250[- ]AUTH[ =](.*)$", ln, re.I)
            if m:
                au["advertised"] = m.group(1).upper().split()
    au["advertised_cleartext"] = [m for m in au["advertised"] if m in CLEARTEXT_MECHS or m in WEAK_MECHS]
    cmd_idx = None
    for idx, c in enumerate(cmds):
        up = c.strip().upper()
        reply = replies[idx + 1] if idx + 1 < len(replies) else None
        if up == "STARTTLS":
            st["requested"], cmd_idx = True, idx
            if reply:
                st["response"] = reply[-1]
                st["accepted"] = reply[-1].startswith("220")
        elif up.startswith("MAIL FROM"):
            tx["mail_from"] += 1
        elif up.startswith("RCPT TO"):
            tx["rcpt_to"] += 1
        elif up.startswith("AUTH "):
            toks = c.split()
            mech = toks[1].upper()
            au["attempted"] = True
            au["mechanisms"].append(mech)
            if mech in CLEARTEXT_MECHS:
                au["credentials_exposed"] = True
                if len(toks) > 2 and mech == "PLAIN":
                    au["username_hint"] = _b64_user(toks[2])
                elif mech == "LOGIN" and idx + 1 < len(cmds):
                    au["username_hint"] = _b64_user(cmds[idx + 1].strip())
            elif mech in WEAK_MECHS:
                au["weak_challenge_response"] = True
            if any(r[-1].startswith("235") for r in replies[idx + 1:]):
                au["success"] = True
        if idx < 40 and up and up != ".":
            d["commands"].append(up.split()[0][:12])
    tx["messages"] = len(bodies)
    d["commands_count"] = len([c for c in cmds if c.strip() and c != "."])
    if cmd_idx is not None:
        st["commands_after_starttls"] = len([c for c in cmds[cmd_idx + 1:] if c.strip() and c != "."])
    _finish(st, tls_started)
    return d, bodies


# ------------------------------------------------------------------ IMAP
def analyze_imap(c2s: bytes, s2c: bytes, tls_started: bool) -> tuple[dict, list[bytes]]:
    d = _blank("IMAP")
    cl, sl = _lines(c2s), _lines(s2c)
    st, au, tx = d["starttls"], d["auth"], d["transactions"]
    if sl and re.match(r"^\* (OK|PREAUTH)", sl[0]):
        d["banner"] = sl[0][2:].strip()
    d["server_software"] = _software(d["banner"])
    caps: set = set()
    for ln in sl:
        m = re.match(r"^\* CAPABILITY (.*)$", ln, re.I) or re.search(r"\[CAPABILITY ([^\]]*)\]", ln, re.I)
        if m:
            caps |= set(m.group(1).upper().split())
    st["advertised"] = "STARTTLS" in caps
    tx["logindisabled"] = "LOGINDISABLED" in caps
    au["advertised"] = sorted(c[5:] for c in caps if c.startswith("AUTH="))
    if not tx["logindisabled"] and caps:
        au["advertised_cleartext"] = ["LOGIN"]
    cmds = []
    for ln in cl:
        m = re.match(r"^(\S+) ([A-Za-z]+)(?: (.*))?$", ln)
        if m:
            cmds.append((m.group(1), m.group(2).upper(), m.group(3) or "", ln))
    st_i = None
    for i, (tag, verb, arg, raw) in enumerate(cmds):
        if verb == "STARTTLS":
            st["requested"], st_i = True, i
            for ln in sl:
                m = re.match(rf"^{re.escape(tag)} (OK|NO|BAD)\b(.*)$", ln, re.I)
                if m:
                    st["response"] = ln
                    st["accepted"] = m.group(1).upper() == "OK"
                    break
        elif verb == "LOGIN":
            au.update(attempted=True, credentials_exposed=True)
            au["mechanisms"].append("LOGIN")
            au["username_hint"] = _mask(arg.split()[0].strip('"')) if arg else None
            au["success"] = any(re.match(rf"^{re.escape(tag)} OK", ln, re.I) for ln in sl) or None
        elif verb == "AUTHENTICATE":
            mech = (arg.split() or ["?"])[0].upper()
            au["attempted"] = True
            au["mechanisms"].append(mech)
            if mech in CLEARTEXT_MECHS:
                au["credentials_exposed"] = True
            elif mech in WEAK_MECHS:
                au["weak_challenge_response"] = True
        elif verb in ("FETCH", "UID"):
            tx["fetch"] += 1
        if i < 40:
            d["commands"].append(verb[:12])
    d["commands_count"] = len(cmds)
    if st_i is not None:
        st["commands_after_starttls"] = len(cmds) - st_i - 1
    _finish(st, tls_started)
    return d, [c2s, s2c]


# ------------------------------------------------------------------ POP3
def analyze_pop3(c2s: bytes, s2c: bytes, tls_started: bool) -> tuple[dict, list[bytes]]:
    d = _blank("POP3")
    st, au, tx = d["starttls"], d["auth"], d["transactions"]
    cmds = [ln for ln in _lines(c2s)]
    lines = _lines(s2c)
    p = 0

    def status():
        nonlocal p
        while p < len(lines) and not lines[p].startswith(("+OK", "-ERR", "+ ", "+")):
            p += 1
        if p >= len(lines):
            return None
        ln = lines[p]; p += 1
        return ln

    banner = status()
    d["banner"] = banner[3:].strip() if banner and banner.startswith("+OK") else None
    d["server_software"] = _software(d["banner"])
    replies = []
    for c in cmds:
        stl = status()
        body: list[str] = []
        toks = c.split()
        verb = toks[0].upper() if toks else ""
        if stl and stl.startswith("+OK") and (verb in ("CAPA", "RETR", "TOP") or (verb in ("LIST", "UIDL", "AUTH") and len(toks) == 1)):
            while p < len(lines) and lines[p] != ".":
                body.append(lines[p]); p += 1
            p += 1
        replies.append((stl, body))
    st_i = None
    for i, c in enumerate(cmds):
        toks = c.split()
        verb = toks[0].upper() if toks else ""
        stl, body = replies[i]
        if verb == "CAPA" and stl and stl.startswith("+OK"):
            up = [b.upper() for b in body]
            st["advertised"] = st["advertised"] or "STLS" in up
            if any(b.startswith("USER") for b in up):
                au["advertised_cleartext"] = ["USER/PASS"]
            for b in up:
                if b.startswith("SASL"):
                    au["advertised"] = b.split()[1:]
        elif verb == "STLS":
            st["requested"], st_i = True, i
            st["response"] = stl
            st["accepted"] = bool(stl and stl.startswith("+OK"))
        elif verb == "USER":
            au.update(attempted=True, credentials_exposed=True)
            au["mechanisms"].append("USER/PASS")
            au["username_hint"] = _mask(toks[1]) if len(toks) > 1 else None
        elif verb == "PASS":
            au["success"] = bool(stl and stl.startswith("+OK"))
        elif verb == "APOP":
            au.update(attempted=True, weak_challenge_response=True)
            au["mechanisms"].append("APOP")
        elif verb == "AUTH" and len(toks) > 1:
            mech = toks[1].upper()
            au["attempted"] = True
            au["mechanisms"].append(mech)
            if mech in CLEARTEXT_MECHS:
                au["credentials_exposed"] = True
        elif verb == "RETR":
            tx["retr"] += 1
        if i < 40 and verb:
            d["commands"].append(verb[:12])
    d["commands_count"] = len(cmds)
    if st_i is not None:
        st["commands_after_starttls"] = len(cmds) - st_i - 1
    _finish(st, tls_started)
    return d, [c2s, s2c]


def _finish(st: dict, tls_started: bool) -> None:
    st["tls_started"] = tls_started
    if tls_started and st["requested"] and st["accepted"] is None:
        st["accepted"] = True
    st["failed"] = bool(st["requested"] and st["accepted"] is False)
    st["injection_suspected"] = bool(tls_started and st["requested"] and st["commands_after_starttls"] > 0)


def analyze_dialog(protocol: str, c2s_plain: bytes, s2c_plain: bytes, tls_started: bool) -> tuple[dict, list[bytes]]:
    fn = {"SMTP": analyze_smtp, "IMAP": analyze_imap, "POP3": analyze_pop3}[protocol]
    return fn(c2s_plain, s2c_plain, tls_started)
