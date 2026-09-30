"""Automatic identification of SMTP / IMAP / POP3 (banner + command + port evidence) and transport mode."""
from __future__ import annotations
import re
from dataclasses import dataclass, field

from ..config import MAIL_PORTS, IMPLICIT_TLS_PORTS, PROTOCOL_MIN_CONFIDENCE
from .tls_parser import find_tls_start

SMTP_BANNER_HINT = re.compile(r"smtp|mail|postfix|exim|sendmail|exchange|qmail|haraka|zimbra|opensmtpd|mx", re.I)
SMTP_CMD = re.compile(r"^(EHLO|HELO|MAIL FROM|RCPT TO|STARTTLS|AUTH|RSET|VRFY|QUIT)\b", re.I | re.M)
IMAP_CMD = re.compile(r"^\S+ (CAPABILITY|LOGIN|AUTHENTICATE|STARTTLS|SELECT|EXAMINE|LIST|NOOP|LOGOUT|ID|IDLE)\b", re.I | re.M)
POP3_CMD = re.compile(r"^(USER|PASS|CAPA|STLS|STAT|APOP|RETR|DELE|UIDL|QUIT|AUTH)\b", re.I | re.M)


@dataclass
class Detection:
    protocol: str
    confidence: float
    mode: str                      # implicit_tls | starttls | plaintext
    tls_start_c2s: int | None
    tls_start_s2c: int | None
    evidence: list = field(default_factory=list)


def detect(flow) -> Detection | None:
    c2s, s2c = flow.c2s.data, flow.s2c.data
    tc, ts_ = find_tls_start(c2s, 1), find_tls_start(s2c, 2)
    c_plain = c2s[: tc if tc is not None else len(c2s)]
    s_plain = s2c[: ts_ if ts_ is not None else len(s2c)]
    head_s = s_plain[:1024].decode("latin-1")
    head_c = c_plain[:2048].decode("latin-1")
    votes = {"SMTP": 0.0, "IMAP": 0.0, "POP3": 0.0}
    ev: list[str] = []
    port = flow.server[1]
    if port in MAIL_PORTS:
        votes[MAIL_PORTS[port][0]] += 0.4
        ev.append(f"server port {port}")
    if re.match(r"^220[ -]", head_s) and (SMTP_BANNER_HINT.search(head_s.split("\n", 1)[0]) or SMTP_CMD.search(head_c)):
        votes["SMTP"] += 0.4; ev.append("SMTP 220 banner")
    if re.match(r"^\* (OK|PREAUTH)", head_s):
        votes["IMAP"] += 0.5; ev.append("IMAP untagged OK banner")
    if re.match(r"^\+OK", head_s):
        votes["POP3"] += 0.5; ev.append("POP3 +OK banner")
    if SMTP_CMD.search(head_c) and not IMAP_CMD.search(head_c):
        votes["SMTP"] += 0.3; ev.append("SMTP commands")
    if IMAP_CMD.search(head_c):
        votes["IMAP"] += 0.4; ev.append("IMAP tagged commands")
    if POP3_CMD.search(head_c) and not IMAP_CMD.search(head_c) and not SMTP_CMD.search(head_c.replace("AUTH", "")):
        votes["POP3"] += 0.3; ev.append("POP3 commands")
    if tc == 0 and port in IMPLICIT_TLS_PORTS:
        votes[MAIL_PORTS[port][0]] += 0.3; ev.append("TLS from first byte on implicit-TLS mail port")
    proto = max(votes, key=votes.get)
    conf = min(votes[proto], 1.0)
    if conf < PROTOCOL_MIN_CONFIDENCE:
        return None
    if tc == 0:
        mode = "implicit_tls"
    elif tc is not None or ts_ is not None:
        mode = "starttls"
    else:
        mode = "plaintext"
    return Detection(proto, round(conf, 2), mode, tc, ts_, ev)
