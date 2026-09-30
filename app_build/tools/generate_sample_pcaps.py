#!/usr/bin/env python3
"""Generate two synthetic mail-server captures for demo/testing:

  securemail_baseline.pcap  - healthy posture (TLS 1.3/1.2, ECDHE+AEAD, valid enterprise-CA certificate, STARTTLS everywhere)
  securemail_drift.pcap     - same servers one month later with realistic regressions:
        TLS 1.1 + 3DES sessions, replaced certificate from an unknown CA, STARTTLS stripping, plaintext SMTP/POP3,
        expiring certificate, 1024-bit DHE, downgrade sentinel, PGP / S-MIME over cleartext, legacy SMTPS server.

Usage:  python tools/generate_sample_pcaps.py [--out ../production_artifacts/samples] [--no-install-ca]
"""
from __future__ import annotations
import argparse
import base64
import datetime as dt
import random
import socket
import sys
from pathlib import Path

import dpkt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

FIN, SYN, PSH, ACK = 0x01, 0x02, 0x08, 0x10
rb = random.randbytes
u16 = lambda n: n.to_bytes(2, "big")  # noqa: E731
u24 = lambda n: n.to_bytes(3, "big")  # noqa: E731


# ------------------------------------------------------------------ certificates
def utc(y, m, d):
    return dt.datetime(y, m, d, tzinfo=dt.timezone.utc)


def mk_cert(cn, org, *, issuer=None, issuer_key=None, bits=2048, nb, na, san=None, ca=False, hash_alg=None, key=None):
    key = key or rsa.generate_private_key(65537, bits)
    subj = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org), x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(issuer.subject if issuer else subj).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False)
    cert = b.sign(issuer_key or key, hash_alg or hashes.SHA256())
    return cert, key


def der(c):
    return c.public_bytes(serialization.Encoding.DER)


def make_pki():
    root, rk = mk_cert("Synthetic Corp Root CA", "Synthetic Corp", nb=utc(2020, 1, 1), na=utc(2040, 1, 1), ca=True)
    inter, ik = mk_cert("Synthetic Corp Issuing CA", "Synthetic Corp", issuer=root, issuer_key=rk, nb=utc(2022, 1, 1), na=utc(2035, 1, 1), ca=True)
    host = ["mail.company.com", "imap.company.com", "smtp.company.com", "pop.company.com"]
    A, _ = mk_cert("mail.company.com", "Company Ltd", issuer=inter, issuer_key=ik, nb=utc(2026, 1, 10), na=utc(2027, 1, 10), san=host)
    rogue_root, rrk = mk_cert("Unknown Trust Services CA", "Unknown Trust", nb=utc(2024, 1, 1), na=utc(2034, 1, 1), ca=True)
    B, _ = mk_cert("mail.company.com", "Company Ltd", issuer=rogue_root, issuer_key=rrk, nb=utc(2026, 9, 20), na=utc(2027, 9, 20), san=host)
    C, _ = mk_cert("mail.company.com", "Company Ltd", issuer=inter, issuer_key=ik, nb=utc(2025, 10, 5), na=utc(2026, 10, 10), san=host)
    key1024 = rsa.generate_private_key(65537, 1024)
    try:
        legacy, _ = mk_cert("legacy-mx.company.com", "Company Ltd", bits=1024, key=key1024, nb=utc(2019, 1, 1), na=utc(2024, 1, 1), hash_alg=hashes.SHA1())
    except Exception:  # noqa: BLE001
        legacy, _ = mk_cert("legacy-mx.company.com", "Company Ltd", bits=1024, key=key1024, nb=utc(2019, 1, 1), na=utc(2024, 1, 1))
    smime, smk = mk_cert("alice@company.com", "Company Ltd", issuer=inter, issuer_key=ik, nb=utc(2026, 1, 10), na=utc(2027, 1, 10))
    return {"root": root, "inter": inter, "A": A, "B": B, "C": C, "legacy": legacy, "smime": (smime, smk)}


# ------------------------------------------------------------------ packet capture model
class Cap:
    def __init__(self):
        self.pkts: list[tuple[float, bytes]] = []
        self.ident = 1

    def add(self, ts, src, sport, dst, dport, seq, ack, flags, payload=b""):
        tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq & 0xFFFFFFFF, ack=ack & 0xFFFFFFFF, flags=flags, win=65535, data=payload)
        ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=6, id=self.ident & 0xFFFF, data=tcp)
        self.ident += 1
        eth = dpkt.ethernet.Ethernet(src=b"\x02\x00\x00\x00\x00\x01", dst=b"\x02\x00\x00\x00\x00\x02", type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
        self.pkts.append((ts, bytes(eth)))

    def write(self, path: Path):
        self.pkts.sort(key=lambda p: p[0])
        with open(path, "wb") as f:
            w = dpkt.pcap.Writer(f)
            for ts, b in self.pkts:
                w.writepkt(b, ts=ts)


class Conn:
    def __init__(self, cap, t, cip, cport, sip, sport, rtt=0.004):
        self.cap, self.t, self.rtt = cap, t, rtt
        self.a = (cip, cport, sip, sport)
        self.cseq, self.sseq = random.randrange(1000, 2 ** 31), random.randrange(1000, 2 ** 31)
        cap.add(t, cip, cport, sip, sport, self.cseq, 0, SYN)
        self.cseq += 1
        self.t += rtt
        cap.add(self.t, sip, sport, cip, cport, self.sseq, self.cseq, SYN | ACK)
        self.sseq += 1
        self.t += 0.0002
        cap.add(self.t, cip, cport, sip, sport, self.cseq, self.sseq, ACK)

    def _send(self, client: bool, data: bytes, think: float):
        if not data:
            return
        cip, cport, sip, sport = self.a
        self.t += think
        segs = [data[i:i + 1400] for i in range(0, len(data), 1400)]
        times = [self.t + i * 0.0002 for i in range(len(segs))]
        if len(segs) > 1 and random.random() < 0.05:
            times[0], times[1] = times[1], times[0]                     # out-of-order delivery
        seq0 = self.cseq if client else self.sseq
        ack = self.sseq if client else self.cseq
        for i, (seg, ts) in enumerate(zip(segs, times)):
            args = (cip, cport, sip, sport) if client else (sip, sport, cip, cport)
            self.cap.add(ts, *args, seq0 + i * 1400, ack, PSH | ACK, seg)
            if random.random() < 0.02:                                   # retransmission
                self.cap.add(ts + 0.2, *args, seq0 + i * 1400, ack, PSH | ACK, seg)
        if client:
            self.cseq += len(data)
        else:
            self.sseq += len(data)
        self.t = max(times) + self.rtt / 2

    def c(self, data, think=0.001):
        self._send(True, data if isinstance(data, bytes) else data.encode(), think)

    def s(self, data, think=0.002):
        self._send(False, data if isinstance(data, bytes) else data.encode(), think)

    def close(self):
        cip, cport, sip, sport = self.a
        self.t += 0.01
        self.cap.add(self.t, cip, cport, sip, sport, self.cseq, self.sseq, FIN | ACK)
        self.cap.add(self.t + self.rtt, sip, sport, cip, cport, self.sseq, self.cseq + 1, FIN | ACK)


# ------------------------------------------------------------------ TLS builders
def ext(t, d):
    return u16(t) + u16(len(d)) + d


def rec(ct, ver, frag):
    return bytes([ct]) + u16(ver) + u16(len(frag)) + frag


def hs(t, body):
    return bytes([t]) + u24(len(body)) + body


MODERN = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
LEGACY = [0xC014, 0xC013, 0x0035, 0x002F, 0x000A, 0x0005]


def hs_client_hello(sni, suites, *, versions=None, legacy=0x0303, groups=(29, 23, 24), fallback=False, ems=True, reneg=True, sid=None):
    e = b""
    if sni:
        n = sni.encode()
        e += ext(0, u16(len(n) + 3) + b"\x00" + u16(len(n)) + n)
    e += ext(10, u16(len(groups) * 2) + b"".join(u16(g) for g in groups)) + ext(11, b"\x01\x00")
    e += ext(13, u16(6) + u16(0x0403) + u16(0x0804) + u16(0x0401))
    if versions:
        e += ext(43, bytes([len(versions) * 2]) + b"".join(u16(v) for v in versions)) + ext(51, u16(36) + u16(29) + u16(32) + rb(32))
    e += ext(35, b"")
    if ems:
        e += ext(23, b"")
    if reneg:
        e += ext(0xFF01, b"\x00")
    sl = list(suites) + ([0x5600] if fallback else [])
    sb = b"".join(u16(s) for s in sl)
    sid = rb(32) if sid is None else sid
    return hs(1, u16(legacy) + rb(32) + bytes([len(sid)]) + sid + u16(len(sb)) + sb + b"\x01\x00" + u16(len(e)) + e), sid


def hs_server_hello(version, suite, sid, *, tls13=False, group=29, reneg=True, ems=True, compression=0, downgrade=False):
    rnd = rb(32)
    if downgrade:
        rnd = rnd[:24] + b"DOWNGRD\x01"
    e = b""
    if tls13:
        e += ext(43, u16(0x0304)) + ext(51, u16(group) + u16(32) + rb(32))
        legacy = 0x0303
    else:
        legacy = version
        if reneg:
            e += ext(0xFF01, b"\x00")
        if ems:
            e += ext(23, b"")
    return hs(2, u16(legacy) + rnd + bytes([len(sid)]) + sid + u16(suite) + bytes([compression]) + u16(len(e)) + e)


def hs_cert(chain):
    body = b"".join(u24(len(d)) + d for d in chain)
    return hs(11, u24(len(body)) + body)


def hs_ske(kex, version, *, curve=23, dh_bits=2048, sigalg=0x0401):
    if kex == "ECDHE":
        b = b"\x03" + u16(curve) + bytes([65]) + b"\x04" + rb(64)
    else:
        p = bytearray(rb(dh_bits // 8)); p[0] |= 0x80
        b = u16(len(p)) + bytes(p) + u16(1) + b"\x02" + u16(len(p)) + rb(len(p))
    if version >= 0x0303:
        b += u16(sigalg) + u16(256) + rb(256)
    else:
        b += u16(128) + rb(128)
    return hs(12, b)


def tls_session(conn: Conn, sp: dict):
    v, suite = sp["version"], sp["suite"]
    versions = [0x0304, 0x0303] if sp.get("offer13", v == 0x0304) else None
    legacy = sp.get("ch_legacy", 0x0303)
    ch, sid = hs_client_hello(sp.get("sni"), sp.get("ch_suites", MODERN), versions=versions, legacy=legacy, fallback=sp.get("fallback", False),
                              ems=sp.get("ems", True), reneg=sp.get("reneg", True))
    conn.c(rec(22, 0x0301, ch))
    if "alert" in sp:
        conn.s(rec(21, 0x0303, bytes([2, sp["alert"]])))
        conn.close()
        return
    if v == 0x0304:
        conn.s(rec(22, 0x0303, hs_server_hello(v, suite, sid, tls13=True, group=sp.get("group", 29))) + rec(20, 0x0303, b"\x01") + rec(23, 0x0303, rb(random.randint(1100, 2400))))
        conn.c(rec(20, 0x0303, b"\x01") + rec(23, 0x0303, rb(74)))
        conn.s(rec(23, 0x0303, rb(230)), think=0.0005)
        ver = 0x0303
    else:
        parts = [hs_server_hello(v, suite, b"", reneg=sp.get("reneg", True), ems=sp.get("ems", True), compression=sp.get("compression", 0), downgrade=sp.get("downgrade", False))]
        if sp.get("chain"):
            parts.append(hs_cert(sp["chain"]))
        kex = sp.get("kex", "ECDHE")
        if kex in ("ECDHE", "DHE"):
            parts.append(hs_ske(kex, v, curve=sp.get("curve", 23), dh_bits=sp.get("dh_bits", 2048), sigalg=sp.get("sigalg", 0x0401)))
        parts.append(hs(14, b""))
        conn.s(b"".join(rec(22, v, p) for p in parts) if random.random() < 0.5 else rec(22, v, b"".join(parts)))
        cke = hs(16, bytes([65]) + b"\x04" + rb(64)) if kex == "ECDHE" else hs(16, u16(256) + rb(256))
        conn.c(rec(22, v, cke) + rec(20, v, b"\x01") + rec(22, v, rb(40)))
        conn.s(rec(22, v, hs(4, rb(200))) + rec(20, v, b"\x01") + rec(22, v, rb(40)) if sp.get("ticket") else rec(20, v, b"\x01") + rec(22, v, rb(40)), think=0.001)
        ver = v
    for _ in range(random.randint(2, 5)):
        conn.c(rec(23, ver, rb(random.randint(40, 300))), think=0.002)
        conn.s(rec(23, ver, rb(random.randint(60, 1400))), think=0.003)
    conn.close()


# ------------------------------------------------------------------ mail dialogs
def ehlo_reply(host, starttls=True, auth=False):
    ls = [f"250-{host}", "250-PIPELINING", "250-SIZE 52428800"] + (["250-STARTTLS"] if starttls else []) + (["250-AUTH PLAIN LOGIN"] if auth else []) + ["250-ENHANCEDSTATUSCODES", "250 8BITMIME"]
    return "\r\n".join(ls) + "\r\n"


def pgp_armor(no_mdc=False):
    body = bytes([0xC1, ((268 - 192) >> 8) + 192, (268 - 192) & 0xFF]) + b"\x03" + rb(8) + b"\x01" + u16(2047) + rb(256)
    body += (bytes([0xC9, 101]) if no_mdc else bytes([0xD2, 101])) + b"\x01" + rb(100)
    b64 = base64.b64encode(body).decode()
    lines = "\r\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PGP MESSAGE-----\r\nVersion: GnuPG v2\r\n\r\n{lines}\r\n=AbCd\r\n-----END PGP MESSAGE-----\r\n"


def smime_signed(pki):
    cert, key = pki["smime"]
    sig = pkcs7.PKCS7SignatureBuilder().set_data(b"Quarterly numbers attached.").add_signer(cert, key, hashes.SHA256()).sign(
        serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
    b64 = base64.b64encode(sig).decode()
    b64 = "\r\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return ('Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg=sha-256; boundary="BND"\r\n\r\n--BND\r\n'
            'Content-Type: text/plain\r\n\r\nQuarterly numbers attached.\r\n--BND\r\nContent-Type: application/x-pkcs7-signature; name="smime.p7s"\r\n'
            f"Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BND--\r\n")


def smtp_transaction(conn, body="Subject: hello\r\n\r\nHi there.\r\n"):
    for cmd, reply in (("MAIL FROM:<alice@company.com>", "250 2.1.0 Ok"), ("RCPT TO:<bob@partner.org>", "250 2.1.5 Ok")):
        conn.c(cmd + "\r\n"); conn.s(reply + "\r\n")
    conn.c("DATA\r\n"); conn.s("354 End data with <CR><LF>.<CR><LF>\r\n")
    conn.c(body + ".\r\n"); conn.s("250 2.0.0 Ok: queued as 4F2A1\r\n")
    conn.c("QUIT\r\n"); conn.s("221 2.0.0 Bye\r\n")
    conn.close()


def smtp_session(conn, host, mode, tls=None, body=None, auth_pre_tls=False):
    conn.s(f"220 {host} ESMTP Postfix\r\n")
    conn.c("EHLO client.example.org\r\n")
    conn.s(ehlo_reply(host, starttls=mode in ("ok", "stripped", "unused"), auth=auth_pre_tls))
    if mode == "ok":
        conn.c("STARTTLS\r\n"); conn.s("220 2.0.0 Ready to start TLS\r\n")
        tls_session(conn, tls)
    elif mode == "stripped":
        conn.c("STARTTLS\r\n"); conn.s("454 4.7.0 TLS not available due to local problem\r\n")
        conn.c("AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n"); conn.s("235 2.7.0 Authentication successful\r\n")
        smtp_transaction(conn, body or "Subject: report\r\n\r\nNumbers.\r\n")
    else:
        smtp_transaction(conn, body or "Subject: hello\r\n\r\nHi there.\r\n")


def imap_session(conn, host, mode, tls=None):
    caps = "IMAP4rev1 SASL-IR ID ENABLE IDLE" + (" STARTTLS LOGINDISABLED" if mode == "starttls" else "")
    conn.s(f"* OK [CAPABILITY {caps}] Dovecot ready.\r\n")
    if mode == "starttls":
        conn.c("a001 STARTTLS\r\n"); conn.s("a001 OK Begin TLS negotiation now.\r\n")
        tls_session(conn, tls)
    else:
        conn.c("a001 LOGIN alice s3cretpw\r\n"); conn.s("a001 OK Logged in\r\n")
        conn.c("a002 SELECT INBOX\r\n"); conn.s("* 3 EXISTS\r\na002 OK [READ-WRITE] Select completed\r\n")
        conn.c("a003 LOGOUT\r\n"); conn.s("* BYE\r\na003 OK Logout completed\r\n"); conn.close()


def pop3_session(conn, mode, tls=None):
    conn.s("+OK Dovecot ready.\r\n")
    conn.c("CAPA\r\n"); conn.s("+OK\r\nCAPA\r\nTOP\r\nUIDL\r\nUSER\r\nSTLS\r\n.\r\n")
    if mode == "stls":
        conn.c("STLS\r\n"); conn.s("+OK Begin TLS negotiation\r\n")
        tls_session(conn, tls)
    else:
        conn.c("USER alice\r\n"); conn.s("+OK\r\n"); conn.c("PASS s3cretpw\r\n"); conn.s("+OK Logged in.\r\n")
        conn.c("STAT\r\n"); conn.s("+OK 2 1830\r\n"); conn.c("QUIT\r\n"); conn.s("+OK Logging out.\r\n"); conn.close()


# ------------------------------------------------------------------ scenarios
class Sim:
    def __init__(self, t0):
        self.cap, self.t = Cap(), t0

    def conn(self, sip, sport, rtt=None):
        self.t += random.uniform(5, 40)
        return Conn(self.cap, self.t, f"10.0.1.{random.randint(10, 200)}", random.randint(40000, 60000), sip, sport, rtt or random.uniform(0.002, 0.012))


def chain_A(p):
    return [der(p["A"]), der(p["inter"])]


def build_baseline(pki, path):
    random.seed(1)
    sim = Sim(dt.datetime(2026, 9, 1, 8, tzinfo=dt.timezone.utc).timestamp())
    H = "mail.company.com"
    jobs = []
    jobs += [("imaps13",)] * 50 + [("imaps12",)] * 30 + [("sub13",)] * 30 + [("sub12",)] * 20 + [("mx13",)] * 25 + [("pops12",)] * 12 + [("imap143",)] * 10
    random.shuffle(jobs)
    for (k,) in jobs:
        s13 = {"version": 0x0304, "suite": random.choice([0x1301, 0x1301, 0x1302]), "sni": H}
        s12 = {"version": 0x0303, "suite": random.choice([0xC030, 0xC02F]), "sni": H, "chain": chain_A(pki), "kex": "ECDHE", "ticket": True}
        if k == "imaps13":
            tls_session(sim.conn("10.0.0.5", 993), s13)
        elif k == "imaps12":
            tls_session(sim.conn("10.0.0.5", 993), s12)
        elif k == "sub13":
            smtp_session(sim.conn("10.0.0.6", 587), H, "ok", s13)
        elif k == "sub12":
            smtp_session(sim.conn("10.0.0.6", 587), H, "ok", s12)
        elif k == "mx13":
            smtp_session(sim.conn("10.0.0.6", 25), H, "ok", s13)
        elif k == "pops12":
            tls_session(sim.conn("10.0.0.7", 995), s12)
        elif k == "imap143":
            imap_session(sim.conn("10.0.0.5", 143), H, "starttls", s13)
    sim.cap.write(path)
    return len(sim.cap.pkts)


def build_drift(pki, path):
    random.seed(2)
    sim = Sim(dt.datetime(2026, 9, 28, 8, tzinfo=dt.timezone.utc).timestamp())
    H = "mail.company.com"
    chB = [der(pki["B"])]
    jobs = ([("imaps13",)] * 30 + [("imaps12B",)] * 20 + [("imaps11",)] * 14 + [("imaps10rc4",)] * 2 + [("imaps_fallback",)] * 2 + [("imaps_alert",)] * 3
            + [("sub13",)] * 20 + [("sub12",)] * 20 + [("sub_strip",)] * 3 + [("mx13",)] * 15 + [("mx_plain",)] * 5 + [("mx_pgp",)] * 1 + [("mx_smime",)] * 1
            + [("pops_C",)] * 10 + [("pops_dhe1024",)] * 2 + [("pop110",)] * 3 + [("imap143",)] * 10 + [("imap143_plain",)] * 2 + [("smtps_legacy",)] * 4)
    random.shuffle(jobs)
    for (k,) in jobs:
        s13 = {"version": 0x0304, "suite": random.choice([0x1301, 0x1302]), "sni": H}
        if k == "imaps13":
            tls_session(sim.conn("10.0.0.5", 993), s13)
        elif k == "imaps12B":
            tls_session(sim.conn("10.0.0.5", 993), {"version": 0x0303, "suite": 0xC030, "sni": H, "chain": chB, "kex": "ECDHE", "ticket": True})
        elif k == "imaps11":
            tls_session(sim.conn("10.0.0.5", 993, rtt=0.02), {"version": 0x0302, "suite": 0x000A, "sni": H, "chain": chB, "kex": "RSA", "ch_suites": LEGACY,
                                                             "ch_legacy": 0x0302, "reneg": False, "ems": False})
        elif k == "imaps10rc4":
            tls_session(sim.conn("10.0.0.5", 993, rtt=0.02), {"version": 0x0301, "suite": 0xC011, "sni": H, "chain": chB, "kex": "ECDHE", "ch_suites": LEGACY,
                                                             "ch_legacy": 0x0301, "reneg": False, "ems": False})
        elif k == "imaps_fallback":
            tls_session(sim.conn("10.0.0.5", 993), {"version": 0x0303, "suite": 0xC02F, "sni": H, "chain": chB, "kex": "ECDHE", "offer13": True, "fallback": True, "downgrade": True})
        elif k == "imaps_alert":
            tls_session(sim.conn("10.0.0.5", 993), {"version": 0x0303, "suite": 0, "sni": H, "alert": 40, "ch_suites": LEGACY})
        elif k == "sub13":
            smtp_session(sim.conn("10.0.0.6", 587), H, "ok", s13)
        elif k == "sub12":
            smtp_session(sim.conn("10.0.0.6", 587), H, "ok", {"version": 0x0303, "suite": 0xC02F, "sni": H, "chain": chain_A(pki), "kex": "ECDHE", "ticket": True})
        elif k == "sub_strip":
            smtp_session(sim.conn("10.0.0.6", 587), H, "stripped")
        elif k == "mx13":
            smtp_session(sim.conn("10.0.0.6", 25), H, "ok", s13)
        elif k == "mx_plain":
            smtp_session(sim.conn("10.0.0.6", 25), H, "none")
        elif k == "mx_pgp":
            smtp_session(sim.conn("10.0.0.6", 25), H, "none", body="Subject: secure\r\nMIME-Version: 1.0\r\n\r\n" + pgp_armor(no_mdc=True))
        elif k == "mx_smime":
            smtp_session(sim.conn("10.0.0.6", 25), H, "none", body="Subject: signed\r\nMIME-Version: 1.0\r\n" + smime_signed(pki))
        elif k == "pops_C":
            tls_session(sim.conn("10.0.0.7", 995), {"version": 0x0303, "suite": 0xC02F, "sni": H, "chain": [der(pki["C"]), der(pki["inter"])], "kex": "ECDHE", "ticket": True})
        elif k == "pops_dhe1024":
            tls_session(sim.conn("10.0.0.7", 995), {"version": 0x0303, "suite": 0x009E, "sni": H, "chain": [der(pki["C"]), der(pki["inter"])], "kex": "DHE", "dh_bits": 1024})
        elif k == "pop110":
            pop3_session(sim.conn("10.0.0.7", 110), "plain")
        elif k == "imap143":
            imap_session(sim.conn("10.0.0.5", 143), H, "starttls", s13)
        elif k == "imap143_plain":
            imap_session(sim.conn("10.0.0.5", 143), H, "plain")
        elif k == "smtps_legacy":
            tls_session(sim.conn("10.0.0.8", 465, rtt=0.03), {"version": 0x0301, "suite": 0x0035, "sni": "legacy-mx.company.com", "chain": [der(pki["legacy"])], "kex": "RSA",
                                                             "ch_suites": LEGACY, "ch_legacy": 0x0301, "reneg": False, "ems": False})
    sim.cap.write(path)
    return len(sim.cap.pkts)


def main():
    root = Path(__file__).resolve().parents[2] / "production_artifacts"
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(root / "samples"))
    ap.add_argument("--no-install-ca", action="store_true", help="do not copy the synthetic enterprise root CA into production_artifacts/trust_store")
    a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    pki = make_pki()
    if not a.no_install_ca:
        ts = root / "trust_store"; ts.mkdir(parents=True, exist_ok=True)
        (ts / "SyntheticCorpRootCA.pem").write_bytes(pki["root"].public_bytes(serialization.Encoding.PEM))
        print(f"installed enterprise root CA -> {ts / 'SyntheticCorpRootCA.pem'}")
    n1 = build_baseline(pki, out / "securemail_baseline.pcap")
    n2 = build_drift(pki, out / "securemail_drift.pcap")
    print(f"wrote {out / 'securemail_baseline.pcap'} ({n1} packets)\nwrote {out / 'securemail_drift.pcap'} ({n2} packets)")


if __name__ == "__main__":
    sys.exit(main())
