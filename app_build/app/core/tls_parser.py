"""Passive TLS record / handshake dissector (SSLv3 - TLS 1.3 visible parts) with JA3/JA3S fingerprints."""
from __future__ import annotations
import hashlib
from .cipher_db import describe, is_grease

VERSION_NAMES = {0x0002: "SSLv2", 0x0300: "SSLv3", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
HS_NAMES = {0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
            11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone",
            15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished", 22: "CertificateStatus"}
ALERT_NAMES = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure", 42: "bad_certificate",
               43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
               47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied", 50: "decode_error", 51: "decrypt_error",
               70: "protocol_version", 71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
               90: "user_canceled", 109: "missing_extension", 112: "unrecognized_name", 116: "certificate_required"}
GROUP_NAMES = {1: "sect163k1", 19: "secp192r1", 21: "secp224r1", 22: "secp256k1", 23: "secp256r1", 24: "secp384r1", 25: "secp521r1",
               26: "brainpoolP256r1", 27: "brainpoolP384r1", 28: "brainpoolP512r1", 29: "x25519", 30: "x448",
               256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192",
               0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024", 0x6399: "X25519Kyber768Draft00"}
PQ_GROUPS = {0x11EB, 0x11EC, 0x11ED, 0x6399}
FFDHE_GROUPS = {256, 257, 258, 259, 260}
WEAK_GROUPS = set(range(1, 21))
SIGALG_NAMES = {0x0101: "rsa_md5", 0x0201: "rsa_pkcs1_sha1", 0x0202: "dsa_sha1", 0x0203: "ecdsa_sha1", 0x0301: "rsa_sha224",
                0x0401: "rsa_pkcs1_sha256", 0x0403: "ecdsa_secp256r1_sha256", 0x0501: "rsa_pkcs1_sha384",
                0x0503: "ecdsa_secp384r1_sha384", 0x0601: "rsa_pkcs1_sha512", 0x0603: "ecdsa_secp521r1_sha512",
                0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512",
                0x0807: "ed25519", 0x0808: "ed448", 0x0809: "rsa_pss_pss_sha256"}
WEAK_SIGALGS = {0x0101, 0x0201, 0x0202, 0x0203, 0x0301}
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def vname(v: int | None) -> str | None:
    return None if v is None else VERSION_NAMES.get(v, f"0x{v:04X}")


class ParseError(Exception):
    pass


class Reader:
    __slots__ = ("d", "p")

    def __init__(self, d: bytes):
        self.d, self.p = d, 0

    def left(self) -> int:
        return len(self.d) - self.p

    def take(self, n: int) -> bytes:
        if n < 0 or self.p + n > len(self.d):
            raise ParseError("truncated")
        v = self.d[self.p:self.p + n]
        self.p += n
        return v

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")


# ------------------------------------------------------------------ locating TLS inside a byte stream
def find_tls_start(data: bytes, expect_hs: int) -> int | None:
    """Offset of the first TLS handshake record whose first message is `expect_hs` (1=ClientHello, 2=ServerHello)."""
    n, i = len(data), 0
    while True:
        i = data.find(b"\x16\x03", i)
        if i == -1 or i + 6 > n:
            return None
        if data[i + 2] <= 4 and data[i + 5] == expect_hs and (i == 0 or data[i - 1] == 0x0A):
            if 4 <= int.from_bytes(data[i + 3:i + 5], "big") <= 18432:
                return i
        i += 1


# ------------------------------------------------------------------ extensions
def _exts(r: Reader) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    if r.left() < 2:
        return out
    total = r.u16()
    sub = Reader(r.take(min(total, r.left())))
    try:
        while sub.left() >= 4:
            t, ln = sub.u16(), sub.u16()
            out.append((t, sub.take(ln)))
    except ParseError:
        pass
    return out


def parse_client_hello(body: bytes) -> dict:
    r = Reader(body)
    legacy = r.u16()
    r.take(32)
    sid = r.take(r.u8())
    cs = Reader(r.take(r.u16()))
    suites = [cs.u16() for _ in range(cs.left() // 2)]
    comps = list(r.take(r.u8()))
    exts = _exts(r)
    d = {"legacy_version": legacy, "session_id": sid, "cipher_suites": suites, "compression": comps,
         "ext_types": [t for t, _ in exts], "sni": None, "alpn": [], "groups": [], "point_formats": [], "sig_algs": [],
         "supported_versions": [], "key_share_groups": [], "session_ticket": False, "ems": False, "reneg": False, "heartbeat": False}
    for t, data in exts:
        try:
            x = Reader(data)
            if t == 0:
                x.u16(); x.u8(); d["sni"] = x.take(x.u16()).decode("ascii", "replace").lower()
            elif t == 10:
                g = Reader(x.take(x.u16())); d["groups"] = [g.u16() for _ in range(g.left() // 2)]
            elif t == 11:
                d["point_formats"] = list(x.take(x.u8()))
            elif t == 13:
                g = Reader(x.take(x.u16())); d["sig_algs"] = [g.u16() for _ in range(g.left() // 2)]
            elif t == 16:
                g = Reader(x.take(x.u16()))
                while g.left():
                    d["alpn"].append(g.take(g.u8()).decode("ascii", "replace"))
            elif t == 43:
                g = Reader(x.take(x.u8())); d["supported_versions"] = [g.u16() for _ in range(g.left() // 2)]
            elif t == 51:
                g = Reader(x.take(x.u16()))
                while g.left() >= 4:
                    d["key_share_groups"].append(g.u16()); g.take(g.u16())
            elif t == 35:
                d["session_ticket"] = True
            elif t == 23:
                d["ems"] = True
            elif t == 0xFF01:
                d["reneg"] = True
            elif t == 15:
                d["heartbeat"] = True
        except ParseError:
            continue
    return d


def parse_server_hello(body: bytes) -> dict:
    r = Reader(body)
    legacy = r.u16()
    rnd = r.take(32)
    sid = r.take(r.u8())
    cipher = r.u16()
    comp = r.u8()
    exts = _exts(r)
    d = {"legacy_version": legacy, "random": rnd, "session_id": sid, "cipher_id": cipher, "compression": comp,
         "ext_types": [t for t, _ in exts], "selected_version": None, "key_share_group": None, "reneg": False, "ems": False,
         "heartbeat": False, "alpn": None, "hrr": rnd == HRR_RANDOM, "psk": False}
    for t, data in exts:
        try:
            x = Reader(data)
            if t == 43:
                d["selected_version"] = x.u16()
            elif t == 51:
                d["key_share_group"] = x.u16()
            elif t == 0xFF01:
                d["reneg"] = True
            elif t == 23:
                d["ems"] = True
            elif t == 15:
                d["heartbeat"] = True
            elif t == 41:
                d["psk"] = True
            elif t == 16:
                x.u16(); d["alpn"] = x.take(x.u8()).decode("ascii", "replace")
        except ParseError:
            continue
    return d


def parse_certificate_msg(body: bytes) -> list[bytes]:
    r = Reader(body)
    total = r.u24()
    rr = Reader(r.take(min(total, r.left())))
    certs: list[bytes] = []
    while rr.left() >= 3:
        ln = rr.u24()
        if ln > rr.left():
            break
        certs.append(rr.take(ln))
    return certs


def parse_server_key_exchange(body: bytes, kex: str, version_id: int) -> dict:
    r = Reader(body)
    out: dict = {"family": kex}
    if kex == "ECDHE":
        ctype = r.u8()
        if ctype != 3:
            raise ParseError("non-named curve")
        gid = r.u16()
        r.take(r.u8())
        out.update(group_id=gid, group=GROUP_NAMES.get(gid, f"curve_{gid}"))
    elif kex == "DHE":
        p = r.take(r.u16())
        r.take(r.u16()); r.take(r.u16())
        out["dh_bits"] = int.from_bytes(p, "big").bit_length()
    else:
        return out
    if version_id >= 0x0303 and r.left() >= 4:
        sa = r.u16()
        out.update(signature_alg_id=sa, signature_algorithm=SIGALG_NAMES.get(sa, f"0x{sa:04X}"), weak_signature=sa in WEAK_SIGALGS)
    return out


def ja3(legacy: int, suites, ext_types, groups, pfs) -> str:
    f = lambda xs: "-".join(str(x) for x in xs if not is_grease(x))  # noqa: E731
    s = f"{legacy},{f(suites)},{f(ext_types)},{f(groups)},{'-'.join(str(x) for x in pfs)}"
    return hashlib.md5(s.encode()).hexdigest()


def ja3s(legacy: int, cipher: int, ext_types) -> str:
    s = f"{legacy},{cipher},{'-'.join(str(x) for x in ext_types if not is_grease(x))}"
    return hashlib.md5(s.encode()).hexdigest()


# ------------------------------------------------------------------ one direction
def parse_direction(data: bytes, start: int, ts_at, is_client: bool) -> dict:
    dp = {"records": [], "messages": [], "alerts": [], "ccs_ts": None, "first_app_ts": None, "app_records": 0,
          "enc_hs_records": 0, "warnings": []}
    hs = bytearray()
    encrypted = False
    pos, n = start, len(data)
    while pos + 5 <= n:
        ct, ver, ln = data[pos], int.from_bytes(data[pos + 1:pos + 3], "big"), int.from_bytes(data[pos + 3:pos + 5], "big")
        if ct not in (20, 21, 22, 23, 24) or (ver >> 8) != 3 or ln > 18432:
            dp["warnings"].append(f"invalid TLS record header at stream offset {pos}")
            break
        end = pos + 5 + ln
        frag = data[pos + 5:end]
        ts = ts_at(min(end, n) - 1)
        dp["records"].append({"type": ct, "version": ver, "length": ln, "offset": pos, "ts": ts})
        if ct == 20:
            dp["ccs_ts"] = dp["ccs_ts"] or ts
            encrypted = True
        elif ct == 21:
            if not encrypted and len(frag) == 2:
                dp["alerts"].append({"level": frag[0], "description": frag[1], "ts": ts})
        elif ct == 22:
            looks_hello = is_client and len(frag) >= 4 and frag[0] == 1 and int.from_bytes(frag[1:4], "big") == len(frag) - 4
            if not encrypted or looks_hello:
                hs += frag
                while len(hs) >= 4:
                    mlen = int.from_bytes(hs[1:4], "big")
                    if len(hs) < 4 + mlen:
                        break
                    dp["messages"].append({"type": hs[0], "body": bytes(hs[4:4 + mlen]), "ts": ts, "offset": pos})
                    del hs[:4 + mlen]
            else:
                dp["enc_hs_records"] += 1
        elif ct == 23:
            dp["app_records"] += 1
            dp["first_app_ts"] = dp["first_app_ts"] or ts
        if len(frag) < ln:
            dp["warnings"].append("truncated TLS record at end of stream")
            break
        pos = end
    return dp


# ------------------------------------------------------------------ whole session
def analyze_tls(c2s, c2s_start: int | None, s2c, s2c_start: int | None) -> dict:
    cdp = parse_direction(c2s.data, c2s_start, c2s.ts_at, True) if c2s_start is not None else None
    sdp = parse_direction(s2c.data, s2c_start, s2c.ts_at, False) if s2c_start is not None else None
    warnings = (cdp["warnings"] if cdp else []) + (sdp["warnings"] if sdp else [])

    ch_raw = None
    for m in (cdp["messages"] if cdp else []):
        if m["type"] == 1:
            try:
                ch_raw = parse_client_hello(m["body"])
                break
            except ParseError:
                warnings.append("malformed ClientHello")
    sh_msgs = [m for m in (sdp["messages"] if sdp else []) if m["type"] == 2]
    sh_raw, hrr = None, False
    for m in sh_msgs:
        try:
            cand = parse_server_hello(m["body"])
        except ParseError:
            warnings.append("malformed ServerHello")
            continue
        hrr = hrr or cand["hrr"]
        sh_raw = cand
    certs_der: list[bytes] = []
    ske_msg = None
    cert_request = ocsp = ticket = False
    for m in (sdp["messages"] if sdp else []):
        if m["type"] == 11 and not certs_der:
            try:
                certs_der = parse_certificate_msg(m["body"])
            except ParseError:
                warnings.append("malformed Certificate message")
        elif m["type"] == 12:
            ske_msg = m
        elif m["type"] == 13:
            cert_request = True
        elif m["type"] == 22:
            ocsp = True
        elif m["type"] == 4:
            ticket = True

    ch = sh = neg = kxd = None
    if ch_raw:
        vers = [v for v in ch_raw["supported_versions"] if not is_grease(v)] or [ch_raw["legacy_version"]]
        suites = [s for s in ch_raw["cipher_suites"] if not is_grease(s)]
        infos = [describe(s) for s in suites]
        ch = {
            "legacy_version": vname(ch_raw["legacy_version"]), "versions_offered": [vname(v) for v in vers],
            "max_version": vname(max(vers)), "min_version": vname(min(vers)), "sni": ch_raw["sni"], "alpn": ch_raw["alpn"],
            "groups": [GROUP_NAMES.get(g, str(g)) for g in ch_raw["groups"] if not is_grease(g)],
            "cipher_count": len(suites),
            "offered_insecure": [i.name for i in infos if i.grade == "insecure"],
            "offered_weak": [i.name for i in infos if i.grade == "weak"],
            "offers_pfs": any(i.forward_secrecy for i in infos), "offers_aead": any(i.aead for i in infos),
            "offers_pq": any(g in PQ_GROUPS for g in ch_raw["key_share_groups"] + ch_raw["groups"]),
            "sig_algs": [SIGALG_NAMES.get(a, f"0x{a:04X}") for a in ch_raw["sig_algs"]],
            "fallback_scsv": 0x5600 in suites, "renegotiation_scsv": 0x00FF in suites, "session_ticket": ch_raw["session_ticket"],
            "ems": ch_raw["ems"], "extension_count": len(ch_raw["ext_types"]), "session_id_len": len(ch_raw["session_id"]),
            "ja3": ja3(ch_raw["legacy_version"], suites, ch_raw["ext_types"], ch_raw["groups"], ch_raw["point_formats"]),
        }
    if sh_raw:
        nv = sh_raw["selected_version"] or sh_raw["legacy_version"]
        tls13 = nv == 0x0304
        info = describe(sh_raw["cipher_id"])
        gid = sh_raw["key_share_group"]
        sentinel = None
        tail = sh_raw["random"][24:]
        if tail == b"DOWNGRD\x01":
            sentinel = "TLS 1.2"
        elif tail == b"DOWNGRD\x00":
            sentinel = "TLS 1.1 or below"
        sh = {"legacy_version": vname(sh_raw["legacy_version"]), "selected_version": vname(nv), "cipher_id": sh_raw["cipher_id"],
              "session_id_len": len(sh_raw["session_id"]), "compression": sh_raw["compression"], "hello_retry_request": hrr,
              "downgrade_sentinel": sentinel, "ja3s": ja3s(sh_raw["legacy_version"], sh_raw["cipher_id"], sh_raw["ext_types"]),
              "secure_renegotiation": sh_raw["reneg"], "extended_master_secret": sh_raw["ems"], "heartbeat": sh_raw["heartbeat"],
              "alpn": sh_raw["alpn"]}
        kex_family = ("DHE" if gid in FFDHE_GROUPS else "ECDHE") if tls13 else info.kex
        kxd = {"family": kex_family}
        if tls13 and gid is not None:
            kxd.update(group_id=gid, group=GROUP_NAMES.get(gid, f"group_{gid}"))
        if not tls13 and ske_msg:
            try:
                kxd.update(parse_server_key_exchange(ske_msg["body"], kex_family, nv))
            except ParseError:
                warnings.append("malformed ServerKeyExchange")
        kxd["pq_hybrid"] = bool(tls13 and gid in PQ_GROUPS)
        kxd["weak_group"] = bool(kxd.get("group_id") in WEAK_GROUPS)
        neg = {"version": vname(nv), "version_id": nv, "cipher_suite": info.name, "cipher_id": sh_raw["cipher_id"],
               "kex": kex_family, "auth": info.auth, "encryption": info.enc, "enc_bits": info.enc_bits, "mode": info.mode,
               "mac": info.mac, "aead": info.aead, "forward_secrecy": bool(info.forward_secrecy or tls13), "grade": info.grade,
               "issues": [i for i in info.issues if not (tls13 and i == "no forward secrecy")],
               "group": kxd.get("group"), "dh_bits": kxd.get("dh_bits"), "pq_hybrid": kxd["pq_hybrid"]}

    # ---- ordered handshake sequence
    events = []
    for dp, tag in ((cdp, "C"), (sdp, "S")):
        if not dp:
            continue
        for m in dp["messages"]:
            events.append((m["ts"] or 0, m["offset"], HS_NAMES.get(m["type"], f"Type{m['type']}")))
        if dp["ccs_ts"]:
            events.append((dp["ccs_ts"], 10 ** 12, "ChangeCipherSpec"))
        if dp["enc_hs_records"]:
            events.append(((dp["ccs_ts"] or 0) + 1e-9, 10 ** 12 + 1, "EncryptedHandshake"))
    events.sort(key=lambda e: (e[0], e[1]))
    sequence = [e[2] for e in events]

    tls13 = bool(neg and neg["version_id"] == 0x0304)
    if tls13:
        completed = bool(cdp and cdp["app_records"] > 0)
        end_ts = cdp["first_app_ts"] if cdp else None
    else:
        completed = bool(cdp and cdp["ccs_ts"] and sdp and sdp["ccs_ts"])
        end_ts = sdp["ccs_ts"] if sdp else None
    start_ts = c2s.ts_at(c2s_start) if c2s_start is not None else (s2c.ts_at(s2c_start) if s2c_start is not None else None)
    duration = (end_ts - start_ts) if (end_ts and start_ts and completed and end_ts >= start_ts) else None
    resumed = False
    if sh_raw and ch_raw:
        if tls13:
            resumed = sh_raw["psk"]
        else:
            resumed = bool(sh_raw["session_id"] and sh_raw["session_id"] == ch_raw["session_id"] and not certs_der)
    alerts = []
    for dp, who in ((cdp, "client"), (sdp, "server")):
        for a in (dp["alerts"] if dp else []):
            alerts.append({"from": who, "level": "fatal" if a["level"] == 2 else "warning",
                           "description": ALERT_NAMES.get(a["description"], str(a["description"]))})
    tls = {
        "present": True, "client_hello": ch, "server_hello": sh, "negotiated": neg, "key_exchange": kxd,
        "handshake_sequence": sequence, "resumed": resumed, "completed": completed, "alerts": alerts,
        "certificate_visible": bool(certs_der), "encrypted_handshake": tls13, "ocsp_stapling": ocsp, "cert_request": cert_request,
        "session_ticket_issued": ticket, "hello_retry": hrr,
        "records": {"c2s": len(cdp["records"]) if cdp else 0, "s2c": len(sdp["records"]) if sdp else 0,
                    "app_data_c2s": cdp["app_records"] if cdp else 0, "app_data_s2c": sdp["app_records"] if sdp else 0},
        "handshake_start_ts": start_ts, "handshake_end_ts": end_ts, "handshake_duration": duration,
        "certificate_der": certs_der, "warnings": warnings,
    }
    return tls


def _safe(fn, default):
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return default
