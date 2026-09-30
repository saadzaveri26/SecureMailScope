"""IANA TLS cipher-suite registry with derived cryptographic attributes and a strength grade."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from functools import lru_cache

IANA_SUITES: dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256", 0x1305: "TLS_AES_128_CCM_8_SHA256",
    0x0000: "TLS_NULL_WITH_NULL_NULL", 0x0001: "TLS_RSA_WITH_NULL_MD5", 0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x0004: "TLS_RSA_WITH_RC4_128_MD5", 0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", 0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA", 0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", 0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
    0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", 0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA", 0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5", 0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA", 0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA", 0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", 0x0096: "TLS_RSA_WITH_SEED_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", 0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", 0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC00C: "TLS_ECDH_RSA_WITH_RC4_128_SHA", 0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", 0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC015: "TLS_ECDH_anon_WITH_NULL_SHA", 0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC09C: "TLS_RSA_WITH_AES_128_CCM", 0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}
SCSV = {0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", 0x5600: "TLS_FALLBACK_SCSV"}


def is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


@dataclass(frozen=True)
class CipherInfo:
    id: int
    name: str
    kex: str
    auth: str
    enc: str
    enc_bits: int
    mode: str
    mac: str
    forward_secrecy: bool
    aead: bool
    grade: str            # insecure | weak | acceptable | strong | unknown | n/a
    issues: tuple

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = f"0x{self.id:04X}"
        d["issues"] = list(self.issues)
        return d


def _parse_enc(tokens: list[str]) -> tuple[str, int, str]:
    t0 = tokens[0] if tokens else ""
    if t0 == "NULL":
        return "NULL", 0, "NONE"
    if "CHACHA20" in tokens:
        return "CHACHA20", 256, "POLY1305"
    if t0 == "3DES":
        return "3DES", 168, "CBC"
    if t0 in ("AES", "CAMELLIA", "ARIA") and len(tokens) > 2 and tokens[1].isdigit():
        mode = next((m for m in ("GCM", "CCM", "CBC") if m in tokens), "CBC")
        return t0, int(tokens[1]), mode
    if t0 == "RC4":
        return "RC4", int(tokens[1]) if len(tokens) > 1 and tokens[1].isdigit() else 128, "STREAM"
    if t0 == "DES40":
        return "DES", 40, "CBC"
    if t0 == "DES":
        return "DES", 56, "CBC"
    if t0 == "RC2":
        return "RC2", 40, "CBC"
    if t0 == "SEED":
        return "SEED", 128, "CBC"
    return t0 or "?", 0, "?"


def _parse(cid: int, name: str) -> CipherInfo:
    if "_WITH_" in name:
        left, right = name[4:].split("_WITH_")
        parts = left.split("_")
        kex = parts[0]
        export = "EXPORT" in parts
        anon = "anon" in parts
        auth = "anon" if anon else ("RSA" if kex == "RSA" else next((p for p in parts[1:] if p != "EXPORT"), kex))
        tokens = right.split("_")
        tls13 = False
    else:
        kex, auth, export, anon, tls13 = "ECDHE", "cert", False, False, True
        tokens = name[4:].split("_")
    enc, bits, mode = _parse_enc(tokens)
    last = tokens[-1] if tokens else ""
    aead = mode in ("GCM", "CCM", "POLY1305")
    mac = "AEAD" if aead else (last if last in ("SHA", "SHA256", "SHA384", "MD5", "NULL") else "?")
    fs = tls13 or kex in ("ECDHE", "DHE")
    issues: list[str] = []
    if enc == "NULL":
        issues.append("NULL encryption (no confidentiality)")
    if export:
        issues.append("EXPORT-grade cryptography (FREAK/Logjam)")
    if anon:
        issues.append("anonymous key exchange (no authentication)")
    if enc == "RC4":
        issues.append("RC4 keystream biases (RFC 7465 prohibits)")
    if enc == "RC2":
        issues.append("RC2 obsolete cipher")
    if enc == "DES":
        issues.append("single DES (56-bit) brute-forceable")
    if enc == "3DES":
        issues.append("3DES 64-bit block, Sweet32 (CVE-2016-2183)")
    if mac == "MD5":
        issues.append("MD5 MAC")
    if kex in ("DH", "ECDH") and not anon:
        issues.append("static (non-ephemeral) Diffie-Hellman")
    if not fs:
        issues.append("no forward secrecy")
    if mode == "CBC" and not tls13:
        issues.append("CBC mode (padding-oracle class: Lucky13/POODLE-TLS)")
    insecure = enc in ("NULL", "RC4", "RC2", "DES") or export or anon or mac == "MD5"
    if insecure:
        grade = "insecure"
    elif enc == "3DES" or kex in ("DH", "ECDH"):
        grade = "weak"
    elif aead and fs:
        grade = "strong"
    else:
        grade = "acceptable"
    return CipherInfo(cid, name, kex, auth, enc, bits, mode, mac, fs, aead, grade, tuple(issues))


@lru_cache(maxsize=None)
def describe(cid: int) -> CipherInfo:
    if is_grease(cid):
        return CipherInfo(cid, "GREASE", "-", "-", "-", 0, "-", "-", False, False, "n/a", ())
    if cid in SCSV:
        return CipherInfo(cid, SCSV[cid], "-", "-", "-", 0, "-", "-", False, False, "n/a", ())
    name = IANA_SUITES.get(cid)
    if not name:
        return CipherInfo(cid, f"UNKNOWN_0x{cid:04X}", "?", "?", "?", 0, "?", "?", False, False, "unknown",
                          ("unrecognised cipher suite",))
    return _parse(cid, name)
