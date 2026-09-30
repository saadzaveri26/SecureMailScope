"""Message-layer protection detection (OpenPGP / S-MIME) inside plaintext mail streams."""
from __future__ import annotations
import base64
import re
from datetime import datetime, timezone

from cryptography.hazmat.primitives.serialization import pkcs7

from .cert_analyzer import describe_certificate
from cryptography import x509

PGP_BLOCK = re.compile(rb"-----BEGIN PGP (MESSAGE|SIGNED MESSAGE|SIGNATURE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK)-----(.*?)(?:-----END PGP \1-----|\Z)", re.S)
PGP_MIME_ENC = re.compile(rb"multipart/encrypted;[^\r\n]*application/pgp-encrypted", re.I)
PGP_MIME_SIG = re.compile(rb"multipart/signed;[^\r\n]*application/pgp-signature", re.I)
SMIME_CT = re.compile(rb"Content-Type:\s*application/(?:x-)?pkcs7-mime;?([^\r\n]*(?:\r?\n[ \t][^\r\n]*)*)", re.I)
SMIME_SIG_CT = re.compile(rb"Content-Type:\s*application/(?:x-)?pkcs7-signature", re.I)
SMIME_SIGNED = re.compile(rb"multipart/signed;([^\r\n]*(?:\r?\n[ \t][^\r\n]*)*)", re.I)
MICALG = re.compile(rb"micalg=\"?(?:pgp-)?([a-z0-9-]+)\"?", re.I)
PKESK_ALGO = {1: "RSA", 2: "RSA", 3: "RSA", 16: "ElGamal", 18: "ECDH", 25: "X25519", 17: "DSA", 19: "ECDSA", 22: "EdDSA"}
WEAK_HASHES = {"md5", "sha1", "sha-1"}


def _openpgp_packets(data: bytes):
    i, out = 0, []
    while i < len(data):
        b = data[i]
        if not b & 0x80:
            break
        try:
            if b & 0x40:
                tag = b & 0x3F; i += 1; l0 = data[i]
                if l0 < 192: ln = l0; i += 1
                elif l0 < 224: ln = ((l0 - 192) << 8) + data[i + 1] + 192; i += 2
                elif l0 == 255: ln = int.from_bytes(data[i + 1:i + 5], "big"); i += 5
                else: out.append((tag, data[i + 1:])); break
            else:
                tag, lt = (b >> 2) & 0xF, b & 3; i += 1
                if lt == 0: ln = data[i]; i += 1
                elif lt == 1: ln = int.from_bytes(data[i:i + 2], "big"); i += 2
                elif lt == 2: ln = int.from_bytes(data[i:i + 4], "big"); i += 4
                else: ln = len(data) - i
            out.append((tag, data[i:i + ln])); i += ln
        except IndexError:
            break
    return out


def _armor_bytes(block: bytes) -> bytes:
    lines = [ln.strip() for ln in block.replace(b"\r", b"").split(b"\n")]
    body, started = [], False
    for ln in lines:
        if not started:
            if ln == b"":
                started = True
            continue
        if ln.startswith(b"="):
            break
        body.append(ln)
    try:
        return base64.b64decode(b"".join(body) + b"=" * (-len(b"".join(body)) % 4))
    except Exception:  # noqa: BLE001
        return b""


def _smime_signer_certs(text: bytes, ref: datetime) -> list[dict]:
    out = []
    m = SMIME_SIG_CT.search(text)
    if not m:
        return out
    tail = text[m.end():]
    parts = re.split(rb"\r?\n\r?\n", tail, maxsplit=1)
    if len(parts) < 2:
        return out
    payload = re.split(rb"\r?\n--", parts[1], maxsplit=1)[0]
    try:
        der = base64.b64decode(re.sub(rb"\s+", b"", payload) + b"=" * (-len(re.sub(rb"\s+", b"", payload)) % 4))
        for c in pkcs7.load_der_pkcs7_certificates(der):
            out.append(describe_certificate(c, ref))
    except Exception:  # noqa: BLE001
        pass
    return out


def scan(plain_streams: list[bytes], ref_ts: float) -> dict:
    blob = b"\n".join(plain_streams)
    ref = datetime.fromtimestamp(ref_ts, tz=timezone.utc)
    res = {"pgp": {"detected": False, "encrypted": 0, "signed": 0, "public_keys": 0, "pgp_mime": False,
                   "no_integrity_protection": 0, "pubkey_algorithms": []},
           "smime": {"detected": False, "enveloped": 0, "signed": 0, "micalg": [], "weak_hash": False, "signer_certificates": []},
           "layer": "none", "evidence": []}
    if len(blob) < 20:
        return res
    p, s = res["pgp"], res["smime"]
    for kind, body in ((m.group(1), m.group(0)) for m in PGP_BLOCK.finditer(blob)):
        p["detected"] = True
        if kind == b"MESSAGE":
            p["encrypted"] += 1
            for tag, tb in _openpgp_packets(_armor_bytes(body)):
                if tag == 1 and len(tb) > 10:
                    a = PKESK_ALGO.get(tb[9], f"algo{tb[9]}")
                    if a not in p["pubkey_algorithms"]:
                        p["pubkey_algorithms"].append(a)
                if tag == 9:
                    p["no_integrity_protection"] += 1
            res["evidence"].append("OpenPGP armored MESSAGE block")
        elif kind == b"SIGNED MESSAGE" or kind == b"SIGNATURE":
            p["signed"] += 1; res["evidence"].append("OpenPGP signature block")
        elif kind == b"PUBLIC KEY BLOCK":
            p["public_keys"] += 1; res["evidence"].append("OpenPGP public key block transmitted")
    if PGP_MIME_ENC.search(blob):
        p["detected"] = p["pgp_mime"] = True
        p["encrypted"] = max(p["encrypted"], 1); res["evidence"].append("PGP/MIME multipart/encrypted")
    if PGP_MIME_SIG.search(blob):
        p["detected"] = p["pgp_mime"] = True
        p["signed"] += 1; res["evidence"].append("PGP/MIME multipart/signed")
    for m in SMIME_CT.finditer(blob):
        params = m.group(1).lower()
        s["detected"] = True
        if b"enveloped-data" in params or b"smime.p7m" in params:
            s["enveloped"] += 1; res["evidence"].append("S/MIME enveloped-data (encrypted)")
        else:
            s["signed"] += 1; res["evidence"].append("S/MIME signed-data")
    for m in SMIME_SIGNED.finditer(blob):
        if b"pkcs7-signature" in m.group(1).lower():
            s["detected"] = True
            s["signed"] += 1
            mm = MICALG.search(m.group(1))
            if mm:
                h = mm.group(1).decode().lower()
                s["micalg"].append(h)
                s["weak_hash"] = s["weak_hash"] or h in WEAK_HASHES
            res["evidence"].append("S/MIME multipart/signed (detached)")
    if s["detected"]:
        s["signer_certificates"] = _smime_signer_certs(blob, ref)
    res["layer"] = "both" if p["detected"] and s["detected"] else "pgp" if p["detected"] else "smime" if s["detected"] else "none"
    return res
