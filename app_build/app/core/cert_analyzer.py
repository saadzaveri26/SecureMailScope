"""X.509 extraction, chain validation, trust evaluation and key/signature strength analysis."""
from __future__ import annotations
import math
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ..config import TRUST_STORE_DIR, CERT_MAX_VALIDITY_DAYS


def _nb(c):
    return getattr(c, "not_valid_before_utc", None) or c.not_valid_before.replace(tzinfo=timezone.utc)


def _na(c):
    return getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=timezone.utc)


def fingerprint(c: x509.Certificate) -> str:
    return ":".join(f"{b:02X}" for b in c.fingerprint(hashes.SHA256()))


def _cn(name: x509.Name) -> str | None:
    a = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return a[0].value if a else None


def _org(name: x509.Name) -> str | None:
    a = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return a[0].value if a else None


class TrustStore:
    def __init__(self):
        self.by_subject: dict[bytes, list[x509.Certificate]] = {}
        self.fps: set[str] = set()
        self.sources: list[str] = []

    def add(self, c: x509.Certificate) -> None:
        self.by_subject.setdefault(c.subject.public_bytes(), []).append(c)
        self.fps.add(fingerprint(c))

    @classmethod
    def load(cls) -> "TrustStore":
        ts = cls()
        try:
            import certifi
            for c in x509.load_pem_x509_certificates(Path(certifi.where()).read_bytes()):
                ts.add(c)
            ts.sources.append("certifi (Mozilla CA bundle)")
        except Exception:  # noqa: BLE001
            pass
        if TRUST_STORE_DIR.exists():
            for f in sorted(TRUST_STORE_DIR.iterdir()):
                if f.suffix.lower() in (".pem", ".crt", ".cer"):
                    try:
                        for c in x509.load_pem_x509_certificates(f.read_bytes()):
                            ts.add(c)
                        ts.sources.append(f"enterprise:{f.name}")
                    except Exception:  # noqa: BLE001
                        try:
                            ts.add(x509.load_der_x509_certificate(f.read_bytes()))
                            ts.sources.append(f"enterprise:{f.name}")
                        except Exception:  # noqa: BLE001
                            pass
        return ts

    def anchor_for(self, chain_last: x509.Certificate) -> str | None:
        if fingerprint(chain_last) in self.fps:
            return chain_last.subject.rfc4514_string()
        for cand in self.by_subject.get(chain_last.issuer.public_bytes(), []):
            try:
                chain_last.verify_directly_issued_by(cand)
                return cand.subject.rfc4514_string()
            except Exception:  # noqa: BLE001
                continue
        return None


@lru_cache(maxsize=1)
def get_trust_store() -> TrustStore:
    return TrustStore.load()


def reload_trust_store() -> TrustStore:
    get_trust_store.cache_clear()
    return get_trust_store()


def _key_info(c: x509.Certificate) -> dict:
    pk = c.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return {"algorithm": "RSA", "size": pk.key_size, "curve": None, "exponent": pk.public_numbers().e}
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return {"algorithm": "EC", "size": pk.curve.key_size, "curve": pk.curve.name, "exponent": None}
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return {"algorithm": "Ed25519", "size": 256, "curve": "ed25519", "exponent": None}
    if isinstance(pk, ed448.Ed448PublicKey):
        return {"algorithm": "Ed448", "size": 456, "curve": "ed448", "exponent": None}
    if isinstance(pk, dsa.DSAPublicKey):
        return {"algorithm": "DSA", "size": pk.key_size, "curve": None, "exponent": None}
    return {"algorithm": "UNKNOWN", "size": 0, "curve": None, "exponent": None}


def _ext(c, cls):
    try:
        return c.extensions.get_extension_for_class(cls).value
    except Exception:  # noqa: BLE001
        return None


def is_self_signed(c: x509.Certificate) -> bool:
    if c.subject != c.issuer:
        return False
    try:
        c.verify_directly_issued_by(c)
        return True
    except Exception:  # noqa: BLE001
        return True


def describe_certificate(c: x509.Certificate, ref: datetime) -> dict:
    nb, na = _nb(c), _na(c)
    try:
        h = c.signature_hash_algorithm
        hname = h.name if h else "intrinsic"
    except Exception:  # noqa: BLE001
        hname = "unknown"
    oid = c.signature_algorithm_oid
    sig_name = getattr(oid, "_name", None) or oid.dotted_string
    san_v = _ext(c, x509.SubjectAlternativeName)
    san = san_v.get_values_for_type(x509.DNSName) if san_v else []
    bc = _ext(c, x509.BasicConstraints)
    ku = _ext(c, x509.KeyUsage)
    eku = _ext(c, x509.ExtendedKeyUsage)
    key_usage = []
    if ku:
        for a in ("digital_signature", "key_encipherment", "key_agreement", "key_cert_sign", "crl_sign"):
            try:
                if getattr(ku, a):
                    key_usage.append(a)
            except ValueError:
                pass
    key = _key_info(c)
    return {
        "fingerprint_sha256": fingerprint(c), "serial": format(c.serial_number, "X"), "version": c.version.name,
        "subject": c.subject.rfc4514_string(), "subject_cn": _cn(c.subject),
        "issuer": c.issuer.rfc4514_string(), "issuer_cn": _cn(c.issuer), "issuer_org": _org(c.issuer),
        "not_before": nb.isoformat(), "not_after": na.isoformat(),
        "validity_days": (na - nb).days, "age_days": math.floor((ref - nb).total_seconds() / 86400),
        "days_remaining": math.floor((na - ref).total_seconds() / 86400),
        "expired": ref > na, "not_yet_valid": ref < nb,
        "public_key": key,
        "signature": {"algorithm": sig_name, "hash": hname, "weak": hname in ("md5", "sha1")},
        "san": san, "wildcard": any(s.startswith("*.") for s in san) or bool((_cn(c.subject) or "").startswith("*.")),
        "is_ca": bool(bc.ca) if bc else False, "key_usage": key_usage,
        "server_auth_eku": (ExtendedKeyUsageOID.SERVER_AUTH in eku) if eku else None,
        "self_signed": is_self_signed(c),
    }


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]:
            return True
    return False


def analyze_chain(der_list: list[bytes], ref_ts: float, sni: str | None, trust: TrustStore) -> dict:
    ref = datetime.fromtimestamp(ref_ts, tz=timezone.utc)
    certs, descs, issues = [], [], []
    for i, der in enumerate(der_list):
        try:
            c = x509.load_der_x509_certificate(der)
            certs.append(c)
            descs.append(describe_certificate(c, ref))
        except Exception as e:  # noqa: BLE001
            issues.append(f"certificate #{i} could not be parsed: {e}")
    if not certs:
        return {"certificates": [], "chain_length": 0, "issues": issues, "trusted": None}
    ordered = True
    broken = None
    for i in range(len(certs) - 1):
        try:
            certs[i].verify_directly_issued_by(certs[i + 1])
        except Exception:  # noqa: BLE001
            ordered, broken = False, i
            issues.append(f"certificate #{i} is not issued by certificate #{i + 1} (bad order or signature)")
            break
    last = certs[-1]
    root_included = descs[-1]["self_signed"]
    anchor = trust.anchor_for(last)
    trusted = anchor is not None
    complete = root_included or trusted
    intermediates_expired = [i for i in range(1, len(descs)) if descs[i]["expired"]]
    host_match = None
    if sni:
        names = descs[0]["san"] or ([descs[0]["subject_cn"]] if descs[0]["subject_cn"] else [])
        host_match = hostname_matches(sni, names)
    return {
        "certificates": descs, "chain_length": len(certs), "ordered": ordered, "broken_link_at": broken,
        "root_included": root_included, "complete": complete, "trusted": trusted, "trust_anchor": anchor,
        "self_signed_leaf": descs[0]["self_signed"], "intermediates_expired": intermediates_expired,
        "hostname_checked": sni, "hostname_match": host_match, "issues": issues,
    }
