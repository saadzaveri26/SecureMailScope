"""Isolation-Forest anomaly detection over session-level cryptographic & handshake features, with explanations."""
from __future__ import annotations
import math
import re
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ..config import ML_MIN_SESSIONS, ML_ANOMALY_THRESHOLD, MODELS_DIR

VER = {"SSLv3": 0, "TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3, "TLS 1.3": 4}
GRADE = {"insecure": 0, "weak": 1, "acceptable": 2, "strong": 3}
KEX = {"RSA": 0, "DH": 1, "ECDH": 1, "DHE": 2, "ECDHE": 3}
TRANSPORT = {"plaintext": 0, "starttls": 1, "implicit_tls": 2}

FEATURES = ["tls_version", "cipher_grade", "forward_secrecy", "aead", "kex_code", "enc_bits", "transport_code", "handshake_ms",
            "packets", "retransmissions", "bytes_c2s_log", "bytes_s2c_log", "duration_s", "cert_visible",
            "cert_validity_days", "cert_key_bits", "cert_weak_sig", "cert_self_signed", "chain_len",
            "client_ciphers", "client_extensions", "hs_msg_count", "fatal_alert", "resumed", "downgrade_sentinel",
            "handshake_complete", "hs_seq_rarity", "ja3_rarity", "ja3s_rarity"]
RARITY = {"hs_seq_rarity", "ja3_rarity", "ja3s_rarity"}
NOISE = {"packets", "retransmissions", "bytes_c2s_log", "bytes_s2c_log", "duration_s", "handshake_ms"}
FLOOR = {"handshake_ms": 5.0, "packets": 3.0, "retransmissions": 1.0, "bytes_c2s_log": 0.7, "bytes_s2c_log": 0.7, "duration_s": 0.5}
DISCRETE = {"hs_msg_count", "client_ciphers", "client_extensions", "cert_validity_days", "tls_version", "cipher_grade", "forward_secrecy", "aead", "kex_code", "enc_bits", "transport_code", "cert_visible",
            "cert_weak_sig", "cert_self_signed", "chain_len", "fatal_alert", "resumed", "downgrade_sentinel", "handshake_complete", "cert_key_bits"}
LABELS = {"tls_version": "Negotiated TLS version", "cipher_grade": "Cipher-suite strength grade", "forward_secrecy": "Forward secrecy",
          "aead": "AEAD cipher", "kex_code": "Key-exchange type", "enc_bits": "Cipher key size (bits)", "transport_code": "Transport mode",
          "handshake_ms": "Handshake duration (ms)", "packets": "Packet count", "retransmissions": "Retransmissions",
          "bytes_c2s_log": "Client->server volume", "bytes_s2c_log": "Server->client volume", "duration_s": "Session duration (s)",
          "cert_visible": "Certificate visibility", "cert_validity_days": "Certificate validity (days)", "cert_key_bits": "Certificate key size", "cert_weak_sig": "Weak certificate signature",
          "cert_self_signed": "Self-signed certificate", "chain_len": "Certificate chain length", "client_ciphers": "Client cipher-suite count",
          "client_extensions": "Client extension count", "hs_msg_count": "Handshake message count", "fatal_alert": "Fatal TLS alert",
          "resumed": "Session resumption", "downgrade_sentinel": "Downgrade sentinel", "handshake_complete": "Handshake completed",
          "hs_seq_rarity": "Handshake message sequence", "ja3_rarity": "Client TLS fingerprint (JA3)", "ja3s_rarity": "Server TLS fingerprint (JA3S)"}
INV = {"tls_version": {v: k for k, v in VER.items()} | {-1: "none"}, "cipher_grade": {v: k for k, v in GRADE.items()} | {-1: "none"},
       "transport_code": {v: k for k, v in TRANSPORT.items()}, "kex_code": {3: "ECDHE", 2: "DHE", 1: "static DH", 0: "RSA", -1: "none"}}


def _signature(s: dict) -> str:
    t = s.get("tls") or {}
    return ">".join(t.get("handshake_sequence") or []) or "-"


def raw_features(s: dict, ctx: dict) -> dict:
    t = s.get("tls") or {}
    neg = t.get("negotiated") or {}
    ch = t.get("client_hello") or {}
    sh = t.get("server_hello") or {}
    chain = s.get("chain") or {}
    leaf = (chain.get("certificates") or [None])[0]
    tr = s["traffic"]

    def rarity(counter: Counter, key) -> float:
        n = max(sum(counter.values()), 1)
        return -math.log(max(counter.get(key, 0), 0.5) / (n + 1))

    return {
        "tls_version": VER.get(neg.get("version"), -1), "cipher_grade": GRADE.get(neg.get("grade"), -1),
        "forward_secrecy": int(bool(neg.get("forward_secrecy"))), "aead": int(bool(neg.get("aead"))),
        "kex_code": KEX.get(neg.get("kex"), -1), "enc_bits": neg.get("enc_bits") or 0,
        "transport_code": TRANSPORT.get(s["transport"]["mode"], -1),
        "handshake_ms": (t.get("handshake_duration") or 0) * 1000, "packets": tr["packets"], "retransmissions": tr["retransmissions"],
        "bytes_c2s_log": math.log1p(tr["bytes_c2s"]), "bytes_s2c_log": math.log1p(tr["bytes_s2c"]),
        "duration_s": s["timing"]["duration"], "cert_visible": int(leaf is not None),
        "cert_validity_days": leaf["validity_days"] if leaf else 0, "cert_key_bits": leaf["public_key"]["size"] if leaf else 0,
        "cert_weak_sig": int(bool(leaf and leaf["signature"]["weak"])), "cert_self_signed": int(bool(leaf and leaf["self_signed"])),
        "chain_len": chain.get("chain_length", 0), "client_ciphers": ch.get("cipher_count", 0), "client_extensions": ch.get("extension_count", 0),
        "hs_msg_count": len(t.get("handshake_sequence") or []), "fatal_alert": int(any(a["level"] == "fatal" for a in t.get("alerts", []))),
        "resumed": int(bool(t.get("resumed"))), "downgrade_sentinel": int(bool(sh.get("downgrade_sentinel"))),
        "handshake_complete": int(bool(t.get("completed"))),
        "hs_seq_rarity": rarity(ctx["seq"], _signature(s)), "ja3_rarity": rarity(ctx["ja3"], ch.get("ja3")),
        "ja3s_rarity": rarity(ctx["ja3s"], sh.get("ja3s")),
    }


def build_context(sessions: list[dict]) -> dict:
    g = lambda s, k, f: ((s.get("tls") or {}).get(k) or {}).get(f)  # noqa: E731
    return {"seq": Counter(_signature(s) for s in sessions),
            "ja3": Counter(g(s, "client_hello", "ja3") for s in sessions),
            "ja3s": Counter(g(s, "server_hello", "ja3s") for s in sessions)}


class AnomalyDetector:
    def __init__(self, n_estimators: int = 200, seed: int = 42):
        self.n_estimators, self.seed = n_estimators, seed
        self.model: IsolationForest | None = None
        self.ctx: dict = {}
        self.ref: dict = {}
        self.n = 0

    # ---- training
    def fit(self, sessions: list[dict]) -> "AnomalyDetector":
        self.ctx = build_context(sessions)
        rows = [raw_features(s, self.ctx) for s in sessions]
        X = np.array([[r[f] for f in FEATURES] for r in rows], dtype=float)
        self.n = len(sessions)
        self.model = IsolationForest(n_estimators=self.n_estimators, max_samples=min(256, self.n), contamination="auto",
                                     random_state=self.seed).fit(X)
        self.ref = {}
        for j, f in enumerate(FEATURES):
            col = X[:, j]
            if f in DISCRETE:
                self.ref[f] = {"counts": dict(Counter(col.tolist()))}
            else:
                med = float(np.median(col))
                mad = float(np.median(np.abs(col - med)))
                self.ref[f] = {"median": med, "sigma": max(1.4826 * mad, 0.25 * abs(med), FLOOR.get(f, 1.0))}
        return self

    # ---- scoring
    def score(self, sessions: list[dict]) -> list[dict]:
        rows = [raw_features(s, self.ctx) for s in sessions]
        X = np.array([[r[f] for f in FEATURES] for r in rows], dtype=float)
        raw = -self.model.score_samples(X)
        out = []
        for i, r in enumerate(rows):
            score = float(np.clip((raw[i] - 0.45) / 0.30, 0, 1))
            reasons, top = self._explain(r)
            out.append({"available": True, "score": round(score, 3), "raw": round(float(raw[i]), 4),
                        "anomalous": bool(score >= ML_ANOMALY_THRESHOLD and reasons), "reasons": reasons, "top_features": top,
                        "reference_sessions": self.n})
        return out

    def _explain(self, r: dict) -> tuple[list[str], list[dict]]:
        cand = []
        for f in FEATURES:
            v, ref = r[f], self.ref[f]
            if f in RARITY:
                if v >= 4.0:                                   # seen in < ~2% of reference sessions
                    cand.append((v, f, v, f"{LABELS[f]} is rare in the reference profile"))
            elif f in DISCRETE:
                freq = ref["counts"].get(v, 0) / max(self.n, 1)
                if freq < 0.05:
                    disp = INV.get(f, {}).get(int(v), v)
                    cand.append((-math.log(max(freq, 1e-4)), f, v, f"{LABELS[f]} = {disp} (seen in {freq * 100:.1f}% of reference sessions)"))
            else:
                z = abs(v - ref["median"]) / ref["sigma"]
                if z >= (8 if f in NOISE else 5):
                    cand.append((z, f, v, f"{LABELS[f]} = {v:.0f} (reference median {ref['median']:.0f})"))
        cand.sort(key=lambda c: -c[0])
        return [c[3] for c in cand[:4]], [{"feature": c[1], "value": round(float(c[2]), 3), "deviation": round(float(c[0]), 2)} for c in cand[:4]]

    # ---- persistence
    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "ctx": self.ctx, "ref": self.ref, "n": self.n, "features": FEATURES}, path)

    @classmethod
    def load(cls, path: Path) -> "AnomalyDetector | None":
        try:
            b = joblib.load(path)
        except Exception:  # noqa: BLE001
            return None
        if b.get("features") != FEATURES:
            return None
        d = cls()
        d.model, d.ctx, d.ref, d.n = b["model"], b["ctx"], b["ref"], b["n"]
        return d


def model_path(endpoint: str) -> Path:
    return MODELS_DIR / (re.sub(r"[^A-Za-z0-9_.-]", "_", endpoint) + ".joblib")


def run_ml(sessions: list[dict]) -> dict:
    """Score all sessions; baseline-trained per-endpoint models take precedence, otherwise self-fit."""
    info = {"engine": "IsolationForest", "models": {}}
    remaining = []
    by_ep: dict = {}
    for s in sessions:
        by_ep.setdefault(s["endpoint"], []).append(s)
    for ep, ss in by_ep.items():
        det = AnomalyDetector.load(model_path(ep)) if model_path(ep).exists() else None
        if det:
            for s, res in zip(ss, det.score(ss)):
                s["ml"] = {**res, "model": "baseline-trained"}
            info["models"][ep] = f"baseline-trained on {det.n} sessions"
        else:
            remaining.extend(ss)
    if len(remaining) >= ML_MIN_SESSIONS:
        det = AnomalyDetector().fit(remaining)
        for s, res in zip(remaining, det.score(remaining)):
            s["ml"] = {**res, "model": "self-fit"}
        info["models"]["(self-fit)"] = f"fitted on {len(remaining)} sessions of this capture"
    else:
        for s in remaining:
            s["ml"] = {"available": False, "score": 0.0, "anomalous": False, "reasons": [], "top_features": [],
                       "model": None, "note": f"fewer than {ML_MIN_SESSIONS} sessions; ML skipped (rules only)"}
    return info
