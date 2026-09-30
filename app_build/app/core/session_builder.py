"""Turns a reassembled TCP flow into a rich, JSON-serialisable email-security session record."""
from __future__ import annotations
from ..config import MAIL_PORTS
from .cert_analyzer import TrustStore, analyze_chain
from .mail_dialog import analyze_dialog
from .message_security import scan as scan_message_security
from .protocol_detector import detect
from .tls_parser import analyze_tls


def build_session(flow, trust: TrustStore) -> dict | None:
    det = detect(flow)
    if det is None:
        return None
    c2s, s2c = flow.c2s, flow.s2c
    plain_c = c2s.data[: det.tls_start_c2s] if det.tls_start_c2s is not None else c2s.data
    plain_s = s2c.data[: det.tls_start_s2c] if det.tls_start_s2c is not None else s2c.data
    tls_started = det.tls_start_c2s is not None or det.tls_start_s2c is not None
    dialog, plain_streams = analyze_dialog(det.protocol, plain_c, plain_s, tls_started)
    tls = analyze_tls(c2s, det.tls_start_c2s, s2c, det.tls_start_s2c) if tls_started else None

    chain, sni = None, None
    if tls:
        sni = (tls["client_hello"] or {}).get("sni")
        der = tls.pop("certificate_der", [])
        if der:
            chain = analyze_chain(der, flow.start_ts, sni, trust)
    leaf = chain["certificates"][0] if chain and chain["certificates"] else None
    server_name = sni or (leaf["san"][0] if leaf and leaf["san"] else (leaf or {}).get("subject_cn"))
    msg = scan_message_security(plain_streams, flow.start_ts)

    cip, sip = flow.client, flow.server
    exp = MAIL_PORTS.get(sip[1])
    return {
        "session_id": f"S-{flow.stream_id}", "tcp_stream": flow.stream_id,
        "client": f"{cip[0]}:{cip[1]}", "client_ip": cip[0], "client_port": cip[1],
        "server": f"{sip[0]}:{sip[1]}", "server_ip": sip[0], "server_port": sip[1], "endpoint": f"{sip[0]}:{sip[1]}",
        "server_name": server_name,
        "protocol": det.protocol, "protocol_confidence": det.confidence, "protocol_evidence": det.evidence,
        "transport": {"mode": det.mode, "encrypted": tls_started, "expected_mode_for_port": exp[1] if exp else None},
        "dialog": dialog, "tls": tls, "chain": chain, "message_security": msg,
        "timing": {"start_ts": flow.start_ts, "end_ts": flow.end_ts, "duration": round(flow.end_ts - flow.start_ts, 6),
                   "handshake_duration": tls["handshake_duration"] if tls else None, "tcp_rtt": flow.rtt},
        "traffic": {"packets": len(flow.packets), "bytes_c2s": c2s.bytes, "bytes_s2c": s2c.bytes,
                    "retransmissions": c2s.retransmissions + s2c.retransmissions, "gaps": c2s.gaps + s2c.gaps,
                    "termination": flow.termination},
        "warnings": (tls["warnings"] if tls else []),
        "findings": [], "ml": None, "risk": None,
    }
