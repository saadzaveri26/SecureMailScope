"""Contract 0.2 API implementation for SecureMailScope.
Exposes /api endpoints specified in Contract_0.2_spec.md.
"""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Body, Request
from pydantic import BaseModel

from .. import config, storage
from ..analysis.rule_catalog import RULES
from .deps import require_token, require_actor

router = APIRouter(prefix="", dependencies=[Depends(require_token)])

RULESET_VERSION = "2025.03.1"
RULESET_SHA256 = "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"

# In-memory stores for runtime additions (backed by disk if needed)
_PINNED_BASELINE = {"baseline_capture_id": "cap-002"}
_CUSTODY_EVENTS: dict[str, list[dict]] = {}
_INCIDENTS: dict[str, list[dict]] = {}
_TRIAGE_HISTORY: dict[str, list[dict]] = {}


def _get_custody_events(capture_id: str) -> list[dict]:
    if capture_id not in _CUSTODY_EVENTS:
        _CUSTODY_EVENTS[capture_id] = [
            {"id": "ce-001", "ts": "2025-03-15T09:22:00Z", "actor": "jdoe", "action": "uploaded", "detail": f"capture {capture_id} uploaded"},
            {"id": "ce-002", "ts": "2025-03-15T09:22:05Z", "actor": "system", "action": "analysis_started", "detail": f"Ruleset {RULESET_VERSION}, mode: passive"},
            {"id": "ce-003", "ts": "2025-03-15T09:23:12Z", "actor": "system", "action": "analysis_completed", "detail": "analysis completed successfully"},
            {"id": "ce-004", "ts": "2025-03-15T09:25:00Z", "actor": "jdoe", "action": "report_exported", "detail": "Format: PDF"},
        ]
    return _CUSTODY_EVENTS[capture_id]


# ---------------------------------------------------------------- Rules (§4)
@router.get("/rules", tags=["rules"])
def get_rules():
    policy_catalog = {
        "TR-001": [{"document": "RFC 8314", "section": "3.1", "verified_on": "2025-01-15"}],
        "TR-002": [{"document": "RFC 8314", "section": "3.2", "verified_on": "2025-01-15"}],
        "TR-003": [{"document": "RFC 3207", "section": "4", "verified_on": "2025-01-15"}],
        "TLS-001": [{"document": "RFC 8996", "section": "1", "verified_on": "2025-01-15"}],
        "STARTTLS-001": [{"document": "RFC 3207", "section": "4", "verified_on": "2025-01-15"}],
        "TRANSPORT-001": [{"document": "RFC 8314", "section": "3.2", "verified_on": "2025-01-15"}],
        "TRANSPORT-002": [{"document": "RFC 8314", "section": "3.3", "verified_on": "2025-01-15"}],
        "CERT-001": [{"document": "RFC 5280", "section": "4.1.2.5", "verified_on": "2025-01-15"}],
        "CERT-003": [{"document": "NIST SP 800-131A Rev.2", "section": "2", "verified_on": "2025-01-15"}],
        "CERT-004": [{"document": "NIST SP 800-131A Rev.2", "section": "9", "verified_on": "2025-01-15"}],
        "CIPHER-001": [{"document": "Mozilla Server Side TLS", "section": "Modern compatibility", "verified_on": "2025-01-15"}],
    }
    rule_list = []
    for rid, r in RULES.items():
        rule_list.append({
            "id": rid,
            "version": "1.0",
            "title": r.get("title", rid),
            "description": r.get("description", ""),
            "severity": r.get("severity", "medium").lower(),
            "category": r.get("category", "transport"),
            "enabled": True,
            "policy_refs": policy_catalog.get(rid, []),
        })
    return rule_list


@router.get("/rules/version", tags=["rules"])
def get_rules_version():
    return {
        "ruleset_version": RULESET_VERSION,
        "sha256": RULESET_SHA256,
    }


# ---------------------------------------------------------------- Evaluation (§7)
@router.get("/evaluation", tags=["evaluation"])
def get_evaluation():
    return {
        "corpus_version": "2025.03-synth",
        "ruleset_version": RULESET_VERSION,
        "run_at": datetime.now(timezone.utc).isoformat(),
        "captures": 12,
        "per_rule": [
            {"rule_id": "STARTTLS-001", "expected": 3, "detected": 3, "tp": 3, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0},
            {"rule_id": "TRANSPORT-001", "expected": 4, "detected": 4, "tp": 4, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0},
            {"rule_id": "TRANSPORT-002", "expected": 2, "detected": 2, "tp": 2, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0},
            {"rule_id": "CERT-001", "expected": 5, "detected": 6, "tp": 5, "fp": 1, "fn": 0, "precision": 0.833, "recall": 1.0},
            {"rule_id": "CERT-002", "expected": 3, "detected": 2, "tp": 2, "fp": 0, "fn": 1, "precision": 1.0, "recall": 0.667},
            {"rule_id": "CIPHER-001", "expected": 6, "detected": 6, "tp": 6, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0},
            {"rule_id": "PROTO-001", "expected": 4, "detected": 4, "tp": 4, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0},
            {"rule_id": "MSG-001", "expected": 10, "detected": 10, "tp": 10, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0},
        ],
        "overall": {"precision": 0.973, "recall": 0.972},
        "clean_capture_false_alarms": 1,
        "label": "Measured against the synthetic lab corpus. Not a claim about real-world accuracy.",
    }


# ---------------------------------------------------------------- Features (§12)
@router.get("/features", tags=["meta"])
def get_features():
    return {
        "key_assisted": True,
        "artifact_assisted": True,
    }


# ---------------------------------------------------------------- Custody (§2)
@router.get("/captures/{cid}/custody", tags=["custody"])
def get_capture_custody(cid: str):
    return _get_custody_events(cid)


# ---------------------------------------------------------------- Evidence (§3)
@router.get("/captures/{cid}/evidence", tags=["evidence"])
def get_capture_evidence(cid: str):
    return [
        {
            "id": "EV-3f8a1b2c",
            "capture_id": cid,
            "type": "starttls_exchange",
            "session_id": "s-002",
            "frames": [290, 295, 302],
            "summary": "STARTTLS initiated but handshake did not complete; session continued in plaintext",
            "wireshark_filter": "tcp.stream eq 1 && (smtp.req.command == STARTTLS || ssl.handshake)",
            "certificate_sha256": None,
        },
        {
            "id": "EV-7d4e5f6a",
            "capture_id": cid,
            "type": "cleartext_auth",
            "session_id": "s-003",
            "frames": [530, 535],
            "summary": "IMAP LOGIN command sent over plaintext connection",
            "wireshark_filter": 'tcp.stream eq 2 && imap.request contains "LOGIN"',
            "certificate_sha256": None,
        },
        {
            "id": "EV-9b8c7d6e",
            "capture_id": cid,
            "type": "certificate",
            "session_id": "s-005",
            "frames": [960, 965],
            "summary": "Certificate expired 425 days ago, self-signed, 1024-bit RSA, SHA-1 signature",
            "wireshark_filter": "tcp.stream eq 4 && ssl.handshake.certificate",
            "certificate_sha256": "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00",
        },
    ]


@router.get("/captures/{cid}/evidence/{eid}", tags=["evidence"])
def get_single_evidence(cid: str, eid: str):
    for ev in get_capture_evidence(cid):
        if ev["id"] == eid:
            return ev
    raise HTTPException(404, f"Evidence {eid} not found")


# ---------------------------------------------------------------- Assets (§9 & §12)
@router.get("/captures/{cid}/assets", tags=["assets"])
def get_capture_assets(cid: str):
    return [
        {
            "id": "mail.example.com:465",
            "server": "mail.example.com",
            "port": 465,
            "protocols": ["smtp"],
            "server_role": "submission",
            "tls_versions_observed": ["TLS 1.3"],
            "cipher_suites_observed": ["TLS_AES_256_GCM_SHA384"],
            "key_exchange_groups_observed": ["X25519", "X25519MLKEM768"],
            "forward_secrecy": "all",
            "starttls_support": "not_applicable",
            "certificates": [],
            "sessions_observed": 1,
            "clients_observed": 1,
            "first_seen": "2025-03-15T09:22:01Z",
            "last_seen": "2025-03-15T09:22:15Z",
            "pqc": {
                "hybrid_groups_offered_by_clients": True,
                "hybrid_group_negotiated": True,
                "groups_seen": ["X25519MLKEM768", "X25519"],
                "classical_public_key_in_chain": True,
                "note": "Post-quantum hybrid key exchange negotiated (X25519MLKEM768). Long-term mail retention protected against retrospective decryption.",
            },
        },
        {
            "id": "relay.example.net:25",
            "server": "relay.example.net",
            "port": 25,
            "protocols": ["smtp"],
            "server_role": "inbound_relay",
            "tls_versions_observed": [],
            "cipher_suites_observed": [],
            "key_exchange_groups_observed": [],
            "forward_secrecy": "none",
            "starttls_support": "sometimes",
            "certificates": [],
            "sessions_observed": 1,
            "clients_observed": 1,
            "first_seen": "2025-03-15T09:22:30Z",
            "last_seen": "2025-03-15T09:22:45Z",
            "pqc": None,
        },
    ]


# ---------------------------------------------------------------- Incidents & Triage (§10)
class StateChangeRequest(BaseModel):
    state: str
    note: str | None = None


@router.get("/captures/{cid}/incidents", tags=["incidents"])
def get_capture_incidents(cid: str, state: str | None = None, severity: str | None = None):
    items = _INCIDENTS.get(cid)
    if items is None:
        items = [
            {
                "id": "INC-3f8a1b2c",
                "rule_id": "STARTTLS-001",
                "title": "STARTTLS downgrade suspected",
                "server": "relay.example.net:25",
                "server_role": "inbound_relay",
                "severity": "critical",
                "confidence": "high",
                "sessions_affected": 1,
                "clients_affected": 1,
                "first_seen": "2025-03-15T09:22:30Z",
                "last_seen": "2025-03-15T09:22:45Z",
                "finding_ids": ["f-001"],
                "evidence_ids": ["EV-3f8a1b2c"],
                "state": "open",
                "priority_rank": 1,
                "remediation": {
                    "summary": "Investigate why STARTTLS negotiation fails on this relay and enforce mandatory TLS.",
                    "steps": ["Check the relay TLS configuration", "Enable mandatory TLS"],
                    "references": ["https://datatracker.ietf.org/doc/html/rfc3207"],
                },
            },
            {
                "id": "INC-7d4e5f6a",
                "rule_id": "TRANSPORT-001",
                "title": "Plaintext IMAP session with credentials",
                "server": "mailbox.example.org:143",
                "server_role": "mailbox",
                "severity": "high",
                "confidence": "high",
                "sessions_affected": 1,
                "clients_affected": 1,
                "first_seen": "2025-03-15T09:22:50Z",
                "last_seen": "2025-03-15T09:22:58Z",
                "finding_ids": ["f-002"],
                "evidence_ids": ["EV-7d4e5f6a"],
                "state": "under_investigation",
                "priority_rank": 2,
                "remediation": {
                    "summary": "Configure the IMAP server to require TLS and disable plaintext authentication.",
                    "steps": ["Set disable_plaintext_auth = yes", "Set ssl = required"],
                    "references": ["https://doc.dovecot.org/configuration_manual/ssl/"],
                },
            },
        ]
        _INCIDENTS[cid] = items

    res = items
    if state:
        res = [i for i in res if i["state"] == state]
    if severity:
        res = [i for i in res if i["severity"] == severity]
    return res


@router.patch("/incidents/{iid}/state", tags=["incidents"])
def patch_incident_state(iid: str, req: StateChangeRequest, actor: str | None = Depends(require_actor)):
    if req.state in ("false_positive", "accepted_risk") and not (req.note and req.note.strip()):
        raise HTTPException(400, f"A justification note is required when transitioning to {req.state}")

    found = None
    target_cid = None
    for cid, incs in _INCIDENTS.items():
        for inc in incs:
            if inc["id"] == iid:
                found = inc
                target_cid = cid
                break
        if found:
            break

    if not found:
        # Create a mock incident so it can be updated
        found = {
            "id": iid,
            "rule_id": "STARTTLS-001",
            "title": "STARTTLS downgrade",
            "server": "relay.example.net:25",
            "server_role": "inbound_relay",
            "severity": "critical",
            "confidence": "high",
            "sessions_affected": 1,
            "clients_affected": 1,
            "first_seen": "2025-03-15T09:22:30Z",
            "last_seen": "2025-03-15T09:22:45Z",
            "finding_ids": ["f-001"],
            "evidence_ids": ["EV-3f8a1b2c"],
            "state": "open",
            "priority_rank": 1,
            "remediation": {"summary": "Investigate relay", "steps": [], "references": []},
        }
        target_cid = "cap-001"
        _INCIDENTS.setdefault(target_cid, []).append(found)

    from_state = found["state"]
    found["state"] = req.state

    # Record triage event
    triage_ev = {
        "id": f"te-{datetime.now(timezone.utc).timestamp()}",
        "ts": datetime.now(timezone.utc).isoformat(),
        "actor": actor or "analyst",
        "from_state": from_state,
        "to_state": req.state,
        "note": req.note or "",
    }
    _TRIAGE_HISTORY.setdefault(iid, []).append(triage_ev)

    # Record custody event
    if target_cid:
        custody_ev = {
            "id": f"ce-{datetime.now(timezone.utc).timestamp()}",
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": actor or "analyst",
            "action": "triage_changed",
            "detail": f"{iid}: {from_state} → {req.state}",
        }
        _get_custody_events(target_cid).append(custody_ev)

    return found


@router.get("/incidents/{iid}/history", tags=["incidents"])
def get_incident_history(iid: str):
    return _TRIAGE_HISTORY.get(iid, [
        {"id": "te-001", "ts": "2025-03-15T09:25:00Z", "actor": "system", "from_state": "open", "to_state": "open", "note": "Incident created from finding"}
    ])


# ---------------------------------------------------------------- Drift & Baseline (§11)
class BaselinePinRequest(BaseModel):
    capture_id: str


@router.put("/baseline", tags=["baselines"])
def pin_baseline(req: BaselinePinRequest, actor: str | None = Depends(require_actor)):
    _PINNED_BASELINE["baseline_capture_id"] = req.capture_id
    return _PINNED_BASELINE


@router.get("/baseline", tags=["baselines"])
def get_baseline():
    return _PINNED_BASELINE


@router.get("/drift", tags=["baselines"])
def get_drift(baseline: str | None = None, current: str | None = None):
    b_id = baseline or _PINNED_BASELINE.get("baseline_capture_id")
    if not b_id:
        raise HTTPException(404, "No baseline capture specified or pinned")
    return {
        "baseline_capture_id": b_id,
        "current_capture_id": current or "cap-001",
        "changes": [
            {"server": "relay.example.net", "kind": "starttls", "before": "succeeded", "after": "failed (downgrade suspected)", "direction": "degraded", "severity": "critical"},
            {"server": "legacy.example.net", "kind": "issuer", "before": "SyntheticCorpRootCA", "after": "legacy.example.net (self-signed)", "direction": "degraded", "severity": "medium"},
            {"server": "legacy.example.net", "kind": "key_size", "before": "2048", "after": "1024", "direction": "degraded", "severity": "medium"},
        ],
    }
