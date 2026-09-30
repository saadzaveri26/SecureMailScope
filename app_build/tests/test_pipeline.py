import hashlib

import pytest

from app.analysis import baseline as bl
from app.analysis.drift import js_divergence
from app.analysis.pipeline import analyze_pcap
from app.core.cipher_db import describe
from app import storage


def run(path, **kw):
    b = path.read_bytes()
    return analyze_pcap(path, filename=path.name, sha256=hashlib.sha256(b).hexdigest(), size=len(b), **kw)


@pytest.fixture(scope="module")
def baseline_doc(artifacts):
    return run(artifacts / "baseline.pcap", compare_baseline=False, create_baseline=True)


@pytest.fixture(scope="module")
def drift_doc(artifacts, baseline_doc):
    return run(artifacts / "drift.pcap")


def test_cipher_registry():
    assert describe(0xC030).grade == "strong" and describe(0xC030).forward_secrecy
    assert describe(0x000A).grade == "weak" and describe(0x000A).enc == "3DES"
    assert describe(0xC011).grade == "insecure" and describe(0x1301).forward_secrecy
    assert describe(0x009C).grade == "acceptable" and not describe(0x009C).forward_secrecy


def test_js_divergence():
    assert js_divergence({"a": 1}, {"a": 5}) == 0
    assert js_divergence({"a": 1}, {"b": 1}) == pytest.approx(1.0)


def test_reconstruction_and_identification(baseline_doc):
    s = baseline_doc["summary"]
    assert s["sessions"] == 177 and baseline_doc["source"]["tcp_streams"] == 177
    assert s["sessions_by_protocol"] == {"IMAP": 90, "SMTP": 75, "POP3": 12}
    assert s["sessions_by_transport"] == {"starttls": 85, "implicit_tls": 92}
    assert s["tls_versions"] == {"TLS 1.3": 115, "TLS 1.2": 62}
    assert s["forward_secrecy_ratio"] == 1.0


def test_baseline_posture_is_healthy(baseline_doc):
    assert baseline_doc["posture"]["overall"]["score"] >= 90
    assert not [f for f in baseline_doc["findings"] if f["severity"] in ("CRITICAL", "HIGH")]
    # enterprise CA in trust store => chain trusted, no certificate findings
    assert not [f for f in baseline_doc["findings"] if f["category"] == "certificate" and f["severity"] != "INFO"]


def test_baselines_created(baseline_doc):
    b = storage.load_baseline("10.0.0.5:993")
    assert b and b["profile"]["tls_versions"] == {"TLS 1.3": 50, "TLS 1.2": 30}
    assert b["model"]["type"] == "IsolationForest" and b["integrity_sha256"]
    assert len(b["profile"]["certificates"]) == 1


def test_rules_fire_on_drift_capture(drift_doc):
    rules = {f["rule_id"] for f in drift_doc["findings"]}
    for r in ("TR-001", "TR-002", "TR-003", "TLS-001", "TLS-003", "TLS-005", "CS-001", "CS-002", "CS-004", "CS-006", "CE-001", "CE-003", "CE-004",
              "CE-005", "CE-008", "MS-001", "MS-002", "MS-004", "ML-001"):
        assert r in rules, r
    top = drift_doc["findings"][0]
    assert top["severity"] == "CRITICAL" and top["priority"] == "P1"


def test_credentials_never_stored(drift_doc):
    import json
    blob = json.dumps(drift_doc, default=str)
    leaked = [needle for needle in ("s3cretpw", "AGFsaWNlAHNlY3JldA") if needle in blob]   # cleartext password / base64 AUTH PLAIN blob
    assert leaked == []
    assert drift_doc["summary"]["credential_exposures"] >= 3


def test_starttls_stripping_detected(drift_doc):
    s = next(x for x in drift_doc["sessions"] if x["dialog"]["starttls"]["failed"])
    assert s["endpoint"] == "10.0.0.6:587" and s["transport"]["mode"] == "plaintext"
    assert any(f["rule_id"] == "TR-003" and f["severity"] == "CRITICAL" for f in s["findings"])


def test_message_layer(drift_doc):
    ml = drift_doc["summary"]["message_layer"]
    assert ml["pgp_sessions"] == 1 and ml["smime_sessions"] == 1 and ml["plaintext_with_message_protection"] == 2
    sm = next(x for x in drift_doc["sessions"] if x["message_security"]["smime"]["detected"])
    assert sm["message_security"]["smime"]["signer_certificates"]


def test_drift_engine(drift_doc):
    d = drift_doc["drift"]
    assert d["status"] == "DRIFT_DETECTED" and d["baseline_compared"]
    titles = " | ".join(i["title"] for i in d["items"])
    assert "TLS 1.1 traffic detected" in titles and "Certificate change detected" in titles and "possible stripping" in titles
    tls11 = next(i for i in d["items"] if i["title"] == "TLS 1.1 traffic detected")
    assert tls11["affected_sessions"] == 14 and tls11["severity"] == "HIGH"
    assert tls11["baseline"] == "TLS 1.2 / TLS 1.3 only" and tls11["evidence"][0]["handshake_message"] == "ServerHello"
    cert = next(i for i in d["items"] if i["endpoint"] == "10.0.0.5:993" and i["dimension"] == "certificate")
    assert cert["severity"] == "HIGH" and any("Issuer changed" in o for o in cert["observed"])
    assert d["endpoints"]["10.0.0.5:993"]["status"] == "DEGRADED"
    assert "10.0.0.8:465" in " ".join(d["notes"])


def test_ml_uses_baseline_model_and_explains(drift_doc):
    assert "baseline-trained" in drift_doc["ml"]["models"]["10.0.0.5:993"]
    tls11 = [a for a in drift_doc["anomalies"] if any("TLS 1.1" in r for r in a["reasons"])]
    assert len(tls11) >= 10 and all(a["score"] >= 0.5 for a in tls11)


def test_explainable_card(drift_doc):
    from app.analysis.risk_engine import explain_session
    from app.analysis.common import inflate_certs
    inflate_certs(drift_doc)
    worst = max(drift_doc["sessions"], key=lambda s: s["risk"]["score"])
    card = explain_session(worst)
    assert card["risk_level"] in ("HIGH", "CRITICAL") and card["why"] and card["recommendation"]
    assert {"Transport"} <= {r["label"] for r in card["rows"]}


def test_weak_signature_rule_on_mutated_session(drift_doc):
    """cryptography >= 46 cannot *sign* with SHA-1, so exercise CE-010 by mutating a parsed legacy-server session."""
    import copy
    from app.analysis.common import inflate_certs
    from app.analysis.rules import evaluate_session
    inflate_certs(drift_doc)
    s = copy.deepcopy(next(x for x in drift_doc["sessions"] if x["endpoint"] == "10.0.0.8:465"))
    s["chain"]["certificates"][0]["signature"].update(hash="sha1", weak=True)
    hit = next(h for h in evaluate_session(s) if h["rule_id"] == "CE-010")
    assert hit["severity"] == "HIGH" and hit["variant"] == "SHA1"
    s["chain"]["certificates"][0]["signature"].update(hash="md5")
    assert next(h for h in evaluate_session(s) if h["rule_id"] == "CE-010")["severity"] == "CRITICAL"
