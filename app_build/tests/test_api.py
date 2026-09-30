import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client(artifacts):
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def ids(client, artifacts):
    with open(artifacts / "baseline.pcap", "rb") as f:
        r = client.post("/api/v1/analyses", files=[("files", ("baseline.pcap", f, "application/vnd.tcpdump.pcap"))], data={"compare_baseline": "false"})
    assert r.status_code == 200, r.text
    base = r.json()["results"][0]["analysis_id"]
    assert client.post("/api/v1/baselines", json={"analysis_id": base}).status_code == 200
    with open(artifacts / "drift.pcap", "rb") as f:
        r = client.post("/api/v1/analyses", files=[("files", ("drift.pcap", f, "application/octet-stream"))])
    return base, r.json()["results"][0]["analysis_id"]


def test_health_and_meta(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/api/v1/meta/rules").json()["count"] > 40
    assert client.get("/api/v1/meta/cipher-suites?grade=insecure").json()["count"] > 5


def test_rejects_non_pcap(client):
    r = client.post("/api/v1/analyses", files=[("files", ("x.pcap", b"not a pcap at all", "application/octet-stream"))])
    assert r.status_code == 400


def test_analysis_endpoints(client, ids):
    _, aid = ids
    assert client.get("/api/v1/analyses").json()["count"] >= 2
    f = client.get(f"/api/v1/analyses/{aid}/findings?severity=HIGH").json()
    assert f["count"] > 5 and f["findings"][0]["rank"] == 1
    s = client.get(f"/api/v1/analyses/{aid}/sessions?protocol=IMAP&tls_version=TLS 1.1&limit=5").json()
    assert s["total"] == 14 and s["sessions"][0]["risk_level"] in ("HIGH", "CRITICAL")
    d = client.get(f"/api/v1/analyses/{aid}/sessions/{s['sessions'][0]['session_id']}").json()
    assert d["explanation"]["why"] and d["session"]["chain"]["certificates"]
    assert client.get(f"/api/v1/analyses/{aid}/drift").json()["status"] == "DRIFT_DETECTED"
    assert client.get(f"/api/v1/analyses/{aid}/anomalies").json()["count"] > 10
    assert client.get(f"/api/v1/analyses/{aid}/certificates").json()["count"] >= 3
    assert client.get(f"/api/v1/analyses/{aid}/message-security").json()["summary"]["pgp_sessions"] == 1
    assert client.get(f"/api/v1/analyses/{aid}/posture").json()["remediation_plan"]


def test_reports(client, ids):
    _, aid = ids
    for fmt, magic in (("pdf", b"%PDF"), ("html", b"<!doctype html>"), ("json", b"{")):
        r = client.get(f"/api/v1/analyses/{aid}/report?format={fmt}")
        assert r.status_code == 200 and r.content.startswith(magic) and len(r.content) > 5000
    assert set(client.post(f"/api/v1/analyses/{aid}/reports").json()["files"]) == {"json", "html", "pdf"}


def test_dashboard_and_baselines(client, ids):
    o = client.get("/api/v1/dashboard/overview").json()
    assert not o["empty"] and len(o["trend"]) >= 2 and o["findings_by_severity"]["CRITICAL"] > 0
    assert o["trend"][0]["posture_score"] > o["trend"][-1]["posture_score"]
    assert client.get("/api/v1/dashboard/trend?endpoint=10.0.0.5:993").json()["points"]
    b = client.get("/api/v1/baselines").json()
    assert b["count"] == 5
    assert client.get("/api/v1/baselines/10.0.0.5:993/history").status_code == 200
    base, _ = ids
    assert client.post(f"/api/v1/analyses/{base}/drift/recompute").json()["status"] == "NO_DRIFT"


def test_async_job(client, artifacts):
    with open(artifacts / "baseline.pcap", "rb") as f:
        r = client.post("/api/v1/analyses", files=[("files", ("b.pcap", f, "application/octet-stream"))], data={"wait": "false"})
    jid = r.json()["job"]["job_id"]
    assert client.get(f"/api/v1/analyses/jobs/{jid}").json()["status"] in ("queued", "running", "done")
