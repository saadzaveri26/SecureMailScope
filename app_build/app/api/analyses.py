from __future__ import annotations
import hashlib
import uuid
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.concurrency import run_in_threadpool

from .. import config, jobs, storage
from ..analysis import pipeline
from ..analysis.common import inflate_certs
from ..analysis.risk_engine import explain_session
from ..analysis.rule_catalog import SEV_RANK
from ..core.pcap_reader import InvalidCapture, PCAP_MAGICS, PCAPNG_MAGIC
from .deps import require_token, require_actor

router = APIRouter(prefix="/analyses", tags=["analyses"], dependencies=[Depends(require_token)])


async def _save_upload(f: UploadFile) -> tuple[Path, str, int]:
    name = storage.safe_name(f.filename or "upload.pcap")
    dest = config.UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{name}"
    h, size, first = hashlib.sha256(), 0, b""
    limit = config.MAX_UPLOAD_MB * 1024 * 1024
    with open(dest, "wb") as out:
        while chunk := await f.read(1024 * 1024):
            if not first:
                first = chunk[:4]
            size += len(chunk)
            if size > limit:
                out.close(); dest.unlink(missing_ok=True)
                raise HTTPException(413, f"{f.filename}: exceeds {config.MAX_UPLOAD_MB} MB limit")
            h.update(chunk); out.write(chunk)
    if first not in PCAP_MAGICS and first != PCAPNG_MAGIC:
        dest.unlink(missing_ok=True)
        raise HTTPException(400, f"{f.filename}: not a PCAP/PCAPNG file")
    return dest, h.hexdigest(), size


def _run(path: Path, name: str, sha: str, size: int, batch: str, compare: bool, create_bl: bool, analyst: str | None) -> dict:
    doc = pipeline.analyze_pcap(path, filename=name, sha256=sha, size=size, batch_id=batch, compare_baseline=compare, create_baseline=create_bl, analyst=analyst)
    return doc["report_summary"]


def _job(job_id: str, items: list, batch: str, compare: bool, create_bl: bool, analyst: str | None) -> None:
    jobs.update(job_id, status="running")
    ids, errs = [], []
    for path, name, sha, size in items:
        try:
            ids.append(_run(path, name, sha, size, batch, compare, create_bl, analyst)["analysis_id"])
        except (InvalidCapture, Exception) as e:  # noqa: BLE001
            errs.append({"file": name, "error": str(e)})
    from datetime import datetime, timezone
    jobs.update(job_id, status="done" if ids else "error", analysis_ids=ids, errors=errs, finished_at=datetime.now(timezone.utc).isoformat())


@router.post("", summary="Upload one or many PCAP/PCAPNG files and analyse them")
async def upload(background: BackgroundTasks, files: list[UploadFile] = File(...), compare_baseline: bool = Form(True), create_baseline: bool = Form(False),
                 wait: bool = Form(True), analyst: str | None = Form(None)):
    saved = [(*(await _save_upload(f)), f.filename or "upload.pcap") for f in files]
    items = [(p, name, sha, size) for p, sha, size, name in saved]
    batch = f"BATCH-{uuid.uuid4().hex[:8]}"
    if not wait:
        j = jobs.create([i[1] for i in items])
        background.add_task(_job, j["job_id"], items, batch, compare_baseline, create_baseline, analyst)
        return {"batch_id": batch, "job": j}
    results, errors = [], []
    for path, name, sha, size in items:
        try:
            results.append(await run_in_threadpool(_run, path, name, sha, size, batch, compare_baseline, create_baseline, analyst))
        except InvalidCapture as e:
            errors.append({"file": name, "error": str(e)})
    if not results:
        raise HTTPException(400, {"errors": errors})
    return {"batch_id": batch, "results": results, "errors": errors}


@router.get("/jobs/{job_id}", summary="Status of an asynchronous analysis job")
def job_status(job_id: str):
    j = jobs.get(job_id)
    if not j:
        raise HTTPException(404, "job not found")
    return j


def _doc(aid: str, inflate: bool = False) -> dict:
    try:
        d = storage.load_analysis(aid)
    except KeyError:
        raise HTTPException(404, f"analysis {aid} not found")
    return inflate_certs(d) if inflate else d


@router.get("", summary="List analyses (summaries)")
def list_analyses(batch_id: str | None = None, limit: int = Query(100, le=500)):
    s = storage.list_summaries()
    if batch_id:
        s = [x for x in s if x.get("batch_id") == batch_id]
    return {"count": len(s), "analyses": s[:limit]}


@router.get("/{aid}", summary="Full analysis (without per-session detail unless include_sessions=true)")
def get_analysis(aid: str, include_sessions: bool = False):
    d = _doc(aid)
    if not include_sessions:
        d = {k: v for k, v in d.items() if k != "sessions"}
    return d


@router.delete("/{aid}")
def delete(aid: str):
    if not storage.delete_analysis(aid):
        raise HTTPException(404, "not found")
    return {"deleted": aid}


@router.get("/{aid}/sessions", summary="Paginated, filterable session table")
def sessions(aid: str, protocol: str | None = None, endpoint: str | None = None, transport: str | None = None, tls_version: str | None = None,
             risk_level: str | None = None, min_risk: int = 0, anomalous: bool | None = None, sort: str = "risk", offset: int = 0, limit: int = Query(50, le=500)):
    rows = []
    for s in _doc(aid)["sessions"]:
        neg = (s["tls"] or {}).get("negotiated") or {}
        if protocol and s["protocol"] != protocol.upper() or endpoint and s["endpoint"] != endpoint or transport and s["transport"]["mode"] != transport:
            continue
        if tls_version and neg.get("version") != tls_version or risk_level and s["risk"]["level"] != risk_level.upper() or s["risk"]["score"] < min_risk:
            continue
        if anomalous is not None and bool((s["ml"] or {}).get("anomalous")) != anomalous:
            continue
        rows.append({"session_id": s["session_id"], "tcp_stream": s["tcp_stream"], "protocol": s["protocol"], "client": s["client"], "server": s["server"], "endpoint": s["endpoint"],
                     "server_name": s["server_name"], "transport": s["transport"]["mode"], "tls_version": neg.get("version"), "cipher_suite": neg.get("cipher_suite"),
                     "key_exchange": neg.get("kex"), "forward_secrecy": neg.get("forward_secrecy"), "risk_score": s["risk"]["score"], "risk_level": s["risk"]["level"],
                     "ml_score": (s["ml"] or {}).get("score"), "anomalous": (s["ml"] or {}).get("anomalous"), "findings": len(s["findings"]), "start_ts": s["timing"]["start_ts"]})
    rows.sort(key=(lambda r: -r["risk_score"]) if sort == "risk" else (lambda r: r["tcp_stream"]))
    return {"total": len(rows), "offset": offset, "limit": limit, "sessions": rows[offset:offset + limit]}


@router.get("/{aid}/sessions/{sid}", summary="Full session record + explainable assessment card")
def session_detail(aid: str, sid: str):
    d = _doc(aid, inflate=True)
    s = next((x for x in d["sessions"] if x["session_id"] == sid or str(x["tcp_stream"]) == sid), None)
    if not s:
        raise HTTPException(404, "session not found")
    return {"session": s, "explanation": explain_session(s)}


@router.get("/{aid}/findings", summary="Prioritised findings")
def findings(aid: str, severity: str | None = None, category: str | None = None, endpoint: str | None = None, include_info: bool = False):
    f = _doc(aid)["findings"]
    if not include_info:
        f = [x for x in f if x["severity"] != "INFO"]
    if severity:
        f = [x for x in f if SEV_RANK[x["severity"]] >= SEV_RANK[severity.upper()]]
    if category:
        f = [x for x in f if x["category"] == category]
    if endpoint:
        f = [x for x in f if x["endpoint"] == endpoint]
    return {"count": len(f), "findings": f}


@router.get("/{aid}/posture")
def posture(aid: str):
    d = _doc(aid)
    return {"posture": d["posture"], "remediation_plan": d["remediation_plan"]}


@router.get("/{aid}/anomalies")
def anomalies(aid: str):
    d = _doc(aid)
    return {"ml": d["ml"], "count": len(d["anomalies"]), "anomalies": d["anomalies"]}


@router.get("/{aid}/certificates")
def certificates(aid: str):
    d = _doc(aid)
    return {"count": len(d["certificates"]), "certificates": list(d["certificates"].values())}


@router.get("/{aid}/drift")
def drift(aid: str):
    return _doc(aid)["drift"]


@router.post("/{aid}/drift/recompute", summary="Re-run baseline comparison (e.g. after creating/updating a baseline)")
def recompute(aid: str):
    d = pipeline.recompute_drift(_doc(aid))
    return d["drift"]


@router.get("/{aid}/message-security", summary="PGP / S-MIME message-layer detections")
def message_security(aid: str):
    d = _doc(aid)
    rows = [{"session_id": s["session_id"], "tcp_stream": s["tcp_stream"], "protocol": s["protocol"], "server": s["server"], "transport": s["transport"]["mode"],
             **s["message_security"]} for s in d["sessions"] if s["message_security"]["layer"] != "none"]
    return {"summary": d["summary"]["message_layer"], "sessions": rows}
