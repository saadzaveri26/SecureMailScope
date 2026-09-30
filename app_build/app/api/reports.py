from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse

from .. import config, storage
from ..reports import html_report, json_report, pdf_report
from .deps import require_key

router = APIRouter(tags=["reports"], dependencies=[Depends(require_key)])
MEDIA = {"json": "application/json", "html": "text/html", "pdf": "application/pdf"}


def _generate(aid: str, fmt: str):
    try:
        doc = storage.load_analysis(aid)
    except KeyError:
        raise HTTPException(404, "analysis not found")
    path = config.REPORTS_DIR / f"SecureMailScope_{aid}.{fmt}"
    if fmt == "pdf":
        path.write_bytes(pdf_report.render(doc))
    else:
        path.write_text((html_report.render(doc) if fmt == "html" else json_report.render(doc)), encoding="utf-8")
    return path


@router.get("/analyses/{aid}/report", summary="Download the forensic report (json | html | pdf)")
async def report(aid: str, format: str = "html", download: bool = False):
    if format not in MEDIA:
        raise HTTPException(400, "format must be json, html or pdf")
    path = await run_in_threadpool(_generate, aid, format)
    return FileResponse(path, media_type=MEDIA[format], filename=path.name if download or format != "html" else None)


@router.post("/analyses/{aid}/reports", summary="Generate all three report formats into production_artifacts/reports")
async def generate_all(aid: str):
    out = {}
    for fmt in MEDIA:
        out[fmt] = (await run_in_threadpool(_generate, aid, fmt)).name
    return {"analysis_id": aid, "files": out, "directory": str(config.REPORTS_DIR)}


@router.get("/reports", summary="List generated report files")
def list_reports():
    return {"reports": [{"file": p.name, "size": p.stat().st_size} for p in sorted(config.REPORTS_DIR.glob("SecureMailScope_*"))]}


@router.get("/reports/{filename}")
def get_report(filename: str):
    p = config.REPORTS_DIR / storage.safe_name(filename)
    if not p.exists():
        raise HTTPException(404, "not found")
    return FileResponse(p, media_type=MEDIA.get(p.suffix[1:], "application/octet-stream"), filename=p.name)
