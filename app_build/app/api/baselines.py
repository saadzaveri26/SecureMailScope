from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import storage
from ..analysis import baseline as bl
from .deps import require_token

router = APIRouter(prefix="/baselines", tags=["baselines & drift"], dependencies=[Depends(require_token)])


class BaselineIn(BaseModel):
    analysis_id: str
    endpoints: list[str] | None = None
    notes: str = ""


@router.get("", summary="List active baselines")
def list_baselines():
    b = storage.list_baselines()
    return {"count": len(b), "baselines": [{k: x[k] for k in ("baseline_id", "endpoint", "version", "created_at", "source", "posture", "model", "notes")}
                                           | {"protocol": x["profile"]["protocol"], "sessions": x["profile"]["session_count"], "server_name": x["profile"]["server_name"]} for x in b]}


@router.post("", summary="Create/replace baselines from an analysis (the 'known good' capture)")
def create(body: BaselineIn):
    try:
        doc = storage.load_analysis(body.analysis_id)
    except KeyError:
        raise HTTPException(404, "analysis not found")
    return bl.create_from_analysis(doc, body.endpoints, body.notes)


@router.get("/{endpoint}")
def get_one(endpoint: str):
    b = storage.load_baseline(endpoint)
    if not b:
        raise HTTPException(404, "no baseline for endpoint")
    return b


@router.get("/{endpoint}/history")
def history(endpoint: str):
    return {"endpoint": endpoint, "versions": storage.baseline_history(endpoint)}


@router.delete("/{endpoint}")
def delete(endpoint: str):
    if not storage.delete_baseline(endpoint):
        raise HTTPException(404, "no baseline for endpoint")
    return {"deleted": endpoint}
