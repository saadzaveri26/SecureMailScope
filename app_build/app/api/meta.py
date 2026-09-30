from __future__ import annotations
from fastapi import APIRouter, Depends

from .. import config
from ..analysis.rule_catalog import RULES
from ..core.cert_analyzer import get_trust_store, reload_trust_store
from ..core.cipher_db import IANA_SUITES, describe
from .deps import require_key

router = APIRouter(prefix="/meta", tags=["meta"], dependencies=[Depends(require_key)])


@router.get("/rules", summary="Detection rule catalogue")
def rules():
    return {"count": len(RULES), "rules": list(RULES.values())}


@router.get("/cipher-suites", summary="Cipher suite registry with strength grades")
def ciphers(grade: str | None = None):
    rows = [describe(i).to_dict() for i in IANA_SUITES]
    return {"count": len(rows), "cipher_suites": [r for r in rows if not grade or r["grade"] == grade]}


@router.get("/trust-store")
def trust():
    t = get_trust_store()
    return {"anchors": len(t.fps), "sources": t.sources, "enterprise_dir": str(config.TRUST_STORE_DIR)}


@router.post("/trust-store/reload", summary="Reload CA certificates after adding files to production_artifacts/trust_store")
def trust_reload():
    t = reload_trust_store()
    return {"anchors": len(t.fps), "sources": t.sources}
