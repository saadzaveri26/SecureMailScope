"""SecureMailScope FastAPI application."""
from __future__ import annotations
import warnings
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import config
from .api import analyses, baselines, dashboard, meta, reports
from .core.cert_analyzer import get_trust_store

warnings.filterwarnings("ignore")


@asynccontextmanager
async def lifespan(_: FastAPI):
    config.ensure_dirs()
    get_trust_store()
    yield


app = FastAPI(title="SecureMailScope API", version=config.APP_VERSION, lifespan=lifespan,
              description="AI-assisted passive cryptographic security posture assessment for SMTP/IMAP/POP3 (PCAP forensics).")
app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
for r in (analyses.router, baselines.router, dashboard.router, reports.router, meta.router):
    app.include_router(r, prefix="/api/v1")


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "app": config.APP_NAME, "version": config.APP_VERSION, "artifacts_dir": str(config.ARTIFACTS_DIR)}
