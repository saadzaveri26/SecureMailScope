"""Tiny in-memory job registry for asynchronous (wait=false) analyses."""
from __future__ import annotations
import threading
import uuid
from datetime import datetime, timezone

_jobs: dict[str, dict] = {}
_lock = threading.Lock()


def create(files: list[str]) -> dict:
    j = {"job_id": f"J-{uuid.uuid4().hex[:10]}", "status": "queued", "files": files, "analysis_ids": [], "errors": [],
         "created_at": datetime.now(timezone.utc).isoformat(), "finished_at": None}
    with _lock:
        _jobs[j["job_id"]] = j
    return j


def update(job_id: str, **kw) -> None:
    with _lock:
        _jobs[job_id].update(kw)


def get(job_id: str) -> dict | None:
    return _jobs.get(job_id)


def all_jobs() -> list[dict]:
    return sorted(_jobs.values(), key=lambda j: j["created_at"], reverse=True)
