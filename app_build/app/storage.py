"""File-based persistence under production_artifacts/ (atomic writes; no external DB required)."""
from __future__ import annotations
import json
import os
import re
import tempfile
import threading
from pathlib import Path

from . import config

_lock = threading.Lock()


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"), default=str)
    os.replace(tmp, path)


def read_json(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------- analyses
def save_analysis(doc: dict, summary: dict) -> None:
    with _lock:
        write_json(config.ANALYSES_DIR / f"{doc['analysis_id']}.json", doc)
        write_json(config.ANALYSES_DIR / f"{doc['analysis_id']}.summary.json", summary)


def load_analysis(aid: str) -> dict:
    p = config.ANALYSES_DIR / f"{safe_name(aid)}.json"
    if not p.exists():
        raise KeyError(aid)
    return read_json(p)


def load_summary(aid: str) -> dict:
    p = config.ANALYSES_DIR / f"{safe_name(aid)}.summary.json"
    if not p.exists():
        raise KeyError(aid)
    return read_json(p)


def list_summaries() -> list[dict]:
    out = []
    for p in config.ANALYSES_DIR.glob("*.summary.json"):
        try:
            out.append(read_json(p))
        except Exception:  # noqa: BLE001
            continue
    out.sort(key=lambda s: s.get("created_at", ""), reverse=True)
    return out


def delete_analysis(aid: str) -> bool:
    ok = False
    for suffix in (".json", ".summary.json"):
        p = config.ANALYSES_DIR / f"{safe_name(aid)}{suffix}"
        if p.exists():
            p.unlink(); ok = True
    return ok


# ---------------------------------------------------------------- baselines
def baseline_path(endpoint: str) -> Path:
    return config.BASELINES_DIR / f"{safe_name(endpoint)}.json"


def save_baseline(doc: dict) -> None:
    with _lock:
        p = baseline_path(doc["endpoint"])
        if p.exists():                                     # archive previous version
            old = read_json(p)
            write_json(config.BASELINES_DIR / "history" / safe_name(doc["endpoint"]) / f"v{old.get('version', 0)}.json", old)
            doc["version"] = old.get("version", 0) + 1
        else:
            doc["version"] = 1
        write_json(p, doc)


def load_baseline(endpoint: str) -> dict | None:
    p = baseline_path(endpoint)
    return read_json(p) if p.exists() else None


def list_baselines() -> list[dict]:
    out = []
    for p in sorted(config.BASELINES_DIR.glob("*.json")):
        try:
            out.append(read_json(p))
        except Exception:  # noqa: BLE001
            continue
    return out


def baseline_history(endpoint: str) -> list[dict]:
    d = config.BASELINES_DIR / "history" / safe_name(endpoint)
    return [read_json(p) for p in sorted(d.glob("v*.json"))] if d.exists() else []


def delete_baseline(endpoint: str) -> bool:
    p = baseline_path(endpoint)
    m = config.MODELS_DIR / f"{safe_name(endpoint)}.joblib"
    ok = p.exists()
    for x in (p, m):
        if x.exists():
            x.unlink()
    return ok
