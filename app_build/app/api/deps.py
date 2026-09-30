from __future__ import annotations
from fastapi import Header, HTTPException

from .. import config


def require_key(x_api_key: str | None = Header(default=None)) -> None:
    if config.API_KEY and x_api_key != config.API_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")
