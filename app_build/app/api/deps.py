from __future__ import annotations
from fastapi import Header, HTTPException, Request

from .. import config


def require_token(x_access_token: str | None = Header(default=None)) -> None:
    if config.API_KEY and x_access_token != config.API_KEY:
        raise HTTPException(status_code=401, detail="missing or invalid X-Access-Token")


def require_actor(request: Request, x_actor: str | None = Header(default=None)) -> str | None:
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not x_actor or not x_actor.strip():
            raise HTTPException(status_code=400, detail="X-Actor header is required for state-changing requests")
        if len(x_actor) > 64:
            raise HTTPException(status_code=400, detail="X-Actor must be at most 64 characters")
        return x_actor.strip()
    return x_actor.strip() if x_actor else None


# Backward compatibility alias for 0.1
require_key = require_token

