"""Hub collector server — receives incidents from agents over HTTP.

Usage:
    python -m scanner hub --port 8765 --api-key <key> --data-dir hub_data

Endpoints:
    POST /api/v1/incidents          — agent pushes an incident
    GET  /api/v1/fleet              — list all known hosts
    GET  /api/v1/hosts/{id}/incidents — incidents for one host
    GET  /api/v1/health             — unauthenticated liveness check

Authentication:
    Every request (except /health) must include:
        X-API-Key: <key>
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def create_app(store: Any, api_key: str):  # type: ignore[return]
    try:
        from fastapi import FastAPI, Header, HTTPException, Depends, Request
    except ImportError:
        raise ImportError(
            "fastapi is required for the hub server.\n"
            "Install with: pip install fastapi uvicorn"
        )

    from scanner.hub.store import HubStore

    app = FastAPI(title="Scanner Hub", version="0.1.0")

    def _check_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
        if x_api_key != api_key:
            raise HTTPException(status_code=401, detail="Invalid API key")

    @app.get("/api/v1/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/incidents")
    async def receive_incident(
        request: Request,
        _: None = Depends(_check_key),
    ) -> dict[str, bool]:
        payload: dict = await request.json()
        host_id = payload.get("host_id", "unknown")
        store.put_incident(host_id, payload)
        logger.info("Received incident from host=%s severity=%s",
                    host_id, payload.get("severity"))
        return {"ok": True}

    @app.get("/api/v1/fleet")
    async def fleet(_: None = Depends(_check_key)) -> list[dict[str, Any]]:
        return store.list_hosts()

    @app.get("/api/v1/hosts/{host_id}/incidents")
    async def host_incidents(
        host_id: str,
        limit: int = 200,
        _: None = Depends(_check_key),
    ) -> list[dict[str, Any]]:
        return store.list_incidents(host_id, limit)

    return app


def run_hub(
    host: str = "0.0.0.0",
    port: int = 8765,
    api_key: str = "",
    data_dir: str = "hub_data",
) -> None:
    if not api_key:
        raise ValueError("--api-key is required to start the hub")

    try:
        import uvicorn
    except ImportError:
        raise ImportError(
            "uvicorn is required for the hub server.\n"
            "Install with: pip install fastapi uvicorn"
        )

    from scanner.hub.store import HubStore

    store = HubStore(data_dir)
    app = create_app(store, api_key)

    logger.info("Starting Scanner Hub on %s:%d  data-dir=%s", host, port, data_dir)
    uvicorn.run(app, host=host, port=port, log_level="info")
