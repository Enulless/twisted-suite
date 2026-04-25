"""HTTP client wrapper for the engine API.

Used by the CLI and worker to avoid hand-coding requests calls everywhere.
Synchronous httpx for simplicity (the worker is single-threaded and the CLI
is one-shot).
"""

from __future__ import annotations

from typing import Any

import httpx

from ..core.settings import Settings, get_settings
from ..engine.auth import read_token


class EngineClient:
    """Tiny HTTP client. Constructs Authorization headers and parses JSON."""

    def __init__(self, base_url: str | None = None, token: str | None = None,
                 *, settings: Settings | None = None, timeout: float = 30.0):
        s = settings or get_settings()
        self._base = (base_url or s.engine_url).rstrip("/")
        self._token = token or read_token(s) or ""
        self._client = httpx.Client(base_url=self._base, timeout=timeout,
                                    headers=self._auth_headers())

    def _auth_headers(self) -> dict[str, str]:
        h = {"User-Agent": "twisted-client/0.1"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> EngineClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ──────────────────────────── HTTP verbs ────────────────────────────

    def get(self, path: str, *, params: dict | None = None) -> Any:
        r = self._client.get(path, params=params)
        r.raise_for_status()
        return r.json() if r.content else None

    def post(self, path: str, *, json: Any = None, params: dict | None = None) -> Any:
        r = self._client.post(path, json=json, params=params)
        r.raise_for_status()
        return r.json() if r.content else None

    def delete(self, path: str) -> None:
        r = self._client.delete(path)
        if r.status_code not in (200, 204):
            r.raise_for_status()

    # ──────────────────────────── Convenience ────────────────────────────

    def health(self) -> dict:
        r = self._client.get("/health")
        r.raise_for_status()
        return r.json()

    def register_worker(self, payload: dict) -> dict:
        return self.post("/workers/register", json=payload)

    def heartbeat(self, worker_id: str) -> dict:
        return self.post(f"/workers/{worker_id}/heartbeat")

    def claim_next(self, worker_id: str, runtime: str, capabilities: list[str]) -> dict | None:
        return self.get("/jobs/next",
                        params={"worker_id": worker_id, "runtime": runtime,
                                "capabilities": capabilities})

    def submit_result(self, job_id: int, payload: dict) -> dict:
        return self.post(f"/jobs/{job_id}/result", json=payload)

    def mark_running(self, job_id: int) -> dict:
        return self.post(f"/jobs/{job_id}/start")
