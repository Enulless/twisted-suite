"""Worker daemon: long-poll the engine, dispatch modules, report results."""

from __future__ import annotations

import logging
import socket
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from .. import __version__
from ..client.api import EngineClient
from ..core.runner import default_linux_capabilities, default_windows_capabilities
from ..core.settings import Settings, get_settings
from .dispatch import dispatch, serialise_result

log = logging.getLogger("twisted.worker")


@dataclass
class WorkerConfig:
    runtime: str  # 'linux' | 'windows'
    worker_id: str
    hostname: str
    capabilities: list[str]
    poll_interval: float
    heartbeat_interval: float
    settings: Settings


def make_default_config(runtime: str, *, settings: Settings | None = None,
                        worker_id: str | None = None,
                        capabilities: list[str] | None = None) -> WorkerConfig:
    s = settings or get_settings()
    if runtime not in ("linux", "windows"):
        raise ValueError("runtime must be 'linux' or 'windows'")
    if capabilities is None:
        capabilities = (default_linux_capabilities()
                        if runtime == "linux" else default_windows_capabilities())
    if worker_id is None:
        worker_id = f"{runtime}-{socket.gethostname()}-{uuid.uuid4().hex[:6]}"
    return WorkerConfig(
        runtime=runtime, worker_id=worker_id, hostname=socket.gethostname(),
        capabilities=sorted(set(capabilities)),
        poll_interval=s.worker_poll_interval,
        heartbeat_interval=s.worker_heartbeat_interval,
        settings=s,
    )


class WorkerDaemon:
    """Polls the engine for jobs and runs them.

    Designed to be testable: pass ``client_factory`` to inject a fake
    EngineClient, ``loop_iterations`` to bound the loop, and ``sleep`` to
    bypass real sleeps in tests.
    """

    def __init__(self, config: WorkerConfig, *,
                 client_factory: Callable[[], EngineClient] | None = None,
                 sleep: Callable[[float], None] | None = None):
        self.config = config
        self._client_factory = client_factory or (lambda: EngineClient(settings=config.settings))
        self._sleep = sleep or time.sleep
        self._client: EngineClient | None = None
        self._stopped = False

    @property
    def client(self) -> EngineClient:
        if self._client is None:
            self._client = self._client_factory()
        return self._client

    def stop(self) -> None:
        self._stopped = True

    def register(self) -> dict:
        payload = {
            "id": self.config.worker_id,
            "hostname": self.config.hostname,
            "os": self.config.runtime,
            "capabilities": list(self.config.capabilities),
            "version": __version__,
        }
        return self.client.register_worker(payload)

    def _claim_one(self) -> dict | None:
        return self.client.claim_next(
            self.config.worker_id, self.config.runtime, list(self.config.capabilities)
        )

    def _execute(self, offer: dict) -> dict:
        try:
            self.client.mark_running(offer["job_id"])
        except Exception:  # noqa: BLE001 - keep going even if /start fails
            log.exception("worker: /jobs/%s/start failed", offer["job_id"])
        result = dispatch(
            offer,
            worker_host=("windows" if self.config.runtime == "windows" else "wsl"),
            worker_id=self.config.worker_id,
        )
        payload = serialise_result(result)
        self.client.submit_result(offer["job_id"], payload)
        return payload

    def run(self, *, max_iterations: int | None = None) -> int:
        """Main loop. Returns the number of jobs processed.

        ``max_iterations`` bounds the loop for testing — None means run
        forever (until ``stop()`` or KeyboardInterrupt).
        """
        self.register()
        log.info("worker %s registered (caps=%s)",
                 self.config.worker_id, self.config.capabilities)
        last_heartbeat = time.monotonic()
        processed = 0
        i = 0
        while not self._stopped:
            i += 1
            offer = None
            try:
                offer = self._claim_one()
            except Exception:  # noqa: BLE001
                log.exception("worker: claim failed")
            if offer:
                try:
                    self._execute(offer)
                    processed += 1
                except Exception:  # noqa: BLE001
                    log.exception("worker: dispatch failed for job %s", offer.get("job_id"))
            else:
                if time.monotonic() - last_heartbeat >= self.config.heartbeat_interval:
                    try:
                        self.client.heartbeat(self.config.worker_id)
                        last_heartbeat = time.monotonic()
                    except Exception:  # noqa: BLE001
                        log.exception("worker: heartbeat failed")
                self._sleep(self.config.poll_interval)
            if max_iterations is not None and i >= max_iterations:
                break
        return processed


def main(runtime: str = "linux") -> None:
    logging.basicConfig(level=logging.INFO)
    cfg = make_default_config(runtime)
    WorkerDaemon(cfg).run()
