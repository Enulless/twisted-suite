"""Module dispatch — load a ``pkg.mod:callable`` reference and invoke it."""

from __future__ import annotations

import contextlib
import importlib
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.evidence import sha256_file
from ..core.paths import to_canonical
from ..modules.base import ModuleContext, ModuleResult


def resolve_callable(ref: str) -> Callable[[ModuleContext], ModuleResult]:
    """Resolve a 'package.module:callable' reference to a callable."""
    if ":" not in ref:
        raise ValueError(f"module ref must be 'pkg.mod:callable', got {ref!r}")
    mod_name, _, attr = ref.partition(":")
    mod = importlib.import_module(mod_name)
    if not hasattr(mod, attr):
        raise AttributeError(f"{mod_name} has no attribute {attr!r}")
    fn = getattr(mod, attr)
    if not callable(fn):
        raise TypeError(f"{ref} is not callable")
    return fn  # type: ignore[return-value]


def dispatch(offer: dict, *, worker_host: str = "wsl",
             worker_id: str | None = None, scope: Any | None = None) -> ModuleResult:
    """Resolve and run the module referenced in a JobOffer.

    Returns a ``ModuleResult`` (success or error). Catches exceptions raised
    by the module so the worker can always report something back to the
    engine instead of dying mid-job.
    """
    module_ref = offer.get("module")
    if not module_ref:
        return ModuleResult(success=False, error="walkthrough job has no module to dispatch")

    work_dir = Path(to_canonical(offer.get("work_dir", "."))).expanduser()
    work_dir.mkdir(parents=True, exist_ok=True)

    ctx = ModuleContext(
        engagement_id=int(offer.get("engagement_id", 0)),
        step_id=str(offer.get("step_id", "")),
        procedure=str(offer.get("procedure", "")),
        stage=offer.get("stage"),
        params=dict(offer.get("params") or {}),
        work_dir=work_dir,
        scope=scope,
        timestamp=datetime.now(),
        worker_id=worker_id,
        worker_host=worker_host,
    )

    try:
        fn = resolve_callable(module_ref)
    except (ImportError, ValueError, AttributeError, TypeError) as e:
        return ModuleResult(success=False, error=f"failed to resolve module {module_ref}: {e}")

    try:
        result = fn(ctx)
    except Exception as e:  # noqa: BLE001 — module failure must not crash worker
        return ModuleResult(success=False, error=f"module raised: {type(e).__name__}: {e}")

    if not isinstance(result, ModuleResult):
        return ModuleResult(success=False, error=f"module returned {type(result).__name__}, expected ModuleResult")
    return result


def serialise_result(result: ModuleResult) -> dict:
    """Convert a ModuleResult into the JSON payload expected by /jobs/<id>/result.

    Auto-fills SHA-256 + size for evidence whose file actually exists on disk.
    """
    artifact_paths = [to_canonical(p) for p in (result.artifacts or [])]
    evidence_payload: list[dict] = []
    for ev in result.evidence or []:
        sha = ev.sha256
        size = ev.size_bytes
        canonical = to_canonical(ev.path)
        p = Path(canonical)
        if p.exists():
            if sha is None:
                with contextlib.suppress(OSError):
                    sha = sha256_file(p)
            if size is None:
                with contextlib.suppress(OSError):
                    size = p.stat().st_size
        evidence_payload.append({
            "path": canonical, "kind": ev.kind, "note": ev.note,
            "sha256": sha, "size_bytes": size, "host": ev.host,
        })

    return {
        "success": bool(result.success),
        "summary": result.summary,
        "error": result.error,
        "artifact_paths": artifact_paths,
        "assets": [
            {"host": a.host, "ip": a.ip, "env_type": a.env_type,
             "source": a.source, "in_scope": a.in_scope, "extra": a.extra}
            for a in (result.assets or [])
        ],
        "findings": [
            {"title": f.title, "severity": f.severity, "cwe": f.cwe,
             "affected_component": f.affected_component, "description": f.description,
             "repro_steps": f.repro_steps, "remediation": f.remediation,
             "references": f.references or [], "cvss_vector": f.cvss_vector,
             "cvss_score": f.cvss_score, "asset_host": (f.extra or {}).get("asset_host")
                if f.extra else None}
            for f in (result.findings or [])
        ],
        "evidence": evidence_payload,
        "extra": dict(result.extra or {}),
    }
