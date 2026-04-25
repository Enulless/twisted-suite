"""Certificate Transparency log harvesting via crt.sh.

Ported and generalised from recon_ovh.py's ``crtsh_enum``. Honours the
engagement scope: out-of-scope subdomains are dropped before being
returned as AssetUpdate rows.
"""

from __future__ import annotations

import json
import re
from typing import Any

import requests

from ...core.paths import to_canonical
from ...core.storage import write_artifact
from ..base import AssetUpdate, EvidenceRef, ModuleContext, ModuleResult

CRTSH_URL = "https://crt.sh/"
DEFAULT_TIMEOUT = 30
USER_AGENT = "TwistedRecon/0.1 (+bug-bounty-research)"


def _query_crtsh(domain: str, *, session: requests.Session | None = None,
                 timeout: int = DEFAULT_TIMEOUT) -> list[dict[str, Any]]:
    """Hit the crt.sh JSON endpoint for ``%.<domain>`` and return raw rows."""
    sess = session or requests.Session()
    r = sess.get(
        CRTSH_URL,
        params={"q": f"%.{domain}", "output": "json"},
        timeout=timeout,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    r.raise_for_status()
    # crt.sh occasionally returns NDJSON-like output without surrounding []
    text = r.text.strip()
    if not text:
        return []
    try:
        data = r.json()
    except json.JSONDecodeError:
        # Try repairing NDJSON
        rows = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if line and line.startswith("{"):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        data = rows
    if not isinstance(data, list):
        return []
    return data


def extract_subdomains(rows: list[dict[str, Any]], domain: str) -> set[str]:
    """Pull every name that ends in ``domain`` out of name_value / common_name."""
    found: set[str] = set()
    suffix = domain.lower().rstrip(".")
    for row in rows:
        for field_name in ("name_value", "common_name"):
            blob = row.get(field_name) or ""
            for raw in re.split(r"[\s,]+", blob):
                name = raw.strip().lower().lstrip("*.").rstrip(".")
                if not name:
                    continue
                if name == suffix or name.endswith("." + suffix):
                    found.add(name)
    return found


def run(ctx: ModuleContext) -> ModuleResult:
    """Module entry point."""
    domain = (ctx.params or {}).get("domain")
    if not domain:
        return ModuleResult(success=False, error="missing required param 'domain'")

    try:
        rows = _query_crtsh(domain, timeout=int(ctx.params.get("timeout", DEFAULT_TIMEOUT)))
    except requests.RequestException as e:
        return ModuleResult(success=False, error=f"crt.sh request failed: {e}")

    found = extract_subdomains(rows, domain)
    in_scope: set[str] = set(found)
    dropped: set[str] = set()
    if ctx.scope is not None:
        kept, drops = ctx.scope.filter(found)
        in_scope = set(kept)
        dropped = set(drops)

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    json_path = ctx.work_dir / f"crtsh_{domain.replace('.', '_')}_{ts}.json"
    txt_path = ctx.work_dir / f"crtsh_{domain.replace('.', '_')}_{ts}.txt"

    payload = {
        "tool": "crt.sh",
        "domain": domain,
        "queried_at": ctx.timestamp.isoformat(),
        "row_count": len(rows),
        "subdomain_count": len(found),
        "in_scope": sorted(in_scope),
        "dropped_oos": sorted(dropped),
    }
    write_artifact(json_path, json.dumps(payload, indent=2))

    txt_lines = [
        f"crt.sh harvest for {domain}",
        f"Queried at {ctx.timestamp.isoformat()}",
        f"Rows returned : {len(rows)}",
        f"Unique subs   : {len(found)}",
        f"In-scope kept : {len(in_scope)}",
        f"OOS dropped   : {len(dropped)}",
        "",
        "── In-scope ──",
        *sorted(in_scope),
    ]
    if dropped:
        txt_lines += ["", "── Dropped (OOS) ──", *sorted(dropped)]
    write_artifact(txt_path, "\n".join(txt_lines))

    assets = [AssetUpdate(host=h, source="crt.sh") for h in sorted(in_scope)]
    evidence = [
        EvidenceRef(path=to_canonical(json_path), kind="command_output",
                    note="crt.sh JSON dump", host=ctx.worker_host),
        EvidenceRef(path=to_canonical(txt_path), kind="command_output",
                    note="crt.sh summary", host=ctx.worker_host),
    ]
    summary = (
        f"crt.sh: {len(found)} unique subdomain(s) for {domain}; "
        f"{len(in_scope)} in scope, {len(dropped)} dropped"
    )

    return ModuleResult(
        success=True,
        artifacts=[json_path, txt_path],
        assets=assets,
        evidence=evidence,
        summary=summary,
        extra={"row_count": len(rows), "subdomain_count": len(found)},
    )
