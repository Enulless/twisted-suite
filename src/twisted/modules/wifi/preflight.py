"""WiFi pre-flight: hardware + permission + WSL detection.

Hard-blocks running monitor-mode steps inside WSL2 unless the
``TWISTED_WIFI_USBIPD`` env var is set (acknowledging the operator
has bound a USB WiFi adapter via usbipd-win).
"""

from __future__ import annotations

import contextlib
import json
import os

from ...core.paths import is_wsl, to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import EvidenceRef, ModuleContext, ModuleResult


def list_wifi_interfaces() -> list[str]:
    if not tool_available("iw"):
        return []
    r = run_cmd(["iw", "dev"], timeout=10)
    interfaces = []
    for line in r.stdout.splitlines():
        s = line.strip()
        if s.startswith("Interface "):
            interfaces.append(s.split()[1])
    return interfaces


def supports_monitor(interface: str) -> bool:
    """Read the phy's supported interface modes."""
    if not tool_available("iw"):
        return False
    r = run_cmd(["iw", "dev", interface, "info"], timeout=5)
    if not r.ok:
        return False
    phy = None
    for line in r.stdout.splitlines():
        s = line.strip()
        if s.startswith("wiphy"):
            with contextlib.suppress(IndexError):
                phy = f"phy{s.split()[1]}"
    if phy:
        info = run_cmd(["iw", "phy", phy, "info"], timeout=5)
        return "monitor" in info.stdout.lower()
    return False


def is_root() -> bool:
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def run(ctx: ModuleContext) -> ModuleResult:
    interfaces = list_wifi_interfaces()
    monitor_capable = {iface: supports_monitor(iface) for iface in interfaces}
    in_wsl = is_wsl()
    usbipd_acknowledged = os.environ.get("TWISTED_WIFI_USBIPD") == "1"
    can_proceed = bool(interfaces) and any(monitor_capable.values())

    blocking_reasons: list[str] = []
    if not interfaces:
        blocking_reasons.append("no wireless interfaces detected (iw dev returned empty)")
    elif not any(monitor_capable.values()):
        blocking_reasons.append("no detected interface advertises monitor-mode support")
    if in_wsl and not usbipd_acknowledged:
        blocking_reasons.append(
            "WSL2 detected and TWISTED_WIFI_USBIPD!=1 — USB passthrough is "
            "required for monitor mode in WSL. Set TWISTED_WIFI_USBIPD=1 only "
            "after binding a compatible USB adapter via usbipd-win."
        )
        can_proceed = False
    if not is_root():
        blocking_reasons.append("monitor-mode operations require root (sudo)")
        can_proceed = False

    payload = {
        "wsl": in_wsl,
        "usbipd_acknowledged": usbipd_acknowledged,
        "is_root": is_root(),
        "interfaces": interfaces,
        "monitor_capable": monitor_capable,
        "can_proceed": can_proceed,
        "blocking_reasons": blocking_reasons,
    }

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    json_path = ctx.work_dir / f"wifi_preflight_{ts}.json"
    write_artifact(json_path, json.dumps(payload, indent=2))

    if not can_proceed:
        return ModuleResult(
            success=False,
            artifacts=[json_path],
            error="; ".join(blocking_reasons),
            summary=f"wifi_preflight: BLOCKED ({len(blocking_reasons)} reason(s))",
            extra=payload,
        )

    return ModuleResult(
        success=True,
        artifacts=[json_path],
        evidence=[EvidenceRef(path=to_canonical(json_path), kind="command_output",
                              note="wifi preflight", host=ctx.worker_host)],
        summary=(f"wifi_preflight: ok; interfaces={interfaces}, "
                 f"monitor_capable={ {k:v for k,v in monitor_capable.items() if v} }"),
        extra=payload,
    )
