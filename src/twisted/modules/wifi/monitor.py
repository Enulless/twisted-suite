"""airmon-ng monitor-mode wrapper."""

from __future__ import annotations

import re

from ...core.runner import run_cmd, tool_available
from ..base import ModuleContext, ModuleResult

_MON_RE = re.compile(r"\bon\s+\[?[^\s\]]*?\]?(?P<iface>\w*mon)\b", re.IGNORECASE)


def enable(ctx: ModuleContext) -> ModuleResult:
    interface = (ctx.params or {}).get("interface")
    if not interface:
        return ModuleResult(success=False, error="missing required param 'interface'")
    if not tool_available("airmon-ng"):
        return ModuleResult(success=False, error="airmon-ng not installed (apt install aircrack-ng)")

    kill = run_cmd(["airmon-ng", "check", "kill"], timeout=20)
    enable_cmd = run_cmd(["airmon-ng", "start", interface], timeout=30)
    text = enable_cmd.stdout + "\n" + enable_cmd.stderr
    if not enable_cmd.ok and "monitor mode" not in text.lower():
        return ModuleResult(success=False, error=enable_cmd.error or enable_cmd.combined_output()[-200:])

    # Determine the resulting monitor interface name. Common formats:
    #   "monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon"
    #   "monitor mode enabled on wlan0mon"
    mon_iface = interface
    m = _MON_RE.search(text)
    if m and m.group("iface"):
        mon_iface = m.group("iface")

    return ModuleResult(
        success=True,
        summary=f"monitor mode enabled on {mon_iface} (was {interface})",
        extra={"interface": interface, "monitor_interface": mon_iface,
               "kill_output": kill.combined_output()[-500:],
               "start_output": enable_cmd.combined_output()[-500:]},
    )


def disable(ctx: ModuleContext) -> ModuleResult:
    interface = (ctx.params or {}).get("interface")
    if not interface:
        return ModuleResult(success=False, error="missing required param 'interface'")
    if not tool_available("airmon-ng"):
        return ModuleResult(success=False, error="airmon-ng not installed")
    r = run_cmd(["airmon-ng", "stop", interface], timeout=15)
    return ModuleResult(success=r.ok, summary=f"monitor mode disabled on {interface}")
