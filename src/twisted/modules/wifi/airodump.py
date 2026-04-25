"""airodump-ng passive enumeration wrapper.

Runs airodump-ng with CSV output for ``duration`` seconds, then parses
the resulting CSV into a list of {bssid, essid, channel, encryption,
power, clients}.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import EvidenceRef, ModuleContext, ModuleResult


def parse_airodump_csv(path: Path) -> dict[str, list]:
    """airodump CSV has two sections: APs and clients, separated by a blank line.

    Header rows look like:
      BSSID, First time seen, ..., ESSID, Key
      Station MAC, First time seen, ..., Probed ESSIDs

    Both header rows are skipped; the section we're in flips when a blank
    line OR a "Station MAC" header line appears.
    """
    aps: list[dict] = []
    clients: list[dict] = []
    section = "ap"
    with path.open() as fp:
        reader = csv.reader(fp)
        for row in reader:
            row = [c.strip() for c in row]
            if not any(row):
                continue  # ignore blanks; section flip only on Station MAC header
            head = row[0].lower()
            if head.startswith("bssid"):
                section = "ap"
                continue
            if head.startswith("station mac"):
                section = "client"
                continue
            if section == "ap" and len(row) >= 14:
                aps.append({
                    "bssid": row[0], "first_seen": row[1], "last_seen": row[2],
                    "channel": row[3], "speed": row[4], "privacy": row[5],
                    "cipher": row[6], "auth": row[7], "power": row[8],
                    "beacons": row[9], "iv": row[10], "lan_ip": row[11],
                    "id_length": row[12], "essid": row[13],
                })
            elif section == "client" and len(row) >= 6:
                clients.append({
                    "station_mac": row[0], "first_seen": row[1], "last_seen": row[2],
                    "power": row[3], "packets": row[4], "bssid": row[5],
                    "probed_essids": ",".join(row[6:]) if len(row) > 6 else "",
                })
    return {"aps": aps, "clients": clients}


def scan(ctx: ModuleContext) -> ModuleResult:
    interface = (ctx.params or {}).get("interface")
    if not interface:
        return ModuleResult(success=False, error="missing required param 'interface'")
    if not tool_available("airodump-ng"):
        return ModuleResult(success=False, error="airodump-ng not installed")
    duration = int((ctx.params or {}).get("duration", 60))

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    out_prefix = ctx.work_dir / f"airodump_{ts}"
    cmd = ["timeout", str(duration), "airodump-ng", interface, "-w", str(out_prefix),
           "--output-format", "csv,pcap", "--write-interval", "5"]
    run_cmd(cmd, timeout=duration + 10)

    csv_path = out_prefix.with_suffix(".csv")
    pcap_path = out_prefix.with_suffix(".cap")
    parsed = {"aps": [], "clients": []}
    if csv_path.exists():
        parsed = parse_airodump_csv(csv_path)
    json_path = ctx.work_dir / f"airodump_{ts}.json"
    write_artifact(json_path, json.dumps(parsed, indent=2))

    artifacts = [json_path]
    evidence = [EvidenceRef(path=to_canonical(json_path), kind="command_output",
                             note="airodump CSV parsed", host=ctx.worker_host)]
    if csv_path.exists():
        artifacts.append(csv_path)
    if pcap_path.exists():
        artifacts.append(pcap_path)
        evidence.append(EvidenceRef(path=to_canonical(pcap_path), kind="pcap",
                                     note="airodump capture", host=ctx.worker_host))

    return ModuleResult(
        success=True,
        artifacts=artifacts,
        evidence=evidence,
        summary=(f"airodump: {len(parsed['aps'])} AP(s), "
                 f"{len(parsed['clients'])} client(s) over {duration}s"),
        extra={"ap_count": len(parsed["aps"]), "client_count": len(parsed["clients"])},
    )
