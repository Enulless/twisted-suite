"""Convert pcap -> hashcat 22000 + run hashcat dictionary attack."""

from __future__ import annotations

import re
from pathlib import Path

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ..base import EvidenceRef, FindingDraft, ModuleContext, ModuleResult


def _convert_pcap(pcap_path: str, hash_path: str) -> tuple[bool, str]:
    if not tool_available("hcxpcapngtool"):
        return False, "hcxpcapngtool not installed"
    r = run_cmd(["hcxpcapngtool", "-o", hash_path, pcap_path], timeout=60)
    if not Path(hash_path).exists() or Path(hash_path).stat().st_size == 0:
        return False, r.combined_output()[-500:] or "hash file empty"
    return True, "ok"


def run(ctx: ModuleContext) -> ModuleResult:
    pcap_path = (ctx.params or {}).get("pcap_path")
    if not pcap_path or not Path(pcap_path).exists():
        return ModuleResult(success=False, error="pcap_path missing or file not present")
    if not tool_available("hashcat"):
        return ModuleResult(success=False, error="hashcat not installed")
    wordlist = (ctx.params or {}).get("wordlist", "/usr/share/wordlists/rockyou.txt")
    if not Path(wordlist).exists():
        return ModuleResult(success=False, error=f"wordlist not found: {wordlist}")
    rules = (ctx.params or {}).get("rules")

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    hash_path = ctx.work_dir / f"hashcat_input_{ts}.hc22000"
    pot_path = ctx.work_dir / f"hashcat_pot_{ts}.txt"

    ok, msg = _convert_pcap(pcap_path, str(hash_path))
    if not ok:
        return ModuleResult(success=False, error=f"hcxpcapngtool conversion failed: {msg}")

    cmd = ["hashcat", "-m", "22000", str(hash_path), wordlist, "--potfile-path", str(pot_path)]
    if rules:
        cmd += ["-r", rules]
    timeout = int((ctx.params or {}).get("timeout", 600))
    r = run_cmd(cmd, timeout=timeout)

    cracked = ""
    findings: list[FindingDraft] = []
    if pot_path.exists():
        body = pot_path.read_text()
        # Format: <hash>:<plaintext>
        for line in body.splitlines():
            m = re.match(r"^[^:]+:([^:]+):.*$", line) or re.match(r"^[^:]+:(.+)$", line)
            if m:
                cracked = m.group(1)
                break
    if cracked:
        findings.append(FindingDraft(
            title=f"WPA2 passphrase recovered from captured handshake",
            severity="critical",
            cwe="CWE-521",
            affected_component=f"WPA2-PSK on {pcap_path}",
            description="The pre-shared key for the captured 4-way handshake was recovered offline.",
            remediation=("Rotate the WPA2 passphrase. Switch to WPA3-SAE where supported; "
                         "use a passphrase >= 16 random characters."),
        ))

    return ModuleResult(
        success=True,
        artifacts=[hash_path, pot_path] if pot_path.exists() else [hash_path],
        findings=findings,
        evidence=[EvidenceRef(path=to_canonical(hash_path), kind="command_output",
                              note="hashcat input", host=ctx.worker_host)],
        summary=(f"hashcat: input={hash_path.name}; "
                 f"{'CRACKED' if cracked else 'NOT cracked (within wordlist + rules)'}"),
        extra={"cracked": bool(cracked)},
    )
