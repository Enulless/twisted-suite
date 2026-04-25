"""TLS / certificate inspection.

Lightweight wrapper around openssl s_client + x509 -text. Records the
issuer, validity dates, key strength, and SAN list. Heavier deprecated-
protocol / cipher analysis (testssl.sh) lands in Phase 2.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import EvidenceRef, FindingDraft, ModuleContext, ModuleResult

CERT_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


def fetch_cert_text(host: str, port: int = 443, *, timeout: int = 10) -> str:
    """Return ``openssl x509 -noout -text`` for the first cert presented."""
    s = run_cmd(
        ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"],
        timeout=timeout, input_text=""
    )
    cert_match = CERT_BLOCK.search(s.stdout)
    if not cert_match:
        return ""
    cert_pem = cert_match.group(0)
    text = run_cmd(["openssl", "x509", "-noout", "-text"], timeout=timeout, input_text=cert_pem)
    return text.stdout


def parse_cert_text(text: str) -> dict:
    """Pull issuer / subject / validity / SAN / key-bits / key-algo out of
    ``openssl x509 -text`` output.

    ``key_algorithm`` is normalised to one of ``"rsa" | "ec" | "dsa" |
    "ed25519" | "ed448" | None`` so downstream weak-key checks can pick
    the right threshold (RSA-2048 ≢ ECDSA-256)."""
    out: dict = {"subject": None, "issuer": None, "not_before": None,
                 "not_after": None, "san": [], "key_bits": None,
                 "key_algorithm": None, "signature_algorithm": None}
    if not text:
        return out
    sub = re.search(r"Subject:\s*(.+)", text)
    iss = re.search(r"Issuer:\s*(.+)", text)
    nb = re.search(r"Not Before\s*:\s*(.+)", text)
    na = re.search(r"Not After\s*:\s*(.+)", text)
    sig = re.search(r"Signature Algorithm:\s*(\S+)", text)
    bits = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", text)
    pka = re.search(r"Public Key Algorithm:\s*(\S+)", text)
    if sub:
        out["subject"] = sub.group(1).strip()
    if iss:
        out["issuer"] = iss.group(1).strip()
    if nb:
        out["not_before"] = nb.group(1).strip()
    if na:
        out["not_after"] = na.group(1).strip()
    if sig:
        out["signature_algorithm"] = sig.group(1).strip()
    if bits:
        out["key_bits"] = int(bits.group(1))
    if pka:
        out["key_algorithm"] = _normalise_key_algorithm(pka.group(1).strip())
    san_block = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*(.+)", text)
    if san_block:
        out["san"] = [s.strip().removeprefix("DNS:")
                      for s in san_block.group(1).split(",") if s.strip()]
    return out


def _normalise_key_algorithm(raw: str) -> str | None:
    """Map openssl's algorithm OID/name to a short canonical label."""
    s = raw.lower()
    if "rsa" in s:
        return "rsa"
    if "ecpublickey" in s or s.startswith("ec") or s == "id-ecpublickey":
        return "ec"
    if "ed25519" in s:
        return "ed25519"
    if "ed448" in s:
        return "ed448"
    if "dsa" in s:
        return "dsa"
    return None


# Algorithm-aware weak-key thresholds. RSA/DSA ≥ 2048 is the modern
# baseline; for elliptic-curve keys, NIST/CNSA consider ≥ 224 bits
# acceptable (P-256 is 256 bits and stronger than RSA-2048). Ed25519 /
# Ed448 have fixed key sizes that are always strong, so we skip the
# check for them.
_MIN_KEY_BITS_BY_ALGO: dict[str, int] = {
    "rsa": 2048,
    "dsa": 2048,
    "ec": 224,
}


def is_weak_key(algorithm: str | None, bits: int | None) -> bool:
    """True iff (algorithm, bits) is below the modern recommended floor."""
    if bits is None:
        return False
    if algorithm is None:
        # Conservative fallback: assume RSA semantics if openssl didn't
        # report an algorithm. Better a false positive than missing a
        # genuinely weak RSA key.
        return bits < 2048
    threshold = _MIN_KEY_BITS_BY_ALGO.get(algorithm)
    if threshold is None:
        return False  # ed25519 / ed448 — fixed strong sizes
    return bits < threshold


def _parse_openssl_date(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip().rstrip(" GMT").strip()
    for fmt in ("%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def audit(host: str, *, port: int = 443, timeout: int = 10) -> dict:
    text = fetch_cert_text(host, port=port, timeout=timeout)
    parsed = parse_cert_text(text)
    parsed["host"] = host
    parsed["port"] = port
    parsed["raw_text"] = text
    return parsed


def run(ctx: ModuleContext) -> ModuleResult:
    hosts: list[str] = (ctx.params or {}).get("hosts") or []
    single_host = (ctx.params or {}).get("host")
    if single_host and single_host not in hosts:
        hosts = [single_host, *hosts]
    if not hosts:
        return ModuleResult(success=False, error="missing required param 'host' or 'hosts'")
    if not tool_available("openssl"):
        return ModuleResult(success=False, error="openssl not installed")

    if ctx.scope is not None:
        kept, _ = ctx.scope.filter(hosts)
        hosts = kept

    timeout = int(ctx.params.get("timeout", 10))
    audits = [audit(h, timeout=timeout) for h in hosts]

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    json_path = ctx.work_dir / f"tls_audit_{ts}.json"
    write_artifact(json_path, json.dumps(
        [{k: v for k, v in a.items() if k != "raw_text"} for a in audits], indent=2,
    ))

    findings: list[FindingDraft] = []
    now = datetime.utcnow()
    for a in audits:
        host = a.get("host")
        bits = a.get("key_bits")
        algo = a.get("key_algorithm")
        if is_weak_key(algo, bits):
            algo_label = (algo or "unknown").upper()
            findings.append(FindingDraft(
                title=f"Weak TLS key strength ({algo_label} {bits}-bit) on {host}",
                severity="high", cwe="CWE-326",
                affected_component=f"https://{host}",
                description=(
                    f"Server certificate uses a {bits}-bit {algo_label} public key, "
                    f"below the modern recommended floor."
                ),
                remediation="Reissue with at least a 2048-bit RSA or ECDSA P-256 key.",
            ))
        not_after = _parse_openssl_date(a.get("not_after"))
        if not_after is not None:
            days = (not_after - now).days
            if days < 0:
                findings.append(FindingDraft(
                    title=f"Expired TLS certificate on {host}",
                    severity="high", cwe="CWE-295",
                    affected_component=f"https://{host}",
                    description=f"Certificate expired on {not_after.isoformat()}.",
                    remediation="Renew the certificate immediately.",
                ))
            elif days < 30:
                findings.append(FindingDraft(
                    title=f"TLS certificate expiring within 30 days on {host}",
                    severity="medium", cwe="CWE-295",
                    affected_component=f"https://{host}",
                    description=f"Certificate expires {not_after.isoformat()} ({days} days).",
                    remediation="Renew the certificate before the expiry date.",
                ))

    return ModuleResult(
        success=True,
        artifacts=[json_path],
        findings=findings,
        evidence=[
            EvidenceRef(path=to_canonical(json_path), kind="command_output",
                        note="TLS audit JSON", host=ctx.worker_host),
        ],
        summary=f"tls_audit: {len(hosts)} host(s); {len(findings)} draft finding(s)",
    )
