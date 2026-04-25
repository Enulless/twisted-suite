"""RoE tool-policy evaluation.

Evaluates whether a procedure step is allowed for a specific
engagement based on the rows in ``engagement_tool_policy``. Default-
allow semantics: a step runs unless an explicit row blocks it (either
the step itself or one of the capabilities it requires).

Three named presets seed common RoE shapes when an operator hasn't
hand-curated their own list:

- ``open_bug_bounty``  — everything allowed (the default; clears the
  policy table for the engagement).
- ``no_dos``           — blocks DoS-adjacent capabilities (``wrk``,
  ``aireplay-ng``, ``locust``, ``monitor-mode``) and any procedure
  step explicitly named for stress / saturation.
- ``read_only_recon``  — blocks every active capability; only the
  passive-recon stages of bug bounty stay allowed.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from . import models as m
from .procedures import Step

# ──────────────────────────── Result type ────────────────────────────


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str | None = None
    target_kind: str | None = None       # "step" | "capability"
    target_value: str | None = None       # the offending step_id or cap

    @classmethod
    def allow(cls) -> PolicyDecision:
        return cls(allowed=True)

    @classmethod
    def deny_step(cls, step_id: str, note: str | None = None) -> PolicyDecision:
        return cls(
            allowed=False,
            reason=note or f"step {step_id!r} is blocked by RoE",
            target_kind="step",
            target_value=step_id,
        )

    @classmethod
    def deny_capability(cls, cap: str, note: str | None = None) -> PolicyDecision:
        return cls(
            allowed=False,
            reason=note or f"capability {cap!r} is blocked by RoE",
            target_kind="capability",
            target_value=cap,
        )


# ──────────────────────────── Loaders ────────────────────────────


def _load_policy(session: Session, engagement_id: int
                 ) -> tuple[dict[str, m.EngagementToolPolicy],
                            dict[str, m.EngagementToolPolicy]]:
    """Return ``(steps, capabilities)`` dicts of blocked rows for an
    engagement. Allowed rows are excluded (default is allow).
    """
    rows = session.query(m.EngagementToolPolicy).filter(
        m.EngagementToolPolicy.engagement_id == engagement_id,
        m.EngagementToolPolicy.allowed == False,  # noqa: E712 - SA needs ==
    ).all()
    blocked_steps: dict[str, m.EngagementToolPolicy] = {}
    blocked_caps: dict[str, m.EngagementToolPolicy] = {}
    for r in rows:
        if r.target_kind == m.ToolPolicyKind.STEP:
            blocked_steps[r.target_value] = r
        else:
            blocked_caps[r.target_value] = r
    return blocked_steps, blocked_caps


# ──────────────────────────── Evaluation ────────────────────────────


def is_step_allowed(session: Session, engagement_id: int,
                    step: Step) -> PolicyDecision:
    """Decide whether ``step`` may run for ``engagement_id``.

    Algorithm:
      1. If a policy row blocks ``step.id`` directly → deny (step).
      2. Else if any policy row blocks one of the capabilities in
         ``step.requires`` → deny (capability — cascade).
      3. Else allow.
    """
    blocked_steps, blocked_caps = _load_policy(session, engagement_id)
    if step.id in blocked_steps:
        row = blocked_steps[step.id]
        note = (f"{row.note} (RoE)" if row.note
                else f"step {step.id!r} is blocked by RoE")
        return PolicyDecision.deny_step(step.id, note)
    for cap in step.requires or []:
        if cap in blocked_caps:
            row = blocked_caps[cap]
            note = (f"{row.note} (capability {cap!r} blocked by RoE)" if row.note
                    else f"step blocked: required capability {cap!r} is blocked by RoE")
            return PolicyDecision.deny_capability(cap, note)
    return PolicyDecision.allow()


def is_step_id_allowed(session: Session, engagement_id: int,
                       step_id: str, requires: Iterable[str]) -> PolicyDecision:
    """Lower-level variant when only the id + requires list are
    available (e.g. inside the worker-claim path that has the Job row
    but not the procedure ``Step`` object)."""
    blocked_steps, blocked_caps = _load_policy(session, engagement_id)
    if step_id in blocked_steps:
        row = blocked_steps[step_id]
        return PolicyDecision.deny_step(
            step_id,
            (f"{row.note} (RoE)" if row.note
             else f"step {step_id!r} is blocked by RoE"),
        )
    for cap in requires or []:
        if cap in blocked_caps:
            row = blocked_caps[cap]
            return PolicyDecision.deny_capability(
                cap,
                (f"{row.note} (capability {cap!r} blocked by RoE)" if row.note
                 else f"step blocked: required capability {cap!r} is blocked by RoE"),
            )
    return PolicyDecision.allow()


# ──────────────────────────── CRUD helpers ────────────────────────────


def upsert_policy(session: Session, engagement_id: int,
                  *, target_kind: str, target_value: str,
                  allowed: bool, note: str | None = None
                  ) -> m.EngagementToolPolicy:
    """Insert or update a single (engagement, kind, target) row."""
    kind_enum = m.ToolPolicyKind(target_kind)
    existing = session.query(m.EngagementToolPolicy).filter(
        m.EngagementToolPolicy.engagement_id == engagement_id,
        m.EngagementToolPolicy.target_kind == kind_enum,
        m.EngagementToolPolicy.target_value == target_value,
    ).one_or_none()
    if existing is None:
        row = m.EngagementToolPolicy(
            engagement_id=engagement_id,
            target_kind=kind_enum, target_value=target_value,
            allowed=allowed, note=note,
        )
        session.add(row)
        return row
    existing.allowed = allowed
    existing.note = note
    return existing


def clear_policy(session: Session, engagement_id: int) -> int:
    """Delete every policy row for an engagement. Returns count."""
    count = session.query(m.EngagementToolPolicy).filter(
        m.EngagementToolPolicy.engagement_id == engagement_id,
    ).delete()
    return count


# ──────────────────────────── Presets ────────────────────────────


# Capabilities considered DoS-adjacent — the "no_dos" preset blocks them
# for engagements where the RoE rules out availability impact.
DOS_CAPABILITIES = ("wrk", "aireplay-ng", "locust", "monitor-mode")

# Step-id substring patterns for DoS-shaped operations even when the
# step doesn't `requires:` a DoS-adjacent capability (e.g. "stress" /
# "escalating" in WP).
DOS_STEP_SUBSTRINGS = ("escalating", "stress", "deauth", "saturation")

# Capabilities that are inherently active probes / vulnerability
# scanners — disallowed in a "read-only" RoE.
ACTIVE_CAPABILITIES = (
    "nmap", "nikto", "sqlmap", "wpscan", "ab", "wrk", "locust",
    "aireplay-ng", "airodump-ng", "airmon-ng", "wash", "reaver",
    "hashcat", "hcxpcapngtool", "monitor-mode", "responder",
    "crackmapexec", "enum4linux-ng",
)

PRESETS = ("open_bug_bounty", "no_dos", "read_only_recon")


def apply_preset(session: Session, engagement_id: int, preset: str,
                 procedures: Any | None = None) -> dict[str, Any]:
    """Apply a named preset, replacing any previous rows.

    ``procedures`` is a ProcedureLoader — needed so the preset can
    walk every step in every loaded procedure to compute targeted
    step-id blocks. May be omitted for tests; in that case only
    capability rules are applied.

    Returns a summary dict with counts.
    """
    if preset not in PRESETS:
        raise ValueError(f"unknown preset {preset!r}; choices: {PRESETS}")

    cleared = clear_policy(session, engagement_id)
    cap_blocks: list[str] = []
    step_blocks: list[str] = []
    note_for_preset = {
        "no_dos": "blocked by 'no_dos' preset",
        "read_only_recon": "blocked by 'read_only_recon' preset",
    }.get(preset)

    if preset == "open_bug_bounty":
        return {"preset": preset, "cleared": cleared,
                "capability_blocks": [], "step_blocks": []}

    if preset == "no_dos":
        for cap in DOS_CAPABILITIES:
            upsert_policy(session, engagement_id,
                          target_kind="capability", target_value=cap,
                          allowed=False, note=note_for_preset)
            cap_blocks.append(cap)
        # Also block stress / escalating step ids by name match
        if procedures is not None:
            for proc in procedures.all().values():
                for step in proc.all_steps():
                    name = step.id.lower()
                    if any(sub in name for sub in DOS_STEP_SUBSTRINGS):
                        upsert_policy(session, engagement_id,
                                      target_kind="step",
                                      target_value=step.id,
                                      allowed=False, note=note_for_preset)
                        step_blocks.append(step.id)

    elif preset == "read_only_recon":
        for cap in ACTIVE_CAPABILITIES:
            upsert_policy(session, engagement_id,
                          target_kind="capability", target_value=cap,
                          allowed=False, note=note_for_preset)
            cap_blocks.append(cap)
        # Also block all wifi.phase2+ and wp_stress.phase2+ steps
        # explicitly — they are inherently active.
        if procedures is not None:
            for proc in procedures.all().values():
                for step in proc.all_steps():
                    if proc.id == "wifi" and step.stage in (
                            "phase2", "phase3", "phase4") or proc.id == "wp_stress" and step.stage in (
                            "phase2", "phase3"):
                        upsert_policy(session, engagement_id,
                                      target_kind="step",
                                      target_value=step.id,
                                      allowed=False, note=note_for_preset)
                        step_blocks.append(step.id)

    return {"preset": preset, "cleared": cleared,
            "capability_blocks": cap_blocks, "step_blocks": step_blocks}


# ──────────────────────────── Inventory helpers ────────────────────────────


def all_known_capabilities(procedures: Any) -> list[str]:
    """Sorted unique capability tags across every loaded procedure."""
    caps: set[str] = set()
    for proc in procedures.all().values():
        for step in proc.all_steps():
            caps.update(step.requires or [])
    return sorted(caps)
