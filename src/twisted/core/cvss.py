"""CVSS 3.1 base-score calculator.

Implements the official base-metric formula from:
https://www.first.org/cvss/v3.1/specification-document

Only the *base* metric group is implemented here (sufficient for the
bug-bounty report template). Temporal and environmental modifiers can be
added later if needed.
"""

from __future__ import annotations

from dataclasses import dataclass

# ──────────────────────────── Metric values ────────────────────────────

# Attack Vector
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
# Attack Complexity
_AC = {"L": 0.77, "H": 0.44}
# Privileges Required (PR has different weights when scope is changed)
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
# User Interaction
_UI = {"N": 0.85, "R": 0.62}
# CIA impact
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
# Scope
_SCOPES = {"U", "C"}


METRIC_NAMES = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


@dataclass
class CVSS3:
    av: str
    ac: str
    pr: str
    ui: str
    s: str
    c: str
    i: str
    a: str

    def vector(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}/UI:{self.ui}/"
            f"S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}"
        )

    def base_score(self) -> float:
        return base_score(self.av, self.ac, self.pr, self.ui, self.s, self.c, self.i, self.a)

    def severity(self) -> str:
        return severity_for_score(self.base_score())


# ──────────────────────────── Pure functions ────────────────────────────


def _round_up(value: float) -> float:
    """CVSS v3.1 'roundup' — round up to the nearest tenth."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (int_input // 10000 + 1) / 10


def base_score(
    av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str
) -> float:
    """Compute the CVSS v3.1 Base Score from raw metric letters.

    Letters are case-insensitive. Raises ``ValueError`` on unknown values.
    """
    av_v = av.upper()
    ac_v = ac.upper()
    pr_v = pr.upper()
    ui_v = ui.upper()
    s_v = s.upper()
    c_v = c.upper()
    i_v = i.upper()
    a_v = a.upper()

    if s_v not in _SCOPES:
        raise ValueError(f"invalid scope: {s_v}")
    if av_v not in _AV:
        raise ValueError(f"invalid AV: {av_v}")
    if ac_v not in _AC:
        raise ValueError(f"invalid AC: {ac_v}")
    if ui_v not in _UI:
        raise ValueError(f"invalid UI: {ui_v}")
    for label, val in (("C", c_v), ("I", i_v), ("A", a_v)):
        if val not in _CIA:
            raise ValueError(f"invalid {label}: {val}")
    pr_table = _PR_CHANGED if s_v == "C" else _PR_UNCHANGED
    if pr_v not in pr_table:
        raise ValueError(f"invalid PR: {pr_v}")

    iss = 1 - ((1 - _CIA[c_v]) * (1 - _CIA[i_v]) * (1 - _CIA[a_v]))
    if s_v == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = 8.22 * _AV[av_v] * _AC[ac_v] * pr_table[pr_v] * _UI[ui_v]

    if impact <= 0:
        return 0.0
    if s_v == "U":
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)
    return _round_up(score)


def severity_for_score(score: float) -> str:
    """Map a base score to its NVD severity bucket."""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def parse_vector(vector: str) -> CVSS3:
    """Parse a CVSS:3.1/AV:.../AC:.../... vector string.

    Lenient: accepts metrics in any order, missing leading prefix, mixed case.
    Raises ``ValueError`` if any of the eight base metrics is missing.
    """
    raw = vector.strip()
    if raw.upper().startswith("CVSS:3."):
        raw = raw.split("/", 1)[1] if "/" in raw else ""
    parts = [p for p in raw.split("/") if p]
    metrics: dict[str, str] = {}
    for p in parts:
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        metrics[k.upper()] = v.upper()

    missing = [m for m in METRIC_NAMES if m not in metrics]
    if missing:
        raise ValueError(f"missing CVSS metrics: {missing}")

    return CVSS3(
        av=metrics["AV"], ac=metrics["AC"], pr=metrics["PR"], ui=metrics["UI"],
        s=metrics["S"], c=metrics["C"], i=metrics["I"], a=metrics["A"],
    )
