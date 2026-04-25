"""Rules of Engagement enforcement.

Generalised port of ``is_in_scope`` from the original recon_ovh.py:
- Exact-match hosts (``api.ovh.com``)
- Wildcard parent domains (``soyoustart.com`` matches ``foo.soyoustart.com``)
- Out-of-scope regex patterns checked first; if matched, the host is rejected
  even if it would otherwise be in scope

A ``Scope`` is normally constructed from the ``scope_rule`` rows of a single
engagement, but it also accepts plain Python lists for tests and quick scripts.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from .models import ScopeKind, ScopeRule


@dataclass
class Scope:
    exact: set[str] = field(default_factory=set)
    wildcards: set[str] = field(default_factory=set)
    oos_patterns: list[re.Pattern[str]] = field(default_factory=list)

    @classmethod
    def from_rules(cls, rules: Iterable[ScopeRule]) -> Scope:
        s = cls()
        for r in rules:
            if r.kind == ScopeKind.EXACT:
                s.exact.add(r.pattern.strip().lower().rstrip("."))
            elif r.kind == ScopeKind.WILDCARD:
                s.wildcards.add(r.pattern.strip().lower().lstrip("*.").rstrip("."))
            elif r.kind == ScopeKind.OOS:
                s.oos_patterns.append(re.compile(r.pattern, re.IGNORECASE))
        return s

    @classmethod
    def from_lists(
        cls,
        exact: Iterable[str] | None = None,
        wildcards: Iterable[str] | None = None,
        oos: Iterable[str] | None = None,
    ) -> Scope:
        s = cls()
        for h in exact or []:
            s.exact.add(h.strip().lower().rstrip("."))
        for w in wildcards or []:
            s.wildcards.add(w.strip().lower().lstrip("*.").rstrip("."))
        for p in oos or []:
            s.oos_patterns.append(re.compile(p, re.IGNORECASE))
        return s

    def is_in_scope(self, host: str) -> bool:
        """Return True iff ``host`` is permitted by the configured rules.

        Out-of-scope patterns are checked first and short-circuit the result.
        """
        if not host:
            return False
        h = host.strip().lower().rstrip(".")
        for pat in self.oos_patterns:
            if pat.fullmatch(h) or pat.match(h):
                return False
        if h in self.exact:
            return True
        return any(h == w or h.endswith("." + w) for w in self.wildcards)

    def filter(self, hosts: Iterable[str]) -> tuple[list[str], list[str]]:
        """Split a host list into (in_scope, dropped) lists, deduplicated."""
        in_scope: list[str] = []
        dropped: list[str] = []
        seen: set[str] = set()
        for h in hosts:
            key = (h or "").strip().lower().rstrip(".")
            if not key or key in seen:
                continue
            seen.add(key)
            (in_scope if self.is_in_scope(key) else dropped).append(key)
        return sorted(in_scope), sorted(dropped)


def parse_scope_file(path: str) -> Scope:
    """Parse a simple scope text file.

    Format::

        # comment
        exact: api.ovh.com
        wildcard: soyoustart.com
        oos: .*\\.osp\\.ovh\\.com$
    """
    s = Scope()
    with open(path) as fp:
        for raw in fp:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            kind, _, value = line.partition(":")
            kind = kind.strip().lower()
            value = value.strip()
            if not value:
                continue
            if kind == "exact":
                s.exact.add(value.lower().rstrip("."))
            elif kind == "wildcard":
                s.wildcards.add(value.lower().lstrip("*.").rstrip("."))
            elif kind in ("oos", "out-of-scope", "exclude"):
                s.oos_patterns.append(re.compile(value, re.IGNORECASE))
    return s
