"""Scope / RoE enforcement tests.

Mirror the original recon_ovh.py rules: exact api.ovh.com / www.ovh.com,
wildcard soyoustart.com, OOS *.osp.ovh.com.
"""

from __future__ import annotations

import pytest

from twisted.core.models import ScopeKind, ScopeRule
from twisted.core.scope import Scope, parse_scope_file


@pytest.fixture
def ovh_scope() -> Scope:
    return Scope.from_lists(
        exact=["api.ovh.com", "www.ovh.com"],
        wildcards=["soyoustart.com"],
        oos=[r".*\.osp\.ovh\.com$"],
    )


class TestIsInScope:
    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("api.ovh.com", True),
            ("www.ovh.com", True),
            ("API.OVH.COM", True),  # case-insensitive
            ("api.ovh.com.", True),  # trailing dot
            ("soyoustart.com", True),  # bare wildcard root
            ("eu.soyoustart.com", True),  # subdomain of wildcard
            ("a.b.c.soyoustart.com", True),  # deep subdomain
            ("evil-soyoustart.com", False),  # wildcard requires "." separator
            ("ovh.com", False),  # not exact / no wildcard
            ("manager.ovh.com", False),  # ovh.com not a wildcard
            ("foo.osp.ovh.com", False),  # OOS pattern
            ("bar.osp.ovh.com", False),
            ("", False),
            ("   ", False),
        ],
    )
    def test_basic_decisions(self, ovh_scope: Scope, host: str, expected: bool) -> None:
        assert ovh_scope.is_in_scope(host) is expected

    def test_oos_overrides_wildcard(self) -> None:
        s = Scope.from_lists(
            wildcards=["example.com"],
            oos=[r".*\.internal\.example\.com$"],
        )
        assert s.is_in_scope("foo.example.com") is True
        assert s.is_in_scope("foo.internal.example.com") is False


class TestFilter:
    def test_filter_splits_and_dedupes(self, ovh_scope: Scope) -> None:
        in_scope, dropped = ovh_scope.filter(
            [
                "api.ovh.com",
                "API.OVH.COM",  # dedupe
                "eu.soyoustart.com",
                "foo.osp.ovh.com",
                "manager.ovh.com",
                "",
                "  ",
                "soyoustart.com",
            ]
        )
        assert "api.ovh.com" in in_scope
        assert "eu.soyoustart.com" in in_scope
        assert "soyoustart.com" in in_scope
        assert "foo.osp.ovh.com" in dropped
        assert "manager.ovh.com" in dropped
        # Dedup
        assert len([h for h in in_scope if h == "api.ovh.com"]) == 1


class TestFromRules:
    def test_constructs_from_orm_rule_objects(self) -> None:
        rules = [
            ScopeRule(kind=ScopeKind.EXACT, pattern="api.ovh.com"),
            ScopeRule(kind=ScopeKind.WILDCARD, pattern="*.soyoustart.com"),
            ScopeRule(kind=ScopeKind.OOS, pattern=r".*\.osp\.ovh\.com$"),
        ]
        s = Scope.from_rules(rules)
        assert s.is_in_scope("api.ovh.com") is True
        assert s.is_in_scope("foo.soyoustart.com") is True
        assert s.is_in_scope("foo.osp.ovh.com") is False


class TestParseScopeFile:
    def test_parses_inline_format(self, tmp_path) -> None:
        p = tmp_path / "scope.txt"
        p.write_text(
            "# OVH bug bounty\n"
            "exact: api.ovh.com\n"
            "exact: www.ovh.com\n"
            "wildcard: soyoustart.com\n"
            "oos: .*\\.osp\\.ovh\\.com$\n"
            "\n"
        )
        s = parse_scope_file(str(p))
        assert s.is_in_scope("api.ovh.com") is True
        assert s.is_in_scope("eu.soyoustart.com") is True
        assert s.is_in_scope("foo.osp.ovh.com") is False
