"""Tests for the CVSS v3.1 base-score calculator.

Reference scores cross-checked against FIRST's official online calculator:
https://www.first.org/cvss/calculator/3.1
"""

from __future__ import annotations

import pytest

from twisted.core.cvss import (
    CVSS3,
    base_score,
    parse_vector,
    severity_for_score,
)


class TestBaseScore:
    @pytest.mark.parametrize(
        ("metrics", "expected"),
        [
            # Heartbleed-style: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N -> 7.5 High
            (("N", "L", "N", "N", "U", "H", "N", "N"), 7.5),
            # Unauth RCE: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 Critical
            (("N", "L", "N", "N", "U", "H", "H", "H"), 9.8),
            # Reflected XSS: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> 6.1 Medium
            (("N", "L", "N", "R", "C", "L", "L", "N"), 6.1),
            # Stored XSS authenticated: AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N -> 5.4 Medium
            (("N", "L", "L", "R", "C", "L", "L", "N"), 5.4),
            # Local privesc: AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H -> 7.8 High
            (("L", "L", "L", "N", "U", "H", "H", "H"), 7.8),
            # Lowest non-zero: AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N -> 1.6 Low
            (("P", "H", "H", "R", "U", "L", "N", "N"), 1.6),
            # All-none: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N -> 0.0 None
            (("N", "L", "N", "N", "U", "N", "N", "N"), 0.0),
        ],
    )
    def test_known_vectors(self, metrics: tuple, expected: float) -> None:
        score = base_score(*metrics)
        assert score == pytest.approx(expected, abs=0.05)

    def test_invalid_metrics_raise(self) -> None:
        with pytest.raises(ValueError):
            base_score("Z", "L", "N", "N", "U", "H", "H", "H")
        with pytest.raises(ValueError):
            base_score("N", "L", "N", "N", "X", "H", "H", "H")


class TestSeverityBuckets:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0.0, "None"),
            (0.1, "Low"),
            (3.9, "Low"),
            (4.0, "Medium"),
            (6.9, "Medium"),
            (7.0, "High"),
            (8.9, "High"),
            (9.0, "Critical"),
            (10.0, "Critical"),
        ],
    )
    def test_buckets(self, score: float, expected: str) -> None:
        assert severity_for_score(score) == expected


class TestVectorParsing:
    def test_parse_full_prefixed_vector(self) -> None:
        v = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert v.av == "N" and v.s == "U" and v.c == "H"
        assert v.base_score() == pytest.approx(9.8, abs=0.05)
        assert v.severity() == "Critical"

    def test_parse_unprefixed_vector_lower_case(self) -> None:
        v = parse_vector("av:n/ac:l/pr:n/ui:r/s:c/c:l/i:l/a:n")
        assert v.base_score() == pytest.approx(6.1, abs=0.05)

    def test_round_trip_vector_string(self) -> None:
        original = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        v = parse_vector(original)
        assert v.vector() == original

    def test_missing_metric_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")  # no /A


class TestCVSS3Dataclass:
    def test_dataclass_helpers(self) -> None:
        v = CVSS3(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N")
        assert v.base_score() == pytest.approx(7.5, abs=0.05)
        assert v.severity() == "High"
        assert "AV:N" in v.vector()
