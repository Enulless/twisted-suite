"""Unit tests for the RoE tool-policy helper."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from twisted.core import models as m
from twisted.core import tool_policy as tp
from twisted.core.db import init_schema, make_engine, make_session_factory
from twisted.core.procedures import ProcedureLoader, Step


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    eng = make_engine(url=f"sqlite:///{tmp_path}/twisted.db")
    init_schema(eng)
    factory: sessionmaker[Session] = make_session_factory(eng)
    s = factory()
    e = m.Engagement(client="ACME", primary_domain="acme.example",
                     status=m.EngagementStatus.ACTIVE)
    s.add(e)
    s.flush()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def loader() -> ProcedureLoader:
    p = ProcedureLoader()
    p.all()
    return p


def _step(step_id: str = "bb.stage4.nmap_full",
          requires: list[str] | None = None,
          stage: str = "stage4", procedure: str = "bb",
          name: str = "Nmap full",
          mode: str = "auto", runtime: str = "linux") -> Step:
    return Step(id=step_id, name=name, stage=stage, procedure=procedure,
                mode=mode, runtime=runtime, requires=requires or [])


# ──────────────────────────── PolicyDecision ────────────────────────────


class TestPolicyDecision:
    def test_allow(self) -> None:
        d = tp.PolicyDecision.allow()
        assert d.allowed is True
        assert d.reason is None
        assert d.target_kind is None

    def test_deny_step(self) -> None:
        d = tp.PolicyDecision.deny_step("bb.stage4.nmap_full")
        assert d.allowed is False
        assert d.target_kind == "step"
        assert "bb.stage4.nmap_full" in d.reason
        assert d.target_value == "bb.stage4.nmap_full"

    def test_deny_capability_with_note(self) -> None:
        d = tp.PolicyDecision.deny_capability("wrk", "no DoS per RoE")
        assert d.allowed is False
        assert d.target_kind == "capability"
        assert d.target_value == "wrk"
        assert d.reason == "no DoS per RoE"


# ──────────────────────────── is_step_allowed ────────────────────────────


class TestIsStepAllowed:
    def test_default_allow_when_no_rows(self, session) -> None:
        eng_id = session.query(m.Engagement).first().id
        decision = tp.is_step_allowed(session, eng_id,
                                      _step("bb.stage1.crtsh"))
        assert decision.allowed is True

    def test_explicit_step_block_denies(self, session) -> None:
        eng_id = session.query(m.Engagement).first().id
        tp.upsert_policy(session, eng_id, target_kind="step",
                         target_value="bb.stage4.nmap_full",
                         allowed=False, note="no aggressive scans")
        session.flush()
        decision = tp.is_step_allowed(session, eng_id,
                                      _step("bb.stage4.nmap_full"))
        assert decision.allowed is False
        assert decision.target_kind == "step"
        assert "no aggressive scans" in decision.reason

    def test_capability_block_cascades(self, session) -> None:
        eng_id = session.query(m.Engagement).first().id
        tp.upsert_policy(session, eng_id, target_kind="capability",
                         target_value="wrk",
                         allowed=False, note="no DoS")
        session.flush()
        # Step requires wrk → cascade-blocked
        decision = tp.is_step_allowed(
            session, eng_id,
            _step("wp_stress.phase2.escalating", requires=["wrk", "ab"]),
        )
        assert decision.allowed is False
        assert decision.target_kind == "capability"
        assert decision.target_value == "wrk"
        # Step that doesn't require wrk → still allowed
        decision = tp.is_step_allowed(
            session, eng_id,
            _step("bb.stage1.crtsh", requires=[]),
        )
        assert decision.allowed is True

    def test_explicit_step_block_wins_over_cap_check(self, session) -> None:
        """If a step is blocked directly, the deny reason cites the
        step (not a capability). This matters for the UI."""
        eng_id = session.query(m.Engagement).first().id
        tp.upsert_policy(session, eng_id, target_kind="step",
                         target_value="x.y.z",
                         allowed=False, note="direct block")
        tp.upsert_policy(session, eng_id, target_kind="capability",
                         target_value="cap1",
                         allowed=False, note="cap block")
        session.flush()
        decision = tp.is_step_allowed(
            session, eng_id, _step("x.y.z", requires=["cap1"]),
        )
        assert decision.allowed is False
        assert decision.target_kind == "step"

    def test_allow_row_does_not_block(self, session) -> None:
        """Rows with allowed=True are treated as default — not as an
        explicit block."""
        eng_id = session.query(m.Engagement).first().id
        tp.upsert_policy(session, eng_id, target_kind="step",
                         target_value="bb.stage1.crtsh",
                         allowed=True, note="explicitly allowed")
        session.flush()
        decision = tp.is_step_allowed(session, eng_id,
                                      _step("bb.stage1.crtsh"))
        assert decision.allowed is True

    def test_separate_engagements_have_separate_policies(self, session) -> None:
        eng_a = session.query(m.Engagement).first()
        eng_b = m.Engagement(client="other")
        session.add(eng_b)
        session.flush()
        tp.upsert_policy(session, eng_a.id, target_kind="capability",
                         target_value="wrk",
                         allowed=False)
        session.flush()
        step = _step("wp_stress.phase2.escalating", requires=["wrk"])
        assert tp.is_step_allowed(session, eng_a.id, step).allowed is False
        assert tp.is_step_allowed(session, eng_b.id, step).allowed is True


# ──────────────────────────── upsert / clear ────────────────────────────


class TestUpsertAndClear:
    def test_upsert_inserts_then_updates(self, session) -> None:
        eng_id = session.query(m.Engagement).first().id
        first = tp.upsert_policy(session, eng_id, target_kind="step",
                                  target_value="bb.stage1.crtsh",
                                  allowed=False, note="initial")
        session.flush()
        second = tp.upsert_policy(session, eng_id, target_kind="step",
                                   target_value="bb.stage1.crtsh",
                                   allowed=True, note="lifted")
        session.flush()
        assert first.id == second.id
        assert second.allowed is True
        assert second.note == "lifted"
        rows = session.query(m.EngagementToolPolicy).filter_by(
            engagement_id=eng_id).all()
        assert len(rows) == 1

    def test_clear_removes_only_for_engagement(self, session) -> None:
        eng_a = session.query(m.Engagement).first()
        eng_b = m.Engagement(client="b")
        session.add(eng_b)
        session.flush()
        tp.upsert_policy(session, eng_a.id, target_kind="step",
                         target_value="x", allowed=False)
        tp.upsert_policy(session, eng_b.id, target_kind="step",
                         target_value="x", allowed=False)
        session.flush()
        deleted = tp.clear_policy(session, eng_a.id)
        session.flush()
        assert deleted == 1
        remaining = session.query(m.EngagementToolPolicy).all()
        assert len(remaining) == 1
        assert remaining[0].engagement_id == eng_b.id


# ──────────────────────────── Presets ────────────────────────────


class TestPresets:
    def test_unknown_preset_raises(self, session) -> None:
        with pytest.raises(ValueError) as exc:
            tp.apply_preset(session, 1, "make_up_a_preset")
        assert "unknown preset" in str(exc.value).lower()

    def test_open_bug_bounty_clears_existing(self, session, loader) -> None:
        eng_id = session.query(m.Engagement).first().id
        tp.upsert_policy(session, eng_id, target_kind="capability",
                         target_value="wrk", allowed=False)
        session.flush()
        result = tp.apply_preset(session, eng_id, "open_bug_bounty", loader)
        session.flush()
        assert result["preset"] == "open_bug_bounty"
        assert result["cleared"] == 1
        rows = session.query(m.EngagementToolPolicy).filter_by(
            engagement_id=eng_id).all()
        assert rows == []

    def test_no_dos_blocks_dos_caps(self, session, loader) -> None:
        eng_id = session.query(m.Engagement).first().id
        result = tp.apply_preset(session, eng_id, "no_dos", loader)
        session.flush()
        assert "wrk" in result["capability_blocks"]
        assert "aireplay-ng" in result["capability_blocks"]
        # And blocks stress/escalating-shaped steps
        assert any("escalating" in s for s in result["step_blocks"])
        # Verify that an actual step that requires wrk is now blocked
        decision = tp.is_step_allowed(
            session, eng_id,
            _step("wp_stress.phase2.escalating", requires=["wrk"]),
        )
        assert decision.allowed is False

    def test_read_only_recon_blocks_active_caps(self, session, loader) -> None:
        eng_id = session.query(m.Engagement).first().id
        result = tp.apply_preset(session, eng_id, "read_only_recon", loader)
        session.flush()
        # Active scanners blocked
        for cap in ("nmap", "nikto", "sqlmap", "wpscan"):
            assert cap in result["capability_blocks"]
        # Passive recon stays open — bb.stage1.crtsh has empty requires,
        # so default-allow keeps it green even after the preset.
        decision = tp.is_step_allowed(
            session, eng_id, _step("bb.stage1.crtsh", requires=[]),
        )
        assert decision.allowed is True
        # Active testing blocked via cap cascade
        decision = tp.is_step_allowed(
            session, eng_id,
            _step("bb.stage4.nmap_top", requires=["nmap"]),
        )
        assert decision.allowed is False


# ──────────────────────────── all_known_capabilities ────────────────────────────


class TestKnownCapabilities:
    def test_includes_expected_caps(self, loader) -> None:
        caps = tp.all_known_capabilities(loader)
        # Sample of caps that appear in the shipped procedure YAMLs
        for expected in ("nmap", "wrk", "wpscan", "aireplay-ng", "openssl"):
            assert expected in caps
        # Sorted
        assert caps == sorted(caps)

    def test_dedupes_across_procedures(self, loader) -> None:
        # Capabilities shouldn't appear twice even though e.g. `network`
        # is required by many steps.
        caps = tp.all_known_capabilities(loader)
        assert len(caps) == len(set(caps))
