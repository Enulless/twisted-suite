"""Schema-level tests for the SQLAlchemy models."""

from __future__ import annotations

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from twisted.core import models as m


class TestSchemaCreation:
    def test_all_expected_tables_present(self, engine_in_memory) -> None:
        names = set(inspect(engine_in_memory).get_table_names())
        expected = {
            "engagement",
            "scope_rule",
            "asset",
            "port",
            "technology",
            "cve",
            "risk_score",
            "finding",
            "evidence",
            "step_run",
            "worker",
            "job",
            "training_progress",
        }
        missing = expected - names
        assert not missing, f"missing tables: {missing}"


class TestEngagement:
    def test_engagement_basic_round_trip(self, session: Session) -> None:
        eng = m.Engagement(client="OVH", primary_domain="ovh.com")
        session.add(eng)
        session.commit()
        loaded = session.scalar(select(m.Engagement).where(m.Engagement.client == "OVH"))
        assert loaded is not None
        assert loaded.status == m.EngagementStatus.PLANNING
        assert loaded.created_at is not None

    def test_client_unique(self, session: Session) -> None:
        session.add(m.Engagement(client="OVH"))
        session.commit()
        session.add(m.Engagement(client="OVH"))
        with pytest.raises(IntegrityError):
            session.commit()


class TestScopeRule:
    def test_scope_rule_persists_with_kind(self, session: Session) -> None:
        eng = m.Engagement(client="OVH")
        eng.scope_rules.append(m.ScopeRule(kind=m.ScopeKind.EXACT, pattern="api.ovh.com"))
        eng.scope_rules.append(m.ScopeRule(kind=m.ScopeKind.WILDCARD, pattern="soyoustart.com"))
        eng.scope_rules.append(m.ScopeRule(kind=m.ScopeKind.OOS, pattern=r".*\.osp\.ovh\.com$"))
        session.add(eng)
        session.commit()

        loaded = session.scalar(select(m.Engagement).where(m.Engagement.client == "OVH"))
        kinds = sorted(r.kind for r in loaded.scope_rules)
        assert kinds == sorted([m.ScopeKind.EXACT, m.ScopeKind.WILDCARD, m.ScopeKind.OOS])


class TestAsset:
    def test_asset_with_ports_techs_cves(self, session: Session) -> None:
        eng = m.Engagement(client="ACME", primary_domain="acme.example")
        asset = m.Asset(host="api.acme.example", env_type="production", source="crt.sh")
        eng.assets.append(asset)
        session.add(eng)
        session.commit()

        asset.ports.append(m.Port(port=443, proto="tcp", service="https", version="nginx/1.20.1"))
        asset.techs.append(m.Technology(name="nginx", version="1.20.1", source="banner"))
        asset.cves.append(
            m.CVE(cve_id="CVE-2021-23017", cvss_score=7.7, severity="High", summary="DNS resolver bug")
        )
        session.commit()

        loaded = session.scalar(select(m.Asset).where(m.Asset.host == "api.acme.example"))
        assert len(loaded.ports) == 1
        assert loaded.ports[0].service == "https"
        assert loaded.cves[0].cve_id == "CVE-2021-23017"
        assert loaded.in_scope is True

    def test_unique_host_per_engagement(self, session: Session) -> None:
        eng = m.Engagement(client="ACME")
        eng.assets.append(m.Asset(host="api.acme.example"))
        eng.assets.append(m.Asset(host="api.acme.example"))
        session.add(eng)
        with pytest.raises(IntegrityError):
            session.commit()


class TestFindingAndEvidence:
    def test_finding_with_evidence(self, session: Session) -> None:
        eng = m.Engagement(client="ACME")
        f = m.Finding(
            engagement=eng,
            title="Reflected XSS in /search",
            severity=m.FindingSeverity.HIGH,
            cvss_score=7.4,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            cwe="CWE-79",
            description="...",
            repro_steps="1. Navigate to /search?q=<script>alert(1)</script>",
        )
        f.evidence.append(
            m.Evidence(
                engagement=eng,
                kind=m.EvidenceKind.SCREENSHOT,
                path="/mnt/c/Users/awhwt/OneDrive/Desktop/Twisted/data/evidence/raw/xss1.png",
                sha256="a" * 64,
                size_bytes=12345,
                host="windows",
            )
        )
        session.add(eng)
        session.commit()

        loaded = session.scalar(select(m.Finding).where(m.Finding.title.like("Reflected XSS%")))
        assert loaded.severity == m.FindingSeverity.HIGH
        assert len(loaded.evidence) == 1
        assert loaded.evidence[0].host == "windows"


class TestJobLifecycle:
    def test_job_attached_to_step_run(self, session: Session) -> None:
        eng = m.Engagement(client="ACME")
        sr = m.StepRun(
            engagement=eng, procedure="bb", stage="stage1", step_id="bb.stage1.crtsh"
        )
        sr.job = m.Job(runtime=m.JobRuntime.EITHER, requires=["network"])
        session.add(eng)
        session.commit()

        loaded = session.scalar(select(m.StepRun).where(m.StepRun.step_id == "bb.stage1.crtsh"))
        assert loaded.job is not None
        assert loaded.job.state == m.JobState.PENDING
        assert loaded.job.runtime == m.JobRuntime.EITHER

    def test_one_job_per_step_run(self, session: Session) -> None:
        eng = m.Engagement(client="ACME")
        sr = m.StepRun(
            engagement=eng, procedure="bb", stage="stage1", step_id="bb.stage1.crtsh"
        )
        sr.job = m.Job(runtime=m.JobRuntime.LINUX)
        session.add(eng)
        session.commit()

        # Now trying to add a second job for the same step_run should fail
        from sqlalchemy.exc import IntegrityError
        session.add(m.Job(step_run_id=sr.id, runtime=m.JobRuntime.LINUX))
        with pytest.raises(IntegrityError):
            session.commit()


class TestWorker:
    def test_worker_registration(self, session: Session) -> None:
        w = m.Worker(
            id="wsl-null-1",
            hostname="ubuntu-wsl",
            os="linux",
            capabilities=["nmap", "dig", "openssl"],
            version="0.1.0",
        )
        session.add(w)
        session.commit()

        loaded = session.get(m.Worker, "wsl-null-1")
        assert loaded.status == m.WorkerStatus.ONLINE
        assert "nmap" in loaded.capabilities


class TestRiskScore:
    def test_multiple_scores_per_asset(self, session: Session) -> None:
        eng = m.Engagement(client="ACME")
        a = m.Asset(host="dev.acme.example", env_type="dev")
        eng.assets.append(a)
        session.add(eng)
        session.commit()

        a.risk_scores.append(m.RiskScore(factor="software_age", points=2))
        a.risk_scores.append(m.RiskScore(factor="missing_csp", points=2))
        a.risk_scores.append(m.RiskScore(factor="env_dev", points=3))
        session.commit()

        total = sum(r.points for r in a.risk_scores)
        assert total == 7


class TestSqlitePragmas:
    def test_wal_mode_enabled_on_file_db(self, file_engine) -> None:
        with file_engine.connect() as conn:
            mode = conn.exec_driver_sql("PRAGMA journal_mode").scalar()
            fk = conn.exec_driver_sql("PRAGMA foreign_keys").scalar()
        assert mode.lower() == "wal"
        assert fk == 1
