"""Asset (master spreadsheet) routes."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from ...core import models as m
from ...core.db import session_scope
from ...core.scope import Scope
from ..auth import require_token_dep
from ..schemas import AssetOut, AssetUpsert

router = APIRouter(prefix="/engagements/{engagement_id}/assets", tags=["assets"],
                   dependencies=[require_token_dep])


def _serialise(a: m.Asset) -> AssetOut:
    return AssetOut.model_validate(a)


def _scope_for(engagement: m.Engagement) -> Scope:
    return Scope.from_rules(engagement.scope_rules)


def upsert_assets_in_session(
    session,
    engagement: m.Engagement,
    items: list[AssetUpsert],
    *,
    scope: Scope | None = None,
    now: datetime | None = None,
) -> list[m.Asset]:
    """Shared upsert helper. Caller is responsible for transaction commit."""
    scope = scope or _scope_for(engagement)
    now = now or datetime.now(UTC)
    out: list[m.Asset] = []
    seen_in_batch: dict[str, m.Asset] = {}
    for item in items:
        host = (item.host or "").strip().lower().rstrip(".")
        if not host:
            continue
        in_scope_decision = item.in_scope if item.in_scope is not None else scope.is_in_scope(host)

        existing = seen_in_batch.get(host)
        if existing is None:
            existing = session.execute(
                select(m.Asset).where(
                    m.Asset.engagement_id == engagement.id, m.Asset.host == host,
                )
            ).scalar_one_or_none()

        if existing is None:
            a = m.Asset(
                engagement_id=engagement.id, host=host, ip=item.ip,
                env_type=item.env_type, source=item.source,
                in_scope=in_scope_decision, extra=item.extra,
                discovered_at=now, last_seen=now,
            )
            session.add(a)
            seen_in_batch[host] = a
            out.append(a)
        else:
            existing.last_seen = now
            if item.ip:
                existing.ip = item.ip
            if item.env_type:
                existing.env_type = item.env_type
            if item.source:
                existing.source = item.source
            if item.extra:
                merged = dict(existing.extra or {})
                merged.update(item.extra)
                existing.extra = merged
            existing.in_scope = in_scope_decision
            seen_in_batch[host] = existing
            if existing not in out:
                out.append(existing)
    return out


@router.get("", response_model=list[AssetOut])
def list_assets(engagement_id: int, request: Request,
                in_scope: bool | None = None,
                env: str | None = None) -> list[AssetOut]:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        q = select(m.Asset).where(m.Asset.engagement_id == engagement_id)
        if in_scope is not None:
            q = q.where(m.Asset.in_scope == in_scope)
        if env is not None:
            q = q.where(m.Asset.env_type == env)
        rows = s.execute(q.order_by(m.Asset.host)).scalars().all()
        return [_serialise(a) for a in rows]


@router.post("", response_model=list[AssetOut])
def upsert_assets(engagement_id: int, payload: list[AssetUpsert],
                  request: Request) -> list[AssetOut]:
    """Upsert a batch of assets. Used by workers reporting back from a step."""
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        out = upsert_assets_in_session(s, e, payload)
        s.flush()
        return [_serialise(a) for a in out]


@router.get("/detail")
def list_assets_detail(engagement_id: int, request: Request) -> list[dict]:
    """Return assets with nested ports, techs, cves, and risk-score rows."""
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        rows = s.execute(
            select(m.Asset).where(m.Asset.engagement_id == engagement_id).order_by(m.Asset.host)
        ).scalars().all()
        out: list[dict] = []
        for a in rows:
            out.append({
                "id": a.id, "host": a.host, "ip": a.ip, "env_type": a.env_type,
                "in_scope": a.in_scope, "risk_total": a.risk_total,
                "ports": [{"port": p.port, "proto": p.proto, "service": p.service,
                           "version": p.version} for p in a.ports],
                "techs": [{"name": t.name, "version": t.version,
                           "category": t.category, "source": t.source}
                          for t in a.techs],
                "cves": [{"cve_id": c.cve_id, "cvss_score": c.cvss_score,
                          "severity": c.severity, "summary": c.summary} for c in a.cves],
                "risk_scores": [{"factor": r.factor, "points": r.points, "note": r.note}
                                for r in a.risk_scores],
            })
        return out


@router.post("/{asset_id}/techs")
def attach_techs(engagement_id: int, asset_id: int,
                 payload: list[dict], request: Request) -> list[dict]:
    """Upsert technology rows for an asset. Used by Wappalyzer / fingerprint modules."""
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        a = s.get(m.Asset, asset_id)
        if a is None or a.engagement_id != engagement_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
        added: list[m.Technology] = []
        for item in payload:
            name = (item.get("name") or "").strip()
            if not name:
                continue
            existing = next((t for t in a.techs if t.name.lower() == name.lower()), None)
            if existing is None:
                t = m.Technology(asset_id=asset_id, name=name,
                                 version=item.get("version"),
                                 category=item.get("category"),
                                 source=item.get("source"))
                s.add(t)
                added.append(t)
            else:
                if item.get("version"):
                    existing.version = item["version"]
                if item.get("source"):
                    existing.source = item["source"]
                added.append(existing)
        s.flush()
        return [{"id": t.id, "name": t.name, "version": t.version} for t in added]


@router.post("/{asset_id}/cves")
def attach_cves(engagement_id: int, asset_id: int,
                payload: list[dict], request: Request) -> list[dict]:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        a = s.get(m.Asset, asset_id)
        if a is None or a.engagement_id != engagement_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
        added: list[m.CVE] = []
        for item in payload:
            cve_id = (item.get("cve_id") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            if any(c.cve_id == cve_id for c in a.cves):
                continue
            c = m.CVE(asset_id=asset_id, cve_id=cve_id,
                      cvss_score=item.get("cvss_score"),
                      severity=item.get("severity"),
                      summary=item.get("summary"),
                      references=item.get("references") or [])
            s.add(c)
            added.append(c)
        s.flush()
        return [{"id": c.id, "cve_id": c.cve_id, "cvss_score": c.cvss_score} for c in added]


@router.post("/{asset_id}/risk")
def update_risk(engagement_id: int, asset_id: int, payload: dict,
                request: Request) -> dict:
    """Update an asset's risk_total + replace its risk_score breakdown rows."""
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        a = s.get(m.Asset, asset_id)
        if a is None or a.engagement_id != engagement_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
        # Replace breakdown
        for r in list(a.risk_scores):
            s.delete(r)
        breakdown = payload.get("breakdown") or []
        total = 0
        for item in breakdown:
            pts = int(item.get("points", 0))
            total += pts
            s.add(m.RiskScore(asset_id=asset_id,
                              factor=str(item.get("factor", "unknown")),
                              points=pts,
                              note=item.get("note")))
        a.risk_total = int(payload.get("total", total))
        s.flush()
        return {"asset_id": a.id, "risk_total": a.risk_total,
                "breakdown_rows": len(breakdown)}

