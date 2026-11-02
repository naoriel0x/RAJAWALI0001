from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from datetime import timedelta
from app.core.timezone import as_wib, now_wib
import logging

from app.core.database import get_db
from app.models.attacker import Attacker, AttackerStatus
from app.models.event import Event, EventSeverity, EventType
from app.models.threat import Threat, ThreatLevel
from app.schemas.threat import DashboardStats

router = APIRouter()
logger = logging.getLogger(__name__)

MITRE_TECHNIQUE_NAMES = {
    "T1595": "Active Scanning",
    "T1046": "Network Service Discovery",
    "T1110": "Brute Force",
    "T1059": "Command Execution",
    "T1071": "Application Layer Protocol",
    "T1083": "File Discovery",
    "T1087": "Account Discovery",
    "T1190": "Exploit Public Application",
}


@router.get("", response_model=DashboardStats, summary="Return dashboard statistics")
async def get_dashboard(db: AsyncSession = Depends(get_db)):
    now = now_wib()
    since_24h = now - timedelta(hours=24)

    total_attackers = (await db.execute(select(func.count()).select_from(Attacker))).scalar_one()

    active_threats = (
        await db.execute(
            select(func.count()).select_from(Attacker).where(
                Attacker.status == AttackerStatus.MONITORING
            )
        )
    ).scalar_one()

    blocked_ips = (
        await db.execute(
            select(func.count()).select_from(Attacker).where(Attacker.is_blocked == 1)
        )
    ).scalar_one()

    events_last_24h = (
        await db.execute(
            select(func.count()).select_from(Event).where(Event.timestamp >= since_24h)
        )
    ).scalar_one()

    telemetry_events = (
        await db.execute(
            select(Event.timestamp, Event.severity)
            .where(Event.timestamp >= since_24h)
        )
    ).all()
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    telemetry_buckets = {
        current_hour - timedelta(hours=offset): 0
        for offset in range(23, -1, -1)
    }
    severity_mix = {severity.value: 0 for severity in EventSeverity}
    for timestamp, severity in telemetry_events:
        if timestamp is None:
            continue
        event_time_wib = as_wib(timestamp)
        event_hour = event_time_wib.replace(minute=0, second=0, microsecond=0)
        if event_hour in telemetry_buckets:
            telemetry_buckets[event_hour] += 1
        severity_value = severity.value if hasattr(severity, "value") else str(severity)
        if severity_value in severity_mix:
            severity_mix[severity_value] += 1
    telemetry = [
        {"hour": bucket.strftime("%I %p"), "count": count}
        for bucket, count in telemetry_buckets.items()
    ]

    critical_threats = (
        await db.execute(
            select(func.count()).select_from(Threat).where(
                Threat.threat_level == ThreatLevel.CRITICAL
            )
        )
    ).scalar_one()

    country_rows = (
        await db.execute(
            select(Attacker.country_code, func.count(Attacker.id).label("count"))
            .where(Attacker.country_code.isnot(None))
            .group_by(Attacker.country_code)
            .order_by(desc("count"))
            .limit(10)
        )
    ).all()
    top_countries = [{"country": r.country_code, "count": r.count} for r in country_rows]

    type_rows = (
        await db.execute(
            select(Event.event_type, func.count(Event.id).label("count"))
            .group_by(Event.event_type)
        )
    ).all()
    attack_types = {r.event_type: r.count for r in type_rows}

    mitre_rows = (
        await db.execute(
            select(Event.mitre_technique, func.count(Event.id).label("count"))
            .where(Event.mitre_technique.isnot(None))
            .group_by(Event.mitre_technique)
            .order_by(desc("count"))
            .limit(15)
        )
    ).all()
    mitre_heatmap = [
        {
            "technique_id": r.mitre_technique,
            "name": MITRE_TECHNIQUE_NAMES.get(r.mitre_technique, r.mitre_technique),
            "count": r.count,
        }
        for r in mitre_rows
    ]

    recent_rows = (
        await db.execute(
            select(Event).order_by(desc(Event.timestamp)).limit(10)
        )
    ).scalars().all()
    recent_events = [
        {
            "id": str(e.id),
            "event_type": e.event_type,
            "src_ip": e.src_ip,
            "severity": e.severity,
            "timestamp": as_wib(e.timestamp).isoformat() if e.timestamp else None,
        }
        for e in recent_rows
    ]

    avg_score_result = (await db.execute(select(func.avg(Attacker.threat_score)))).scalar_one()
    threat_score_avg = round(float(avg_score_result or 0.0), 2)

    return DashboardStats(
        total_attackers=total_attackers,
        active_threats=active_threats,
        blocked_ips=blocked_ips,
        events_last_24h=events_last_24h,
        critical_threats=critical_threats,
        top_countries=top_countries,
        attack_types_breakdown=attack_types,
        mitre_heatmap=mitre_heatmap,
        recent_events=recent_events,
        threat_score_avg=threat_score_avg,
        telemetry=telemetry,
        severity_mix=severity_mix,
    )


@router.get("/live", summary="Live event stream (last 20 events)")
async def live_feed(db: AsyncSession = Depends(get_db)):
    events = (
        await db.execute(
            select(Event).order_by(desc(Event.timestamp)).limit(20)
        )
    ).scalars().all()

    return [
        {
            "id": str(e.id),
            "event_type": e.event_type,
            "src_ip": e.src_ip,
            "severity": e.severity,
            "tool_detected": e.tool_detected,
            "mitre_technique": e.mitre_technique,
            "timestamp": as_wib(e.timestamp).isoformat() if e.timestamp else None,
        }
        for e in events
    ]