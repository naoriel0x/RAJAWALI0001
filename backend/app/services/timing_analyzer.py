import logging
import numpy as np
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.event import Event
from app.models.threat import Threat

logger = logging.getLogger(__name__)

async def analyze_timing(attacker_id: str, db: AsyncSession) -> dict:
    attacker_uuid = str(attacker_id)
    events_res = await db.execute(
        select(Event)
        .where(Event.attacker_id == attacker_uuid)
        .order_by(Event.timestamp.asc())
    )
    events = events_res.scalars().all()

    threat_res = await db.execute(
        select(Threat).where(Threat.attacker_id == attacker_uuid)
    )
    threat = threat_res.scalar_one_or_none()
    if threat is None:
        threat = Threat(attacker_id=attacker_uuid)
        db.add(threat)

    if len(events) < 3:
        threat.timing_pattern = "insufficient_data"
        await db.flush()
        return {
            "pattern":          "insufficient_data",
            "avg_interval_ms":  None,
            "min_interval_ms":  None,
            "max_interval_ms":  None,
            "std_interval_ms":  None,
            "verdict":          "Not enough events to analyze"
        }

    timestamps = [e.timestamp for e in events if e.timestamp]
    intervals  = []

    for i in range(1, len(timestamps)):
        delta_ms = (timestamps[i] - timestamps[i-1]).total_seconds() * 1000
        if delta_ms >= 0:
            intervals.append(delta_ms)

    if not intervals:
        threat.timing_pattern = "unknown"
        await db.flush()
        return {"pattern": "unknown", "avg_interval_ms": None}

    avg_ms  = float(np.mean(intervals))
    min_ms  = float(np.min(intervals))
    max_ms  = float(np.max(intervals))
    std_ms  = float(np.std(intervals))
    cv      = std_ms / max(avg_ms, 1)
    pattern, verdict = _classify_pattern(avg_ms, cv, min_ms, max_ms)
    threat.avg_interval_ms = round(avg_ms, 2)
    threat.min_interval_ms = round(min_ms, 2)
    threat.max_interval_ms = round(max_ms, 2)
    threat.timing_pattern = pattern
    await db.flush()

    return {
        "pattern":          pattern,
        "avg_interval_ms":  round(avg_ms, 2),
        "min_interval_ms":  round(min_ms, 2),
        "max_interval_ms":  round(max_ms, 2),
        "std_interval_ms":  round(std_ms, 2),
        "cv":               round(cv, 3),
        "total_intervals":  len(intervals),
        "verdict":          verdict
    }


def _classify_pattern(avg_ms: float, cv: float, min_ms: float, max_ms: float) -> tuple:
    if avg_ms < 100:
        return "burst", "Automated burst attack — likely flood or DoS tool"

    if avg_ms > 60000:
        return "slow_and_low", "Slow and low attack — possible APT or manual stealth recon"

    if cv < 0.3:
        return "automated", "Highly automated — bot or scripted attack, low human involvement"

    if cv > 0.8:
        return "manual", "Manual attack — human operator detected, high skill likely"

    return "mixed", "Mixed pattern — human operator using automated tools"