from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional
import logging

from app.core.database import get_db, in_memory_store
from app.core.timezone import now_wib
from app.models.attacker import Attacker, AttackerStatus
from app.models.event import Event, EventType, EventSeverity
from app.schemas.event import EventIngest, EventResponse, EventListResponse
from app.schemas.attacker import AttackerResponse
from app.services.threat_intel import get_ip_geolocation
from app.services.mitre_mapper import map_to_mitre
from app.services.ml_profiler import profile_attacker
from app.services.timing_analyzer import analyze_timing
from app.utils.ip_utils import normalize_ip

router = APIRouter()
logger = logging.getLogger(__name__)


async def _run_event_analysis(attacker_id: str, db: AsyncSession) -> None:
    try:
        await profile_attacker(attacker_id, db)
        await analyze_timing(attacker_id, db)
        await db.commit()
        logger.info("Analysis completed for attacker %s", attacker_id)
    except Exception:
        await db.rollback()
        logger.exception("Analysis failed for attacker %s", attacker_id)


def _map_severity(event_type: str) -> EventSeverity:
    critical = {EventType.IP_BLOCKED, EventType.TARPIT_APPLIED}
    high = {EventType.SSH_COMMAND, EventType.LURE_ACCESS, EventType.FAKE_INTEL_FED}
    medium = {EventType.SSH_LOGIN, EventType.HTTP_CRAWL}
    low = {EventType.SSH_CONNECT, EventType.HTTP_REQUEST, EventType.BANNER_GRAB}

    try:
        et = EventType(event_type)
    except ValueError:
        return EventSeverity.INFO

    if et in critical:
        return EventSeverity.CRITICAL
    if et in high:
        return EventSeverity.HIGH
    if et in medium:
        return EventSeverity.MEDIUM
    if et in low:
        return EventSeverity.LOW
    return EventSeverity.INFO


async def _get_or_create_attacker(ip: str, db: AsyncSession) -> Attacker:
    normalized_ip = normalize_ip(ip)
    if normalized_ip is None:
        raise HTTPException(status_code=422, detail="Invalid source IP address")

    result = await db.execute(select(Attacker).where(Attacker.ip_address == normalized_ip))
    attacker = result.scalar_one_or_none()

    if not attacker:
        attacker = Attacker(ip_address=normalized_ip)
        db.add(attacker)
        await db.flush()
        logger.info(f"New attacker registered: {normalized_ip}")

    if not attacker.country_name and not attacker.country_code:
        location = await get_ip_geolocation(normalized_ip)
        for field in ("country_code", "country_name", "isp", "org", "hostname"):
            value = location.get(field)
            if value:
                setattr(attacker, field, value)

    return attacker


@router.post("/ingest", summary="Ingest an event from the honeypot")
async def ingest_event(
    payload: EventIngest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    attacker = await _get_or_create_attacker(payload.src_ip, db)

    severity = _map_severity(payload.event_type)
    mitre = map_to_mitre(payload.event_type, {"username": payload.username})

    event = Event(
        attacker_id=attacker.id,
        event_type=EventType(payload.event_type),
        severity=severity,
        src_ip=attacker.ip_address,
        src_port=payload.src_port,
        dst_port=payload.dst_port,
        protocol=payload.protocol,
        raw_payload=payload.raw_payload,
        parsed_data=payload.parsed_data,
        username=payload.username,
        password=None,
        command=payload.command,
        http_method=payload.http_method,
        http_path=payload.http_path,
        user_agent=payload.user_agent,
        headers=payload.headers,
        timestamp=now_wib(),
        mitre_technique=mitre["technique_id"],
        mitre_technique_name=mitre["technique_name"],
        tool_detected=payload.tool_detected,
    )
    db.add(event)

    attacker.total_events = (attacker.total_events or 0) + 1
    if payload.event_type in ("ssh_connect", "ssh_login", "ssh_command"):
        attacker.ssh_attempts = (attacker.ssh_attempts or 0) + 1
    if payload.event_type in ("http_request", "http_crawl"):
        attacker.http_attempts = (attacker.http_attempts or 0) + 1
    if payload.event_type == "ssh_login":
        attacker.login_attempts = (attacker.login_attempts or 0) + 1
    if payload.event_type == "ssh_command":
        attacker.commands_executed = (attacker.commands_executed or 0) + 1

    if payload.tool_detected and payload.tool_detected not in (attacker.tools_detected or []):
        attacker.tools_detected = [*(attacker.tools_detected or []), payload.tool_detected]
    if mitre["technique_id"] not in (attacker.mitre_ttps or []):
        attacker.mitre_ttps = [*(attacker.mitre_ttps or []), mitre["technique_id"]]

    await db.commit()
    await db.refresh(event)

    in_memory_store[f"last_event:{payload.src_ip}"] = payload.event_type
    background_tasks.add_task(_run_event_analysis, str(attacker.id), db)

    logger.info(f"Event ingested: {payload.event_type} from {attacker.ip_address}")
    return {"status": "ok", "event_id": str(event.id), "attacker_id": str(attacker.id)}


@router.get("", response_model=EventListResponse, summary="List all events")
async def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    event_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Event)

    if event_type:
        query = query.where(Event.event_type == event_type)
    if src_ip:
        query = query.where(Event.src_ip == src_ip)
    if severity:
        query = query.where(Event.severity == severity)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()

    query = query.order_by(desc(Event.timestamp)).offset((page - 1) * page_size).limit(page_size)
    events = (await db.execute(query)).scalars().all()

    return EventListResponse(total=total, page=page, page_size=page_size, data=list(events))


@router.get("/{event_id}", response_model=EventResponse, summary="Get event details by ID")
async def get_event(event_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Event).where(Event.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event