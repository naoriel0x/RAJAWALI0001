from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional
import logging

from app.core.database import get_db
from app.models.attacker import Attacker, AttackerStatus
from app.models.threat import Threat, ThreatLevel
from app.schemas.attacker import AttackerResponse, AttackerListResponse, AttackerSummary, AttackerUpdate
from app.schemas.threat import ThreatResponse
from app.core.timezone import now_wib

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/attackers", response_model=AttackerListResponse, summary="List all attackers")
async def list_attackers(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    min_score: Optional[float] = None,
    country: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Attacker)

    if status:
        query = query.where(Attacker.status == status)
    if min_score is not None:
        query = query.where(Attacker.threat_score >= min_score)
    if country:
        query = query.where(Attacker.country_code == country.upper())

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()

    query = query.order_by(desc(Attacker.threat_score)).offset((page - 1) * page_size).limit(page_size)
    attackers = (await db.execute(query)).scalars().all()

    return AttackerListResponse(total=total, page=page, page_size=page_size, data=list(attackers))


@router.get("/attackers/{attacker_id}", response_model=AttackerResponse, summary="Get attacker details")
async def get_attacker(attacker_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Attacker).where(Attacker.id == attacker_id))
    attacker = result.scalar_one_or_none()
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")
    return attacker


@router.patch("/attackers/{attacker_id}", response_model=AttackerResponse, summary="Update attacker")
async def update_attacker(
    attacker_id: str,
    payload: AttackerUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Attacker).where(Attacker.id == attacker_id))
    attacker = result.scalar_one_or_none()
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")

    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(attacker, field, value)

    await db.commit()
    await db.refresh(attacker)
    return attacker


@router.post("/attackers/{attacker_id}/block", summary="Block attacker IP")
async def block_attacker(attacker_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Attacker).where(Attacker.id == attacker_id))
    attacker = result.scalar_one_or_none()
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")

    attacker.is_blocked = 1
    attacker.status = AttackerStatus.BLOCKED
    attacker.blocked_at = now_wib()
    await db.commit()

    logger.warning(f"Attacker blocked: {attacker.ip_address}")
    return {"status": "blocked", "ip": attacker.ip_address}


@router.get("/profiles", response_model=list[ThreatResponse], summary="List threat profiles")
async def list_threat_profiles(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    threat_level: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Threat)
    if threat_level:
        query = query.where(Threat.threat_level == threat_level)

    query = query.order_by(desc(Threat.threat_score)).offset((page - 1) * page_size).limit(page_size)
    threats = (await db.execute(query)).scalars().all()
    return list(threats)


@router.get("/profiles/{attacker_id}", response_model=ThreatResponse, summary="Threat profile by attacker ID")
async def get_threat_profile(attacker_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Threat).where(Threat.attacker_id == attacker_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="No threat profile exists for this attacker")
    return threat