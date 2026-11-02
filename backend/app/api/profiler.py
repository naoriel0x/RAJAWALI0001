from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import logging

from app.core.database import get_db
from app.models.attacker import Attacker
from app.models.threat import Threat
from app.schemas.threat import ThreatResponse

router = APIRouter()
logger = logging.getLogger(__name__)


async def _run_profiling(attacker_id: str, db: AsyncSession) -> None:
    try:
        from app.services.ml_profiler import profile_attacker
        from app.services.timing_analyzer import analyze_timing
        await profile_attacker(attacker_id, db)
        await analyze_timing(attacker_id, db)
        await db.commit()
        logger.info("Profiling completed for attacker %s", attacker_id)
    except Exception:
        await db.rollback()
        logger.exception("Profiling failed for %s", attacker_id)


@router.post("/analyze/{attacker_id}", summary="Trigger ML profiling for one attacker")
async def analyze_attacker(
    attacker_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Attacker).where(Attacker.id == attacker_id))
    attacker = result.scalar_one_or_none()
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")

    background_tasks.add_task(_run_profiling, attacker_id, db)
    return {"status": "profiling_queued", "attacker_id": attacker_id}


@router.post("/analyze-all", summary="Trigger ML profiling for all active attackers")
async def analyze_all(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Attacker).where(Attacker.total_events > 0)
    )
    attackers = result.scalars().all()

    for attacker in attackers:
        background_tasks.add_task(_run_profiling, str(attacker.id), db)

    return {"status": "profiling_queued", "count": len(attackers)}


@router.get("/result/{attacker_id}", response_model=ThreatResponse, summary="Get profiling results")
async def get_profile_result(attacker_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Threat).where(Threat.attacker_id == attacker_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(
            status_code=404,
            detail="No profiling result exists. Run /analyze/{attacker_id} first."
        )
    return threat