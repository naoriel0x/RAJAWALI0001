import httpx
import logging
from datetime import timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.attacker import Attacker
from app.models.threat import ThreatIntelCache
from app.core.config import settings
from app.core.timezone import now_wib

logger = logging.getLogger(__name__)

ABUSEIPDB_URL   = "https://api.abuseipdb.com/api/v2/check"
IPAPI_URL       = "http://ip-api.com/json"
CACHE_TTL_HOURS = 24

async def check_ip_reputation(ip: str, db: AsyncSession) -> dict:
    cached = await db.execute(
        select(ThreatIntelCache).where(ThreatIntelCache.ip_address == ip)
    )
    cache = cached.scalar_one_or_none()

    now = now_wib()
    if cache and cache.expires_at and cache.expires_at > now:
        logger.info(f"Cache hit for {ip}")
        return {
            "ip": ip,
            "is_malicious": bool(cache.is_malicious),
            "abuse_confidence": cache.abuse_confidence,
            "categories": cache.categories,
            "source": "cache"
        }

    result = {
        "ip": ip,
        "is_malicious": False,
        "abuse_confidence": 0.0,
        "categories": [],
        "source": "fresh"
    }

    if settings.ABUSE_CH_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    ABUSEIPDB_URL,
                    headers={
                        "Key": settings.ABUSE_CH_API_KEY,
                        "Accept": "application/json"
                    },
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90,
                        "verbose": True
                    }
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    confidence = data.get("abuseConfidenceScore", 0)
                    result["is_malicious"]      = confidence > 25
                    result["abuse_confidence"]  = confidence
                    result["categories"]        = data.get("usageType", "").split(",")
                    result["raw"]               = data
        except Exception as e:
            logger.warning(f"AbuseIPDB check failed for {ip}: {e}")
    else:
        result["source"] = "unavailable"
        logger.info("AbuseIPDB API key is not configured; reputation remains unverified for %s", ip)

    if cache:
        cache.is_malicious      = int(result["is_malicious"])
        cache.abuse_confidence  = result["abuse_confidence"]
        cache.categories        = result["categories"]
        cache.cached_at         = now
        cache.expires_at        = now + timedelta(hours=CACHE_TTL_HOURS)
    else:
        new_cache = ThreatIntelCache(
            ip_address          = ip,
            is_malicious        = int(result["is_malicious"]),
            abuse_confidence    = result["abuse_confidence"],
            categories          = result["categories"],
            cached_at           = now,
            expires_at          = now + timedelta(hours=CACHE_TTL_HOURS)
        )
        db.add(new_cache)

    attacker_result = await db.execute(
        select(Attacker).where(Attacker.ip_address == ip)
    )
    attacker = attacker_result.scalar_one_or_none()
    if attacker:
        attacker.is_known_malicious = int(result["is_malicious"])
        attacker.abuse_confidence   = result["abuse_confidence"]

    await db.flush()
    logger.info(f"Threat intel for {ip}: malicious={result['is_malicious']}, confidence={result['abuse_confidence']}")
    return result


async def get_ip_geolocation(ip: str) -> dict:
    from app.utils.ip_utils import is_public_ip

    if not is_public_ip(ip):
        return {}

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{IPAPI_URL}/{ip}")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") != "success":
                    return {}
                return {
                    "country_code": data.get("countryCode"),
                    "country_name": data.get("country"),
                    "isp":          data.get("isp"),
                    "org":          data.get("org"),
                    "hostname":     data.get("reverse"),
                }
    except Exception as e:
        logger.warning(f"Geolocation failed for {ip}: {e}")
    return {}