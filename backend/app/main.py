from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import secrets
from fastapi import Request

from app.core.database import init_db, init_redis, close_redis
from app.core.config import settings
from app.api import auth, logs, profiler, reports, threats, dashboard
from app.core.security import decode_token

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("RAJAWALI Backend starting...")
    await init_db()
    await init_redis()
    logger.info("All systems ready.")
    yield
    logger.info("RAJAWALI Backend shutting down...")
    await close_redis()

app = FastAPI(
    title="RAJAWALI",
    description="Reconnaissance Awareness & Judgment for Active Warfare Intelligence",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENV.lower() != "production" else None,
    redoc_url="/redoc" if settings.ENV.lower() != "production" else None,
    openapi_url="/openapi.json" if settings.ENV.lower() != "production" else None,
)

# CORS - allow frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    if settings.ENV.lower() == "production" and request.url.path.startswith("/api/") and request.url.path != "/api/auth/token":
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        token = supplied or request.cookies.get("rajawali_session", "")
        if request.url.path == "/api/logs/ingest":
            valid = bool(settings.HONEYPOT_TOKEN and secrets.compare_digest(
                request.headers.get("X-Honeypot-Token", ""), settings.HONEYPOT_TOKEN
            ))
        else:
            valid = bool(token and decode_token(token))
        if not valid:
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if settings.ENV.lower() == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

app.include_router(auth.router,       prefix="/api/auth",      tags=["Authentication"])
app.include_router(logs.router,       prefix="/api/logs",      tags=["Logs"])
app.include_router(profiler.router,   prefix="/api/profiler",  tags=["Profiler"])
app.include_router(reports.router,    prefix="/api/reports",   tags=["Reports"])
app.include_router(threats.router,    prefix="/api/threats",   tags=["Threats"])
app.include_router(dashboard.router,  prefix="/api/dashboard", tags=["Dashboard"])

@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "operational",
        "system": "RAJAWALI",
        "version": "1.0.0"
    }

@app.get("/", tags=["Root"])
async def root():
    return {
        "system": "RAJAWALI",
        "tagline": "Reconnaissance Awareness & Judgment for Active Warfare Intelligence",
        "status": "active",
        "docs": "/docs"
    }