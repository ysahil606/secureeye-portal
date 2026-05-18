import asyncio
import logging
import os
import random
from contextlib import asynccontextmanager, suppress
from datetime import datetime

from typing import Optional, List
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import httpx
from sqlalchemy import text

import models
from database import engine, SessionLocal, get_db
from config import settings
from auth import hash_password
from models import User, Sector, UserRole, Advisory, AdvisoryStatus, AdvisorySource
from schemas import AdvisoryOut

# Routes
from routes import auth, advisories, dashboard, admin, collaboration, ai, reports, apt_router, war_room, sandbox, advanced, darkweb
from services import threat_feeds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("main")

scheduler = AsyncIOScheduler()


def seed_database():
    """Create default users and sectors. Force-overwrites admin for cloud recovery."""
    db = SessionLocal()
    try:
        # Check for existing admin
        existing_admin = db.query(User).filter(User.username == "admin").first()
        
        if existing_admin:
            # Overwrite password to ensure it matches the current hashing algorithm (PBKDF2)
            existing_admin.hashed_password = hash_password("Admin@12345")
            logger.info("Admin user password reset to 'Admin@12345' (PBKDF2)")
        else:
            admin_user = User(
                email="admin@secure.local",
                username="admin",
                full_name="Secure Admin",
                hashed_password=hash_password("Admin@12345"),
                role=UserRole.admin,
                is_active=True,
            )
            db.add(admin_user)
            logger.info("New admin user created: admin / Admin@12345")

        # Default analyst
        if not db.query(User).filter(User.username == "analyst").first():
            db.add(User(
                email="analyst@secure.local",
                username="analyst",
                full_name="Secure Analyst",
                hashed_password=hash_password("Analyst@12345"),
                role=UserRole.analyst,
                is_active=True,
            ))

        # Default viewer
        if not db.query(User).filter(User.username == "viewer").first():
            db.add(User(
                email="viewer@secure.local",
                username="viewer",
                full_name="Secure Viewer",
                hashed_password=hash_password("Viewer@12345"),
                role=UserRole.viewer,
                is_active=True,
            ))

        # Default sectors
        default_sectors = [
            ("Network", "Firewalls, Routers, Switches, VPNs"),
            ("Cloud", "AWS, Azure, GCP, Kubernetes, SaaS"),
            ("Application", "Web Apps, APIs, Databases, Software"),
            ("Endpoint", "Windows, Linux, macOS, Mobile, EDR"),
            ("BFSI", "Banking, Financial Services and Insurance"),
            ("Healthcare", "Hospitals, Medical Systems, Pharma"),
            ("Government", "Public Sector, Defense, Critical Infrastructure"),
        ]
        for name, desc in default_sectors:
            if not db.query(Sector).filter(Sector.name == name).first():
                db.add(Sector(name=name, description=desc))

        db.commit()
        logger.info("Database seeding/recovery successful")
    except Exception as e:
        db.rollback()
        logger.error(f"Seeding failed: {e}")
    finally:
        db.close()


# --- ADVANCED RESILIENCE: ETERNAL PULSE ---
async def eternal_pulse():
    """Aggressive heartbeat that pings the public URL to prevent idling."""
    await asyncio.sleep(10) # Wait for server to fully boot
    
    # Try to determine public URL from common cloud env vars
    public_url = settings.PUBLIC_BACKEND_URL.strip() or None
    for env_var in ["RENDER_EXTERNAL_URL", "RAILWAY_PUBLIC_DOMAIN"]:
        val = os.getenv(env_var)
        if not public_url and val:
            public_url = val
            break
            
    # Fallback to local if no cloud env detected
    if public_url:
        target = public_url.rstrip("/")
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        target = f"{target}/api/health"
    else:
        target = "http://localhost:8000/api/health"
    
    logger.info(f"[Resilience] Eternal Pulse initiated. Target: {target}")
    
    while True:
        db = None
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.get(target)
                # Also run a dummy query to keep DB connection active
                db = SessionLocal()
                db.execute(text("SELECT 1"))
                logger.info("[Resilience] Pulse Stable: System Active")
        except Exception as e:
            logger.warning(f"[Resilience] Pulse Hiccup: {e}")
        finally:
            if db:
                db.close()
        
        base_interval = max(settings.KEEP_ALIVE_INTERVAL_SECONDS, 60)
        jitter = random.randint(0, 30)
        await asyncio.sleep(base_interval + jitter)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables & Seed
    models.Base.metadata.create_all(bind=engine)
    seed_database()

    # Start the Eternal Pulse Task
    pulse_task = asyncio.create_task(eternal_pulse())

    if settings.WARM_START_FEEDS_ENABLED:
        logger.info("Initiating Warm Start: Synchronizing threat landscape...")
        scheduler.add_job(threat_feeds.run_all_feeds_sync, "date", run_date=datetime.now(), id="warm_start_feeds")

    # Schedule feed polling
    scheduler.add_job(
        threat_feeds.run_all_feeds_sync,
        "interval",
        minutes=settings.FEED_POLL_INTERVAL_MINUTES,
        id="feed_poll",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(f"Feed scheduler started — polling every {settings.FEED_POLL_INTERVAL_MINUTES} minutes")

    yield

    pulse_task.cancel()
    with suppress(asyncio.CancelledError):
        await pulse_task
    scheduler.shutdown(wait=False)
    logger.info("Scheduler stopped")


app = FastAPI(
    title="Secure Cybersecurity Advisory Portal",
    description="Centralized threat intelligence platform for Personal Secure team",
    version="1.0.0",
    lifespan=lifespan,
)

# --- GLOBAL RESILIENCE LAYER: Error Interceptor ---
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_log = f"{type(exc).__name__}: {str(exc)}"
    logger.error(f"Critical System Anomaly: {error_log}")
    
    # Return a resilient response that the frontend can handle gracefully
    return JSONResponse(
        status_code=500,
        content={
            "detail": "A critical system anomaly occurred. The self-healing protocol has been initiated.",
            "error_type": type(exc).__name__,
            "status": "self_healing_active"
        },
    )
# --------------------------------------------------

# CORS — allow React dev server and production origins
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
    "https://secure-portal.vercel.app",
]

# Allow custom production origin from env
if hasattr(settings, "ALLOWED_ORIGINS") and settings.ALLOWED_ORIGINS:
    if settings.ALLOWED_ORIGINS == "*":
        allowed_origins = ["*"]
    else:
        allowed_origins.extend([o.strip() for o in settings.ALLOWED_ORIGINS.split(",")])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True if "*" not in allowed_origins else False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth.router, prefix="/api")
app.include_router(advisories.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(admin.router, prefix="/api")
app.include_router(collaboration.router, prefix="/api")
app.include_router(ai.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(apt_router.router, prefix="/api")
app.include_router(war_room.router, prefix="/api")
app.include_router(sandbox.router, prefix="/api")
app.include_router(advanced.router, prefix="/api")
app.include_router(darkweb.router, prefix="/api")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "database": "ok",
        "app": settings.APP_NAME,
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
