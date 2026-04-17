import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime

from typing import Optional, List
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.asyncio import AsyncIOScheduler

# --- MONKEYPATCH FOR PASSLIB/BCRYPT BUG ---
import passlib.handlers.bcrypt
from passlib.handlers.bcrypt import bcrypt as _bcrypt
if not hasattr(_bcrypt, "__about__"):
    _bcrypt.__about__ = type("About", (object,), {"__version__": "4.0.1"})

# Completely disable the long password check that crashes on Render
def mock_detect_wrap_bug(ident): return False
passlib.handlers.bcrypt.detect_wrap_bug = mock_detect_wrap_bug
# ------------------------------------------

import models
from database import engine, SessionLocal, get_db
from config import settings
from auth import hash_password
from models import User, Sector, UserRole, Advisory, AdvisoryStatus, AdvisorySource
from schemas import AdvisoryOut

# Routes
from routes import auth, advisories, dashboard, admin, collaboration, ai, reports, apt_router, war_room, sandbox
from services import threat_feeds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("main")

scheduler = AsyncIOScheduler()


def seed_database():
    """Create default admin user and sectors on first run."""
    db = SessionLocal()
    try:
        # Default admin user
        if not db.query(User).filter(User.username == "admin").first():
            admin_user = User(
                email="admin@secureeye.local",
                username="admin",
                full_name="SecureEye Admin",
                hashed_password=hash_password("admin"),
                role=UserRole.admin,
                is_active=True,
            )
            db.add(admin_user)
            logger.info("Default admin user created: admin / admin")

        # Default analyst
        if not db.query(User).filter(User.username == "analyst").first():
            analyst = User(
                email="analyst@secureeye.local",
                username="analyst",
                full_name="SecureEye Analyst",
                hashed_password=hash_password("Analyst@123"),
                role=UserRole.analyst,
                is_active=True,
            )
            db.add(analyst)

        # Default viewer
        if not db.query(User).filter(User.username == "viewer").first():
            viewer = User(
                email="viewer@secureeye.local",
                username="viewer",
                full_name="SecureEye Viewer",
                hashed_password=hash_password("Viewer@123"),
                role=UserRole.viewer,
                is_active=True,
            )
            db.add(viewer)

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
        logger.info("Database seeded successfully")
    except Exception as e:
        db.rollback()
        logger.error(f"Seeding failed: {e}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables
    models.Base.metadata.create_all(bind=engine)
    seed_database()

    # Schedule feed polling
    scheduler.add_job(
        threat_feeds.run_all_feeds,
        "interval",
        minutes=settings.FEED_POLL_INTERVAL_MINUTES,
        id="feed_poll",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(f"Feed scheduler started — polling every {settings.FEED_POLL_INTERVAL_MINUTES} minutes")

    yield

    scheduler.shutdown(wait=False)
    logger.info("Scheduler stopped")


app = FastAPI(
    title="SecureEye Cybersecurity Advisory Portal",
    description="Centralized threat intelligence platform for Wipro SecureEye team",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow React dev server and production origins
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
    "https://secureeye-portal.vercel.app",
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


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
