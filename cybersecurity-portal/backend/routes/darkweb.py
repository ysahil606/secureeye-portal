import httpx
import logging
from datetime import datetime, timedelta
from hashlib import sha256

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from auth import get_current_active_user
from database import get_db
from models import Advisory, IOC
from config import settings

logger = logging.getLogger("darkweb")
router = APIRouter(prefix="/darkweb", tags=["Dark Web Monitor"])


def normalize_query(value: str) -> str:
    cleaned = value.strip().lower()
    return cleaned.replace("https://", "").replace("http://", "").split("/")[0]


@router.get("/scan")
async def scan_darkweb(
    q: str = Query(..., min_length=2),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """
    Performs a real-time exposure scan using BreachDirectory API 
    combined with local threat intelligence.
    """
    keyword = normalize_query(q)
    now = datetime.utcnow()
    leaks = []
    mentions = []
    
    # 1. REAL-TIME BREACH DIRECTORY SCAN (External API)
    if settings.BREACH_DIRECTORY_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                # BreachDirectory RapidAPI or Direct API
                url = f"https://breachdirectory.p.rapidapi.com/v1/search?term={keyword}"
                headers = {
                    "X-RapidAPI-Key": settings.BREACH_DIRECTORY_API_KEY,
                    "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
                }
                r = await client.get(url, headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    for item in data.get("result", []):
                        leaks.append({
                            "id": f"bd-{sha256(str(item).encode()).hexdigest()[:8]}",
                            "email": item.get("email") or keyword,
                            "source": item.get("sources", ["Data Breach"])[0],
                            "date": item.get("date", now.date().isoformat()),
                            "severity": "critical" if item.get("password") else "high",
                            "status": "open",
                            "has_password": bool(item.get("password")),
                            "hint": item.get("password") or "SHA-1 Hash Found"
                        })
        except Exception as e:
            logger.error(f"BreachDirectory API failed: {e}")

    # 2. LOCAL INTELLIGENCE SCAN (Our Database)
    advisory_hits = (
        db.query(Advisory)
        .filter(or_(Advisory.title.ilike(f"%{keyword}%"), Advisory.description.ilike(f"%{keyword}%")))
        .order_by(Advisory.created_at.desc())
        .limit(10)
        .all()
    )
    ioc_hits = db.query(IOC).filter(IOC.value.ilike(f"%{keyword}%")).limit(10).all()

    for item in advisory_hits:
        mentions.append({
            "id": f"adv-{item.id}",
            "title": item.title,
            "snippet": (item.description or "Internal intelligence match").strip()[:200],
            "onion_site": "indexed-advisory",
            "severity": item.severity.value if item.severity else "medium",
        })

    for item in ioc_hits:
        mentions.append({
            "id": f"ioc-{item.id}",
            "title": f"IOC match for {item.value}",
            "snippet": f"Identified in Secure Intelligence Feed: {item.source}",
            "onion_site": "darkweb-ioc-store",
            "severity": "high",
        })

    # 3. FALLBACK GENERATOR (Only if NO real data was found and no API key exists)
    if not leaks and not mentions and not settings.BREACH_DIRECTORY_API_KEY:
        # Simulation mode for demo
        if "." in keyword:
            leaks.append({
                "id": f"sim-{sha256(keyword.encode()).hexdigest()[:8]}",
                "email": f"admin@{keyword}",
                "source": "Simulated Breach Log",
                "date": (now - timedelta(days=45)).date().isoformat(),
                "severity": "high",
                "status": "open",
                "is_simulated": True
            })

    return {
        "query": keyword,
        "scanned_at": now.isoformat(),
        "exposure_level": "Critical" if any(l['severity'] == 'critical' for l in leaks) else "Elevated" if leaks or mentions else "Low",
        "leaks": leaks,
        "mentions": mentions,
        "api_active": bool(settings.BREACH_DIRECTORY_API_KEY),
        "recommendations": [
            "Initiate immediate password reset for all exposed identities.",
            "Verify MFA health for identified high-risk accounts.",
            "Cross-reference found IOCs with internal SIEM/EDR logs.",
            "Monitor dark web forums for further mentions of this domain."
        ],
    }
