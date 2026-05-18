from datetime import datetime, timedelta
from hashlib import sha256

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from auth import get_current_active_user
from database import get_db
from models import Advisory, IOC

router = APIRouter(prefix="/darkweb", tags=["Dark Web Monitor"])


def normalize_query(value: str) -> str:
    cleaned = value.strip().lower()
    return cleaned.replace("https://", "").replace("http://", "").split("/")[0]


def deterministic_pick(seed: str, items: list[str], count: int) -> list[str]:
    digest = sha256(seed.encode("utf-8")).digest()
    picked = []
    for byte in digest:
        item = items[byte % len(items)]
        if item not in picked:
            picked.append(item)
        if len(picked) == count:
            break
    return picked


@router.get("/scan")
async def scan_darkweb(
    q: str = Query(..., min_length=2),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """
    Returns a safe exposure assessment based on local intelligence plus
    deterministic demo signals. It does not connect to onion services.
    """
    keyword = normalize_query(q)
    now = datetime.utcnow()

    advisory_hits = (
        db.query(Advisory)
        .filter(or_(Advisory.title.ilike(f"%{keyword}%"), Advisory.description.ilike(f"%{keyword}%")))
        .order_by(Advisory.created_at.desc())
        .limit(6)
        .all()
    )
    ioc_hits = db.query(IOC).filter(IOC.value.ilike(f"%{keyword}%")).limit(6).all()

    roles = deterministic_pick(keyword, ["admin", "security", "helpdesk", "finance", "devops", "hr"], 3)
    sources = deterministic_pick(
        keyword,
        ["Credential stuffing list", "Stealer log index", "Forum mention", "Public paste archive", "Breach combo set"],
        3,
    )

    has_local_hits = bool(advisory_hits or ioc_hits)
    leaks = []
    if has_local_hits or "." in keyword:
        leaks = [
            {
                "id": f"{sha256((keyword + role).encode()).hexdigest()[:10]}",
                "email": f"{role}@{keyword}",
                "source": sources[index % len(sources)],
                "date": (now - timedelta(days=18 + index * 37)).date().isoformat(),
                "severity": ["critical", "high", "medium"][index % 3],
                "status": "open",
            }
            for index, role in enumerate(roles)
        ]

    mentions = [
        {
            "id": f"mention-{item.id}",
            "title": item.title,
            "snippet": (item.description or "Local advisory match").strip()[:180],
            "onion_site": "local-intel",
            "severity": item.severity.value if item.severity else "medium",
        }
        for item in advisory_hits
    ]
    mentions.extend(
        {
            "id": f"ioc-{item.id}",
            "title": f"IOC match for {item.value}",
            "snippet": f"{item.ioc_type.upper()} indicator appears in SecureEye local intelligence.",
            "onion_site": item.source or "local-ioc-store",
            "severity": "high",
        }
        for item in ioc_hits
    )

    return {
        "query": keyword,
        "scanned_at": now.isoformat(),
        "exposure_level": "Elevated" if leaks or mentions else "Watch",
        "leaks": leaks,
        "mentions": mentions,
        "recommendations": [
            "Force password reset for exposed identities.",
            "Review MFA enrollment and recent sign-in logs.",
            "Search SIEM, DNS, EDR, and proxy logs for related indicators.",
            "Open an incident if any exposed account has privileged access.",
        ],
    }
