from typing import List, Optional
import re
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc

from database import get_db
from models import User, Sector, IOC, FeedLog, UserRole
from auth import get_current_active_user, require_role, hash_password
from schemas import (
    UserCreate, UserUpdate, UserOut,
    SectorCreate, SectorOut,
    IOCCreate, IOCOut, IOCSearchOut, IOCExternalResultOut,
)
from services import threat_feeds

router = APIRouter(prefix="/admin", tags=["Admin"])

IOC_PATTERNS = {
    "ip": re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),
    "domain": re.compile(r"^(?!https?://)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"),
    "url": re.compile(r"^https?://", flags=re.IGNORECASE),
    "hash": re.compile(r"^[a-fA-F0-9]{32,64}$"),
}


def infer_ioc_type(value: str) -> str:
    text = (value or "").strip()
    for ioc_type, pattern in IOC_PATTERNS.items():
        if pattern.match(text):
            return ioc_type
    return "domain" if "." in text and " " not in text else "ip"


def result_matches_ioc_type(item: dict, ioc_type: Optional[str]) -> bool:
    if not ioc_type:
        return True
    haystack = " ".join([
        item.get("title", ""),
        item.get("description", ""),
        item.get("source_url", ""),
        item.get("display_url", ""),
    ]).lower()
    if ioc_type == "ip":
        return bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", haystack))
    if ioc_type == "url":
        return "http://" in haystack or "https://" in haystack
    if ioc_type == "hash":
        return bool(re.search(r"\b[a-fA-F0-9]{32,64}\b", haystack))
    if ioc_type == "domain":
        return "." in haystack
    return True


# ── Users ─────────────────────────────────────────────────────────────────────
@router.get("/users", response_model=List[UserOut])
async def list_users(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.admin)),
):
    return db.query(User).order_by(desc(User.created_at)).all()


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    data: UserCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.admin)),
):
    if db.query(User).filter((User.email == data.email) | (User.username == data.username)).first():
        raise HTTPException(status_code=400, detail="Email or username already exists")
    user = User(
        email=data.email,
        username=data.username,
        full_name=data.full_name,
        role=data.role,
        hashed_password=hash_password(data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.put("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    data: UserUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.admin)),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    for k, v in data.model_dump(exclude_none=True).items():
        setattr(user, k, v)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.admin)),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    db.delete(user)
    db.commit()


# ── Sectors ───────────────────────────────────────────────────────────────────
@router.get("/sectors", response_model=List[SectorOut])
async def list_sectors(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    return db.query(Sector).all()


@router.post("/sectors", response_model=SectorOut, status_code=201)
async def create_sector(
    data: SectorCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.admin)),
):
    if db.query(Sector).filter(Sector.name == data.name).first():
        raise HTTPException(status_code=400, detail="Sector already exists")
    sector = Sector(**data.model_dump())
    db.add(sector)
    db.commit()
    db.refresh(sector)
    return sector


@router.put("/sectors/{sector_id}", response_model=SectorOut)
async def update_sector(
    sector_id: int,
    data: SectorCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.admin)),
):
    sector = db.query(Sector).filter(Sector.id == sector_id).first()
    if not sector:
        raise HTTPException(status_code=404, detail="Sector not found")
    sector.name = data.name
    sector.description = data.description
    db.commit()
    db.refresh(sector)
    return sector


@router.delete("/sectors/{sector_id}", status_code=204)
async def delete_sector(
    sector_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.admin)),
):
    sector = db.query(Sector).filter(Sector.id == sector_id).first()
    if not sector:
        raise HTTPException(status_code=404, detail="Sector not found")
    sector.is_active = False
    db.commit()


# ── Feeds ─────────────────────────────────────────────────────────────────────
@router.post("/feeds/run")
async def run_feeds(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    """Manually trigger threat feed ingestion."""
    background_tasks.add_task(threat_feeds.run_all_feeds_sync)
    return {"message": "Feed ingestion started in background"}


@router.get("/feeds/logs")
async def get_feed_logs(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    logs = db.query(FeedLog).order_by(desc(FeedLog.run_at)).limit(limit).all()
    return logs


# ── IOC Management ────────────────────────────────────────────────────────────
@router.get("/iocs", response_model=List[IOCOut])
async def list_iocs(
    ioc_type: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    q = db.query(IOC)
    if ioc_type:
        q = q.filter(IOC.ioc_type == ioc_type)
    if search:
        q = q.filter(IOC.value.ilike(f"%{search}%"))
    return q.order_by(desc(IOC.first_seen)).limit(200).all()


@router.get("/iocs/live-search", response_model=IOCSearchOut)
async def live_ioc_search(
    search: str,
    ioc_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    normalized_search = search.strip()
    inferred_type = ioc_type or infer_ioc_type(normalized_search)

    local_query = db.query(IOC)
    if inferred_type:
        local_query = local_query.filter(IOC.ioc_type == inferred_type)
    local_query = local_query.filter(IOC.value.ilike(f"%{normalized_search}%"))
    local_items = local_query.order_by(desc(IOC.first_seen)).limit(100).all()

    external_search = await threat_feeds.search_live_sources(normalized_search, limit_per_source=6)
    external_items = []
    for item in external_search["items"]:
        if not result_matches_ioc_type(item, inferred_type):
            continue
        external_items.append(
            IOCExternalResultOut(
                value=normalized_search,
                ioc_type=inferred_type,
                source_name=item.get("source_name") or "Web",
                source_url=item.get("source_url"),
                display_url=item.get("display_url"),
                description=item.get("description"),
                tags=item.get("tags", []),
            )
        )

    return IOCSearchOut(
        query=normalized_search,
        local_items=local_items,
        external_items=external_items,
        local_total=len(local_items),
        external_total=len(external_items),
        total=len(local_items) + len(external_items),
        search_mode=external_search.get("search_mode", "web_search"),
        configuration_hint=external_search.get("configuration_hint"),
    )


@router.post("/iocs", response_model=IOCOut, status_code=201)
async def create_ioc(
    data: IOCCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    ioc = IOC(**data.model_dump())
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc


@router.delete("/iocs/{ioc_id}", status_code=204)
async def delete_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.admin)),
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    db.delete(ioc)
    db.commit()
