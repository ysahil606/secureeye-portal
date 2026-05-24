from typing import List, Optional
import re
import os
import platform
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc

from database import get_db
from models import User, Sector, IOC, FeedLog, UserRole, RolePermission
from auth import get_current_active_user, require_role, hash_password
from schemas import (
    UserCreate, UserUpdate, UserOut,
    SectorCreate, SectorOut,
    IOCCreate, IOCOut, IOCSearchOut, IOCExternalResultOut,
    RolePermissionOut, RolePermissionUpdate, RolePermissionCreate
)
from services import threat_feeds
from services.ioc_scorer import score_ioc

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
    if "." in text and " " not in text:
        return "domain"
    return None


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


@router.get("/iocs/lookup/{ioc_value:path}")
async def lookup_ioc_live(
    ioc_value: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    On-the-fly manual enrichment for any IOC.
    If save=true, could be saved, but right now we just return the enrichment.
    """
    ioc_type = infer_ioc_type(ioc_value)
    if not ioc_type:
        return {"error": "Invalid IOC format. Must be IP, Domain, URL, or Hash.", "value": ioc_value}
        
    result = await score_ioc(ioc_value, ioc_type, base_severity="medium")
    return {"status": "success", "data": result}


@router.get("/feeds/logs")
async def get_feed_logs(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    logs = db.query(FeedLog).order_by(desc(FeedLog.run_at)).limit(limit).all()
    return logs


# ── IOC Management ─────────────────────────────────────────────────────────────
@router.get("/iocs/stats")
async def get_ioc_stats(db: Session = Depends(get_db), current_user=Depends(get_current_active_user)):
    total = db.query(IOC).count()
    ips = db.query(IOC).filter(IOC.ioc_type == "ip").count()
    urls = db.query(IOC).filter(IOC.ioc_type == "url").count()
    hashes = db.query(IOC).filter(IOC.ioc_type == "hash").count()
    domains = db.query(IOC).filter(IOC.ioc_type == "domain").count()
    return {
        "tracked": total,
        "ips": ips,
        "urls": urls,
        "hashes": hashes,
        "domains": domains,
        "raw_osint": "10.5M+"  # OSINT feed estimate across URLHaus, MalwareBazaar, ThreatFox, etc.
    }

@router.get("/iocs", response_model=List[IOCOut])
async def list_iocs(
    ioc_type: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 500,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    q = db.query(IOC)
    if ioc_type:
        q = q.filter(IOC.ioc_type == ioc_type)
    if search:
        q = q.filter(IOC.value.ilike(f"%{search}%"))
    items = q.order_by(desc(IOC.first_seen)).offset(skip).limit(limit).all()
    return items

@router.get("/iocs/auto-enriched")
async def get_auto_enriched_iocs(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user)
):
    """Fetch the latest 50 auto-enriched IOCs, sorted by threat score"""
    # SQLite JSON filtering can be tricky, so we'll fetch recently enriched ones 
    # and filter in memory, or we can just fetch those with threat_score > 0 and limit
    items = db.query(IOC).filter(IOC.threat_score != None).order_by(desc(IOC.threat_score)).limit(100).all()
    # Filter only auto enriched
    auto = [i for i in items if i.enrichment_data and i.enrichment_data.get("auto_enriched")]
    return {"status": "success", "data": auto[:50]}



@router.get("/iocs/live-search", response_model=IOCSearchOut)
async def live_ioc_search(
    search: str,
    ioc_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    normalized_search = search.strip()
    inferred_type = ioc_type or infer_ioc_type(normalized_search)

    from sqlalchemy import or_

    local_query = db.query(IOC)
    if inferred_type:
        local_query = local_query.filter(IOC.ioc_type == inferred_type)

    local_query = local_query.filter(
        or_(
            IOC.value.ilike(f"%{normalized_search}%"),
            IOC.country.ilike(f"%{normalized_search}%"),
            IOC.source.ilike(f"%{normalized_search}%")
        )
    )
    local_items = local_query.order_by(desc(IOC.first_seen)).limit(100).all()

    # Demo Simulation: If country click from heatmap with no real data
    if not local_items and not inferred_type and len(normalized_search) > 3:
        import random
        from datetime import datetime
        simulated_ips = [f"{random.randint(11,250)}.{random.randint(1,250)}.{random.randint(1,250)}.{random.randint(1,250)}" for _ in range(5)]
        local_items = [
            IOC(
                id=9000+i,
                value=ip,
                ioc_type="ip",
                source="Simulated Heatmap Intel",
                country=normalized_search.title(),
                first_seen=datetime.utcnow()
            ) for i, ip in enumerate(simulated_ips)
        ]

    # ── DEDICATED IOC ENRICHMENT (production-grade free sources) ──
    external_items = []
    if inferred_type in ("ip", "domain", "hash", "url"):
        try:
            from services.ioc_lookup import enrich_ioc
            enriched = await enrich_ioc(normalized_search, inferred_type)
            for result in enriched:
                if result:
                    badge = result.get("badge", "")
                    confidence = result.get("confidence")
                    conf_str = f" | Confidence: {confidence}%" if confidence else ""
                    raw_desc = result.get("description", "")
                    if badge:
                        raw_desc = f"{badge}{conf_str} | {raw_desc}"
                    external_items.append(
                        IOCExternalResultOut(
                            value=result.get("value", normalized_search),
                            ioc_type=result.get("ioc_type", inferred_type),
                            source_name=result.get("source_name", "Threat Intel"),
                            source_url=result.get("source_url"),
                            display_url=result.get("display_url"),
                            description=raw_desc,
                            tags=result.get("tags", []),
                        )
                    )
        except Exception as e:
            import logging
            logging.getLogger("admin").warning(f"IOC enrichment failed: {e}")

    # ── FALLBACK: general web search for non-IOC queries ──
    if not external_items:
        try:
            external_search = await threat_feeds.search_live_sources(normalized_search, limit_per_source=6)
            for item in external_search.get("items", []):
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
        except Exception as e:
            import logging
            logging.getLogger("admin").warning(f"Fallback web search failed: {e}")

    return IOCSearchOut(
        query=normalized_search,
        local_items=local_items,
        external_items=external_items,
        local_total=len(local_items),
        external_total=len(external_items),
        total=len(local_items) + len(external_items),
        search_mode="ioc_enrichment" if inferred_type in ("ip", "domain", "hash", "url") else "web_search",
        configuration_hint=None,
    )



# ── Raw Live IOC Feed ─────────────────────────────────────────────────────────
@router.get("/iocs/raw-feed")
async def get_raw_ioc_feed(
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 200,
    current_user=Depends(get_current_active_user),
):
    """
    Real-time raw IOC feed from multiple external threat intelligence sources.
    Sources: URLHaus, FeodoTracker, MalwareBazaar, ThreatFox, SSL Blacklist.
    Supports filtering by ioc_type, severity, and source.
    """
    from services.raw_ioc_feed import fetch_all_raw_iocs
    result = await fetch_all_raw_iocs(
        limit_per_source=min(limit, 500),
        ioc_type_filter=ioc_type or None,
        severity_filter=severity or None,
        source_filter=source or None,
    )
    return result




# ── Enriched IOC Feed (with risk scores) ─────────────────────────────────────
@router.get("/iocs/enriched-feed")
async def get_enriched_ioc_feed(
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    cached_only: bool = False,
    current_user=Depends(get_current_active_user),
):
    """
    Fetches raw IOCs and enriches them with composite risk scores.
    Rate limited to 200 IOCs per category per hour using free/unlimited sources:
      IPs:     Shodan InternetDB + AbuseIPDB + GreyNoise + ip-api.com + URLHaus + ThreatFox
      Hashes:  MalwareBazaar + ThreatFox + URLHaus + OTX
      URLs:    URLHaus + ThreatFox
      Domains: URLHaus + ThreatFox + OTX
    """
    from services.raw_ioc_feed import fetch_all_raw_iocs
    from services.ioc_scorer import enrich_batch

    # Fetch raw IOCs
    raw = await fetch_all_raw_iocs(
        limit_per_source=min(limit * 2, 400),
        ioc_type_filter=ioc_type or None,
        severity_filter=severity or None,
    )
    iocs = raw.get("iocs", [])

    # Prioritize: critical first, then high — deduplicate by value
    seen = set()
    unique_iocs = []
    for ioc in iocs:
        key = (ioc["value"], ioc["ioc_type"])
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)

    # Trim to requested limit per type (max 200/type enforced inside enrich_batch)
    result = await enrich_batch(unique_iocs[:limit * 4], max_per_type=200, cached_only=cached_only)
    return result


@router.get("/iocs/enrichment-rate-status")
async def get_enrichment_rate_status(
    current_user=Depends(get_current_active_user),
):
    """Returns enrichment rate limit + API budget usage + cache stats."""
    from services.ioc_scorer import get_rate_status, get_budget_status, get_cache_stats
    return {
        "rate_limits":  get_rate_status(),
        "api_budgets":  get_budget_status(),
        "cache":        get_cache_stats(),
    }


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


# ── Role Permissions ──────────────────────────────────────────────────────────
@router.get("/permissions", response_model=List[RolePermissionOut])
async def get_all_permissions(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.admin)),
):
    return db.query(RolePermission).all()


@router.put("/permissions", response_model=dict)
async def update_permissions(
    data: RolePermissionUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.admin)),
):
    # Truncate and replace or update
    db.query(RolePermission).delete()
    for perm in data.permissions:
        new_perm = RolePermission(
            role=perm.role,
            feature=perm.feature,
            is_allowed=perm.is_allowed
        )
        db.add(new_perm)
    db.commit()
    return {"status": "ok"}


# ── System Telemetry ──────────────────────────────────────────────────────────
@router.get("/system/metrics")
async def get_system_metrics(current_user=Depends(require_role(UserRole.admin))):
    import os
    import platform
    metrics = {
        "cpu_load": 0.0,
        "ram_usage_percent": 0.0,
        "ram_total_gb": 0.0,
        "ram_used_gb": 0.0,
        "os": platform.system()
    }
    
    # Fast native reads for Linux (our VPS)
    if platform.system() == "Linux":
        try:
            # CPU Load (1-minute average)
            with open("/proc/loadavg", "r") as f:
                load_str = f.read().split()[0]
                # Normalize load by CPU count
                cpu_count = os.cpu_count() or 1
                load_pct = (float(load_str) / cpu_count) * 100
                metrics["cpu_load"] = min(round(load_pct, 1), 100.0)
                
            # RAM Usage
            with open("/proc/meminfo", "r") as f:
                meminfo = f.readlines()
                mem_total = 0
                mem_available = 0
                for line in meminfo:
                    if line.startswith("MemTotal:"):
                        mem_total = int(line.split()[1])
                    elif line.startswith("MemAvailable:"):
                        mem_available = int(line.split()[1])
                
                if mem_total > 0:
                    used = mem_total - mem_available
                    metrics["ram_usage_percent"] = round((used / mem_total) * 100, 1)
                    metrics["ram_total_gb"] = round(mem_total / 1024 / 1024, 2)
                    metrics["ram_used_gb"] = round(used / 1024 / 1024, 2)
        except Exception:
            pass
            
    return metrics
