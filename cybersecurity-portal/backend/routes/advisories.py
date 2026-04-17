from datetime import datetime, timedelta
from typing import Optional, List
import re

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func, desc, String

from database import get_db
from models import Advisory, AdvisoryStatus, AdvisorySource, SeverityLevel, User, UserRole
from auth import get_current_active_user, require_role
from schemas import (
    AdvisoryCreate,
    AdvisoryUpdate,
    AdvisoryOut,
    AdvisoryListOut,
    ExternalSearchResultOut,
    SmartSearchOut,
)
from services.alert_service import trigger_critical_alerts
from services import threat_feeds
from config import settings

router = APIRouter(prefix="/advisories", tags=["Advisories"])


def _apply_viewer_scope(query, current_user: User):
    if current_user.role == UserRole.viewer:
        query = query.filter(Advisory.status == AdvisoryStatus.published)
    return query


def _check_critical(advisory: Advisory):
    """Auto-flag critical based on CVSS score or KEV status."""
    if (advisory.cvss_score and advisory.cvss_score >= settings.CRITICAL_CVSS_THRESHOLD) or advisory.is_kev:
        advisory.is_critical_alert = True
    else:
        advisory.is_critical_alert = False


def extract_iocs(text: str):
    """
    Extract common IOC patterns from text.
    Returns a dict with IPs, domains, URLs, hashes, and CVEs.
    """
    text = text or ""
    return {
        "ips": re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text),
        "domains": re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text),
        "urls": re.findall(r"https?://[^\s]+", text),
        "hashes": re.findall(r"\b[a-fA-F0-9]{32,64}\b", text),
        "cves": re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE),
    }


@router.get("", response_model=AdvisoryListOut)
async def list_advisories(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    sector_id: Optional[int] = None,
    source: Optional[str] = None,
    is_kev: Optional[bool] = None,
    is_zero_day: Optional[bool] = None,
    is_critical: Optional[bool] = None,
    mitre_ttp: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    q = _apply_viewer_scope(db.query(Advisory), current_user)

    if status:
        q = q.filter(Advisory.status == status)
    if severity:
        q = q.filter(Advisory.severity == severity)
    if sector_id:
        q = q.filter(Advisory.sector_id == sector_id)
    if source:
        q = q.filter(Advisory.source == source)
    if is_kev is not None:
        q = q.filter(Advisory.is_kev == is_kev)
    if is_zero_day is not None:
        q = q.filter(Advisory.is_zero_day == is_zero_day)
    if is_critical is not None:
        q = q.filter(Advisory.is_critical_alert == is_critical)
    if mitre_ttp:
        q = q.filter(func.cast(Advisory.mitre_ttps, String).ilike(f"%{mitre_ttp}%"))
    if search:
        term = f"%{search}%"
        q = q.filter(or_(
            Advisory.title.ilike(term),
            Advisory.description.ilike(term),
            Advisory.mitigation.ilike(term),
        ))

    total = q.count()
    items = q.order_by(desc(Advisory.created_at)).offset((page - 1) * per_page).limit(per_page).all()

    return AdvisoryListOut(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=(total + per_page - 1) // per_page,
    )


@router.get("/search", response_model=SmartSearchOut)
async def smart_search(
    q: str = Query(..., min_length=1),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Smart search across:
    - title / description / mitigation / ai_summary
    - CVE IDs
    - IOC list
    - affected vendors
    - attack types
    - APT groups
    - MITRE ATT&CK TTPs

    Also auto-detects IOCs from matching result text and merges them into the
    returned iocs field.
    """
    term = f"%{q}%"

    query = _apply_viewer_scope(db.query(Advisory), current_user).filter(
        or_(
            Advisory.title.ilike(term),
            Advisory.description.ilike(term),
            Advisory.mitigation.ilike(term),
            Advisory.ai_summary.ilike(term),

            func.cast(Advisory.cve_ids, String).ilike(term),
            func.cast(Advisory.iocs, String).ilike(term),
            func.cast(Advisory.affected_vendors, String).ilike(term),
            func.cast(Advisory.attack_types, String).ilike(term),
            func.cast(Advisory.apt_groups, String).ilike(term),
            func.cast(Advisory.mitre_ttps, String).ilike(term),
        )
    )

    local_total = query.count()
    raw_items = query.order_by(desc(Advisory.created_at)).offset((page - 1) * per_page).limit(per_page).all()

    items = []
    for adv in raw_items:
        adv_out = AdvisoryOut.model_validate(adv)

        text_blob = " ".join([
            adv.title or "",
            adv.description or "",
            adv.mitigation or "",
            adv.ai_summary or "",
            " ".join(adv.cve_ids or []) if isinstance(adv.cve_ids, list) else "",
            " ".join(adv.affected_vendors or []) if isinstance(adv.affected_vendors, list) else "",
            " ".join(adv.attack_types or []) if isinstance(adv.attack_types, list) else "",
            " ".join(adv.apt_groups or []) if isinstance(adv.apt_groups, list) else "",
            " ".join(adv.mitre_ttps or []) if isinstance(adv.mitre_ttps, list) else "",
        ])

        extracted = extract_iocs(text_blob)

        merged_iocs = list(adv_out.iocs or [])
        for category, values in extracted.items():
            for value in values:
                ioc_item = {
                    "type": category[:-1] if category.endswith("s") else category,
                    "value": value,
                    "detected": True,
                }
                if ioc_item not in merged_iocs:
                    merged_iocs.append(ioc_item)

        adv_out.iocs = merged_iocs
        items.append(adv_out)

    external_search = await threat_feeds.search_live_sources(q, limit_per_source=4)
    external_items = external_search["items"]
    configuration_hint = external_search.get("configuration_hint")
    if (
        settings.WEB_SEARCH_PROVIDER.strip().lower() == "google"
        and (not settings.GOOGLE_SEARCH_API_KEY or not settings.GOOGLE_SEARCH_ENGINE_ID)
    ):
        configuration_hint = "Add GOOGLE_SEARCH_API_KEY and GOOGLE_SEARCH_ENGINE_ID in backend/.env to enable Google-style web search."

    return SmartSearchOut(
        query=q,
        local_items=items,
        external_items=[ExternalSearchResultOut(**item) for item in external_items],
        external_provider=external_search["provider"],
        search_mode=external_search["search_mode"],
        configuration_hint=configuration_hint,
        local_total=local_total,
        external_total=len(external_items),
        total=local_total + len(external_items),
    )


@router.get("/timeline")
async def get_timeline(
    source: Optional[AdvisorySource] = None,
    sector_id: Optional[int] = None,
    is_critical: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Threat timeline endpoint — returns advisories grouped by date."""
    query = db.query(Advisory).filter(Advisory.status == AdvisoryStatus.published)
    
    if source:
        query = query.filter(Advisory.source == source)
    if sector_id:
        query = query.filter(Advisory.sector_id == sector_id)
    if is_critical is not None:
        query = query.filter(Advisory.is_critical_alert == is_critical)
        
    advisories = (
        query
        .order_by(desc(Advisory.published_at), desc(Advisory.created_at))
        .limit(50)
        .all()
    )
    from schemas import AdvisoryOut # ensure available
    return {"items": [AdvisoryOut.model_validate(a) for a in advisories]}


@router.get("/{advisory_id}", response_model=AdvisoryOut)
async def get_advisory(
    advisory_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    advisory = _apply_viewer_scope(
        db.query(Advisory).filter(Advisory.id == advisory_id),
        current_user,
    ).first()
    if not advisory:
        raise HTTPException(status_code=404, detail="Advisory not found")
    return advisory


@router.post("", response_model=AdvisoryOut, status_code=201)
async def create_advisory(
    data: AdvisoryCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    advisory = Advisory(
        **data.model_dump(),
        source=AdvisorySource.manual,
        status=AdvisoryStatus.pending,
        author_id=current_user.id,
    )
    _check_critical(advisory)
    db.add(advisory)
    db.commit()
    db.refresh(advisory)
    return advisory


@router.put("/{advisory_id}", response_model=AdvisoryOut)
async def update_advisory(
    advisory_id: int,
    data: AdvisoryUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    advisory = db.query(Advisory).filter(Advisory.id == advisory_id).first()
    if not advisory:
        raise HTTPException(status_code=404, detail="Advisory not found")

    for k, v in data.model_dump(exclude_none=True).items():
        setattr(advisory, k, v)

    _check_critical(advisory)
    db.commit()
    db.refresh(advisory)
    return advisory


@router.post("/{advisory_id}/publish", response_model=AdvisoryOut)
async def publish_advisory(
    advisory_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    advisory = db.query(Advisory).filter(Advisory.id == advisory_id).first()
    if not advisory:
        raise HTTPException(status_code=404, detail="Advisory not found")

    advisory.status = AdvisoryStatus.published
    advisory.published_at = datetime.utcnow()

    _check_critical(advisory)
    db.commit()
    db.refresh(advisory)

    if advisory.is_critical_alert:
        background_tasks.add_task(trigger_critical_alerts, advisory, db)

    return advisory


@router.post("/{advisory_id}/reject", response_model=AdvisoryOut)
async def reject_advisory(
    advisory_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    advisory = db.query(Advisory).filter(Advisory.id == advisory_id).first()
    if not advisory:
        raise HTTPException(status_code=404, detail="Advisory not found")

    advisory.status = AdvisoryStatus.rejected
    db.commit()
    db.refresh(advisory)
    return advisory


@router.delete("/{advisory_id}", status_code=204)
async def delete_advisory(
    advisory_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    advisory = db.query(Advisory).filter(Advisory.id == advisory_id).first()
    if not advisory:
        raise HTTPException(status_code=404, detail="Advisory not found")

    db.delete(advisory)
    db.commit()
