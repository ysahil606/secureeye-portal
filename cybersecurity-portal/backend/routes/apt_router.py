from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from database import get_db
from models import APTGroup, Advisory, AdvisoryStatus
from auth import get_current_active_user

router = APIRouter(prefix="/apt", tags=["APT Encyclopedia"])

@router.get("/groups")
async def list_apt_groups(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """List all tracked threat actors."""
    return db.query(APTGroup).all()

@router.get("/groups/{group_id}")
async def get_apt_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get detailed profile of a threat actor and related advisories."""
    group = db.query(APTGroup).filter(APTGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Simple keyword match for related advisories
    related = db.query(Advisory).filter(
        Advisory.status == AdvisoryStatus.published,
        Advisory.description.ilike(f"%{group.name}%")
    ).limit(10).all()

    return {
        "group": group,
        "related_advisories": related
    }

@router.get("/mitre/heatmap")
async def get_mitre_heatmap(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Aggregates TTPs across all published advisories for heatmap."""
    advisories = db.query(Advisory).filter(Advisory.status == AdvisoryStatus.published).all()
    
    stats = {}
    for adv in advisories:
        for ttp in (adv.mitre_ttps or []):
            stats[ttp] = stats.get(ttp, 0) + 1
    
    return stats
