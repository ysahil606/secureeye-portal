from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_
from typing import Optional, List
from pydantic import BaseModel

from database import get_db
from auth import get_current_active_user
from models import HuntHypothesis, MitreCache
from services.threat_hunter import generate_threat_hunting_hypotheses
from services.mitre_service import sync_mitre_attack_db

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])


class GenerateRequest(BaseModel):
    sector: str = "All Sectors"
    count: int = 5


class UpdateStatusRequest(BaseModel):
    status: str
    analyst_notes: Optional[str] = None


@router.get("/stats")
async def get_threat_hunting_stats(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Return dashboard summary metrics for Threat Hunting."""
    total = db.query(HuntHypothesis).count()
    open_cnt = db.query(HuntHypothesis).filter(HuntHypothesis.status == "open").count()
    in_progress_cnt = db.query(HuntHypothesis).filter(HuntHypothesis.status == "in_progress").count()
    confirmed_cnt = db.query(HuntHypothesis).filter(HuntHypothesis.status == "confirmed").count()
    fp_cnt = db.query(HuntHypothesis).filter(HuntHypothesis.status == "false_positive").count()
    
    # Calculate conversion / true positive rate
    completed_total = confirmed_cnt + fp_cnt
    true_positive_rate = round((confirmed_cnt / completed_total * 100), 1) if completed_total > 0 else 0.0

    # Group by severity
    severity_counts = dict(
        db.query(HuntHypothesis.severity, func.count(HuntHypothesis.id))
        .group_by(HuntHypothesis.severity).all()
    )

    # Group by MITRE tactic
    tactic_counts = dict(
        db.query(HuntHypothesis.mitre_tactic, func.count(HuntHypothesis.id))
        .group_by(HuntHypothesis.mitre_tactic).order_by(desc(func.count(HuntHypothesis.id))).limit(6).all()
    )

    # Group by Sector
    sector_counts = dict(
        db.query(HuntHypothesis.target_sector, func.count(HuntHypothesis.id))
        .group_by(HuntHypothesis.target_sector).all()
    )

    # Total cached MITRE techniques
    mitre_count = db.query(MitreCache).count()

    return {
        "total_hypotheses": total,
        "open_count": open_cnt,
        "in_progress_count": in_progress_cnt,
        "confirmed_count": confirmed_cnt,
        "false_positive_count": fp_cnt,
        "true_positive_rate_percent": true_positive_rate,
        "severity_distribution": severity_counts,
        "top_tactics": tactic_counts,
        "sector_distribution": sector_counts,
        "cached_mitre_techniques": mitre_count
    }


@router.get("/hypotheses")
async def list_hypotheses(
    status: Optional[str] = Query(None, description="Filter by status: open, in_progress, confirmed, false_positive, archived"),
    sector: Optional[str] = Query(None, description="Filter by target sector"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    tactic: Optional[str] = Query(None, description="Filter by MITRE tactic"),
    search: Optional[str] = Query(None, description="Search term across title, hypothesis, or technique ID"),
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """List threat hunting hypotheses with rich filtering and pagination."""
    query = db.query(HuntHypothesis)

    if status:
        query = query.filter(HuntHypothesis.status == status)
    if sector and sector != "All Sectors":
        query = query.filter(HuntHypothesis.target_sector == sector)
    if severity:
        query = query.filter(HuntHypothesis.severity == severity.lower())
    if tactic:
        query = query.filter(HuntHypothesis.mitre_tactic.ilike(f"%{tactic}%"))
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                HuntHypothesis.title.ilike(search_term),
                HuntHypothesis.hypothesis.ilike(search_term),
                HuntHypothesis.mitre_technique_id.ilike(search_term),
                HuntHypothesis.mitre_name.ilike(search_term)
            )
        )

    total_count = query.count()
    items = query.order_by(desc(HuntHypothesis.created_at)).offset(skip).limit(limit).all()

    return {
        "total": total_count,
        "skip": skip,
        "limit": limit,
        "hypotheses": items
    }


@router.get("/hypotheses/{hypothesis_id}")
async def get_hypothesis(
    hypothesis_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get single hypothesis detail by ID."""
    hypo = db.query(HuntHypothesis).filter(HuntHypothesis.id == hypothesis_id).first()
    if not hypo:
        raise HTTPException(status_code=404, detail="Hypothesis not found.")
    return hypo


@router.post("/generate")
async def trigger_generate_hypotheses(
    body: GenerateRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Manually trigger AI threat hunting hypothesis generation."""
    try:
        res = await generate_threat_hunting_hypotheses(db=db, sector=body.sector, count=body.count)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hypothesis generation failed: {str(e)}")


@router.patch("/hypotheses/{hypothesis_id}/status")
async def update_hypothesis_status(
    hypothesis_id: int,
    body: UpdateStatusRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Update hunt status (open -> in_progress -> confirmed/false_positive) and analyst notes."""
    valid_statuses = ["open", "in_progress", "confirmed", "false_positive", "archived"]
    if body.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    hypo = db.query(HuntHypothesis).filter(HuntHypothesis.id == hypothesis_id).first()
    if not hypo:
        raise HTTPException(status_code=404, detail="Hypothesis not found.")

    hypo.status = body.status
    if body.analyst_notes is not None:
        hypo.analyst_notes = body.analyst_notes

    try:
        db.commit()
        db.refresh(hypo)
        return hypo
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update status: {str(e)}")


@router.delete("/hypotheses/{hypothesis_id}")
async def delete_hypothesis(
    hypothesis_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Delete a threat hunting hypothesis."""
    hypo = db.query(HuntHypothesis).filter(HuntHypothesis.id == hypothesis_id).first()
    if not hypo:
        raise HTTPException(status_code=404, detail="Hypothesis not found.")

    db.delete(hypo)
    try:
        db.commit()
        return {"status": "success", "message": f"Hypothesis {hypothesis_id} deleted."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete: {str(e)}")


@router.post("/mitre/sync")
async def trigger_mitre_sync(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Trigger manual sync of MITRE ATT&CK techniques database."""
    try:
        result = await sync_mitre_attack_db(db)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MITRE sync failed: {str(e)}")


@router.get("/mitre/techniques")
async def list_mitre_techniques(
    search: Optional[str] = Query(None),
    tactic: Optional[str] = Query(None),
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """List cached MITRE ATT&CK techniques."""
    query = db.query(MitreCache)
    if tactic:
        query = query.filter(MitreCache.tactic.ilike(f"%{tactic}%"))
    if search:
        query = query.filter(
            or_(
                MitreCache.technique_id.ilike(f"%{search}%"),
                MitreCache.name.ilike(f"%{search}%")
            )
        )
    return query.limit(limit).all()


@router.get("/hypotheses/{hypothesis_id}/export-sigma", response_class=PlainTextResponse)
async def export_sigma_rule(
    hypothesis_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Export hypothesis Sigma rule as a downloadable YAML file."""
    hypo = db.query(HuntHypothesis).filter(HuntHypothesis.id == hypothesis_id).first()
    if not hypo:
        raise HTTPException(status_code=404, detail="Hypothesis not found.")

    rule_content = hypo.sigma_rule or f"# No Sigma rule generated for hypothesis {hypothesis_id}"
    filename = f"sigma_{hypo.mitre_technique_id or 'rule'}_{hypothesis_id}.yml"

    return PlainTextResponse(
        content=rule_content,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
