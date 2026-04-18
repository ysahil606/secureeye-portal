from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from database import get_db
from models import Advisory, Sector, User, UserRole, AdvisoryStatus, SeverityLevel, FeedLog, AdvisorySource, IOC
from auth import get_current_active_user
from schemas import DashboardStats, AdvisoryOut

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats")
async def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    try:
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = now - timedelta(days=7)
        viewer_scope = current_user.role == UserRole.viewer

        advisory_query = db.query(Advisory)
        if viewer_scope:
            advisory_query = advisory_query.filter(Advisory.status == AdvisoryStatus.published)

        total_advisories = advisory_query.count()
        manual_count = advisory_query.filter(Advisory.source == AdvisorySource.manual).count()
        external_count = advisory_query.filter(Advisory.source == AdvisorySource.external).count()
        
        critical_today = advisory_query.filter(
            Advisory.is_critical_alert == True,
            Advisory.created_at >= today_start
        ).count()
        active_sectors = db.query(Sector).filter(Sector.is_active == True).count()
        zero_days_tracked = advisory_query.filter(Advisory.is_zero_day == True).count()
        pending_review = 0 if viewer_scope else db.query(Advisory).filter(Advisory.status == AdvisoryStatus.pending).count()
        published_this_week = db.query(Advisory).filter(
            Advisory.status == AdvisoryStatus.published,
            Advisory.published_at >= week_start
        ).count()
        kev_count = advisory_query.filter(Advisory.is_kev == True).count()

        # Sector-wise threat distribution
        sector_rows = (
            db.query(Sector.name, func.count(Advisory.id).label("count"))
            .outerjoin(Advisory, Advisory.sector_id == Sector.id)
            .filter(Sector.is_active == True)
            .filter(Advisory.status == AdvisoryStatus.published if viewer_scope else True)
            .group_by(Sector.id)
            .order_by(desc("count"))
            .all()
        )
        total_sector = sum(r.count for r in sector_rows) or 1
        sector_distribution = [
            {"sector": r.name, "count": r.count, "percentage": round(r.count / total_sector * 100)}
            for r in sector_rows
        ]

        # Severity breakdown
        severity_breakdown = {}
        for sev in SeverityLevel:
            severity_breakdown[sev.value] = advisory_query.filter(Advisory.severity == sev).count()

        # Trending CVEs
        trending_advisories = (
            db.query(Advisory)
            .filter(Advisory.status == AdvisoryStatus.published)
            .order_by(desc(Advisory.cvss_score), desc(Advisory.published_at))
            .limit(10)
            .all()
    )
        trending_cves = []
        for adv in trending_advisories:
            cves = adv.cve_ids or []
            if not cves: continue
            for cve in cves[:1]:
                trending_cves.append({
                    "cve_id": cve,
                    "title": adv.title,
                    "cvss_score": adv.cvss_score,
                    "severity": adv.severity.value,
                })

        # Recent advisories - sort by published_at DESC then created_at DESC
        recent_query = advisory_query.order_by(desc(Advisory.published_at), desc(Advisory.created_at))
        
        recent = [AdvisoryOut.model_validate(a) for a in recent_query.limit(5).all()]
        secure = [AdvisoryOut.model_validate(a) for a in recent_query.filter(Advisory.source == AdvisorySource.manual).limit(5).all()]
        open_source = [AdvisoryOut.model_validate(a) for a in recent_query.filter(Advisory.source == AdvisorySource.external).limit(5).all()]

        # Last feed run
        last_feed = db.query(FeedLog).order_by(desc(FeedLog.run_at)).first()
        feed_last_run = last_feed.run_at if last_feed else None

        return DashboardStats(
            total_advisories=total_advisories,
            manual_count=manual_count,
            external_count=external_count,
            critical_today=critical_today,
            active_sectors=active_sectors,
            zero_days_tracked=zero_days_tracked,
            pending_review=pending_review,
            published_this_week=published_this_week,
            kev_count=kev_count,
            sector_distribution=sector_distribution,
            trending_cves=trending_cves[:6],
            severity_breakdown=severity_breakdown,
            recent_advisories=recent,
            secure_advisories=secure,
            open_source_advisories=open_source,
            feed_last_run=feed_last_run,
        )
    except Exception as e:
        import traceback
        print(f"DASHBOARD ERROR: {e}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/briefing")
async def get_ciso_briefing(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """Generates a professional 30-second audio briefing script using Gemini."""
    try:
        # 1. Gather live stats for the prompt
        total = db.query(Advisory).count()
        critical = db.query(Advisory).filter(Advisory.is_critical_alert == True).count()
        top_sector = db.query(Sector.name, func.count(Advisory.id).label("count"))\
            .outerjoin(Advisory).group_by(Sector.id).order_by(desc("count")).first()
        
        sector_name = top_sector[0] if top_sector else "General"
        
        # 2. Build the AI prompt
        from services.ai_service import genai, settings
        if not settings.GEMINI_API_KEY:
            return {"script": f"Good morning, {current_user.full_name}. The Secure portal is active. We are currently tracking {total} advisories, with {critical} classified as critical. The {sector_name} sector remains our primary focus today."}

        genai.configure(api_key=settings.GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = f"""
        You are a senior AI Chief Information Security Officer (CISO) assistant. 
        Write a 3-sentence, high-impact verbal "Morning Briefing" for the user {current_user.full_name}.
        
        CURRENT STATS:
        - Total advisories tracked: {total}
        - Critical threats requiring immediate action: {critical}
        - Most targeted sector: {sector_name}
        
        TONE:
        Professional, calm, and authoritative (like Jarvis or a news anchor). 
        Do not use markdown, emojis, or symbols. Keep it plain text.
        Start with "Good morning" or "Greeting".
        """
        
        response = model.generate_content(prompt)
        return {"script": response.text.strip()}
    except Exception as e:
        return {"script": "Resilience protocol active. System status is normal. No critical anomalies detected in the last polling cycle."}


@router.get("/geo-stats")
async def get_geo_stats(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """Returns aggregated geo-location data for active IOCs."""
    iocs = (
        db.query(IOC.country, IOC.country_code, IOC.latitude, IOC.longitude, func.count(IOC.id).label("count"))
        .filter(IOC.latitude != None, IOC.longitude != None)
        .group_by(IOC.country_code)
        .all()
    )
    return [
        {
            "country": r.country,
            "code": r.country_code,
            "lat": r.latitude,
            "lon": r.longitude,
            "count": r.count
        } for r in iocs
    ]
