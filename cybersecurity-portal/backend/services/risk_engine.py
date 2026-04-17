import logging
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
from models import Advisory, AdvisoryStatus, IOC, Sector

logger = logging.getLogger("risk_engine")

def calculate_all_sector_risk(db: Session):
    """Update risk scores for all active sectors."""
    sectors = db.query(Sector).filter(Sector.is_active == True).all()
    week_ago = datetime.utcnow() - timedelta(days=7)

    for sector in sectors:
        # 1. Base Score from Critical/High advisories (last 7 days)
        critical_count = db.query(Advisory).filter(
            Advisory.sector_id == sector.id,
            Advisory.status == AdvisoryStatus.published,
            Advisory.severity == 'critical',
            Advisory.published_at >= week_ago
        ).count()

        high_count = db.query(Advisory).filter(
            Advisory.sector_id == sector.id,
            Advisory.status == AdvisoryStatus.published,
            Advisory.severity == 'high',
            Advisory.published_at >= week_ago
        ).count()

        # 2. Zero-Day Bonus
        zeroday_count = db.query(Advisory).filter(
            Advisory.sector_id == sector.id,
            Advisory.status == AdvisoryStatus.published,
            Advisory.is_zero_day == True,
            Advisory.published_at >= week_ago
        ).count()

        # 3. Calculation
        # Score = (Critical * 25) + (High * 15) + (ZeroDay * 40)
        # Maxed at 100
        raw_score = (critical_count * 25) + (high_count * 15) + (zeroday_count * 40)
        
        # Add a baseline if any older active threats exist
        if raw_score < 10:
            total_active = db.query(Advisory).filter(Advisory.sector_id == sector.id, Advisory.status == AdvisoryStatus.published).count()
            raw_score += min(total_active * 0.5, 10)

        sector.risk_score = min(float(raw_score), 100.0)
    
    db.commit()
    logger.info("Sector risk scores recalculated.")
