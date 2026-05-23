import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, func

from database import SessionLocal
from models import IOC, Advisory
from services.ioc_scorer import score_ioc
import asyncio

logger = logging.getLogger("auto_enricher")

async def auto_enrich_priority_iocs():
    """
    Background job to run every 24 hours.
    Picks ~50 high-priority IOCs (MNCs, major attacks) across all categories (ip, domain, hash, url).
    """
    logger.info("Starting 24h auto-enrichment for priority IOCs...")
    db: Session = SessionLocal()
    try:
        # Define MNC / Major Attack keywords
        priority_keywords = [
            "microsoft", "google", "apple", "amazon", "meta", "bank",
            "apt", "cobalt strike", "ransomware", "emotet", "solarwinds", "cisa"
        ]
        
        # Build keyword filter
        keyword_filters = [
            func.lower(Advisory.title).like(f"%{kw}%") for kw in priority_keywords
        ] + [
            func.lower(Advisory.description).like(f"%{kw}%") for kw in priority_keywords
        ]
        
        # Find critical advisories matching priority
        critical_advisories = db.query(Advisory).filter(
            or_(
                Advisory.is_critical_alert == True,
                Advisory.is_kev == True,
                Advisory.severity == "critical",
                or_(*keyword_filters)
            )
        ).all()
        
        priority_advisory_ids = [adv.id for adv in critical_advisories]
        
        # Get unenriched or outdated IOCs (>24h old enrichment)
        day_ago = datetime.now(timezone.utc) - timedelta(hours=24)
        
        # We need ~12 from each category: ip, domain, hash, url
        categories = ["ip", "domain", "hash", "url"]
        selected_iocs = []
        
        for cat in categories:
            # Query IOCs for this category
            # We want ones that are either never enriched, or enriched > 24h ago
            cat_iocs = db.query(IOC).filter(
                IOC.ioc_type == cat,
                IOC.is_active == True
            ).order_by(desc(IOC.first_seen)).all()
            
            # Filter priority manually due to JSON field complexities
            priority_pool = []
            standard_pool = []
            
            for ioc in cat_iocs:
                # Check if it was enriched recently
                last_enriched = ioc.enrichment_data.get("last_enriched") if ioc.enrichment_data else None
                if last_enriched:
                    try:
                        le_dt = datetime.fromisoformat(last_enriched)
                        if le_dt.tzinfo is None:
                            le_dt = le_dt.replace(tzinfo=timezone.utc)
                        if le_dt > day_ago:
                            continue # Skip recently enriched
                    except Exception:
                        pass
                
                # Check priority
                is_priority = False
                for adv_id in ioc.advisory_ids:
                    if adv_id in priority_advisory_ids:
                        is_priority = True
                        break
                
                if is_priority:
                    priority_pool.append(ioc)
                else:
                    standard_pool.append(ioc)
                    
            # Take up to 12 from this category (priority first, then standard)
            chosen = (priority_pool + standard_pool)[:13]
            selected_iocs.extend(chosen)
            
        # Shuffle or process
        logger.info(f"Selected {len(selected_iocs)} IOCs for daily auto-enrichment.")
        
        for ioc in selected_iocs[:50]:
            try:
                result = await score_ioc(ioc.value, ioc.ioc_type, base_severity="high")
                # Update DB
                ioc.threat_score = result.get("risk_score", 0.0)
                if not ioc.enrichment_data:
                    ioc.enrichment_data = {}
                ioc.enrichment_data["last_enriched"] = datetime.now(timezone.utc).isoformat()
                ioc.enrichment_data["risk_label"] = result.get("risk_label")
                ioc.enrichment_data["auto_enriched"] = True
                ioc.enrichment_data["score_details"] = result.get("source_details")
                # Sleep to prevent hitting rate limits on free APIs
                await asyncio.sleep(2.0)
            except Exception as e:
                logger.error(f"Failed to auto-enrich {ioc.value}: {e}")
                
        db.commit()
        logger.info("24h auto-enrichment cycle completed.")
        
    except Exception as e:
        logger.error(f"Auto-enrichment error: {e}")
    finally:
        db.close()
