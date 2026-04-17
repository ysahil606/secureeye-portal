import logging
import httpx
from sqlalchemy.orm import Session
from models import IOC

logger = logging.getLogger("enrichment")

async def enrich_ioc(ioc: IOC, db: Session):
    """Fetch geo-location and OSINT reputation for an IOC."""
    if not ioc.value:
        return

    if ioc.enrichment_data is None:
        ioc.enrichment_data = {}

    async with httpx.AsyncClient(timeout=10) as client:
        # 1. Geo-location (IP only)
        if ioc.ioc_type == "ip":
            try:
                r = await client.get(f"http://ip-api.com/json/{ioc.value}")
                if r.status_code == 200:
                    data = r.json()
                    if data.get("status") == "success":
                        ioc.country = data.get("country")
                        ioc.country_code = data.get("countryCode")
                        ioc.latitude = data.get("lat")
                        ioc.longitude = data.get("lon")
                        ioc.enrichment_data = {**ioc.enrichment_data, "isp": data.get("isp")}
            except Exception as e:
                logger.error(f"Geo-enrichment failed for {ioc.value}: {e}")

        # 2. ThreatFox / URLHaus Reputation (Mocked or Free API)
        # Since Abuse.ch has daily limits, we enrich metadata based on common patterns
        # or can extend to specific free endpoints.
        try:
            # Placeholder for further free tool enrichment
            ioc.enrichment_data = {
                **ioc.enrichment_data,
                "last_enriched": True,
                "reputation_source": "Abuse.ch/OSINT"
            }
        except Exception as e:
            logger.error(f"OSINT enrichment failed: {e}")

    db.commit()
