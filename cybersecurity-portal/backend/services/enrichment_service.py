import logging
import httpx
from sqlalchemy.orm import Session
from models import IOC
from config import settings

logger = logging.getLogger("enrichment")

async def enrich_ioc(ioc: IOC, db: Session):
    """
    Fetch professional-grade OSINT intelligence for an IOC.
    1. IP Reputation & Confidence: AbuseIPDB
    2. Domain/Hash/IP Context: AlienVault OTX
    3. Geo-location: IP-API
    """
    if not ioc.value:
        return

    if ioc.enrichment_data is None:
        ioc.enrichment_data = {}

    async with httpx.AsyncClient(timeout=15) as client:
        
        # --- 1. IP SPECIFIC ENRICHMENT ---
        if ioc.ioc_type == "ip":
            # A. Geo-location
            try:
                r = await client.get(f"http://ip-api.com/json/{ioc.value}")
                if r.status_code == 200:
                    data = r.json()
                    if data.get("status") == "success":
                        ioc.country = data.get("country")
                        ioc.country_code = data.get("countryCode")
                        ioc.latitude = data.get("lat")
                        ioc.longitude = data.get("lon")
                        ioc.enrichment_data["isp"] = data.get("isp")
            except Exception as e:
                logger.error(f"Geo-enrichment failed for {ioc.value}: {e}")

            # B. AbuseIPDB Reputation (1,000/day limit)
            if settings.ABUSEIPDB_API_KEY:
                try:
                    headers = {
                        "Key": settings.ABUSEIPDB_API_KEY,
                        "Accept": "application/json"
                    }
                    params = {"ipAddress": ioc.value, "maxAgeInDays": "90"}
                    ar = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                    if ar.status_code == 200:
                        abuse_data = ar.json().get("data", {})
                        ioc.threat_score = float(abuse_data.get("abuseConfidenceScore", 0))
                        ioc.enrichment_data["abuse_score"] = abuse_data.get("abuseConfidenceScore")
                        ioc.enrichment_data["usage_type"] = abuse_data.get("usageType")
                        ioc.enrichment_data["total_reports"] = abuse_data.get("totalReports")
                        ioc.enrichment_data["last_reported"] = abuse_data.get("lastReportedAt")
                except Exception as e:
                    logger.error(f"AbuseIPDB enrichment failed for {ioc.value}: {e}")

        # --- 2. MULTI-IOC ENRICHMENT (AlienVault OTX) ---
        if settings.ALIENVAULT_OTX_API_KEY:
            try:
                otx_headers = {"X-OTX-API-KEY": settings.ALIENVAULT_OTX_API_KEY}
                # Determine OTX section based on type
                otx_section = "IPv4" if ioc.ioc_type == "ip" else "domain" if ioc.ioc_type == "domain" else "file"
                otx_url = f"https://otx.alienvault.com/api/v1/indicators/{otx_section}/{ioc.value}/general"
                
                or_res = await client.get(otx_url, headers=otx_headers)
                if or_res.status_code == 200:
                    otx_data = or_res.json()
                    ioc.enrichment_data["otx_pulse_count"] = otx_data.get("pulse_info", {}).get("count", 0)
                    ioc.enrichment_data["otx_tags"] = [t for t in otx_data.get("tags", [])[:5]]
                    
                    # If we don't have a score yet (non-IP or AbuseIPDB failed), estimate from OTX
                    if ioc.threat_score == 0:
                        pulse_count = otx_data.get("pulse_info", {}).get("count", 0)
                        ioc.threat_score = min(pulse_count * 10, 95)
            except Exception as e:
                logger.error(f"AlienVault OTX enrichment failed for {ioc.value}: {e}")

    ioc.enrichment_data["last_enriched"] = datetime.utcnow().isoformat()
    db.commit()
