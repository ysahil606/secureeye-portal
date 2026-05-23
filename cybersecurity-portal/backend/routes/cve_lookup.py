import httpx
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, List
import logging
from datetime import datetime, timezone
from services.ai_service import get_ai_summary

logger = logging.getLogger("cve_lookup")
router = APIRouter()

MNC_LIST = ["Microsoft", "Apple", "Google", "Cisco", "Fortinet", "Palo Alto", "VMware", "Oracle", "Adobe", "Atlassian", "Ivanti", "Trend Micro"]

from services.zeroday_aggregator import get_unified_zerodays

@router.get("/actively-exploited")
async def get_actively_exploited(limit: int = 50):
    """
    Fetches the unified zero-day feed from CISA KEV, Project Zero, and Exploit-DB.
    """
    try:
        return await get_unified_zerodays(limit=limit)
    except Exception as e:
        logger.error(f"Error fetching unified actively exploited vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch actively exploited vulnerabilities")

from database import get_db
from sqlalchemy.orm import Session
from models import Advisory
from sqlalchemy import cast, String, or_

@router.get("/lookup/{cve_id}")
async def lookup_cve(cve_id: str, db: Session = Depends(get_db)):
    """
    Fetches CVE details from local DB first, then MITRE or NVD.
    """
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format. Must start with CVE-")
        
    try:
        # Check local DB first for tracked or simulated zero-days
        local_advisory = db.query(Advisory).filter(
            or_(
                Advisory.title.ilike(f"%{cve_id}%"),
                cast(Advisory.cve_ids, String).ilike(f"%{cve_id}%")
            )
        ).first()
        
        if local_advisory:
            data = {
                "id": cve_id,
                "summary": local_advisory.description or "No description provided.",
                "cvss": {"score": local_advisory.cvss_score},
                "vendorProject": ", ".join(local_advisory.affected_vendors) if local_advisory.affected_vendors else "Unknown",
                "vulnerabilityName": local_advisory.title,
                "dateAdded": str(local_advisory.created_at)
            }
            return {"status": "success", "source": "local", "data": data}

        # MITRE CVE API is very fast
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
            if r.status_code == 200:
                data = r.json()
                return {"status": "success", "source": "mitre", "data": data}
            
            # Fallback to NVD
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            r2 = await client.get(nvd_url)
            if r2.status_code == 200:
                data = r2.json()
                return {"status": "success", "source": "nvd", "data": data}
                
        raise HTTPException(status_code=404, detail="CVE not found in Local Database, MITRE, or NVD.")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error looking up CVE {cve_id}: {e}")
        raise HTTPException(status_code=500, detail="Error looking up CVE")

from pydantic import BaseModel
class SummaryRequest(BaseModel):
    content: str

@router.post("/lookup/{cve_id}/ai-summary")
async def generate_cve_summary(cve_id: str, req: SummaryRequest):
    """
    Generates a professional AI summary for the given CVE content.
    """
    try:
        # Add CVE context explicitly
        full_content = f"CVE ID: {cve_id}\n\n{req.content}"
        report = await get_ai_summary(full_content)
        return {"status": "success", "report": report}
    except Exception as e:
        logger.error(f"Error generating summary for {cve_id}: {e}")
        raise HTTPException(status_code=500, detail="AI generation failed")
