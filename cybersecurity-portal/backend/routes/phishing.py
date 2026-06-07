"""
Phishing Monitor API Routes v2
"""
import logging
from fastapi import APIRouter, Depends, Query, HTTPException

from auth import get_current_active_user
from services.phishing_monitor import run_phishing_scan, normalize_domain
from services.phishing_enricher import enrich_domain

logger = logging.getLogger("phishing_routes")
router = APIRouter(prefix="/phishing", tags=["Phishing Monitor"])


@router.get("/scan")
async def scan_phishing(
    domain: str = Query(..., min_length=2, description="Domain to scan (e.g. paypal.com)"),
    current_user=Depends(get_current_active_user),
):
    """
    Two-stream phishing scan.
    Stream A: Lookalike domain generators (dnstwist + crt.sh)
    Stream B: Known phishing feeds (PhishTank, OpenPhish, PhishStats, Phishing.Database, URLScan)
    """
    clean = normalize_domain(domain)
    if not clean or "." not in clean:
        raise HTTPException(status_code=400, detail="Please provide a valid domain (e.g. paypal.com)")

    logger.info(f"[PhishMonitor v2] Scan: {clean} by {current_user.username}")
    results = await run_phishing_scan(clean)
    return results


@router.get("/enrich")
async def enrich_phishing_domain(
    domain: str = Query(..., min_length=2, description="Domain to enrich with WHOIS, DNS, verdict, screenshot"),
    current_user=Depends(get_current_active_user),
):
    """
    On-click enrichment for a specific domain.
    Returns: WHOIS, DNS records, multi-engine malicious verdict, live screenshot.
    """
    clean = normalize_domain(domain)
    if not clean or "." not in clean:
        raise HTTPException(status_code=400, detail="Invalid domain")

    logger.info(f"[Enricher] Enriching: {clean} by {current_user.username}")
    result = await enrich_domain(clean)
    return result


@router.get("/screenshot-status")
async def get_screenshot_status(
    scan_id: str = Query(..., description="URLScan.io scan UUID"),
    current_user=Depends(get_current_active_user),
):
    """
    Poll for a pending URLScan.io screenshot status.
    """
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"https://urlscan.io/api/v1/result/{scan_id}/")
            if r.status_code == 200:
                data = r.json()
                return {
                    "status": "ready",
                    "screenshot_url": f"https://urlscan.io/screenshots/{scan_id}.png",
                    "scan_url": f"https://urlscan.io/result/{scan_id}/",
                    "page_title": data.get("page", {}).get("title", ""),
                }
            elif r.status_code == 404:
                return {"status": "pending", "message": "Scan still processing"}
    except Exception as e:
        pass
    return {"status": "unavailable"}
