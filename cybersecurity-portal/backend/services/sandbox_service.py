"""
Malware Sandbox Service
Integrates with Hybrid Analysis (Falcon Sandbox) to fetch behavior reports.
"""
import logging
import httpx
from config import settings

logger = logging.getLogger("sandbox")

HYBRID_ANALYSIS_API = "https://www.hybrid-analysis.com/api/v2"

async def get_sandbox_report(file_hash: str) -> dict:
    """
    Search for an existing malware analysis report using a file hash.
    Uses Hybrid Analysis Public API.
    """
    if not file_hash or len(file_hash) < 32:
        return {"error": "Invalid file hash format"}

    headers = {
        "User-Agent": "Falcon Sandbox",
        "api-key": settings.SMTP_PASSWORD if len(settings.SMTP_PASSWORD) > 20 else "" # Placeholder or add HYBRID_ANALYSIS_API_KEY to config
    }

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            # First search for the hash
            r = await client.post(
                f"{HYBRID_ANALYSIS_API}/search/hash",
                data={"hash": file_hash},
                headers={"User-Agent": "Falcon"}
            )
            
            if r.status_code == 200:
                results = r.json()
                if results and len(results) > 0:
                    report = results[0] # Get the latest report
                    return {
                        "found": True,
                        "verdict": report.get("verdict", "unknown"),
                        "threat_score": report.get("threat_score"),
                        "vx_family": report.get("vx_family"),
                        "analysis_start_time": report.get("analysis_start_time"),
                        "environment_description": report.get("environment_description"),
                        "report_url": f"https://www.hybrid-analysis.com/sample/{report.get('sha256')}"
                    }
            
            return {"found": False, "message": "No existing report found for this hash."}
        except Exception as e:
            logger.error(f"Sandbox lookup failed: {e}")
            return {"error": "Connection to sandbox service failed."}
