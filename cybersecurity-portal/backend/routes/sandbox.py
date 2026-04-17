from fastapi import APIRouter, Depends, HTTPException
from auth import get_current_active_user
from services.sandbox_service import get_sandbox_report

router = APIRouter(prefix="/sandbox", tags=["Malware Sandbox"])

@router.get("/report/{file_hash}")
async def fetch_report(
    file_hash: str,
    current_user = Depends(get_current_active_user)
):
    """Fetch behavioral analysis for a file hash."""
    report = await get_sandbox_report(file_hash)
    if "error" in report:
        raise HTTPException(status_code=503, detail=report["error"])
    return report
