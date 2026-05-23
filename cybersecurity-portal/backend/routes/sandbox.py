from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from auth import get_current_active_user
from services.sandbox_service import get_sandbox_report, analyze_url, local_static_analysis, calculate_sha256

router = APIRouter(prefix="/sandbox", tags=["DeepScan Lab"])

@router.get("/report/{file_hash}")
async def fetch_report(
    file_hash: str,
    current_user = Depends(get_current_active_user)
):
    """Fetch behavioral analysis for a file hash from cloud sandbox."""
    report = await get_sandbox_report(file_hash)
    if "error" in report:
        raise HTTPException(status_code=503, detail=report["error"])
    return report

@router.post("/scan-url")
async def scan_url(
    url: str = Form(...),
    mode: str = Form("basic"),
    current_user = Depends(get_current_active_user)
):
    """Perform deep analysis on a suspicious link."""
    try:
        return await analyze_url(url, mode)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan-file")
async def scan_file(
    file: UploadFile = File(...),
    mode: str = Form("basic"),
    current_user = Depends(get_current_active_user)
):
    """
    Perform local static analysis and check cloud reputation for an uploaded file.
    """
    content = await file.read()
    filename = file.filename
    
    # 1. Local Static Scan
    local_report = await local_static_analysis(content, filename)
    
    # 2. Cloud Reputation Check & Detonation (via Hash or direct submission)
    cloud_report = await get_sandbox_report(local_report["sha256"], content, filename, mode)
    
    return {
        "local_analysis": local_report,
        "cloud_analysis": cloud_report
    }

@router.post("/scan-hash")
async def scan_hash(
    hash: str = Form(...),
    mode: str = Form("basic"),
    current_user = Depends(get_current_active_user)
):
    """
    Query cloud threat intelligence for a direct file hash (MD5, SHA1, SHA256).
    """
    try:
        cloud_report = await get_sandbox_report(hash, None, "", mode)
        # Wrap it so the UI handles it just like a file scan
        return {
            "local_analysis": None,
            "cloud_analysis": cloud_report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
