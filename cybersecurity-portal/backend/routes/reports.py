from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from database import get_db
from models import Advisory
from services.report_service import generate_advisory_pdf
from auth import get_current_active_user

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/advisory/{advisory_id}")
async def download_advisory_report(
    advisory_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Download a technical PDF bulletin for a specific advisory."""
    advisory = db.query(Advisory).filter(Advisory.id == advisory_id).first()
    if not advisory:
        raise HTTPException(status_code=404, detail="Advisory not found")
    
    pdf_buffer = generate_advisory_pdf(advisory)
    
    filename = f"Secure_Bulletin_{advisory_id}.pdf"
    return Response(
        content=pdf_buffer.getvalue(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )
