from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from auth import get_current_active_user
from services import ai_service

router = APIRouter(prefix="/ai", tags=["AI"])

class AIAnalyzeRequest(BaseModel):
    url: Optional[str] = None
    text: Optional[str] = None

@router.post("/analyze")
async def analyze_threat(
    req: AIAnalyzeRequest,
    current_user = Depends(get_current_active_user)
):
    if not req.url and not req.text:
        raise HTTPException(status_code=400, detail="Either URL or Text must be provided")
    
    content = ""
    if req.url:
        content = await ai_service.scrape_link(req.url)
        if not content:
            raise HTTPException(status_code=400, detail="Failed to scrape content from the provided URL")
    else:
        content = req.text

    summary = await ai_service.get_ai_summary(content)
    return {"summary": summary}
