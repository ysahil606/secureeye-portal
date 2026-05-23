from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from auth import get_current_active_user
from services import ai_service
from database import get_db
from sqlalchemy.orm import Session
from models import Advisory
import logging

logger = logging.getLogger("ai_router")
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
    context_hint = ""

    if req.url:
        scraped = await ai_service.scrape_link(req.url)
        if scraped:
            content = scraped
        else:
            logger.warning(f"Scraping failed for {req.url}. Falling back to Groq knowledge base.")
            content = req.url
            context_hint = f"[NOTE: The URL could not be scraped. Use your knowledge base to analyze this URL/domain and generate an intelligence brief about any known threats, malware, or suspicious activity associated with it: {req.url}]"
    else:
        content = req.text

    final_content = f"{context_hint}\n\n{content}" if context_hint else content
    summary = await ai_service.get_ai_summary(final_content)
    return {"summary": summary}

@router.post("/generate-playbook/{advisory_id}")
async def generate_playbook(
    advisory_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    advisory = db.query(Advisory).filter(Advisory.id == advisory_id).first()
    if not advisory:
        raise HTTPException(status_code=404, detail="Advisory not found")
        
    prompt = f"""Act as a Tier 3 Incident Response Commander. 
Generate a clear, step-by-step tactical remediation playbook for the following threat.
Do not use markdown formatting like bolding or headers. Use plain text structured as clear sequential steps.

Threat Title: {advisory.title}
Threat Description: {advisory.description}
"""
    playbook = await ai_service.summarize_threat_report(prompt)
    return {"playbook": playbook}

@router.post("/predict-impact/{advisory_id}")
async def predict_impact(
    advisory_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    advisory = db.query(Advisory).filter(Advisory.id == advisory_id).first()
    if not advisory:
        raise HTTPException(status_code=404, detail="Advisory not found")
        
    prompt = f"""Act as an expert Cyber Threat Intelligence Forecaster. 
Predict the potential blast radius, long-term impact, and likely future evolution of this threat over the next 6-12 months.
Do not use markdown formatting like bolding or headers. Keep it as a highly professional plain-text intelligence forecast paragraph.

Threat Title: {advisory.title}
Threat Description: {advisory.description}
"""
    prediction = await ai_service.summarize_threat_report(prompt)
    return {"prediction": prediction}
