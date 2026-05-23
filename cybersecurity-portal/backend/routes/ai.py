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

class AIChatRequest(BaseModel):
    message: str
    history: list = []

import re
import httpx
from bs4 import BeautifulSoup
import asyncio

async def _duckduckgo_search(query: str) -> str:
    """Live Web Browsing Engine - Multi-strategy DuckDuckGo scraper"""
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    # Strategy 1: DuckDuckGo Lite (more bot-friendly, no JS required)
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            encoded_query = query.replace(" ", "+")
            r = await client.post(
                "https://lite.duckduckgo.com/lite/",
                data={"q": f"{query} cybersecurity", "kl": "us-en"},
                headers=headers
            )
            if r.status_code in (200, 202):
                soup = BeautifulSoup(r.text, 'html.parser')
                # DDG Lite uses table rows with class 'result-link' and 'result-snippet'
                snippets = []
                for td in soup.find_all('td', class_='result-snippet'):
                    text = td.get_text(strip=True)
                    if text and len(text) > 30:
                        snippets.append(text)
                    if len(snippets) >= 3:
                        break
                if snippets:
                    logger.info(f"Web search found {len(snippets)} results via DDG Lite")
                    return "\n".join([f"- {s}" for s in snippets])
    except Exception as e:
        logger.warning(f"DDG Lite search failed: {e}")

    # Strategy 2: DuckDuckGo HTML fallback (accept any 2xx)
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            r = await client.get(
                f"https://html.duckduckgo.com/html/?q={query}+cybersecurity+threat",
                headers=headers
            )
            if r.status_code < 300:
                soup = BeautifulSoup(r.text, 'html.parser')
                snippets = []
                for sel in ['result__snippet', 'result-snippet', 'result__a']:
                    elements = soup.find_all(class_=sel)
                    for el in elements[:3]:
                        text = el.get_text(strip=True)
                        if text and len(text) > 30:
                            snippets.append(text)
                    if snippets:
                        break
                if snippets:
                    logger.info(f"Web search found {len(snippets)} results via DDG HTML")
                    return "\n".join([f"- {s}" for s in snippets])
    except Exception as e:
        logger.warning(f"DDG HTML search failed: {e}")

    logger.warning(f"All web search strategies failed for: {query}")
    return ""

@router.post("/chat")
async def chat_endpoint(
    req: AIChatRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    # Fetch 5 most recent advisories to give the bot context
    recent_advisories = db.query(Advisory).order_by(Advisory.published_at.desc()).limit(5).all()
    context = "--- LOCAL DATABASE CONTEXT ---\\n"
    for a in recent_advisories:
        context += f"Title: {a.title} | Severity: {a.severity} | CVE: {a.cve_ids}\\n"

    # Dynamic CVE Lookup (Fallback to Shodan CVE API)
    cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", req.message, re.IGNORECASE)
    if cve_match:
        cve_id = cve_match.group(1).upper()
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"https://cvedb.shodan.io/cve/{cve_id}")
                if r.status_code == 200:
                    data = r.json()
                    if data:
                        context += f"\\n--- LIVE OSINT DATA FOR {cve_id} ---\\n"
                        context += f"Summary: {data.get('summary', 'N/A')}\\n"
                        context += f"CVSS: {data.get('cvss', 'N/A')}\\n"
                        context += f"EPSS Score: {data.get('epss', 'N/A')}\\n"
                elif r.status_code == 429:
                    logger.warning(f"Rate limited by Shodan for {cve_id}")
        except Exception as e:
            logger.error(f"Failed to fetch live CVE data for {cve_id}: {e}")

    # LIVE WEB SEARCH CAPABILITY
    if len(req.message) > 5:
        search_results = await _duckduckgo_search(req.message)
        if search_results:
            context += f"\\n--- LIVE INTERNET SEARCH RESULTS FOR USER QUERY ---\\n{search_results}\\n"

    response = await ai_service.chat_with_assistant(req.message, req.history, context)
    return {"reply": response}
