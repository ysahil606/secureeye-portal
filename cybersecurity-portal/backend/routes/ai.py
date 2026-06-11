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
        
    prompt = f"""You are an elite Cyber Threat Intelligence Forecaster at SecureEye Global Operations Center.
Analyze the threat below and produce a STRUCTURED intelligence forecast in EXACTLY this format.
ALWAYS use ## headers and bullet points with •. Do NOT deviate from the section structure.

## Blast Radius Assessment
[2-3 sentences on scope, affected organizations, and scale of impact]

## 6–12 Month Threat Forecast
• [Specific scenario 1 — how attackers will evolve this threat]
• [Specific scenario 2 — integration with attack frameworks or threat groups]
• [Specific scenario 3 — supply chain or lateral movement implications]
• [Specific scenario 4 — patching timeline and exposure window]

## Attribution Indicators
[Known or suspected threat actor types, TTPs, and motivation]

## Evidence Gaps
• [What additional intelligence is needed to refine this forecast]
• [Data sources that would improve confidence level]

Threat Title: {advisory.title}
Threat Description: {advisory.description[:2000]}
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

async def _wikipedia_search(query: str) -> str:
    """Live Web Knowledge Engine — Wikipedia Search API (100% free, no API key)"""
    headers = {"User-Agent": "SecureEye/1.0 (cybersecurity-portal; contact@secureeye.app)"}
    snippets = []
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            # Step 1: Search for the best matching Wikipedia articles
            search_url = "https://en.wikipedia.org/w/api.php"
            params = {
                "action": "query",
                "list": "search",
                "srsearch": f"{query} cybersecurity hacker threat",
                "format": "json",
                "srlimit": 2,
            }
            r = await client.get(search_url, params=params, headers=headers)
            if r.status_code == 200:
                results = r.json().get("query", {}).get("search", [])
                for res in results:
                    title = res.get("title", "")
                    snippet = res.get("snippet", "").replace('<span class="searchmatch">', "").replace("</span>", "")
                    if snippet:
                        snippets.append(f"**{title}**: {snippet}")

                # Step 2: Fetch intro of the top result
                if results:
                    top_title = results[0].get("title", "")
                    intro_r = await client.get(
                        f"https://en.wikipedia.org/api/rest_v1/page/summary/{top_title.replace(' ', '_')}",
                        headers=headers
                    )
                    if intro_r.status_code == 200:
                        intro_data = intro_r.json()
                        extract = intro_data.get("extract", "")
                        if extract and len(extract) > 50:
                            snippets.insert(0, f"**Wikipedia Summary ({top_title})**: {extract[:600]}")

    except Exception as e:
        logger.warning(f"Wikipedia search failed: {e}")

    if snippets:
        logger.info(f"Wikipedia search found {len(snippets)} results for: {query}")
        return "\n".join(snippets)
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

    # LIVE WIKIPEDIA KNOWLEDGE SEARCH
    if len(req.message) > 5:
        search_results = await _wikipedia_search(req.message)
        if search_results:
            context += f"\\n--- LIVE WIKIPEDIA KNOWLEDGE ---\\n{search_results}\\n"

    response = await ai_service.chat_with_assistant(req.message, req.history, context)
    return {"reply": response}
