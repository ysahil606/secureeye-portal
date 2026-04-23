"""
Secure Intelligence AI - Version 10.0 (High-Impact Summary Engine)
Generates concise technical paragraph summaries for advisories and IOCs.
"""
import logging
import httpx
import re
import google.generativeai as genai
from bs4 import BeautifulSoup
from config import settings
from services.threat_feeds import search_live_sources

logger = logging.getLogger("ai_service")

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

async def scrape_link(url: str) -> str:
    """Extract and clean text content from a provided security link."""
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            headers = {"User-Agent": "Secure-Analyst-Bot/4.0"}
            r = await client.get(url, headers=headers)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup(["script", "style", "nav", "footer", "aside", "form"]):
                tag.decompose()
            text = soup.get_text(separator=" ", strip=True)
            return re.sub(r'\s+', ' ', text)[:10000]
    except Exception as e:
        logger.error(f"Scraping failed: {e}")
        return ""

async def get_ai_summary(content: str) -> str:
    """
    Generates a professional threat summary using Gemini AI or fallback logic.
    """
    if settings.GEMINI_API_KEY:
        try:
            genai.configure(api_key=settings.GEMINI_API_KEY)
            # Trying 2.5-flash which appeared in the model list
            model = genai.GenerativeModel('gemini-2.5-flash')
            
            prompt = f"""
            You are a senior cybersecurity analyst at Secure. 
            Analyze the following security content and provide a high-impact, professional summary.
            
            STRUCTURE:
            1. Title: 🛡️ SECURE EXECUTIVE SUMMARY: [CVE-ID or Threat Name]
            2. High-level impact paragraph (max 3-4 sentences).
            3. TECHNICAL ANALYSIS & IMPACT: (Bullet points)
            4. REMEDIATION STRATEGY: (Specific actionable steps)
            
            Keep the tone professional, concise, and focused on risk. 
            Do not use markdown formatting like bolding (**) in the body, keep it clean text suitable for a dashboard terminal.
            
            CONTENT TO ANALYZE:
            {content[:15000]}
            """
            
            response = model.generate_content(prompt)
            if response and response.text:
                return response.text
        except Exception as e:
            logger.error(f"Gemini AI failed: {e}. Falling back to rule-based engine.")

    # FALLBACK RULE-BASED ENGINE
    raw_input = content.strip()
    
    # 1. Gather Context
    if raw_input.startswith("http"):
        raw_context = await scrape_link(raw_input)
    else:
        # If it's a CVE or short text, search live OSINT
        if len(raw_input) < 50:
            research = await search_live_sources(raw_input)
            raw_context = " ".join([f"{i['title']} {i['description']}" for i in research.get("items", [])])
        else:
            raw_context = raw_input

    # 2. Advanced Fact Extraction
    cve_match = CVE_PATTERN.search(raw_context)
    cve_id = cve_match.group(0).upper() if cve_match else "Threat Intelligence"
    
    vendor_match = re.search(r'\b(Horner Automation|Microsoft|Google|Cisco|WordPress|Delta|Apple|Linux|Fortinet)\b', raw_context, re.I)
    vendor = vendor_match.group(0) if vendor_match else "Enterprise Systems"
    
    cvss_match = re.search(r'CVSS\s*(?:3.1|3.0|2.0)?\s*(?:Score:?)?\s*(\d\.\d)', raw_context, re.I)
    cvss = cvss_match.group(1) if cvss_match else "High"

    # Extract technical story sentences
    sentences = [s.strip() for s in re.split(r'[.!?]', raw_context) if len(s.strip()) > 40]
    facts = [s for s in sentences if not any(x in s.lower() for x in ["legal", "privacy", "notification", "anonymous", "researcher"])]

    # 3. Construct the High-Impact Summary
    report = []
    report.append(f"🛡️ SECURE EXECUTIVE SUMMARY: {cve_id}")
    report.append("="*55)
    report.append("")
    
    # --- The Summary Paragraph ---
    if facts:
        summary_para = f"A critical security exposure has been identified in {vendor} involving {facts[0].lower()}. "
        if len(facts) > 1:
            summary_para += f"Analysis indicates that {facts[1].lower()}. "
        summary_para += f"The vulnerability carries a CVSS score of {cvss}, posing a significant risk of unauthorized access or arbitrary code execution."
        report.append(summary_para)
    else:
        report.append(f"Technical analysis identifies a high-severity vulnerability in {vendor} infrastructure. Successful exploitation could allow attackers to bypass security controls and gain unauthorized access to internal systems and services.")

    report.append("")
    report.append("TECHNICAL ANALYSIS & IMPACT:")
    report.append("-" * 30)
    # Technical Bullets (Concise)
    idx = 2
    count = 0
    while count < 4 and idx < len(facts):
        report.append(f"• {facts[idx]}.")
        idx += 1
        count += 1
    
    if not facts:
        report.append("• Critical flaw in input validation or authentication mechanism.")
        report.append("• Potential for persistent access following successful exploitation.")

    report.append("")
    report.append("REMEDIATION STRATEGY:")
    report.append("-" * 30)
    # Adaptive Mitigation
    if "password" in raw_context.lower() or "brute" in raw_context.lower():
        report.append("• Enforce strong password complexity and account lockout policies.")
        report.append("• Implement multi-factor authentication (MFA) for all PLC/Control access.")
    else:
        report.append("• Apply the official vendor security patches and firmware updates immediately.")
        report.append("• Isolate affected control systems from public-facing network segments.")
        
    report.append("• Enable enhanced logging and monitoring for anomalous traffic patterns.")
    
    report.append("")
    report.append("-" * 55)
    report.append(f"Analyst Note: Priority Remediation Required | Generated by Secure Intelligence AI")
    
    return "\n".join(report)

async def summarize_threat_report(prompt: str) -> str:
    """Specialized AI call for short sandbox and URL verdicts."""
    if not settings.GEMINI_API_KEY:
        return "Manual verification recommended. No AI API key configured."
    
    try:
        genai.configure(api_key=settings.GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt)
        if response and response.text:
            return response.text.strip()
    except Exception as e:
        logger.error(f"Quick AI summary failed: {e}")
        return "AI analysis failed. Please review the technical metadata."
