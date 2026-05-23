import asyncio
import os
import sys
from sqlalchemy.orm import Session
from database import SessionLocal
from models import Advisory
from services.ai_service import get_ai_summary, scrape_link
from config import settings
from groq import Groq
import re
from bs4 import BeautifulSoup

# Setup Groq client
if not settings.GROQ_API_KEY:
    print("GROQ_API_KEY not set!")
    sys.exit(1)

client = Groq(api_key=settings.GROQ_API_KEY)

async def generate_100_word_summary(title: str, url: str, existing_desc: str) -> str:
    """Scrapes the URL and uses Groq to generate a concise ~100 word summary."""
    try:
        content = ""
        if url:
            content = await scrape_link(url)
        
        if not content:
            content = existing_desc
            
        prompt = f"""You are an elite cybersecurity analyst. Your task is to write a highly professional, engaging, and precise summary of the following cybersecurity article.
        
REQUIREMENTS:
1. The summary MUST be exactly around 80 to 100 words.
2. It must be written in a single paragraph.
3. No markdown, no bullet points, no asterisks, no hashtags. Just clean, professional plain text.
4. Focus on the core threat, who is impacted, and the potential consequences.

ARTICLE TITLE: {title}
ARTICLE CONTENT:
{content[:8000]}
"""
        url_pollinations = "https://text.pollinations.ai/"
        payload = {
            "messages": [
                {"role": "system", "content": "You write pristine, exactly 100-word executive intelligence briefings."},
                {"role": "user", "content": prompt}
            ],
            "model": "openai-fast",
            "jsonMode": False
        }
        import httpx
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client_http:
            r = await client_http.post(url_pollinations, json=payload, headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"})
            if r.status_code == 200 and r.text:
                return r.text.strip()
        return existing_desc
    except Exception as e:
        print(f"Error generating summary for {title}: {e}")
        return existing_desc

async def main():
    db = SessionLocal()
    try:
        # Get all recent advisories that have a short description or contain "[...]" or "[&#8230;]"
        advisories = db.query(Advisory).order_by(Advisory.created_at.desc()).limit(20).all()
        
        print(f"Found {len(advisories)} advisories. Upgrading to 100-word summaries using Groq...")
        
        for adv in advisories:
            print(f"\nProcessing: {adv.title}")
            print(f"Old length: {len(adv.description or '')}")
            
            new_summary = await generate_100_word_summary(adv.title, adv.source_url, adv.description)
            if new_summary and new_summary != adv.description:
                adv.description = new_summary
                db.commit()
                print(f"SUCCESS: Upgraded summary to ~100 words. New length: {len(new_summary)}")
            else:
                print("SKIPPED: No change or error.")
                
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(main())
