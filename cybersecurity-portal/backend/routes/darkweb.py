"""
Dark Web Monitor — Production-Grade Breach & Exposure Intelligence
Sources:
  1. Have I Been Pwned Passwords API (k-Anonymity, free, no key)
  2. EmailRep.io (email reputation, free, no key for basic)
  3. Local threat intelligence (advisories + IOCs from our DB)
"""
import httpx
import hashlib
import logging
from datetime import datetime
from hashlib import sha256

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from auth import get_current_active_user
from database import get_db
from models import Advisory, IOC
from config import settings
from services.osint_aggregator import osint_aggregator

logger = logging.getLogger("darkweb")
router = APIRouter(prefix="/darkweb", tags=["Dark Web Monitor"])


def normalize_query(value: str) -> str:
    cleaned = value.strip().lower()
    return cleaned.replace("https://", "").replace("http://", "").split("/")[0]


async def _check_hibp_password(password_or_hash: str) -> dict | None:
    """
    Have I Been Pwned Passwords API (v3) — k-Anonymity model.
    Completely free, no API key needed, no rate limit.
    Checks if a password hash has appeared in known breaches.
    """
    try:
        # If it looks like a plain password, hash it first
        if len(password_or_hash) != 40:
            sha1_hash = hashlib.sha1(password_or_hash.encode("utf-8")).hexdigest().upper()
        else:
            sha1_hash = password_or_hash.upper()

        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"}
            )
            if r.status_code == 200:
                for line in r.text.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) == 2 and parts[0] == suffix:
                        return {
                            "found": True,
                            "breach_count": int(parts[1]),
                            "source": "Have I Been Pwned",
                            "severity": "critical" if int(parts[1]) > 100 else "high",
                        }
                return {"found": False, "source": "Have I Been Pwned"}
    except Exception as e:
        logger.error(f"HIBP password check failed: {e}")
    return None


async def _check_emailrep(email: str) -> dict | None:
    """
    EmailRep.io — Free email reputation API. No key needed for basic queries.
    Returns reputation score, breach exposure, suspicious activity, and domain info.
    """
    if "@" not in email:
        return None
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://emailrep.io/{email}",
                headers={"Accept": "application/json", "User-Agent": "SecureEye-Portal/1.0"}
            )
            if r.status_code == 200:
                data = r.json()
                details = data.get("details", {})

                leak_sources = []
                if details.get("credentials_leaked"):
                    leak_sources.append({
                        "id": f"er-cred-{sha256(email.encode()).hexdigest()[:8]}",
                        "email": email,
                        "source": "Credentials Leak (EmailRep)",
                        "date": details.get("last_seen", datetime.utcnow().date().isoformat()),
                        "severity": "critical",
                        "status": "open",
                        "has_password": True,
                        "hint": "Credentials found in breach databases"
                    })
                if details.get("data_breach"):
                    leak_sources.append({
                        "id": f"er-breach-{sha256(email.encode()).hexdigest()[:8]}",
                        "email": email,
                        "source": "Data Breach (EmailRep)",
                        "date": details.get("last_seen", datetime.utcnow().date().isoformat()),
                        "severity": "high",
                        "status": "open",
                        "has_password": False,
                        "hint": "Email found in data breach"
                    })

                return {
                    "reputation": data.get("reputation", "unknown"),
                    "suspicious": data.get("suspicious", False),
                    "details": {
                        "blacklisted": details.get("blacklisted", False),
                        "malicious_activity": details.get("malicious_activity", False),
                        "credential_leaked": details.get("credentials_leaked", False),
                        "data_breach": details.get("data_breach", False),
                        "spam": details.get("spam", False),
                        "free_provider": details.get("free_provider", False),
                        "disposable": details.get("disposable", False),
                        "deliverable": details.get("deliverable", False),
                        "domain_reputation": details.get("domain_reputation", "unknown"),
                        "profiles": details.get("profiles", []),
                    },
                    "leaks": leak_sources,
                }
            elif r.status_code == 429:
                logger.warning("EmailRep rate limited")
    except Exception as e:
        logger.error(f"EmailRep check failed: {e}")
    return None


async def _check_leaklookup(keyword: str) -> list:
    """Leak-Lookup Public API — Free tier, requires API key."""
    # Free tier only returns breach names
    if not getattr(settings, "LEAK_LOOKUP_API_KEY", ""):
        return []
    leaks = []
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            if "@" in keyword:
                query_type = "email_address"
            else:
                query_type = "username"
                
            url = "https://leak-lookup.com/api/search"
            data = {
                "key": settings.LEAK_LOOKUP_API_KEY,
                "type": query_type,
                "query": keyword
            }
            r = await client.post(url, data=data)
            if r.status_code == 200:
                response = r.json()
                if response.get("error") == "false" and response.get("message"):
                    # The free tier returns a dictionary of breaches where the key is the breach name
                    for breach_name in response["message"].keys():
                        leaks.append({
                            "id": f"ll-{sha256(breach_name.encode()).hexdigest()[:8]}",
                            "email": keyword,
                            "source": breach_name,
                            "date": datetime.utcnow().date().isoformat(),
                            "severity": "high",
                            "status": "open",
                            "has_password": True,
                            "hint": "Breach database match via Leak-Lookup"
                        })
    except Exception as e:
        logger.error(f"Leak-Lookup API failed: {e}")
    return leaks


async def _check_breachdirectory(keyword: str) -> list:
    """Legacy BreachDirectory API — only used if key is configured."""
    if not settings.BREACH_DIRECTORY_API_KEY:
        return []
    leaks = []
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            url = f"https://breachdirectory.p.rapidapi.com/v1/search?term={keyword}"
            headers = {
                "X-RapidAPI-Key": settings.BREACH_DIRECTORY_API_KEY,
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
            }
            r = await client.get(url, headers=headers)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("result", []):
                    leaks.append({
                        "id": f"bd-{sha256(str(item).encode()).hexdigest()[:8]}",
                        "email": item.get("email") or keyword,
                        "source": item.get("sources", ["Data Breach"])[0],
                        "date": item.get("date", datetime.utcnow().date().isoformat()),
                        "severity": "critical" if item.get("password") else "high",
                        "status": "open",
                        "has_password": bool(item.get("password")),
                        "hint": item.get("password") or "SHA-1 Hash Found"
                    })
    except Exception as e:
        logger.error(f"BreachDirectory API failed: {e}")
    return leaks


@router.get("/scan")
async def scan_darkweb(
    q: str = Query(..., min_length=2),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """
    Real-time exposure scan using multiple free intelligence sources
    combined with local threat database.
    """
    keyword = normalize_query(q)
    now = datetime.utcnow()
    leaks = []
    mentions = []
    reputation_data = None
    password_check = None
    sources_checked = []

    # 1. EMAIL REPUTATION (EmailRep.io — free, no key)
    if "@" in keyword:
        emailrep = await _check_emailrep(keyword)
        if emailrep:
            sources_checked.append("EmailRep.io")
            reputation_data = {
                "reputation": emailrep["reputation"],
                "suspicious": emailrep["suspicious"],
                "details": emailrep["details"],
            }
            leaks.extend(emailrep.get("leaks", []))

    # 2. PASSWORD EXPOSURE CHECK (HIBP — free, no key)
    if "@" not in keyword and "." not in keyword:
        # Looks like a password or hash — check HIBP
        hibp = await _check_hibp_password(keyword)
        if hibp:
            sources_checked.append("Have I Been Pwned")
            password_check = hibp
            if hibp.get("found"):
                leaks.append({
                    "id": f"hibp-{sha256(keyword.encode()).hexdigest()[:8]}",
                    "email": "password_check",
                    "source": f"HIBP ({hibp['breach_count']} breaches)",
                    "date": now.date().isoformat(),
                    "severity": hibp.get("severity", "high"),
                    "status": "open",
                    "has_password": True,
                    "hint": f"Found in {hibp['breach_count']} data breaches"
                })

    # 3. LEAK LOOKUP (Free tier with key)
    ll_leaks = await _check_leaklookup(keyword)
    if ll_leaks:
        sources_checked.append("Leak-Lookup")
        leaks.extend(ll_leaks)

    # 4. BREACH DIRECTORY (legacy, only if key configured)
    bd_leaks = await _check_breachdirectory(keyword)
    if bd_leaks:
        sources_checked.append("BreachDirectory")
        leaks.extend(bd_leaks)

    # 5. LOCAL INTELLIGENCE SCAN (Our Database)
    advisory_hits = (
        db.query(Advisory)
        .filter(or_(Advisory.title.ilike(f"%{keyword}%"), Advisory.description.ilike(f"%{keyword}%")))
        .order_by(Advisory.created_at.desc())
        .limit(10)
        .all()
    )
    ioc_hits = db.query(IOC).filter(IOC.value.ilike(f"%{keyword}%")).limit(10).all()

    for item in advisory_hits:
        mentions.append({
            "id": f"adv-{item.id}",
            "title": item.title,
            "snippet": (item.description or "Internal intelligence match").strip()[:200],
            "onion_site": "indexed-advisory",
            "severity": item.severity.value if item.severity else "medium",
        })

    for item in ioc_hits:
        mentions.append({
            "id": f"ioc-{item.id}",
            "title": f"IOC match for {item.value}",
            "snippet": f"Identified in Secure Intelligence Feed: {item.source}",
            "onion_site": "darkweb-ioc-store",
            "severity": "high",
        })

    if advisory_hits or ioc_hits:
        sources_checked.append("SecureEye Local DB")

    # 6. RUN OSINT AGGREGATOR (10+ sources)
    aggregated_intel = await osint_aggregator.aggregate_domain_intelligence(keyword)
    
    osint_url_map = {
        "HackerTarget": f"https://hackertarget.com/domain-profiler/?q={keyword}",
        "Crt.sh": f"https://crt.sh/?q={keyword}",
        "URLhaus": f"https://urlhaus.abuse.ch/browse.php?search={keyword}",
        "VirusTotal": f"https://www.virustotal.com/gui/search/{keyword}",
        "AlienVault": f"https://otx.alienvault.com/browse/global/pulses?q={keyword}",
        "GreyNoise": f"https://viz.greynoise.io/query/?gnql={keyword}",
        "AbuseIPDB": f"https://www.abuseipdb.com/check/{keyword}",
        "LeakLookup": "https://leak-lookup.com/search",
        "ThreatFox": f"https://threatfox.abuse.ch/browse/?search={keyword}",
        "OpenPhish": "https://openphish.com/"
    }

    for src in aggregated_intel["open_sources"]:
        if src["source"] not in sources_checked:
            sources_checked.append(src["source"])
        if src.get("count", 0) > 0:
            for finding in src.get("findings", []):
                mentions.append({
                    "id": f"osint-{sha256(str(finding).encode()).hexdigest()[:8]}",
                    "title": f"OSINT: {src['source']}",
                    "snippet": finding,
                    "onion_site": "api-feed",
                    "severity": "high",
                    "url": osint_url_map.get(src['source'], "")
                })
            
    premium_sources_skipped = [src["source"] for src in aggregated_intel["premium_sources"]]

    # Determine exposure level
    exposure_level = "Low"
    if any(l.get("severity") == "critical" for l in leaks) or aggregated_intel["total_threats_found"] > 50:
        exposure_level = "Critical"
    elif leaks or any(m.get("severity") == "high" for m in mentions):
        exposure_level = "Elevated"
    elif mentions:
        exposure_level = "Watch"

    return {
        "query": keyword,
        "scanned_at": now.isoformat(),
        "exposure_level": exposure_level,
        "leaks": leaks,
        "mentions": mentions,
        "reputation": reputation_data,
        "password_check": password_check,
        "sources_checked": sources_checked,
        "premium_sources_skipped": premium_sources_skipped,
        "total_osint_threats": aggregated_intel["total_threats_found"],
        "api_active": True,
        "recommendations": [
            "Initiate immediate password reset for all exposed identities.",
            "Verify MFA health for identified high-risk accounts.",
            "Cross-reference found IOCs with internal SIEM/EDR logs.",
            "Monitor dark web forums for further mentions of this domain.",
            "Check if leaked credentials are reused across other services.",
        ],
    }
