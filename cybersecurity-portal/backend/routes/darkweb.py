"""
Dark Web Monitor — Fully Upgraded Production-Grade Breach & Exposure Intelligence
Free Sources (No API Key Required):
  1. HIBP All Breaches List  — matches against known domain breaches, 100% free
  2. URLScan.io              — scans/screenshots showing domain in malicious context
  3. EmailRep.io             — email reputation + breach signals
  4. HIBP Pwned Passwords    — k-Anonymity password check
  5. URLhaus (abuse.ch)      — malicious URL feed
  6. ThreatFox (abuse.ch)    — IOC feed
  7. OpenPhish               — active phishing feed
  8. HackerTarget            — subdomain/IP mapping
  9. Crt.sh                  — certificate transparency
 10. Shodan InternetDB       — IP vulnerability data
 11. IntelX Phonebook        — public exposure search (no key, limited)
 12. LeakCheck.io Public API — billions of records, no key required
 13. XposedOrNot Public API  — billions of records for emails, no key
 14. Local SecureEye DB      — our own advisories + IOCs
Optional (With API Key):
 14. VirusTotal              — VIRUSTOTAL_API_KEY
 15. AlienVault OTX          — ALIENVAULT_OTX_API_KEY
 16. Leak-Lookup             — LEAK_LOOKUP_API_KEY
 17. BreachDirectory         — BREACH_DIRECTORY_API_KEY
"""
import httpx
import hashlib
import logging
import socket
import asyncio
from datetime import datetime
from hashlib import sha256

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from auth import get_current_active_user
from database import get_db
from models import Advisory, IOC
from config import settings

logger = logging.getLogger("darkweb")
router = APIRouter(prefix="/darkweb", tags=["Dark Web Monitor"])

HEADERS = {"User-Agent": "SecureEye-Portal/2.0 (security-research; contact@secureeye.app)"}


def normalize_query(value: str) -> str:
    cleaned = value.strip().lower()
    return cleaned.replace("https://", "").replace("http://", "").split("/")[0]


SOURCE_LABELS = {
    "emailrep": "EmailRep.io",
    "hibp_domain": "Have I Been Pwned Breach Corpus",
    "hibp_pass": "HIBP Pwned Passwords",
    "urlscan": "URLScan.io",
    "urlhaus": "URLhaus",
    "threatfox": "ThreatFox",
    "openphish": "OpenPhish",
    "shodan": "Shodan InternetDB",
    "intelx": "IntelX Phonebook",
    "leakcheck": "LeakCheck.io",
    "xposedornot": "XposedOrNot",
    "crtsh": "crt.sh Certificate Transparency",
    "hackertarget": "HackerTarget",
    "threatminer": "ThreatMiner",
    "wayback": "Internet Archive CDX",
    "commoncrawl": "Common Crawl Index",
    "bufferover": "BufferOver DNS",
    "leaklookup": "Leak-Lookup",
    "breachdir": "BreachDirectory",
}


def _safe_leak(item: dict) -> dict:
    """Normalize leak records and make sure plaintext secrets are never returned."""
    safe = dict(item)
    for key in ("password", "plain_password", "raw_password", "hash", "sha1", "sha256"):
        if key in safe:
            safe.pop(key, None)
    hint = str(safe.get("hint") or "")
    if len(hint) > 180:
        safe["hint"] = hint[:177] + "..."
    safe.setdefault("status", "open")
    safe.setdefault("has_password", False)
    safe.setdefault("data_classes", [])
    return safe


def _dedupe_records(items: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for item in items:
        key = (
            item.get("id")
            or f"{item.get('source','')}|{item.get('email','')}|{item.get('title','')}"
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 1: HIBP All Breaches (100% Free — No API Key)
# Cross-reference domain against the full HIBP breach database
# ─────────────────────────────────────────────────────────────────────────────
async def _hibp_domain_breach_check(domain: str) -> list:
    """
    Fetches the full HIBP breach list (free, no key) and filters
    breaches whose Domain field matches the search query.
    Returns real, confirmed breach records.
    """
    leaks = []
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            r = await client.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                headers={**HEADERS, "hibp-api-key": getattr(settings, "HIBP_API_KEY", "")}
            )
            if r.status_code == 200:
                breaches = r.json()
                root_name = domain.lower().split(".")[0]
                for breach in breaches:
                    breach_domain = (breach.get("Domain") or "").lower()
                    breach_name = (breach.get("Name") or "").lower()
                    breach_title = (breach.get("Title") or "").lower()
                    if (
                        breach_domain == domain
                        or breach_domain.endswith(f".{domain}")
                        or (breach_domain == root_name and len(root_name) >= 4)
                        or (breach_name == root_name and len(root_name) >= 5)
                        or (breach_title == root_name and len(root_name) >= 5)
                    ):
                        added = breach.get("AddedDate", "")[:10]
                        breach_date = breach.get("BreachDate", added) or added
                        count = breach.get("PwnCount", 0)
                        classes = breach.get("DataClasses", [])
                        has_passwords = "Passwords" in classes
                        leaks.append({
                            "id": f"hibp-{sha256(breach.get('Name','').encode()).hexdigest()[:8]}",
                            "email": f"{count:,} accounts",
                            "source": f"HIBP — {breach.get('Title', breach.get('Name'))}",
                            "date": breach_date,
                            "severity": "critical" if has_passwords else "high",
                            "status": "open",
                            "has_password": has_passwords,
                            "hint": f"Leaked: {', '.join(classes[:4])}" if classes else "Data breach confirmed",
                            "breach_size": count,
                            "data_classes": classes,
                        })
    except Exception as e:
        logger.warning(f"HIBP domain breach check failed: {e}")
    return leaks


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 2: HIBP Pwned Passwords (k-Anonymity, 100% Free)
# ─────────────────────────────────────────────────────────────────────────────
async def _check_hibp_password(password_or_hash: str) -> dict | None:
    try:
        sha1_hash = (
            password_or_hash.upper()
            if len(password_or_hash) == 40
            else hashlib.sha1(password_or_hash.encode()).hexdigest().upper()
        )
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"}
            )
            if r.status_code == 200:
                for line in r.text.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) == 2 and parts[0] == suffix:
                        count = int(parts[1])
                        return {
                            "found": True,
                            "breach_count": count,
                            "source": "Have I Been Pwned Passwords",
                            "severity": "critical" if count > 100 else "high",
                        }
                return {"found": False, "source": "Have I Been Pwned Passwords"}
    except Exception as e:
        logger.error(f"HIBP password check failed: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 3: EmailRep.io (Free, no API key for basic)
# ─────────────────────────────────────────────────────────────────────────────
async def _check_emailrep(email: str) -> dict | None:
    if "@" not in email:
        return None
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://emailrep.io/{email}",
                headers={**HEADERS, "Accept": "application/json"}
            )
            if r.status_code == 200:
                data = r.json()
                details = data.get("details", {})
                leaks = []
                if details.get("credentials_leaked"):
                    leaks.append({
                        "id": f"er-cred-{sha256(email.encode()).hexdigest()[:8]}",
                        "email": email,
                        "source": "EmailRep.io — Credentials Database",
                        "date": details.get("last_seen") or "Unknown",
                        "severity": "critical",
                        "status": "open",
                        "has_password": True,
                        "hint": "Credentials confirmed in breach databases",
                    })
                if details.get("data_breach"):
                    leaks.append({
                        "id": f"er-breach-{sha256(email.encode()).hexdigest()[:8]}",
                        "email": email,
                        "source": "EmailRep.io — Data Breach",
                        "date": details.get("last_seen") or "Unknown",
                        "severity": "high",
                        "status": "open",
                        "has_password": False,
                        "hint": "Email confirmed in data breach",
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
                        "disposable": details.get("disposable", False),
                        "deliverable": details.get("deliverable", False),
                        "domain_reputation": details.get("domain_reputation", "unknown"),
                        "profiles": details.get("profiles", []),
                    },
                    "leaks": leaks,
                }
            elif r.status_code == 429:
                logger.warning("EmailRep rate limited")
    except Exception as e:
        logger.error(f"EmailRep check failed: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 4: URLScan.io (1000 free scans/month, no key for search)
# Detects domain appearing in malicious/phishing scans
# ─────────────────────────────────────────────────────────────────────────────
async def _check_urlscan(domain: str) -> list:
    mentions = []
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain} AND verdicts.malicious:true", "size": 10},
                headers=HEADERS
            )
            if r.status_code == 200:
                results = r.json().get("results", [])
                for result in results[:8]:
                    page = result.get("page", {})
                    verdict = result.get("verdicts", {}).get("overall", {})
                    mentions.append({
                        "id": f"us-{result.get('_id','')[:8]}",
                        "title": f"URLScan: Malicious scan — {page.get('domain', domain)}",
                        "snippet": f"Score: {verdict.get('score', 0)} | Tags: {', '.join(verdict.get('tags', [])[:3]) or 'malicious'}",
                        "onion_site": "urlscan.io",
                        "severity": "critical" if verdict.get("malicious") else "high",
                        "url": result.get("result", ""),
                        "source_icon": "🔍"
                    })
    except Exception as e:
        logger.warning(f"URLScan failed: {e}")
    return mentions


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 4b: LeakCheck.io Public API (Free, no key required)
# Accesses billions of breach records
# ─────────────────────────────────────────────────────────────────────────────
async def _check_leakcheck_public(keyword: str) -> list:
    leaks = []
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.get(
                f"https://leakcheck.io/api/public?check={keyword}",
                headers=HEADERS
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("success") and data.get("found", 0) > 0:
                    sources = data.get("sources", [])
                    fields = data.get("fields", [])
                    has_password = "password" in fields or "hash" in fields
                    for source in sources[:25]:
                        breach_name = source.get("name", "Unknown Breach")
                        breach_date = (source.get("date") or "Unknown")[:10]
                        leaks.append({
                            "id": f"lc-{sha256(breach_name.encode()).hexdigest()[:8]}",
                            "email": keyword,
                            "source": f"LeakCheck.io — {breach_name}",
                            "date": breach_date,
                            "severity": "critical" if has_password else "high",
                            "status": "open",
                            "has_password": has_password,
                            "hint": f"Leaked fields: {', '.join(fields[:5])}" if fields else "Found in leak database",
                        })
    except Exception as e:
        logger.warning(f"LeakCheck.io search failed: {e}")
    return leaks


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 4c: XposedOrNot Public API (Free, no key required)
# Accesses billions of breach records for email checks
# ─────────────────────────────────────────────────────────────────────────────
async def _check_xposedornot(email: str) -> list:
    leaks = []
    if "@" not in email:
        return leaks
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.get(
                f"https://api.xposedornot.com/v1/check-email/{email}",
                headers=HEADERS
            )
            if r.status_code == 200:
                data = r.json()
                breach_lists = data.get("breaches", [])
                
                # The API sometimes returns a list of lists or just a list of strings
                flat_breaches = []
                for b in breach_lists:
                    if isinstance(b, list):
                        flat_breaches.extend(b)
                    else:
                        flat_breaches.append(b)

                for breach_name in flat_breaches:
                    leaks.append({
                        "id": f"xon-{sha256(breach_name.encode()).hexdigest()[:8]}",
                        "email": email,
                        "source": f"XposedOrNot — {breach_name}",
                        "date": "Unknown",
                        "severity": "high",
                        "status": "open",
                        "has_password": False,
                        "hint": "Email found in XposedOrNot breach database",
                    })
            elif r.status_code == 404:
                # 404 means no breaches found for this email on XposedOrNot
                pass
    except Exception as e:
        logger.warning(f"XposedOrNot search failed: {e}")
    return leaks


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 5: IntelX Phonebook Search (Public, limited free)
# Searches for email addresses and credentials tied to a domain
# ─────────────────────────────────────────────────────────────────────────────
async def _check_intelx(domain: str) -> list:
    leaks = []
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            # IntelX phonebook search (free public endpoint, limited results)
            search_r = await client.post(
                "https://2.intelx.io/phonebook/search",
                params={"k": ""},
                json={"term": domain, "maxresults": 20, "media": 0, "target": 2,
                      "terminate": [], "timeout": 10},
                headers=HEADERS
            )
            if search_r.status_code == 200:
                search_data = search_r.json()
                search_id = search_data.get("id")
                if search_id:
                    # Fetch results
                    await asyncio.sleep(1)
                    results_r = await client.get(
                        "https://2.intelx.io/phonebook/search/result",
                        params={"k": "", "id": search_id, "limit": 20},
                        headers=HEADERS
                    )
                    if results_r.status_code == 200:
                        items = results_r.json().get("selectors", [])
                        for item in items[:10]:
                            value = item.get("selectorvalue", "")
                            if "@" in value:  # It's an email
                                leaks.append({
                                    "id": f"ix-{sha256(value.encode()).hexdigest()[:8]}",
                                    "email": value,
                                    "source": "IntelX Phonebook",
                                    "date": "Unknown",
                                    "severity": "high",
                                    "status": "open",
                                    "has_password": False,
                                    "hint": "Email found in IntelX public phonebook index",
                                })
    except Exception as e:
        logger.warning(f"IntelX search failed: {e}")
    return leaks


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 6: Shodan InternetDB (Free, no key)
# Checks IP reputation for the resolved domain
# ─────────────────────────────────────────────────────────────────────────────
async def _check_shodan_ip(domain: str) -> dict | None:
    try:
        ip = socket.gethostbyname(domain)
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(f"https://internetdb.shodan.io/{ip}", headers=HEADERS)
            if r.status_code == 200:
                data = r.json()
                return {
                    "ip": ip,
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "tags": data.get("tags", []),
                    "hostnames": data.get("hostnames", []),
                    "cpes": data.get("cpes", []),
                }
    except Exception as e:
        logger.debug(f"Shodan InternetDB: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 7: URLhaus (abuse.ch) — Malicious URL Feed (Free, no key)
# ─────────────────────────────────────────────────────────────────────────────
async def _check_urlhaus(domain: str) -> list:
    mentions = []
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                json={"host": domain},
                headers=HEADERS
            )
            if r.status_code == 200 and r.json().get("query_status") == "ok":
                urls = r.json().get("urls", [])
                for url_data in urls[:5]:
                    mentions.append({
                        "id": f"uh-{sha256(str(url_data).encode()).hexdigest()[:8]}",
                        "title": f"URLhaus: Malicious URL — {url_data.get('url_status', 'active')}",
                        "snippet": f"Threat: {url_data.get('threat', 'malware')} | Tags: {', '.join(url_data.get('tags') or [])}",
                        "onion_site": "urlhaus.abuse.ch",
                        "severity": "critical",
                        "url": f"https://urlhaus.abuse.ch/url/{url_data.get('id', '')}",
                        "source_icon": "🦠"
                    })
    except Exception as e:
        logger.warning(f"URLhaus failed: {e}")
    return mentions


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 8: ThreatFox (abuse.ch) — IOC Intelligence (Free, no key)
# ─────────────────────────────────────────────────────────────────────────────
async def _check_threatfox(domain: str) -> list:
    mentions = []
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": domain},
                headers=HEADERS
            )
            if r.status_code == 200 and r.json().get("query_status") == "ok":
                iocs = r.json().get("data", [])
                for ioc in iocs[:5]:
                    mentions.append({
                        "id": f"tf-{sha256(str(ioc).encode()).hexdigest()[:8]}",
                        "title": f"ThreatFox: {ioc.get('threat_type', 'IOC')} — {ioc.get('malware', 'Unknown malware')}",
                        "snippet": f"Confidence: {ioc.get('confidence_level', 0)}% | Reporter: {ioc.get('reporter', 'anonymous')}",
                        "onion_site": "threatfox.abuse.ch",
                        "severity": "high",
                        "url": f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}",
                        "source_icon": "🎯"
                    })
    except Exception as e:
        logger.warning(f"ThreatFox failed: {e}")
    return mentions


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 9: OpenPhish — Active Phishing Feed (Free, no key)
# ─────────────────────────────────────────────────────────────────────────────
async def _check_openphish(domain: str) -> list:
    mentions = []
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get("https://openphish.com/feed.txt", headers=HEADERS)
            if r.status_code == 200:
                matches = [url for url in r.text.strip().split("\n") if domain in url]
                for url in matches[:5]:
                    mentions.append({
                        "id": f"op-{sha256(url.encode()).hexdigest()[:8]}",
                        "title": f"OpenPhish: Active Phishing URL Detected",
                        "snippet": url[:120],
                        "onion_site": "openphish.com",
                        "severity": "critical",
                        "url": "https://openphish.com/",
                        "source_icon": "🎣"
                    })
    except Exception as e:
        logger.warning(f"OpenPhish failed: {e}")
    return mentions


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 11: Crt.sh — Certificate Transparency (Free, no key)
# ─────────────────────────────────────────────────────────────────────────────
async def _check_crt_sh(domain: str) -> list:
    mentions = []
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers=HEADERS
            )
            if r.status_code == 200:
                data = r.json()
                subdomains = set()
                for cert in data:
                    name_value = cert.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if sub and "*" not in sub and sub != domain:
                            subdomains.add(sub)
                
                # Report up to 5 exposed subdomains
                for sub in list(subdomains)[:5]:
                    mentions.append({
                        "id": f"crt-{sha256(sub.encode()).hexdigest()[:8]}",
                        "title": f"Crt.sh: Exposed Subdomain via SSL — {sub}",
                        "snippet": f"Found in Certificate Transparency Logs. May expose dev/staging environments.",
                        "onion_site": "crt.sh",
                        "severity": "medium",
                        "url": f"https://crt.sh/?q={sub}",
                        "source_icon": "🔐"
                    })
    except Exception as e:
        logger.warning(f"Crt.sh failed: {e}")
    return mentions


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 12: HackerTarget — DNS/Subdomain Intelligence (Free, no key)
# ─────────────────────────────────────────────────────────────────────────────
async def _check_hackertarget(domain: str) -> list:
    mentions = []
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
            if r.status_code == 200 and "error" not in r.text.lower():
                lines = r.text.strip().split("\n")
                if len(lines) > 0 and lines[0] != "":
                    mentions.append({
                        "id": f"ht-{sha256(domain.encode()).hexdigest()[:8]}",
                        "title": f"HackerTarget: Host Search mapping",
                        "snippet": f"Discovered {len(lines)} associated hosts/IPs mapped to this domain.",
                        "onion_site": "hackertarget.com",
                        "severity": "medium",
                        "url": f"https://api.hackertarget.com/hostsearch/?q={domain}",
                        "source_icon": "🎯"
                    })
    except Exception as e:
        logger.warning(f"HackerTarget failed: {e}")
    return mentions


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 13: Optional paid sources (only if API keys configured)
# ─────────────────────────────────────────────────────────────────────────────
async def _check_threatminer(domain: str) -> list:
    mentions = []
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.get(
                "https://api.threatminer.org/v2/domain.php",
                params={"q": domain, "rt": 1},
                headers=HEADERS,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("status_code") == "200":
                    for item in (data.get("results") or [])[:6]:
                        mentions.append({
                            "id": f"tm-{sha256(str(item).encode()).hexdigest()[:8]}",
                            "title": "ThreatMiner: Passive DNS exposure",
                            "snippet": str(item)[:180],
                            "onion_site": "threatminer.org",
                            "severity": "medium",
                            "url": f"https://www.threatminer.org/domain.php?q={domain}",
                        })
    except Exception as e:
        logger.warning(f"ThreatMiner failed: {e}")
    return mentions


async def _check_wayback_exposure(domain: str) -> list:
    mentions = []
    risky_markers = ("password", "passwd", "secret", "token", "apikey", "api_key", ".env", "backup", "dump", "config")
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            r = await client.get(
                "https://web.archive.org/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "fl": "timestamp,original,statuscode,mimetype",
                    "filter": "statuscode:200",
                    "collapse": "urlkey",
                    "limit": 40,
                },
                headers=HEADERS,
            )
            if r.status_code == 200:
                rows = r.json()
                for row in rows[1:] if isinstance(rows, list) else []:
                    original = row[1] if len(row) > 1 else ""
                    if any(marker in original.lower() for marker in risky_markers):
                        mentions.append({
                            "id": f"wb-{sha256(original.encode()).hexdigest()[:8]}",
                            "title": "Wayback: historically exposed sensitive path",
                            "snippet": original[:180],
                            "onion_site": "web.archive.org",
                            "severity": "high",
                            "url": f"https://web.archive.org/web/*/{original}",
                        })
    except Exception as e:
        logger.warning(f"Wayback exposure search failed: {e}")
    return mentions


async def _check_commoncrawl(domain: str) -> list:
    mentions = []
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            coll = await client.get("https://index.commoncrawl.org/collinfo.json", headers=HEADERS)
            if coll.status_code != 200:
                return mentions
            indexes = coll.json()
            index_id = indexes[0].get("id") if indexes else None
            if not index_id:
                return mentions
            r = await client.get(
                f"https://index.commoncrawl.org/{index_id}-index",
                params={"url": f"*.{domain}/*", "output": "json", "limit": 20},
                headers=HEADERS,
            )
            if r.status_code == 200 and r.text.strip():
                for line in r.text.splitlines():
                    if any(marker in line.lower() for marker in ("password", "secret", "token", ".env", "backup", "dump")):
                        mentions.append({
                            "id": f"cc-{sha256(line.encode()).hexdigest()[:8]}",
                            "title": "Common Crawl: sensitive keyword in indexed URL",
                            "snippet": line[:220],
                            "onion_site": "commoncrawl.org",
                            "severity": "medium",
                            "url": "https://index.commoncrawl.org/",
                        })
                        if len(mentions) >= 5:
                            break
    except Exception as e:
        logger.warning(f"Common Crawl search failed: {e}")
    return mentions


async def _check_bufferover_dns(domain: str) -> list:
    mentions = []
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            r = await client.get(f"https://dns.bufferover.run/dns?q=.{domain}", headers=HEADERS)
            if r.status_code == 200:
                data = r.json()
                records = (data.get("FDNS_A") or []) + (data.get("RDNS") or [])
                if records:
                    mentions.append({
                        "id": f"bo-{sha256(domain.encode()).hexdigest()[:8]}",
                        "title": "BufferOver: passive DNS records found",
                        "snippet": f"{len(records)} DNS records linked to this domain. Review forgotten dev, VPN, staging, and exposed admin endpoints.",
                        "onion_site": "dns.bufferover.run",
                        "severity": "medium",
                        "url": f"https://dns.bufferover.run/dns?q=.{domain}",
                    })
    except Exception as e:
        logger.warning(f"BufferOver DNS failed: {e}")
    return mentions


async def _check_leaklookup(keyword: str) -> list:
    if not getattr(settings, "LEAK_LOOKUP_API_KEY", ""):
        return []
    leaks = []
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            query_type = "email_address" if "@" in keyword else "domain"
            r = await client.post(
                "https://leak-lookup.com/api/search",
                data={"key": settings.LEAK_LOOKUP_API_KEY, "type": query_type, "query": keyword}
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("error") == "false" and data.get("message"):
                    for breach_name in list(data["message"].keys())[:25]:
                        leaks.append({
                            "id": f"ll-{sha256(breach_name.encode()).hexdigest()[:8]}",
                            "email": keyword,
                            "source": f"Leak-Lookup — {breach_name}",
                            "date": "Unknown",
                            "severity": "high",
                            "status": "open",
                            "has_password": True,
                            "hint": "Breach database match via Leak-Lookup",
                        })
    except Exception as e:
        logger.error(f"Leak-Lookup API failed: {e}")
    return leaks


async def _check_breachdirectory(keyword: str) -> list:
    if not getattr(settings, "BREACH_DIRECTORY_API_KEY", ""):
        return []
    leaks = []
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://breachdirectory.p.rapidapi.com/v1/search?term={keyword}",
                headers={
                    "X-RapidAPI-Key": settings.BREACH_DIRECTORY_API_KEY,
                    "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
                }
            )
            if r.status_code == 200:
                for item in r.json().get("result", [])[:50]:
                    leaks.append({
                        "id": f"bd-{sha256(str(item).encode()).hexdigest()[:8]}",
                        "email": item.get("email") or keyword,
                        "source": f"BreachDirectory — {item.get('sources', ['Data Breach'])[0]}",
                        "date": item.get("date") or "Unknown",
                        "severity": "critical" if item.get("password") else "high",
                        "status": "open",
                        "has_password": bool(item.get("password")),
                        "hint": "Password or hash present in breach dataset" if item.get("password") else "SHA-1 hash indicator found",
                    })
    except Exception as e:
        logger.error(f"BreachDirectory API failed: {e}")
    return leaks


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCAN ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/scan")
async def scan_darkweb(
    q: str = Query(..., min_length=2),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """
    Real-time exposure scan using 10+ free intelligence sources
    combined with local threat database. Runs all sources in parallel.
    """
    keyword = normalize_query(q)
    now = datetime.utcnow()
    leaks = []
    mentions = []
    reputation_data = None
    password_check = None
    sources_checked = []
    premium_sources_skipped = []
    shodan_intel = None

    is_email = "@" in q.strip()
    is_domain = "." in keyword and "@" not in keyword
    is_password = not is_email and not is_domain

    # ── Run all sources in parallel ──────────────────────────────────────────
    tasks = []

    if is_email:
        tasks.append(("emailrep", _check_emailrep(keyword)))
        tasks.append(("intelx", _check_intelx(keyword)))
        tasks.append(("leakcheck", _check_leakcheck_public(keyword)))
        tasks.append(("xposedornot", _check_xposedornot(keyword)))
    
    if is_domain:
        tasks.append(("hibp_domain", _hibp_domain_breach_check(keyword)))
        tasks.append(("urlscan", _check_urlscan(keyword)))
        tasks.append(("urlhaus", _check_urlhaus(keyword)))
        tasks.append(("threatfox", _check_threatfox(keyword)))
        tasks.append(("openphish", _check_openphish(keyword)))
        tasks.append(("shodan", _check_shodan_ip(keyword)))
        tasks.append(("intelx", _check_intelx(keyword)))
        tasks.append(("leakcheck", _check_leakcheck_public(keyword)))
        tasks.append(("crtsh", _check_crt_sh(keyword)))
        tasks.append(("hackertarget", _check_hackertarget(keyword)))
        tasks.append(("threatminer", _check_threatminer(keyword)))
        tasks.append(("wayback", _check_wayback_exposure(keyword)))
        tasks.append(("commoncrawl", _check_commoncrawl(keyword)))
        tasks.append(("bufferover", _check_bufferover_dns(keyword)))
        tasks.append(("leaklookup", _check_leaklookup(keyword)))
        tasks.append(("breachdir", _check_breachdirectory(keyword)))

    if is_password:
        tasks.append(("hibp_pass", _check_hibp_password(keyword)))

    # Execute all in parallel
    task_names = [t[0] for t in tasks]
    task_coros = [t[1] for t in tasks]
    results = await asyncio.gather(*task_coros, return_exceptions=True)
    result_map = {task_names[i]: results[i] for i in range(len(results))}
    source_health = {
        SOURCE_LABELS.get(name, name): {
            "status": "error" if isinstance(result_map[name], Exception) else "checked",
            "records": 0 if isinstance(result_map[name], Exception) or result_map[name] is None else (
                len(result_map[name]) if isinstance(result_map[name], list) else 1
            ),
        }
        for name in task_names
    }
    sources_checked = [SOURCE_LABELS.get(name, name) for name in task_names if not isinstance(result_map.get(name), Exception)]

    # ── Process EmailRep ─────────────────────────────────────────────────────
    if "emailrep" in result_map and result_map["emailrep"] and not isinstance(result_map["emailrep"], Exception):
        emailrep = result_map["emailrep"]
        sources_checked.append("EmailRep.io")
        reputation_data = {
            "reputation": emailrep["reputation"],
            "suspicious": emailrep["suspicious"],
            "details": emailrep["details"],
        }
        leaks.extend(emailrep.get("leaks", []))

    # ── Process HIBP Domain Breach ───────────────────────────────────────────
    if "hibp_domain" in result_map and not isinstance(result_map["hibp_domain"], Exception):
        hibp_leaks = result_map["hibp_domain"]
        if hibp_leaks:
            sources_checked.append("Have I Been Pwned")
            leaks.extend(hibp_leaks)
        else:
            sources_checked.append("Have I Been Pwned (clean)")

    # ── Process HIBP Password ────────────────────────────────────────────────
    if "hibp_pass" in result_map and not isinstance(result_map["hibp_pass"], Exception):
        hibp = result_map["hibp_pass"]
        if hibp:
            sources_checked.append("HIBP Passwords")
            password_check = hibp
            if hibp.get("found"):
                leaks.append({
                    "id": f"hibp-{sha256(keyword.encode()).hexdigest()[:8]}",
                    "email": "password_check",
                    "source": f"HIBP Passwords ({hibp['breach_count']:,} breaches)",
                    "date": now.date().isoformat(),
                    "severity": hibp.get("severity", "high"),
                    "status": "open",
                    "has_password": True,
                    "hint": f"Password found in {hibp['breach_count']:,} data breaches",
                })

    # ── Process URLScan ──────────────────────────────────────────────────────
    if "urlscan" in result_map and not isinstance(result_map["urlscan"], Exception):
        urlscan_mentions = result_map["urlscan"]
        if urlscan_mentions:
            sources_checked.append("URLScan.io")
            mentions.extend(urlscan_mentions)

    # ── Process URLhaus ──────────────────────────────────────────────────────
    if "urlhaus" in result_map and not isinstance(result_map["urlhaus"], Exception):
        urlhaus_mentions = result_map["urlhaus"]
        if urlhaus_mentions:
            sources_checked.append("URLhaus (abuse.ch)")
            mentions.extend(urlhaus_mentions)

    # ── Process ThreatFox ────────────────────────────────────────────────────
    if "threatfox" in result_map and not isinstance(result_map["threatfox"], Exception):
        tf_mentions = result_map["threatfox"]
        if tf_mentions:
            sources_checked.append("ThreatFox (abuse.ch)")
            mentions.extend(tf_mentions)

    # ── Process OpenPhish ────────────────────────────────────────────────────
    if "openphish" in result_map and not isinstance(result_map["openphish"], Exception):
        op_mentions = result_map["openphish"]
        if op_mentions:
            sources_checked.append("OpenPhish")
            mentions.extend(op_mentions)

    # ── Process Crt.sh ───────────────────────────────────────────────────────
    if "crtsh" in result_map and not isinstance(result_map["crtsh"], Exception):
        crtsh_mentions = result_map["crtsh"]
        if crtsh_mentions:
            sources_checked.append("Crt.sh Certificate Logs")
            mentions.extend(crtsh_mentions)

    # ── Process HackerTarget ─────────────────────────────────────────────────
    if "hackertarget" in result_map and not isinstance(result_map["hackertarget"], Exception):
        ht_mentions = result_map["hackertarget"]
        if ht_mentions:
            sources_checked.append("HackerTarget")
            mentions.extend(ht_mentions)

    for key in ("threatminer", "wayback", "commoncrawl", "bufferover"):
        if key in result_map and not isinstance(result_map[key], Exception):
            extra_mentions = result_map[key]
            if extra_mentions:
                sources_checked.append(SOURCE_LABELS.get(key, key))
                mentions.extend(extra_mentions)

    # ── Process Shodan ───────────────────────────────────────────────────────
    if "shodan" in result_map and result_map["shodan"] and not isinstance(result_map["shodan"], Exception):
        shodan_intel = result_map["shodan"]
        sources_checked.append("Shodan InternetDB")
        if shodan_intel.get("vulns"):
            for vuln in shodan_intel["vulns"][:5]:
                mentions.append({
                    "id": f"sh-{sha256(vuln.encode()).hexdigest()[:8]}",
                    "title": f"Shodan: {vuln} detected on {shodan_intel['ip']}",
                    "snippet": f"Open ports: {', '.join(str(p) for p in shodan_intel.get('ports', [])[:8])} | Tags: {', '.join(shodan_intel.get('tags', []))}",
                    "onion_site": "shodan.io",
                    "severity": "critical",
                    "url": f"https://www.shodan.io/host/{shodan_intel['ip']}",
                    "source_icon": "🔭"
                })

    # ── Process IntelX ───────────────────────────────────────────────────────
    if "intelx" in result_map and not isinstance(result_map["intelx"], Exception):
        ix_leaks = result_map["intelx"]
        if ix_leaks:
            sources_checked.append("IntelX Phonebook")
            leaks.extend(ix_leaks)

    # ── Process LeakCheck ────────────────────────────────────────────────────
    if "leakcheck" in result_map and not isinstance(result_map["leakcheck"], Exception):
        lc_leaks = result_map["leakcheck"]
        if lc_leaks:
            sources_checked.append("LeakCheck.io")
            leaks.extend(lc_leaks)

    # ── Process XposedOrNot ──────────────────────────────────────────────────
    if "xposedornot" in result_map and not isinstance(result_map["xposedornot"], Exception):
        xon_leaks = result_map["xposedornot"]
        if xon_leaks:
            sources_checked.append("XposedOrNot")
            leaks.extend(xon_leaks)

    # ── Process paid sources ─────────────────────────────────────────────────
    if "leaklookup" in result_map and not isinstance(result_map["leaklookup"], Exception):
        ll = result_map["leaklookup"]
        if ll:
            sources_checked.append("Leak-Lookup")
            leaks.extend(ll)
        elif not getattr(settings, "LEAK_LOOKUP_API_KEY", ""):
            premium_sources_skipped.append("Leak-Lookup (add LEAK_LOOKUP_API_KEY)")

    if "breachdir" in result_map and not isinstance(result_map["breachdir"], Exception):
        bd = result_map["breachdir"]
        if bd:
            sources_checked.append("BreachDirectory")
            leaks.extend(bd)
        elif not getattr(settings, "BREACH_DIRECTORY_API_KEY", ""):
            premium_sources_skipped.append("BreachDirectory (add BREACH_DIRECTORY_API_KEY)")

    # ── Local DB intelligence ─────────────────────────────────────────────────
    advisory_hits = (
        db.query(Advisory)
        .filter(or_(Advisory.title.ilike(f"%{keyword}%"), Advisory.description.ilike(f"%{keyword}%")))
        .order_by(Advisory.created_at.desc())
        .limit(8).all()
    )
    ioc_hits = db.query(IOC).filter(IOC.value.ilike(f"%{keyword}%")).limit(8).all()

    for item in advisory_hits:
        mentions.append({
            "id": f"adv-{item.id}",
            "title": f"Advisory Match: {item.title[:60]}",
            "snippet": (item.description or "")[:180],
            "onion_site": "secureeye-local-db",
            "severity": item.severity.value if item.severity else "medium",
            "source_icon": "🗄️"
        })
    for item in ioc_hits:
        mentions.append({
            "id": f"ioc-{item.id}",
            "title": f"IOC: {item.value[:60]} ({item.ioc_type})",
            "snippet": f"Source: {item.source} | First seen in threat intelligence feed",
            "onion_site": "secureeye-ioc-db",
            "severity": "high",
            "source_icon": "🔴"
        })
    if advisory_hits or ioc_hits:
        sources_checked.append("SecureEye Intelligence DB")

    leaks = _dedupe_records([_safe_leak(item) for item in leaks])
    mentions = _dedupe_records(mentions)
    sources_checked = sorted(set(sources_checked))

    exposed_identities = [
        item.get("email")
        for item in leaks
        if item.get("email") and "accounts" not in str(item.get("email"))
    ]
    compromised_endpoints = [
        item for item in mentions
        if any(
            word in (item.get("title", "") + " " + item.get("snippet", "")).lower()
            for word in ("subdomain", "host", "dns", "shodan", "cve", "admin", "vpn", "staging")
        )
    ]
    data_classes = sorted({
        cls
        for item in leaks
        for cls in (item.get("data_classes") or [])
        if cls
    })

    # ── Determine overall exposure level ─────────────────────────────────────
    critical_count = sum(1 for l in leaks if l.get("severity") == "critical")
    if critical_count >= 2 or len(leaks) >= 5:
        exposure_level = "Critical"
    elif leaks or any(m.get("severity") == "critical" for m in mentions):
        exposure_level = "Elevated"
    elif mentions:
        exposure_level = "Watch"
    else:
        exposure_level = "Low"

    return {
        "query": keyword,
        "scanned_at": now.isoformat(),
        "exposure_level": exposure_level,
        "leaks": leaks,
        "mentions": mentions,
        "reputation": reputation_data,
        "password_check": password_check,
        "shodan_intel": shodan_intel,
        "sources_checked": sources_checked,
        "source_health": source_health,
        "premium_sources_skipped": premium_sources_skipped,
        "exposure_summary": {
            "exposed_identities": len(exposed_identities),
            "password_exposure_count": sum(1 for item in leaks if item.get("has_password")),
            "data_classes": data_classes,
            "compromised_endpoint_signals": len(compromised_endpoints),
            "credential_records_are_redacted": True,
            "note": "SecureEye reports exposure evidence and password-present signals only. Plaintext stolen passwords are not retrieved or displayed.",
        },
        "total_findings": len(leaks) + len(mentions),
        "api_active": True,
        "recommendations": [
            "Force password reset for all exposed accounts immediately.",
            "Enable MFA on all accounts associated with this domain.",
            "Cross-reference leaked credentials against internal Active Directory.",
            "Monitor for credential stuffing attacks against your login portal.",
            "Subscribe to HIBP domain notifications for future breach alerts.",
        ],
    }
