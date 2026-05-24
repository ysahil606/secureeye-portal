import asyncio
import httpx
import logging
import random
from datetime import datetime

logger = logging.getLogger("ticker_service")

# Global cache to hold the latest ticker bytes
TICKER_CACHE = [
    "[SYSTEM] MATRIX THREAT TICKER INITIALIZING...",
    "[SYSTEM] FETCHING LIVE INTELLIGENCE FEED..."
]

async def fetch_cisa_kev():
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
            data = res.json()
            vulns = data.get("vulnerabilities", [])
            # Sort by date added (newest first)
            vulns.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
            bytes_list = []
            for v in vulns[:5]:
                bytes_list.append(f"[🚨 CISA KEV] {v.get('cveID')} - {v.get('vulnerabilityName')} is actively exploited!")
            return bytes_list
    except Exception as e:
        logger.error(f"Failed to fetch CISA KEV: {e}")
        return []

async def fetch_ransomwatch():
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get("https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json", timeout=10)
            data = res.json()
            bytes_list = []
            for post in data[:5]:
                group = post.get('group_name', 'Unknown Syndicate')
                target = post.get('post_title', 'Unknown Target')
                bytes_list.append(f"[💀 RANSOMWARE] {group} has allegedly breached: {target}")
            return bytes_list
    except Exception as e:
        logger.error(f"Failed to fetch Ransomwatch: {e}")
        return []

async def fetch_urlhaus():
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get("https://urlhaus-api.abuse.ch/v1/urls/recent/", timeout=10)
            data = res.json()
            urls = data.get("urls", [])
            bytes_list = []
            for u in urls[:5]:
                host = u.get('urlhost', 'unknown')
                status = u.get('url_status', 'offline')
                if status == 'online':
                    bytes_list.append(f"[🦠 MALWARE] Active distribution site detected at {host} (Status: {status.upper()})")
            return bytes_list
    except Exception as e:
        logger.error(f"Failed to fetch URLhaus: {e}")
        return []

async def fetch_nvd_recent():
    try:
        # We can use circl.lu or nvd API. Circl is fast.
        async with httpx.AsyncClient() as client:
            res = await client.get("https://cve.circl.lu/api/last", timeout=10)
            data = res.json()
            bytes_list = []
            for cve in data[:5]:
                cve_id = cve.get('id')
                cvss = cve.get('cvss', 'N/A')
                bytes_list.append(f"[💥 NEW CVE] {cve_id} published with CVSS Base Score: {cvss}")
            return bytes_list
    except Exception as e:
        logger.error(f"Failed to fetch CIRCL CVEs: {e}")
        return []

async def update_ticker_cache():
    global TICKER_CACHE
    while True:
        try:
            logger.info("Updating Matrix Ticker Cache...")
            new_cache = []
            
            cisa = await fetch_cisa_kev()
            ransom = await fetch_ransomwatch()
            urlhaus = await fetch_urlhaus()
            nvd = await fetch_nvd_recent()
            
            new_cache.extend(cisa)
            new_cache.extend(ransom)
            new_cache.extend(urlhaus)
            new_cache.extend(nvd)
            
            if len(new_cache) > 0:
                random.shuffle(new_cache) # Shuffle for cool effect
                TICKER_CACHE.clear()
                TICKER_CACHE.extend(new_cache)
                logger.info(f"Matrix Ticker updated with {len(TICKER_CACHE)} bytes.")
                
        except Exception as e:
            logger.error(f"Error in ticker update loop: {e}")
            
        # Sleep for 1 hour before fetching again to stay under rate limits
        await asyncio.sleep(3600)

def get_ticker_bytes():
    global TICKER_CACHE
    return TICKER_CACHE
