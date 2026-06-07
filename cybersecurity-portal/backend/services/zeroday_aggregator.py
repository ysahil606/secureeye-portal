import httpx
import logging
import csv
import io
import re
import feedparser
from datetime import datetime

logger = logging.getLogger("zeroday_aggregator")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
PZ_CSV_URL = "https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/export?format=csv"
EDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

# Cache data in memory to avoid parsing CSVs every time
_cache = {}
_cache_time = 0
CACHE_TTL = 21600  # 6 hours

MNC_LIST = ["Microsoft", "Apple", "Google", "Cisco", "Fortinet", "Palo Alto", "VMware", "Oracle", "Adobe", "Atlassian", "Ivanti", "Trend Micro"]

async def fetch_cisa_kev(client: httpx.AsyncClient):
    try:
        r = await client.get(CISA_KEV_URL)
        r.raise_for_status()
        data = r.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        logger.error(f"Failed to fetch CISA KEV: {e}")
        return []

async def fetch_project_zero(client: httpx.AsyncClient) -> set:
    pz_cves = set()
    try:
        # Some endpoints block default httpx agent, use a normal browser agent
        headers = {"User-Agent": "Mozilla/5.0"}
        r = await client.get(PZ_CSV_URL, headers=headers, follow_redirects=True)
        r.raise_for_status()
        
        # Parse CSV
        content = r.text
        reader = csv.reader(io.StringIO(content))
        for i, row in enumerate(reader):
            if i == 0 or not row: continue # Skip header
            cve = row[0].strip()
            if cve.startswith("CVE-"):
                pz_cves.add(cve)
    except Exception as e:
        logger.error(f"Failed to fetch Project Zero: {e}")
    return pz_cves

async def fetch_exploit_db(client: httpx.AsyncClient) -> set:
    edb_cves = set()
    try:
        r = await client.get(EDB_CSV_URL)
        r.raise_for_status()
        
        content = r.text
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            codes = row.get("codes", "")
            # codes may contain multiple CVEs like 'CVE-2021-1234; OSVDB-1234'
            if "CVE-" in codes:
                matches = re.findall(r"CVE-\d{4}-\d{4,7}", codes, re.IGNORECASE)
                for m in matches:
                    edb_cves.add(m.upper())
    except Exception as e:
        logger.error(f"Failed to fetch Exploit-DB: {e}")
    return edb_cves

import asyncio
import time

async def get_unified_zerodays(limit: int = 50, force_refresh: bool = False):
    global _cache, _cache_time
    now = time.time()
    
    if not force_refresh and _cache and (now - _cache_time < CACHE_TTL):
        data = _cache.get("data", [])
        return {"status": "success", "count": min(len(data), limit), "data": data[:limit]}
        
    async with httpx.AsyncClient(timeout=30) as client:
        # Fetch all sources concurrently
        kev_task = asyncio.create_task(fetch_cisa_kev(client))
        pz_task = asyncio.create_task(fetch_project_zero(client))
        edb_task = asyncio.create_task(fetch_exploit_db(client))
        
        kev_data, pz_cves, edb_cves = await asyncio.gather(kev_task, pz_task, edb_task)
        
    # Sort KEV descending by date Added, tie-break with cveID descending so newer vulnerabilities show first
    kev_data.sort(key=lambda x: (x.get("dateAdded", ""), x.get("cveID", "")), reverse=True)
    
    mnc_vulns = []
    other_vulns = []
    
    for v in kev_data:
        cve_id = v.get("cveID", "").upper()
        
        # Enrich with Project Zero and Exploit-DB intel
        v["is_project_zero"] = cve_id in pz_cves
        v["has_public_exploit"] = cve_id in edb_cves
        
        vendor = v.get("vendorProject", "")
        is_mnc = any(m.lower() in vendor.lower() for m in MNC_LIST)
        
        if is_mnc:
            mnc_vulns.append(v)
        else:
            other_vulns.append(v)
            
    # Combine (MNCs prioritized at the top, followed by others, still generally sorted by date)
    combined = mnc_vulns + other_vulns
    
    _cache["data"] = combined
    _cache_time = now
    
    return {"status": "success", "count": min(len(combined), limit), "data": combined[:limit]}
