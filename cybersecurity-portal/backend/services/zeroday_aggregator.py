import httpx
import logging
import csv
import io
import re
import asyncio
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("zeroday_aggregator")

# ── Source URLs ────────────────────────────────────────────────────────────────
CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
PZ_CSV_URL    = "https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/export?format=csv"
EDB_CSV_URL   = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
# CERT/CC VU# database - free curated zero-day advisories (RSS)
CERTCC_RSS    = "https://kb.cert.org/vuls/atomfeed/"
# NVD recent CVEs (published in last 90 days) that are in the KEV
NVD_RECENT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── Cache ──────────────────────────────────────────────────────────────────────
_cache      = {}
_cache_time = 0
CACHE_TTL   = 21600   # 6 hours

MNC_LIST = [
    "Microsoft", "Apple", "Google", "Cisco", "Fortinet", "Palo Alto",
    "VMware", "Oracle", "Adobe", "Atlassian", "Ivanti", "Trend Micro",
    "Citrix", "F5", "SolarWinds", "MOVEit", "Juniper", "Barracuda",
]

# ── Zero-Day Confirmation Criteria ─────────────────────────────────────────────
# A vulnerability is a "confirmed zero-day" when ANY of these are true:
#   1. It was added to CISA KEV within the last RECENT_DAYS days
#   2. It is confirmed by Google Project Zero as exploited in-the-wild
#   3. It was exploited BEFORE or within 30 days of a patch being released
RECENT_DAYS = 180   # entries added to KEV within this window are shown
PATCH_LAG_DAYS = 30 # if KEV added date is within N days of CVE publish = likely zero-day


def _parse_date(s: str) -> datetime | None:
    """Parse YYYY-MM-DD or ISO8601 date strings into UTC datetime."""
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(s[:19], fmt[:len(s[:19])]).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _is_confirmed_zeroday(v: dict, pz_cves: set) -> bool:
    """
    Return True only if this entry qualifies as a confirmed zero-day:
      - Added to CISA KEV within the last RECENT_DAYS, OR
      - Confirmed by Google Project Zero, OR
      - Was exploited before / very shortly after the patch (short patch-lag).
    """
    cve_id = v.get("cveID", "")

    # Criterion 1: Project Zero confirmation (most authoritative)
    if cve_id in pz_cves:
        return True

    date_added = _parse_date(v.get("dateAdded", ""))
    now = datetime.now(timezone.utc)

    # Criterion 2: Recently added to CISA KEV (still actively tracked)
    if date_added and (now - date_added).days <= RECENT_DAYS:
        return True

    # Criterion 3: CVE published date vs KEV date (exploited before/during patch)
    # NVD pubDate is not in KEV, but KEV year from cveID gives a rough signal
    match = re.match(r"CVE-(\d{4})-", cve_id)
    if match and date_added:
        cve_year = int(match.group(1))
        kev_year = date_added.year
        # If the CVE year matches KEV year or KEV was added within 1 year of CVE ⇒ zero-day window
        if kev_year - cve_year <= 1:
            return True

    return False


# ── Source Fetchers ────────────────────────────────────────────────────────────

async def fetch_cisa_kev(client: httpx.AsyncClient) -> list:
    try:
        r = await client.get(CISA_KEV_URL)
        r.raise_for_status()
        return r.json().get("vulnerabilities", [])
    except Exception as e:
        logger.error(f"CISA KEV fetch failed: {e}")
        return []


async def fetch_project_zero(client: httpx.AsyncClient) -> set:
    """
    Fetch Google Project Zero 0-day ITW spreadsheet.
    Returns a set of CVE IDs confirmed by Project Zero.
    """
    pz_cves = set()
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = await client.get(PZ_CSV_URL, headers=headers, follow_redirects=True)
        r.raise_for_status()
        reader = csv.reader(io.StringIO(r.text))
        for i, row in enumerate(reader):
            if i == 0 or not row:
                continue
            cve = row[0].strip()
            if cve.upper().startswith("CVE-"):
                pz_cves.add(cve.upper())
    except Exception as e:
        logger.error(f"Project Zero fetch failed: {e}")
    return pz_cves


async def fetch_exploit_db(client: httpx.AsyncClient) -> set:
    """Returns set of CVE IDs that have a public exploit in Exploit-DB."""
    edb_cves = set()
    try:
        r = await client.get(EDB_CSV_URL)
        r.raise_for_status()
        reader = csv.DictReader(io.StringIO(r.text))
        for row in reader:
            codes = row.get("codes", "")
            if "CVE-" in codes:
                for m in re.findall(r"CVE-\d{4}-\d{4,7}", codes, re.IGNORECASE):
                    edb_cves.add(m.upper())
    except Exception as e:
        logger.error(f"Exploit-DB fetch failed: {e}")
    return edb_cves


async def fetch_certcc_vulns(client: httpx.AsyncClient) -> list:
    """
    Fetch CERT/CC VU# database Atom feed.
    CERT/CC specifically covers novel/zero-day vulnerabilities.
    Returns a list of enrichment dicts keyed by CVE ID.
    """
    results = []
    try:
        import xml.etree.ElementTree as ET
        r = await client.get(CERTCC_RSS, headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
        r.raise_for_status()
        root = ET.fromstring(r.text)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        for entry in root.findall("atom:entry", ns)[:40]:
            title = entry.findtext("atom:title", "", ns)
            summary_el = entry.findtext("atom:summary", "", ns)
            link_el = entry.find("atom:link", ns)
            link = link_el.get("href", "") if link_el is not None else ""
            updated = entry.findtext("atom:updated", "", ns)

            # Extract any CVE IDs from title/summary
            cves = re.findall(r"CVE-\d{4}-\d{4,7}", f"{title} {summary_el}", re.IGNORECASE)
            results.append({
                "title": title,
                "summary": summary_el[:300],
                "link": link,
                "updated": updated[:10] if updated else "",
                "cves": [c.upper() for c in cves],
            })
    except Exception as e:
        logger.error(f"CERT/CC fetch failed: {e}")
    return results


async def fetch_nvd_recent_kev(client: httpx.AsyncClient) -> set:
    """
    Query NVD for CVEs published in the last 90 days that are tagged as KEV.
    This gives us very recent confirmed exploited-in-wild CVEs.
    """
    kev_recent = set()
    try:
        pub_start = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT00:00:00.000")
        pub_end   = datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59.999")
        params = {
            "pubStartDate": pub_start,
            "pubEndDate":   pub_end,
            "isKevRequired": "true",
            "resultsPerPage": 500,
        }
        r = await client.get(NVD_RECENT_URL, params=params, timeout=20)
        if r.status_code == 200:
            for vuln in r.json().get("vulnerabilities", []):
                cve_id = vuln.get("cve", {}).get("id", "")
                if cve_id:
                    kev_recent.add(cve_id.upper())
    except Exception as e:
        logger.error(f"NVD recent KEV fetch failed: {e}")
    return kev_recent


# ── Main Aggregator ────────────────────────────────────────────────────────────

async def get_unified_zerodays(limit: int = 50, force_refresh: bool = False):
    global _cache, _cache_time
    now = time.time()

    if not force_refresh and _cache and (now - _cache_time < CACHE_TTL):
        data = _cache.get("data", [])
        return {"status": "success", "count": min(len(data), limit), "data": data[:limit]}

    async with httpx.AsyncClient(timeout=30) as client:
        kev_task    = asyncio.create_task(fetch_cisa_kev(client))
        pz_task     = asyncio.create_task(fetch_project_zero(client))
        edb_task    = asyncio.create_task(fetch_exploit_db(client))
        certcc_task = asyncio.create_task(fetch_certcc_vulns(client))
        nvd_task    = asyncio.create_task(fetch_nvd_recent_kev(client))

        kev_data, pz_cves, edb_cves, certcc_data, nvd_recent_cves = await asyncio.gather(
            kev_task, pz_task, edb_task, certcc_task, nvd_task
        )

    # Build CERT/CC lookup by CVE
    certcc_by_cve: dict = {}
    for item in certcc_data:
        for cve in item.get("cves", []):
            certcc_by_cve[cve] = item

    # Sort KEV by dateAdded descending
    kev_data.sort(key=lambda x: (x.get("dateAdded", ""), x.get("cveID", "")), reverse=True)

    confirmed_zerodays = []

    for v in kev_data:
        cve_id = v.get("cveID", "").upper()

        # ── FILTER: only confirmed zero-days ──────────────────────────────────
        if not _is_confirmed_zeroday(v, pz_cves):
            # Still include if NVD confirms it was published recently AND in KEV
            if cve_id not in nvd_recent_cves:
                continue   # Skip — not a confirmed zero-day

        # ── Enrichment ────────────────────────────────────────────────────────
        v["is_project_zero"]   = cve_id in pz_cves
        v["has_public_exploit"] = cve_id in edb_cves
        v["is_nvd_recent"]     = cve_id in nvd_recent_cves
        v["certcc"]            = certcc_by_cve.get(cve_id)

        # Confirmation reason label for the UI
        reasons = []
        if cve_id in pz_cves:
            reasons.append("Project Zero")
        if cve_id in nvd_recent_cves:
            reasons.append("NVD Recent")
        date_added = _parse_date(v.get("dateAdded", ""))
        if date_added and (datetime.now(timezone.utc) - date_added).days <= RECENT_DAYS:
            reasons.append("CISA KEV")
        if certcc_by_cve.get(cve_id):
            reasons.append("CERT/CC")
        v["confirmed_by"] = reasons

        confirmed_zerodays.append(v)

    # Sort: Project Zero first, then NVD-recent, then by date
    def sort_key(v):
        pz    = 1 if v.get("is_project_zero") else 0
        nvd   = 1 if v.get("is_nvd_recent") else 0
        mnc   = 1 if any(m.lower() in v.get("vendorProject", "").lower() for m in MNC_LIST) else 0
        return (pz, nvd, mnc, v.get("dateAdded", ""))

    confirmed_zerodays.sort(key=sort_key, reverse=True)

    _cache["data"] = confirmed_zerodays
    _cache_time    = now

    logger.info(f"Zero-day aggregator: {len(confirmed_zerodays)} confirmed zero-days from {len(kev_data)} KEV entries")
    return {
        "status": "success",
        "count": min(len(confirmed_zerodays), limit),
        "data": confirmed_zerodays[:limit],
        "sources": ["CISA KEV", "Google Project Zero", "Exploit-DB", "CERT/CC VU#", "NVD Recent"]
    }
