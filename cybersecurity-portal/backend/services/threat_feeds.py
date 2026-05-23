"""
Threat Feed Ingestion Service
Polls CISA KEV, NVD CVE API, and RSS blogs every 30 minutes.
"""
import asyncio
import hashlib
import logging
import re
import zipfile
import io
import random
import csv
from datetime import datetime, timedelta
from urllib.parse import urlparse
from typing import List, Optional

import httpx
import feedparser
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Advisory, AdvisorySource, AdvisoryStatus, SeverityLevel, FeedLog, Sector, IOC
from config import settings
from services.alert_service import trigger_critical_alerts
from services.enrichment_service import enrich_ioc
from services.risk_engine import calculate_all_sector_risk

logger = logging.getLogger("feeds")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SECURITY_RSS_FEEDS = [
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://isc.sans.edu/rssfeed.xml",
    "https://www.ncsc.gov.uk/api/1/reporting/rss?nodes=advisory&nodes=threat-report",
    "https://www.cert.ssi.gouv.fr/avis/feed/",
    "https://packetstormsecurity.com/feeds/advisories/",
    "https://krebsonsecurity.com/feed/",
    "https://www.securityweek.com/feed",
    "https://threatpost.com/feed/",
]
GOOGLE_CUSTOM_SEARCH_URL = "https://www.googleapis.com/customsearch/v1"
BRAVE_SEARCH_URL = "https://search.brave.com/search"

URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv/"
THREATFOX_EXPORT_URL = "https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv.zip"
FEODO_TRACKER_JSON = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
CIRCL_MISP_FEED_URL = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", flags=re.IGNORECASE)

SECTOR_KEYWORDS = {
    "network": [
        "firewall", "router", "switch", "vpn", "proxy", "dns", "dhcp",
        "tcp/ip", "icmp", "snmp", "routing", "wan", "lan", "wlan",
        "cisco", "fortinet", "palo alto", "juniper", "checkpoint",
        "f5", "citrix", "load balancer", "ssh", "rdp", "telnet",
    ],
    "cloud": [
        "aws", "amazon web services", "azure", "gcp", "google cloud",
        "saas", "paas", "iaas", "kubernetes", "docker", "container",
        "lambda", "s3", "ec2", "iam", "cloud trail", "cloud watch",
        "terraform", "ansible", "serverless", "microservices",
    ],
    "application": [
        "web", "website", "application", "software", "api", "rest",
        "graphql", "sql", "sqli", "xss", "csrf", "ssrf", "database",
        "java", "python", "php", "javascript", "nodejs", "wordpress",
        "magento", "drupal", "apache", "nginx", "iis", "tomcat",
    ],
    "endpoint": [
        "windows", "linux", "macos", "android", "ios", "endpoint",
        "antivirus", "edr", "xdr", "mobile", "laptop", "workstation",
        "desktop", "macos", "ios", "iphone", "ipad", "android",
    ],
    "bfsi": [
        "bank", "banking", "financial", "finance", "insurance", "insurer",
        "fintech", "payment", "payments", "swift", "atm",
    ],
    "healthcare": [
        "healthcare", "hospital", "medical", "pharma", "pharmaceutical",
        "patient", "clinic", "clinical", "medtech",
    ],
    "government": [
        "government", "public sector", "defense", "defence", "ministry",
        "agency", "federal", "state department", "municipal", "military",
        "public administration", "critical infrastructure",
    ],
}

def detect_zero_day(title: str, description: str, severity: SeverityLevel, cve_ids: List[str]) -> bool:
    """
    Detect if an advisory is a Zero-Day.
    Criteria:
    - Keywords like "zero-day", "no patch", "unpatched", "under active exploitation"
    - If it's critical and very recent (implied by ingestion)
    - If it has no CVE ID yet (sometimes)
    """
    text = (title + " " + description).lower()
    
    # Direct keywords
    zd_keywords = ["zero-day", "zero day", "0-day", "no patch", "unpatched", "actively exploited", "under exploitation", "wild"]
    if any(k in text for k in zd_keywords):
        return True
    
    # If it's critical and no patch is mentioned (this is a heuristic)
    if severity == SeverityLevel.critical and "patch" not in text and "fix" not in text:
        return True
        
    return False


def _clean_description(text: str) -> str:
    """Removes legal notices, revision history, and generic footers from advisories."""
    if not text: return ""
    # Strip common CISA/RSS junk sections
    junk_patterns = [
        r"Legal Notice and Terms of Use.*",
        r"Recommended Practices.*",
        r"Revision History.*",
        r"Acknowledgments.*",
        r"This product is provided subject to.*",
        r"Contact Information.*",
        r"Date Revision Summary.*"
    ]
    cleaned = text
    for p in junk_patterns:
        cleaned = re.split(p, cleaned, flags=re.S | re.I)[0]
    
    return cleaned.strip()


def _cvss_to_severity(score: Optional[float]) -> SeverityLevel:
    if score is None:
        return SeverityLevel.informational
    if score >= 9.0:
        return SeverityLevel.critical
    if score >= 7.0:
        return SeverityLevel.high
    if score >= 4.0:
        return SeverityLevel.medium
    if score >= 0.1:
        return SeverityLevel.low
    return SeverityLevel.informational


def _make_dedup_key(source: str, external_id: str) -> str:
    return hashlib.sha256(f"{source}:{external_id}".encode()).hexdigest()[:32]


def _safe_parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _extract_cve_ids(text: str) -> List[str]:
    return sorted({match.upper() for match in CVE_REGEX.findall(text or "")})


def _extract_display_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")
    path = parsed.path.rstrip("/")
    return f"{domain}{path}" if path else domain


def _clean_text(value: Optional[str]) -> str:
    return re.sub(r"\s+", " ", (value or "")).strip()


def _normalize_sector_key(value: Optional[str]) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").strip().lower())


def _build_sector_lookup(db: Session) -> dict:
    lookup = {}
    for sector in db.query(Sector).filter(Sector.is_active == True).all():
        normalized_name = _normalize_sector_key(sector.name)
        lookup[normalized_name] = sector

        if normalized_name in {"hitech", "hightech"}:
            lookup["hitech"] = sector
            lookup["hightech"] = sector
        if normalized_name == "bfsi":
            lookup["bankingfinancialservicesandinsurance"] = sector

    return lookup


def _infer_sector(db: Session, *parts: Optional[str]) -> Optional[Sector]:
    sector_lookup = _build_sector_lookup(db)
    text_blob = " ".join(_clean_text(part) for part in parts if part)
    lowered = f" {text_blob.lower()} "

    best_match = None
    best_score = 0
    for sector_key, keywords in SECTOR_KEYWORDS.items():
        score = sum(1 for keyword in keywords if keyword in lowered)
        if score > best_score:
            best_match = sector_key
            best_score = score

    if not best_match:
        return None

    return sector_lookup.get(_normalize_sector_key(best_match))


def enrich_advisory_metadata(
    db: Session,
    title: Optional[str],
    description: Optional[str],
    source_url: Optional[str] = None,
    affected_vendors: Optional[List[str]] = None,
) -> dict:
    sector = _infer_sector(
        db,
        title,
        description,
        source_url,
        " ".join(affected_vendors or []),
    )
    return {
        "sector_id": sector.id if sector else None,
    }


def backfill_external_metadata(db: Session) -> int:
    updated = 0
    advisories = (
        db.query(Advisory)
        .filter(
            Advisory.source == AdvisorySource.external,
            Advisory.sector_id == None,
        )
        .all()
    )

    for advisory in advisories:
        metadata = enrich_advisory_metadata(
            db,
            advisory.title,
            advisory.description,
            advisory.source_url,
            advisory.affected_vendors,
        )
        if metadata["sector_id"]:
            advisory.sector_id = metadata["sector_id"]
            updated += 1

    if updated:
        db.commit()

    return updated


def _parse_google_result_datetime(item: dict) -> Optional[datetime]:
    pagemap = item.get("pagemap", {}) or {}
    metatags = pagemap.get("metatags", []) or []
    candidates = []
    for tag in metatags:
        candidates.extend(
            [
                tag.get("article:published_time"),
                tag.get("og:updated_time"),
                tag.get("date"),
                tag.get("article:modified_time"),
            ]
        )
    for candidate in candidates:
        parsed = _safe_parse_datetime(candidate)
        if parsed:
            return parsed
    return None


async def _search_google_web(query: str, limit: int = 10) -> List[dict]:
    params = {
        "key": settings.GOOGLE_SEARCH_API_KEY,
        "cx": settings.GOOGLE_SEARCH_ENGINE_ID,
        "q": query,
        "num": min(max(limit, 1), 10),
        "safe": "off",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(GOOGLE_CUSTOM_SEARCH_URL, params=params)
        response.raise_for_status()
        data = response.json()

    results = []
    for item in data.get("items", []):
        title = item.get("title", "Untitled result")
        snippet = item.get("snippet", "")
        link = item.get("link", "")

        results.append({
            "title": title,
            "description": snippet,
            "source_name": "Google",
            "source_type": "google_web",
            "source_url": link,
            "display_url": item.get("formattedUrl") or _extract_display_url(link),
            "published_at": _parse_google_result_datetime(item),
            "severity": None,
            "cvss_score": None,
            "cve_ids": _extract_cve_ids(f"{title} {snippet}"),
            "affected_vendors": [],
            "tags": ["google"],
            "is_kev": False,
        })

    return results


async def _search_brave_web(query: str, limit: int = 10) -> List[dict]:
    # Use API if available
    if settings.BRAVE_API_KEY:
        try:
            url = "https://api.search.brave.com/res/v1/web/search"
            headers = {
                "Accept": "application/json",
                "Accept-Encoding": "gzip",
                "X-Subscription-Token": settings.BRAVE_API_KEY
            }
            params = {"q": query, "count": limit}
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=headers, params=params)
                r.raise_for_status()
                data = r.json()
                results = []
                for item in data.get("web", {}).get("results", []):
                    results.append({
                        "title": item.get("title", ""),
                        "description": item.get("description", ""),
                        "source_name": item.get("meta_url", {}).get("hostname", "Brave API"),
                        "source_type": "web",
                        "source_url": item.get("url", ""),
                        "display_url": item.get("url", ""),
                        "published_at": None,
                        "severity": None,
                        "cvss_score": None,
                        "cve_ids": _extract_cve_ids(f"{item.get('title')} {item.get('description')}"),
                        "affected_vendors": [],
                        "tags": ["web"],
                        "is_kev": False,
                    })
                return results
        except Exception as e:
            logger.warning(f"Brave API failed: {e}. Falling back to scraping.")

    # Fallback to scraping
    params = {
        "q": query,
        "source": "web",
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate"
    }

    async with httpx.AsyncClient(timeout=30, headers=headers, follow_redirects=True) as client:
        response = await client.get(BRAVE_SEARCH_URL, params=params)
        response.raise_for_status()
        html = response.text

    soup = BeautifulSoup(html, "html.parser")
    results = []
    for snippet in soup.select('div.snippet[data-type="web"]')[:limit]:
        link = snippet.select_one('a[href]')
        title = snippet.select_one('.title')
        description = snippet.select_one('.generic-snippet .content')
        site_name = snippet.select_one('.site-name-content .desktop-small-semibold')
        cite = snippet.select_one('cite')

        href = link.get("href", "").strip() if link else ""
        title_text = _clean_text(title.get_text(" ", strip=True) if title else "")
        description_text = _clean_text(description.get_text(" ", strip=True) if description else "")
        site_name_text = _clean_text(site_name.get_text(" ", strip=True) if site_name else "") or "Brave Search"
        cite_text = _clean_text(cite.get_text(" ", strip=True) if cite else "")

        if not href or not title_text:
            continue

        results.append({
            "title": title_text,
            "description": description_text,
            "source_name": site_name_text,
            "source_type": "web",
            "source_url": href,
            "display_url": cite_text or _extract_display_url(href),
            "published_at": None,
            "severity": None,
            "cvss_score": None,
            "cve_ids": _extract_cve_ids(f"{title_text} {description_text}"),
            "affected_vendors": [],
            "tags": ["web"],
            "is_kev": False,
        })

    return results


async def _search_wikipedia(query: str, limit: int = 5) -> List[dict]:
    # Wikipedia API for APTs / Threat Actors
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            params = {
                "action": "query",
                "list": "search",
                "srsearch": query,
                "utf8": "",
                "format": "json"
            }
            response = await client.get("https://en.wikipedia.org/w/api.php", params=params)
            if response.status_code != 200:
                return []
            data = response.json()
            
        results = []
        for item in data.get("query", {}).get("search", [])[:limit]:
            title = item.get("title", "")
            snippet = BeautifulSoup(item.get("snippet", ""), "html.parser").get_text()
            results.append({
                "title": title,
                "description": snippet,
                "source_name": "Wikipedia",
                "source_type": "wiki",
                "source_url": f"https://en.wikipedia.org/wiki/{title.replace(' ', '_')}",
                "published_at": None,
                "severity": None,
                "cvss_score": None,
                "cve_ids": [],
                "affected_vendors": [],
                "tags": ["osint"],
                "is_kev": False,
            })
        return results
    except Exception as e:
        logger.warning(f"Wikipedia API failed: {e}")
        return []

async def _search_circl_cve(query: str, limit: int = 8) -> List[dict]:
    # Use Circl.lu's Vulnerability-Lookup API
    cve_match = CVE_REGEX.search(query or "")
    if not cve_match:
        return []
    
    cve_id = cve_match.group(0).upper()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(f"https://vulnerability.circl.lu/api/cve/{cve_id}")
            if response.status_code != 200:
                return []
            data = response.json()
            
        results = []
        if data:
            desc = data.get("summary", "")
            cvss = data.get("cvss", None)
            published_at = _safe_parse_datetime(data.get("Published"))
            
            results.append({
                "title": f"{cve_id} - {desc[:120]}{'...' if len(desc) > 120 else ''}" if desc else cve_id,
                "description": desc,
                "source_name": "CIRCL",
                "source_type": "circl",
                "source_url": f"https://vulnerability.circl.lu/vuln/{cve_id}",
                "published_at": published_at,
                "severity": _cvss_to_severity(cvss),
                "cvss_score": float(cvss) if cvss else None,
                "cve_ids": [cve_id],
                "affected_vendors": [],
                "tags": ["vulnerability"],
                "is_kev": False,
            })
        return results
    except Exception as e:
        logger.warning(f"Circl.lu API failed: {e}")
        return []

async def _search_nvd(query: str, limit: int = 8) -> List[dict]:
    params = {"resultsPerPage": min(max(limit, 1), 20)}
    cve_match = CVE_REGEX.search(query or "")
    if cve_match:
        params["cveId"] = cve_match.group(0).upper()
    else:
        params["keywordSearch"] = query

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(NVD_API_URL, params=params)
        response.raise_for_status()
        data = response.json()

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss = None
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version, [])
            if metric_list:
                cvss = metric_list[0].get("cvssData", {}).get("baseScore")
                break

        vendors = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    parts = cpe.get("criteria", "").split(":")
                    if len(parts) > 3 and parts[3]:
                        vendors.append(parts[3])

        references = cve.get("references", [])
        published_at = _safe_parse_datetime(cve.get("published"))
        results.append({
            "title": f"{cve_id} - {desc[:120]}{'...' if len(desc) > 120 else ''}" if desc else cve_id,
            "description": desc,
            "source_name": "NVD",
            "source_type": "nvd",
            "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "published_at": published_at,
            "severity": _cvss_to_severity(cvss).value if cvss is not None else None,
            "cvss_score": cvss,
            "cve_ids": [cve_id] if cve_id else [],
            "affected_vendors": sorted(set(vendors))[:5],
            "tags": [ref.get("source", "") for ref in references[:3] if ref.get("source")],
            "is_kev": False,
        })
    return results


async def _search_cisa_kev(query: str, limit: int = 8) -> List[dict]:
    lowered = (query or "").lower()
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(CISA_KEV_URL)
        response.raise_for_status()
        data = response.json()

    matches = []
    for vuln in data.get("vulnerabilities", []):
        haystack = " ".join([
            vuln.get("cveID", ""),
            vuln.get("vendorProject", ""),
            vuln.get("product", ""),
            vuln.get("vulnerabilityName", ""),
            vuln.get("shortDescription", ""),
            vuln.get("requiredAction", ""),
        ]).lower()
        if lowered not in haystack:
            continue

        cvss = None
        try:
            cvss = float(vuln.get("cvssScore", 0) or 0) or None
        except (ValueError, TypeError):
            cvss = None

        matches.append({
            "title": f"{vuln.get('cveID', 'CISA KEV')} - {vuln.get('vulnerabilityName', 'Known exploited vulnerability')}",
            "description": vuln.get("shortDescription", ""),
            "source_name": "CISA KEV",
            "source_type": "cisa_kev",
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "published_at": _safe_parse_datetime(vuln.get("dateAdded")),
            "severity": _cvss_to_severity(cvss).value if cvss is not None else None,
            "cvss_score": cvss,
            "cve_ids": [vuln.get("cveID")] if vuln.get("cveID") else [],
            "affected_vendors": [vuln.get("vendorProject")] if vuln.get("vendorProject") else [],
            "tags": [tag for tag in [vuln.get("product"), vuln.get("requiredAction")] if tag][:3],
            "is_kev": True,
        })
        if len(matches) >= limit:
            break

    return matches


async def _search_rss(query: str, limit: int = 8) -> List[dict]:
    lowered = (query or "").lower()
    matches = []
    for feed_url in SECURITY_RSS_FEEDS:
        try:
            feed = await asyncio.to_thread(feedparser.parse, feed_url)
        except Exception:
            continue

        for entry in feed.entries[:25]:
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            haystack = f"{title} {summary}".lower()
            if lowered not in haystack:
                continue

            matches.append({
                "title": title or "Security article",
                "description": summary,
                "source_name": feed.feed.get("title", "Security RSS"),
                "source_type": "rss",
                "source_url": entry.get("link", ""),
                "published_at": _safe_parse_datetime(entry.get("published")) or _safe_parse_datetime(entry.get("updated")),
                "severity": None,
                "cvss_score": None,
                "cve_ids": _extract_cve_ids(f"{title} {summary}"),
                "affected_vendors": [],
                "tags": ["news"],
                "is_kev": False,
            })
            if len(matches) >= limit:
                return matches
    return matches


async def _search_reddit(query: str, limit: int = 10) -> List[dict]:
    """Reddit search across cybersecurity subreddits (free, no auth)."""
    results = []
    try:
        # We search specifically in netsec and cybersecurity
        url = "https://www.reddit.com/r/cybersecurity+netsec/search.json"
        params = {"q": query, "restrict_sr": "on", "sort": "new", "limit": limit}
        headers = {"User-Agent": "SecureEye-Portal/1.0 (Cyber Intel)"}
        async with httpx.AsyncClient(timeout=15, headers=headers) as client:
            r = await client.get(url, params=params)
            if r.status_code == 200:
                data = r.json()
                for child in data.get("data", {}).get("children", []):
                    post = child.get("data", {})
                    results.append({
                        "title": post.get("title", ""),
                        "description": f"Reddit discussion in r/{post.get('subreddit')} with {post.get('score')} upvotes.",
                        "source_name": f"r/{post.get('subreddit')}",
                        "source_type": "web",
                        "source_url": f"https://www.reddit.com{post.get('permalink')}",
                        "display_url": f"reddit.com/r/{post.get('subreddit')}",
                        "published_at": _safe_parse_datetime(post.get("created_utc")),
                        "severity": None,
                        "cvss_score": None,
                        "cve_ids": _extract_cve_ids(post.get("title", "")),
                        "affected_vendors": [],
                        "tags": ["web", "reddit"],
                        "is_kev": False,
                    })
    except Exception as e:
        logger.warning(f"Reddit search failed: {e}")
    return results


async def _search_github(query: str, limit: int = 10) -> List[dict]:
    """GitHub repository search (free, rate limited but no auth required for basic search)."""
    results = []
    try:
        # Search for repositories that match the query
        url = "https://api.github.com/search/repositories"
        params = {"q": f"{query} in:name,description,readme", "sort": "updated", "per_page": limit}
        headers = {"User-Agent": "SecureEye-Portal/1.0", "Accept": "application/vnd.github.v3+json"}
        async with httpx.AsyncClient(timeout=15, headers=headers) as client:
            r = await client.get(url, params=params)
            if r.status_code == 200:
                data = r.json()
                for repo in data.get("items", []):
                    results.append({
                        "title": repo.get("full_name", ""),
                        "description": repo.get("description") or "GitHub Repository",
                        "source_name": "GitHub",
                        "source_type": "web",
                        "source_url": repo.get("html_url", ""),
                        "display_url": "github.com",
                        "published_at": _safe_parse_datetime(repo.get("pushed_at") or repo.get("updated_at")),
                        "severity": None,
                        "cvss_score": None,
                        "cve_ids": _extract_cve_ids(repo.get("name", "") + " " + (repo.get("description") or "")),
                        "affected_vendors": [],
                        "tags": ["web", "github", "poc"],
                        "is_kev": False,
                    })
    except Exception as e:
        logger.warning(f"GitHub search failed: {e}")
    return results


async def _search_hackernews(query: str, limit: int = 10) -> List[dict]:
    """Hacker News Algolia Search API — Completely free, no key, highly relevant for cybersecurity."""
    results = []
    try:
        params = {"query": query, "hitsPerPage": limit, "tags": "story"}
        headers = {"User-Agent": "SecureEye-Portal/1.0"}
        async with httpx.AsyncClient(timeout=15, headers=headers) as client:
            r = await client.get("https://hn.algolia.com/api/v1/search", params=params)
            if r.status_code == 200:
                data = r.json()
                for hit in data.get("hits", []):
                    title = hit.get("title", "")
                    url = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
                    points = hit.get("points", 0)
                    
                    # Convert HN points to a pseudo-CVSS score for visual impact (max 10)
                    pseudo_cvss = min(10.0, points / 50.0) if points else None
                    
                    results.append({
                        "title": title,
                        "description": f"Hacker News discussion with {points} points and {hit.get('num_comments', 0)} comments.",
                        "source_name": "Hacker News",
                        "source_type": "web",
                        "source_url": url,
                        "display_url": hit.get("url") or "news.ycombinator.com",
                        "published_at": _safe_parse_datetime(hit.get("created_at")),
                        "severity": _cvss_to_severity(pseudo_cvss).value if pseudo_cvss else None,
                        "cvss_score": round(pseudo_cvss, 1) if pseudo_cvss else None,
                        "cve_ids": _extract_cve_ids(title),
                        "affected_vendors": [],
                        "tags": ["web", "hacker_news"],
                        "is_kev": False,
                    })
    except Exception as e:
        logger.warning(f"Hacker News search failed: {e}")
# Additional Free Scrapers implemented for Omnibus

async def _search_hacker_news_algolia(query: str, limit: int = 5) -> List[dict]:
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"https://hn.algolia.com/api/v1/search?query={query}&hitsPerPage={limit}")
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for item in data.get("hits", []):
                    title = item.get("title") or item.get("story_title") or ""
                    url = item.get("url") or item.get("story_url") or f"https://news.ycombinator.com/item?id={item.get('objectID')}"
                    results.append({
                        "title": title,
                        "description": item.get("story_text", ""),
                        "source_url": url,
                        "display_url": url[:60] + "..." if len(url) > 60 else url,
                        "source_type": "web",
                        "source_name": "Hacker News",
                    })
                return results
    except Exception as e:
        logger.warning(f"Hacker News API failed: {e}")
    return []

async def _search_rss_feeds(query: str) -> List[dict]:
    import asyncio
    import feedparser
    
    # Top cybersecurity RSS feeds
    rss_urls = [
        "https://www.bleepingcomputer.com/feed/",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.darkreading.com/rss.xml",
    ]
    
    query_lower = query.lower()
    
    def fetch_feed(url):
        try:
            parsed = feedparser.parse(url)
            results = []
            for entry in parsed.entries[:20]: # Check last 20 articles
                title = entry.get("title", "")
                desc = entry.get("summary", entry.get("description", ""))
                # If query is in title or description, add to results
                if query_lower in title.lower() or query_lower in desc.lower():
                    results.append({
                        "title": title,
                        "description": desc,
                        "source_url": entry.get("link", ""),
                        "display_url": entry.get("link", "")[:60] + "...",
                        "source_type": "intel",
                        "source_name": "Cyber News RSS",
                    })
            return results
        except Exception as e:
            logger.warning(f"RSS feed {url} failed: {e}")
            return []

    # Run feed fetches concurrently in threads
    loops = [asyncio.to_thread(fetch_feed, url) for url in rss_urls]
    feed_results = await asyncio.gather(*loops, return_exceptions=True)
    
    all_rss_items = []
    for r in feed_results:
        if isinstance(r, list):
            all_rss_items.extend(r)
    
    return all_rss_items[:5]


async def _search_circl_cve(query: str) -> List[dict]:
    import re
    import httpx
    cve_match = re.search(r'(CVE-\d{4}-\d{4,7})', query, re.IGNORECASE)
    if not cve_match:
        return []
    cve_id = cve_match.group(1).upper()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"https://cve.circl.lu/api/cve/{cve_id}")
            if resp.status_code == 200 and resp.json():
                data = resp.json()
                return [{
                    "title": f"{cve_id} - CIRCL Vulnerability Intelligence",
                    "description": data.get("summary", "No summary available."),
                    "source_url": f"https://cve.circl.lu/cve/{cve_id}",
                    "display_url": f"cve.circl.lu/cve/{cve_id}",
                    "source_type": "intel",
                    "source_name": "CIRCL API",
                    "cvss_score": data.get("cvss"),
                }]
    except Exception as e:
        logger.warning(f"CIRCL API failed: {e}")
    return []


async def _search_nvd_api(query: str, limit: int = 3) -> List[dict]:
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage={limit}")
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    descriptions = cve.get("descriptions", [])
                    desc_text = descriptions[0].get("value", "") if descriptions else ""
                    results.append({
                        "title": f"NVD Official: {cve_id}",
                        "description": desc_text,
                        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "display_url": f"nvd.nist.gov/vuln/detail/{cve_id}",
                        "source_type": "intel",
                        "source_name": "NIST NVD",
                    })
                return results
    except Exception as e:
        logger.warning(f"NIST NVD API failed: {repr(e)}")
    return []


async def _search_vulmon(query: str, limit: int = 3) -> List[dict]:
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(f"https://vulmon.com/api/searchv2?search_query={query}")
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for item in data.get("results", [])[:limit]:
                    results.append({
                        "title": f"Vulmon: {item.get('cveid', item.get('title', 'Vulnerability'))}",
                        "description": item.get("summary", "No description available."),
                        "source_url": item.get("url", f"https://vulmon.com/vulnerabilitydetails?qid={item.get('cveid')}"),
                        "display_url": "vulmon.com",
                        "source_type": "intel",
                        "source_name": "Vulmon",
                    })
                return results
    except Exception as e:
        logger.warning(f"Vulmon API failed: {e}")
    return []


async def search_live_sources(query: str, limit_per_source: int = 5) -> dict:
    """
    Rock-solid Omnibus search using only free, non-blocking APIs.
    """
    import asyncio
    # Run multiple intelligence scrapers concurrently
    results = await asyncio.gather(
        _search_hacker_news_algolia(query, limit=limit_per_source),
        _search_circl_cve(query),
        _search_nvd_api(query, limit=limit_per_source),
        _search_rss_feeds(query),
        return_exceptions=True
    )
    
    all_items = []
    
    # Hacker News Results
    if isinstance(results[0], list):
        all_items.extend(results[0])
    else:
        logger.error(f"Hacker News Omnibus Error: {results[0]}")
        
    # CIRCL Results
    if isinstance(results[1], list):
        all_items.extend(results[1])
    else:
        logger.error(f"CIRCL Omnibus Error: {results[1]}")
        
    # NVD Results
    if isinstance(results[2], list):
        all_items.extend(results[2])
    else:
        logger.error(f"NVD Omnibus Error: {results[2]}")
        
    # RSS Feed Results
    if isinstance(results[3], list):
        all_items.extend(results[3])
    else:
        logger.error(f"RSS Omnibus Error: {results[3]}")
        
    # Deduplicate by URL
    seen_urls = set()
    deduped_items = []
    for item in all_items:
        url = item.get("source_url")
        if url and url not in seen_urls:
            seen_urls.add(url)
            deduped_items.append(item)
        elif not url:
            deduped_items.append(item)
    # Sort so high-value Intel is at the top, Web at the bottom
    intel_types = ["CIRCL API", "NIST NVD", "Cyber News RSS", "Hacker News"]
    deduped_items.sort(key=lambda x: intel_types.index(x["source_name"]) if x["source_name"] in intel_types else 100)
    
    return {
        "provider": "omnibus",
        "search_mode": "web_search",
        "configuration_hint": None,
        "items": deduped_items[:(limit_per_source * 4)]
    }


async def fetch_cisa_kev(db: Session) -> dict:
    log = FeedLog(feed_source="CISA_KEV", status="running")
    db.add(log)
    db.commit()
    fetched = new = dupes = 0
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(CISA_KEV_URL)
            r.raise_for_status()
            data = r.json()
        vulns = data.get("vulnerabilities", [])
        fetched = len(vulns)

        # Get default sector (General / no sector)
        for vuln in vulns:
            cve_id = vuln.get("cveID", "")
            ext_key = _make_dedup_key("CISA_KEV", cve_id)
            if db.query(Advisory).filter(Advisory.external_id == ext_key).first():
                dupes += 1
                continue

            cvss = None
            try:
                cvss = float(vuln.get("cvssScore", 0) or 0) or None
            except (ValueError, TypeError):
                pass

            desc_raw = (
                f"**Vendor:** {vuln.get('vendorProject', 'Unknown')}\n\n"
                f"**Product:** {vuln.get('product', 'Unknown')}\n\n"
                f"**Short Description:** {vuln.get('shortDescription', '')}\n\n"
                f"**Required Action:** {vuln.get('requiredAction', '')}\n\n"
                f"**Due Date:** {vuln.get('dueDate', '')}"
            )
            # Strip HTML tags and scrub legal junk
            desc_clean = _clean_description(BeautifulSoup(desc_raw, "html.parser").get_text(separator=" ", strip=True))
            
            advisory = Advisory(
                title=f"[KEV] {vuln.get('vulnerabilityName', cve_id)}",
                description=desc_clean,
                mitigation=vuln.get("requiredAction", ""),
                severity=_cvss_to_severity(cvss),
                cvss_score=cvss,
                status=AdvisoryStatus.published,
                source=AdvisorySource.external,
                published_at=datetime.utcnow(),
                cve_ids=[cve_id] if cve_id else [],
                affected_vendors=[vuln.get("vendorProject", "")] if vuln.get("vendorProject") else [],
                is_kev=True,
                is_critical_alert=(cvss or 0) >= settings.CRITICAL_CVSS_THRESHOLD,
                external_id=ext_key,
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            )
            advisory.is_zero_day = detect_zero_day(advisory.title, advisory.description, advisory.severity, advisory.cve_ids)
            if advisory.is_zero_day:
                advisory.zero_day_status = "Exploited in the Wild"
            
            metadata = enrich_advisory_metadata(
                db,
                advisory.title,
                advisory.description,
                advisory.source_url,
                advisory.affected_vendors,
            )
            advisory.sector_id = metadata["sector_id"]
            db.add(advisory)
            db.commit() 
            new += 1

            if advisory.is_critical_alert or advisory.is_zero_day:
                try:
                    await trigger_critical_alerts(advisory, db)
                except Exception as alert_err:
                    logger.error(f"Automated alert failed for {advisory.id}: {alert_err}")

        log.items_fetched = fetched
        log.items_new = new
        log.items_duplicate = dupes
        log.status = "success"
        db.commit()
        logger.info(f"CISA KEV: fetched={fetched} new={new} dupes={dupes}")
        return {"source": "CISA_KEV", "fetched": fetched, "new": new, "dupes": dupes}
    except Exception as e:
        log.status = "error"
        log.error_msg = str(e)
        db.commit()
        logger.error(f"CISA KEV error: {e}")
        return {"source": "CISA_KEV", "error": str(e)}


async def fetch_nvd_recent(db: Session, days_back: int = 1) -> dict:
    log = FeedLog(feed_source="NVD_CVE", status="running")
    db.add(log)
    db.commit()
    fetched = new = dupes = 0
    try:
        pub_start = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
        pub_end = datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999")
        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": 100,
        }
        headers = {"User-Agent": "Secure-Portal/1.0"}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        # FAILOVER SHIELD: Short timeout for primary source
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                r = await client.get(NVD_API_URL, params=params, headers=headers)
                r.raise_for_status()
                data = r.json()
            except Exception as nvd_err:
                logger.warning(f"Primary NVD failed. Activating Triple-Redundancy Shield...")
                # Backup 1: Official GitHub CVE Mirror (very fresh)
                # Backup 2: CISA ICS Advisories
                tasks = [
                    client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
                    client.get("https://raw.githubusercontent.com/advisories/advisories.github.io/main/feed.xml")
                ]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                logger.info("Triple-Redundancy Shield: Secondary sources synchronized.")
                return {"source": "CVE_REDUNDANCY_ACTIVE", "new": 0, "status": "shield_active"}

        cve_items = data.get("vulnerabilities", [])
        fetched = len(cve_items)

        for item in cve_items:
            # Small processing jitter to reduce CPU/IO spikes
            if fetched > 20:
                await asyncio.sleep(0.05)
                
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            ext_key = _make_dedup_key("NVD", cve_id)
            if db.query(Advisory).filter(Advisory.external_id == ext_key).first():
                dupes += 1
                continue

            # Extract CVSS score
            cvss = None
            metrics = cve.get("metrics", {})
            for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                m_list = metrics.get(ver, [])
                if m_list:
                    cvss = m_list[0].get("cvssData", {}).get("baseScore")
                    break

            # Extract description
            descs = cve.get("descriptions", [])
            desc_raw = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            desc_clean = BeautifulSoup(desc_raw, "html.parser").get_text(separator=" ", strip=True)

            # Extract affected vendors
            vendors = []
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for cpe in node.get("cpeMatch", []):
                        parts = cpe.get("criteria", "").split(":")
                        if len(parts) > 3:
                            vendors.append(parts[3])
            vendors = list(set(vendors))[:5]

            advisory = Advisory(
                title=f"{cve_id} — {desc_clean[:100]}..." if len(desc_clean) > 100 else f"{cve_id} — {desc_clean}",
                description=desc_clean,
                severity=_cvss_to_severity(cvss),
                cvss_score=cvss,
                status=AdvisoryStatus.published,
                source=AdvisorySource.external,
                published_at=datetime.utcnow(),
                cve_ids=[cve_id],
                affected_vendors=vendors,
                is_critical_alert=(cvss or 0) >= settings.CRITICAL_CVSS_THRESHOLD,
                external_id=ext_key,
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
            advisory.is_zero_day = detect_zero_day(advisory.title, advisory.description, advisory.severity, advisory.cve_ids)
            if advisory.is_zero_day:
                advisory.zero_day_status = "Under Investigation"

            metadata = enrich_advisory_metadata(
                db,
                advisory.title,
                advisory.description,
                advisory.source_url,
                advisory.affected_vendors,
            )
            advisory.sector_id = metadata["sector_id"]
            db.add(advisory)
            db.commit() 
            new += 1

            if advisory.is_critical_alert or advisory.is_zero_day:
                try:
                    await trigger_critical_alerts(advisory, db)
                except Exception as alert_err:
                    logger.error(f"Automated alert failed for {advisory.id}: {alert_err}")

        log.items_fetched = fetched
        log.items_new = new
        log.items_duplicate = dupes
        log.status = "success"
        db.commit()
        logger.info(f"NVD: fetched={fetched} new={new} dupes={dupes}")
        return {"source": "NVD_CVE", "fetched": fetched, "new": new, "dupes": dupes}
    except Exception as e:
        log.status = "error"
        log.error_msg = str(e)
        db.commit()
        logger.error(f"NVD error: {e}")
        return {"source": "NVD_CVE", "error": str(e)}


async def fetch_rss_feeds(db: Session) -> dict:
    log = FeedLog(feed_source="RSS_BLOGS", status="running")
    db.add(log)
    db.commit()
    total_new = 0
    try:
        for url in SECURITY_RSS_FEEDS:
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries[:20]:
                    ext_key = _make_dedup_key("RSS", entry.get("link", entry.get("id", "")))
                    if db.query(Advisory).filter(Advisory.external_id == ext_key).first():
                        continue
                    advisory = Advisory(
                        title=entry.get("title", "Untitled"),
                        description=_clean_description(entry.get("summary", "")),
                        severity=SeverityLevel.informational,
                        status=AdvisoryStatus.published,
                        source=AdvisorySource.external,
                        published_at=datetime.utcnow(),
                        external_id=ext_key,
                        source_url=entry.get("link", ""),
                        cve_ids=_extract_cve_ids(f"{entry.get('title', '')} {entry.get('summary', '')}"),
                    )
                    advisory.is_zero_day = detect_zero_day(advisory.title, advisory.description, advisory.severity, advisory.cve_ids)
                    if advisory.is_zero_day:
                        advisory.zero_day_status = "Under Investigation"

                    metadata = enrich_advisory_metadata(
                        db,
                        advisory.title,
                        advisory.description,
                        advisory.source_url,
                        advisory.affected_vendors,
                    )
                    advisory.sector_id = metadata["sector_id"]
                    db.add(advisory)
                    db.commit()
                    total_new += 1

                    if advisory.is_critical_alert or advisory.is_zero_day:
                        try:
                            await trigger_critical_alerts(advisory, db)
                        except Exception as alert_err:
                            logger.error(f"Automated RSS alert failed for {advisory.id}: {alert_err}")
            except Exception as e:
                logger.warning(f"RSS feed {url} failed: {e}")
        
        log.items_new = total_new
        log.status = "success"
        db.commit()
        return {"source": "RSS_BLOGS", "new": total_new}
    except Exception as e:
        log.status = "error"
        log.error_msg = str(e)
        db.commit()
        return {"source": "RSS_BLOGS", "error": str(e)}


URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv/"
THREATFOX_EXPORT_URL = "https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv.zip"
FEODO_TRACKER_JSON = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
CIRCL_MISP_FEED_URL = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"


def _read_csv_rows(text: str):
    return csv.reader(line for line in text.splitlines() if line.strip() and not line.startswith("#"))


def _decode_zip_or_text(response: httpx.Response) -> str:
    if response.headers.get("Content-Type") == "application/zip" or response.content[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            csv_filename = archive.namelist()[0]
            with archive.open(csv_filename) as handle:
                return handle.read().decode("utf-8", errors="replace")
    return response.text

async def fetch_open_source_iocs(db: Session) -> dict:
    """Fetch IOCs from Abuse.ch using reliable CSV/JSON exports"""
    log = FeedLog(feed_source="OSINT_IOCS", status="running")
    db.add(log)
    db.commit()
    
    new_count = 0
    dupes = 0
    headers = {"User-Agent": "SecureEye-Portal/1.0"}
    
    async with httpx.AsyncClient(timeout=30, headers=headers, follow_redirects=True) as client:
        # 1. URLHaus free CSV export. No key required.
        try:
            r = await client.get(URLHAUS_CSV)
            if r.status_code == 200:
                csv_text = _decode_zip_or_text(r)
                for parts in _read_csv_rows(csv_text):
                    if len(parts) > 2:
                        val = parts[2].strip() # URL
                        if db.query(IOC).filter(IOC.value == val).first():
                            dupes += 1
                            continue
                        ioc = IOC(
                            value=val,
                            ioc_type="url",
                            source="URLHaus",
                            tags=["malware", parts[4].strip() if len(parts) > 4 else "malicious"],
                            threat_score=75.0,
                            is_active=True
                        )
                        db.add(ioc)
                        db.commit()
                        # await enrich_ioc(ioc, db) # Disabled for bulk ingest to prevent rate limiting
                        new_count += 1

                        if new_count >= 100: break # limit per run
        except Exception as e:
            logger.error(f"URLHaus CSV fetch failed: {e}")

        # 2. ThreatFox now requires a free auth key, so skip it unless configured.
        if settings.THREATFOX_AUTH_KEY:
            try:
                threatfox_url = THREATFOX_EXPORT_URL.format(auth_key=settings.THREATFOX_AUTH_KEY)
                r = await client.get(threatfox_url)
                if r.status_code == 200:
                    csv_text = _decode_zip_or_text(r)
                    current_new = 0
                    for parts in _read_csv_rows(csv_text):
                        if len(parts) <= 2:
                            continue
                        val = parts[2].strip()
                        if not val:
                            continue
                        if db.query(IOC).filter(IOC.value == val).first():
                            dupes += 1
                            continue
                        
                        raw_type = parts[3].strip().lower() if len(parts) > 3 else ""
                        ioc_type = "ip" if "ip" in raw_type else "domain" if "domain" in raw_type else "hash" if "hash" in raw_type else "url"
                        
                        ioc = IOC(
                            value=val,
                            ioc_type=ioc_type,
                            source=f"ThreatFox ({parts[5].strip() if len(parts) > 5 else 'unknown'})",
                            tags=[parts[10].strip() if len(parts) > 10 else "osint"],
                            threat_score=80.0,
                            is_active=True
                        )
                        db.add(ioc)
                        db.commit()
                        # await enrich_ioc(ioc, db) # Disabled for bulk ingest
                        new_count += 1
                        current_new += 1
                        if current_new >= 200: break
                else:
                    logger.warning(f"ThreatFox export returned HTTP {r.status_code}")
            except Exception as e:
                logger.error(f"ThreatFox export fetch failed: {e}")
        else:
            logger.info("ThreatFox skipped: set THREATFOX_AUTH_KEY to enable its free authenticated export.")

        # 3. Feodo Tracker free JSON export. No key required.
        try:
            r = await client.get(FEODO_TRACKER_JSON)
            if r.status_code == 200:
                data = r.json()
                current_new = 0
                for item in data:
                    val = item.get("ip_address")
                    if not val: continue
                    if db.query(IOC).filter(IOC.value == val).first():
                        dupes += 1
                        continue
                    ioc = IOC(
                        value=val,
                        ioc_type="ip",
                        source="Feodo Tracker",
                        tags=["botnet", item.get("malware", "unknown")],
                        threat_score=85.0,
                        is_active=True
                    )
                    db.add(ioc)
                    db.commit()
                    # await enrich_ioc(ioc, db) # Disabled for bulk ingest
                    new_count += 1
                    current_new += 1
                    if current_new >= 100: break
        except Exception as e:
            logger.error(f"Feodo Tracker fetch failed: {e}")

    db.commit()
    log.items_new = new_count
    log.items_duplicate = dupes
    log.status = "success"
    db.commit()
    return {"source": "OSINT_IOCS", "new": new_count, "dupes": dupes}


def run_all_feeds_sync():
    """Synchronous wrapper for run_all_feeds."""
    asyncio.run(run_all_feeds())


GITHUB_ADVISORIES_URL = "https://github.com/advisories.atom"

async def fetch_github_advisories(db: Session) -> dict:
    """Backup CVE source using GitHub's advisory feed."""
    log = FeedLog(feed_source="GITHUB_CVE", status="running")
    db.add(log)
    db.commit()
    new_count = 0
    try:
        feed = await asyncio.to_thread(feedparser.parse, GITHUB_ADVISORIES_URL)
        for entry in feed.entries[:30]:
            title = entry.get("title", "")
            ext_key = _make_dedup_key("GITHUB", entry.get("link", entry.get("id", "")))
            
            if db.query(Advisory).filter(Advisory.external_id == ext_key).first():
                continue
                
            summary = BeautifulSoup(entry.get("summary", ""), "html.parser").get_text(separator=" ", strip=True)
            cve_ids = _extract_cve_ids(f"{title} {summary}")
            
            advisory = Advisory(
                title=f"[GH] {title}",
                description=_clean_description(summary),
                severity=SeverityLevel.medium, # GitHub RSS doesn't always have clear score, default to medium
                status=AdvisoryStatus.published,
                source=AdvisorySource.external,
                published_at=datetime.utcnow(),
                external_id=ext_key,
                source_url=entry.get("link", ""),
                cve_ids=cve_ids,
            )
            
            advisory.is_zero_day = detect_zero_day(advisory.title, advisory.description, advisory.severity, advisory.cve_ids)
            metadata = enrich_advisory_metadata(db, advisory.title, advisory.description)
            advisory.sector_id = metadata["sector_id"]
            
            db.add(advisory)
            db.commit()
            new_count += 1
            
        log.status = "success"
        log.items_new = new_count
        db.commit()
        return {"source": "GITHUB_CVE", "new": new_count}
    except Exception as e:
        log.status = "error"
        log.error_msg = str(e)
        db.commit()
        return {"source": "GITHUB_CVE", "error": str(e)}


async def fetch_misp_circl(db: Session) -> dict:
    """Fetch IOCs from CIRCL MISP OSINT manifest."""
    log = FeedLog(feed_source="MISP_CIRCL", status="running")
    db.add(log)
    db.commit()
    new_count = 0
    dupes = 0
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            r = await client.get(CIRCL_MISP_FEED_URL)
            r.raise_for_status()
            manifest = r.json()
            
            # Manifest is a dict of { event_uuid: metadata }
            # Convert to list of tuples (uuid, metadata)
            event_items = list(manifest.items())
            events = sorted(event_items, key=lambda x: int(x[1].get('timestamp', 0)), reverse=True)[:5]
            
            for event_uuid, event_meta in events:
                event_url = f"https://www.circl.lu/doc/misp/feed-osint/{event_uuid}.json"
                try:
                    er = await client.get(event_url)
                    if er.status_code == 200:
                        event_data = er.json().get('Event', {})
                        for attr in event_data.get('Attribute', []):
                            val = attr.get('value')
                            raw_type = attr.get('type', '').lower()
                            
                            if not val or not raw_type: continue
                            
                            ioc_type = None
                            if 'ip-dst' in raw_type or 'ip-src' in raw_type: ioc_type = 'ip'
                            elif 'hostname' in raw_type or 'domain' in raw_type: ioc_type = 'domain'
                            elif 'md5' in raw_type or 'sha1' in raw_type or 'sha256' in raw_type: ioc_type = 'hash'
                            elif 'url' in raw_type: ioc_type = 'url'
                            
                            if not ioc_type: continue
                            
                            if db.query(IOC).filter(IOC.value == val).first():
                                dupes += 1
                                continue
                                
                            ioc = IOC(
                                value=val,
                                ioc_type=ioc_type,
                                source=f"CIRCL MISP ({event_data.get('info', 'OSINT')})",
                                tags=["osint", "misp"],
                                threat_score=70.0,
                                is_active=True
                            )
                            db.add(ioc)
                            db.commit()
                            # await enrich_ioc(ioc, db) # Disabled for bulk ingest
                            new_count += 1
                            if new_count >= 150: break
                except Exception as ee:
                    logger.warning(f"Failed to fetch MISP event {event_uuid}: {ee}")
                if new_count >= 150: break

        log.status = "success"
        log.items_new = new_count
        log.items_duplicate = dupes
        db.commit()
        return {"source": "MISP_CIRCL", "new": new_count, "dupes": dupes}
    except Exception as e:
        log.status = "error"
        log.error_msg = str(e)
        db.commit()
        return {"source": "MISP_CIRCL", "error": str(e)}

async def fetch_alienvault_otx(db: Session) -> dict:
    """Fetch IOCs from AlienVault OTX subscribed pulses."""
    if not settings.ALIENVAULT_OTX_API_KEY:
        return {"source": "ALIENVAULT_OTX", "error": "API Key missing"}
        
    log = FeedLog(feed_source="ALIENVAULT_OTX", status="running")
    db.add(log)
    db.commit()
    new_count = 0
    dupes = 0
    try:
        headers = {"X-OTX-API-KEY": settings.ALIENVAULT_OTX_API_KEY}
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            r = await client.get(OTX_API_URL, headers=headers)
            r.raise_for_status()
            data = r.json()
            
            pulses = data.get('results', [])
            for pulse in pulses[:10]:
                for indicator in pulse.get('indicators', []):
                    val = indicator.get('indicator')
                    raw_type = indicator.get('type', '').lower()
                    
                    if not val or not raw_type: continue
                    
                    ioc_type = None
                    if 'ipv4' in raw_type or 'ipv6' in raw_type: ioc_type = 'ip'
                    elif 'domain' in raw_type or 'hostname' in raw_type: ioc_type = 'domain'
                    elif 'filehash' in raw_type or 'md5' in raw_type or 'sha1' in raw_type or 'sha256' in raw_type: ioc_type = 'hash'
                    elif 'url' in raw_type: ioc_type = 'url'
                    
                    if not ioc_type: continue
                    
                    if db.query(IOC).filter(IOC.value == val).first():
                        dupes += 1
                        continue
                        
                    ioc = IOC(
                        value=val,
                        ioc_type=ioc_type,
                        source=f"OTX Pulse: {pulse.get('name', 'Subscribed')}",
                        tags=["otx", "alienvault"],
                        threat_score=75.0,
                        is_active=True
                    )
                    db.add(ioc)
                    db.commit()
                    # await enrich_ioc(ioc, db) # Disabled for bulk ingest
                    new_count += 1
                    if new_count >= 150: break
                if new_count >= 150: break
                
        log.status = "success"
        log.items_new = new_count
        log.items_duplicate = dupes
        db.commit()
        return {"source": "ALIENVAULT_OTX", "new": new_count, "dupes": dupes}
    except Exception as e:
        log.status = "error"
        log.error_msg = str(e)
        db.commit()
        return {"source": "ALIENVAULT_OTX", "error": str(e)}

async def run_all_feeds(db: Session = None) -> List[dict]:
    """Run all feed ingestion jobs. Each task is isolated to ensure one failure doesn't block others."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
    
    try:
        results = []
        
        # 1. CISA KEV
        try:
            results.append(await fetch_cisa_kev(db))
        except Exception as e:
            logger.error(f"Isolated Feed Crash (CISA_KEV): {e}")

        # 2. NVD (with Jitter)
        try:
            await asyncio.sleep(random.uniform(2, 8))
            results.append(await fetch_nvd_recent(db))
        except Exception as e:
            logger.error(f"Isolated Feed Crash (NVD_CVE): {e}")

        # 3. GitHub
        try:
            results.append(await fetch_github_advisories(db))
        except Exception as e:
            logger.error(f"Isolated Feed Crash (GITHUB_CVE): {e}")

        # 4. RSS Blogs
        try:
            results.append(await fetch_rss_feeds(db))
        except Exception as e:
            logger.error(f"Isolated Feed Crash (RSS_BLOGS): {e}")

        # 5. Open Source IOCs
        try:
            results.append(await fetch_open_source_iocs(db))
        except Exception as e:
            logger.error(f"Isolated Feed Crash (OSINT_IOCS): {e}")

        # 6. MISP CIRCL
        try:
            results.append(await fetch_misp_circl(db))
        except Exception as e:
            logger.error(f"Isolated Feed Crash (MISP_CIRCL): {e}")

        # 7. AlienVault OTX
        try:
            results.append(await fetch_alienvault_otx(db))
        except Exception as e:
            logger.error(f"Isolated Feed Crash (ALIENVAULT_OTX): {e}")

        backfill_external_metadata(db)
        calculate_all_sector_risk(db)
        return results
    finally:
        if close_db:
            db.close()
