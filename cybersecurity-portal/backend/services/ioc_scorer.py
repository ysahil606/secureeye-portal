"""
IOC Scorer — Production-Grade Enrichment Engine
================================================
Key production features:
  1. TTL Cache       — 4-hour per-IOC cache (cachetools LRU+TTL), no re-enriching same IOC
  2. Budget Tracker  — Per-source daily/hourly counter; gracefully skips when near limit
  3. Retry Backoff   — Exponential retry on 429 / 5xx responses (max 3 retries)
  4. Deduplication   — Same IOC value in batch → enriched once, result shared
  5. CIDR Filter     — Spamhaus DROP network ranges skipped entirely
  6. Concurrency     — Source-specific semaphores to prevent API flooding

Sources (all free):
  IPs:    Shodan InternetDB (unlimited) + AbuseIPDB (1k/day) + GreyNoise + ip-api (45/min)
  Hashes: MalwareBazaar (unlimited) + AlienVault OTX (unlimited)
  Domain: AlienVault OTX (unlimited)
  URL:    AlienVault OTX (unlimited)
"""

import asyncio
import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Optional, Tuple

import httpx

try:
    from cachetools import TTLCache
    _HAS_CACHETOOLS = True
except ImportError:
    _HAS_CACHETOOLS = False

try:
    from config import settings
except ImportError:
    settings = None

logger = logging.getLogger("ioc_scorer")

# ─── Regex helpers ─────────────────────────────────────────────────────────────
_PLAIN_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_CIDR_RE     = re.compile(r"/\d+$")


def _is_plain_ip(v: str) -> bool:
    return bool(_PLAIN_IP_RE.match(v.strip()))


def _is_cidr(v: str) -> bool:
    return bool(_CIDR_RE.search(v))


# ─── TTL Enrichment Cache ──────────────────────────────────────────────────────
# Caches enrichment results per IOC for 4 hours.
# Max 5000 entries (LRU eviction when full).
# Key: (value, ioc_type)
_CACHE_TTL     = 4 * 3600   # 4 hours in seconds
_CACHE_MAXSIZE = 5000

if _HAS_CACHETOOLS:
    import threading
    _enrichment_cache: TTLCache = TTLCache(maxsize=_CACHE_MAXSIZE, ttl=_CACHE_TTL)
    _cache_lock = threading.Lock()
else:
    _enrichment_cache = {}
    _cache_lock = None

_cache_hits   = 0
_cache_misses = 0


def _cache_get(key: tuple) -> Optional[dict]:
    global _cache_hits, _cache_misses
    if _HAS_CACHETOOLS:
        with _cache_lock:
            result = _enrichment_cache.get(key)
    else:
        result = _enrichment_cache.get(key)
    if result is not None:
        _cache_hits += 1
    else:
        _cache_misses += 1
    return result


def _cache_set(key: tuple, value: dict):
    if _HAS_CACHETOOLS:
        with _cache_lock:
            _enrichment_cache[key] = value
    else:
        _enrichment_cache[key] = value


def get_cache_stats() -> dict:
    total = _cache_hits + _cache_misses
    return {
        "cache_size":    len(_enrichment_cache),
        "cache_maxsize": _CACHE_MAXSIZE,
        "cache_ttl_hours": _CACHE_TTL // 3600,
        "cache_hits":    _cache_hits,
        "cache_misses":  _cache_misses,
        "hit_rate_pct":  round((_cache_hits / total * 100) if total else 0, 1),
        "cachetools_available": _HAS_CACHETOOLS,
    }


# ─── Per-Source API Budget Tracker ─────────────────────────────────────────────
# Tracks how many calls each source has used per day/hour.
# When near limit, the source is skipped gracefully.
_SOURCE_BUDGETS = {
    "AbuseIPDB": {"limit": 950,  "window": 86400, "timestamps": []},  # 1000/day, stop at 950
    "ip-api":    {"limit": 40,   "window": 60,    "timestamps": []},  # 45/min,   stop at 40
    "GreyNoise": {"limit": 9000, "window": 86400, "timestamps": []},  # ~10k/day community
    "Shodan":    {"limit": 99000,"window": 86400, "timestamps": []},  # effectively unlimited
    "MalwareBazaar": {"limit": 99000, "window": 86400, "timestamps": []},
    "OTX":       {"limit": 99000, "window": 86400, "timestamps": []},
    "ThreatFox": {"limit": 99000, "window": 86400, "timestamps": []},
    "Pulsedive": {"limit": 99000, "window": 86400, "timestamps": []},
    "urlscan":   {"limit": 99000, "window": 86400, "timestamps": []},
}


def _budget_check(source: str) -> bool:
    """Returns True if we can call this source, False if budget exhausted."""
    cfg = _SOURCE_BUDGETS.get(source)
    if not cfg:
        return True
    now = time.time()
    window_ago = now - cfg["window"]
    cfg["timestamps"] = [t for t in cfg["timestamps"] if t > window_ago]
    return len(cfg["timestamps"]) < cfg["limit"]


def _budget_consume(source: str):
    cfg = _SOURCE_BUDGETS.get(source)
    if cfg:
        cfg["timestamps"].append(time.time())


def get_budget_status() -> dict:
    now = time.time()
    result = {}
    for source, cfg in _SOURCE_BUDGETS.items():
        window_ago = now - cfg["window"]
        recent = [t for t in cfg["timestamps"] if t > window_ago]
        window_label = "day" if cfg["window"] == 86400 else "min"
        result[source] = {
            "used":      len(recent),
            "limit":     cfg["limit"],
            "remaining": max(0, cfg["limit"] - len(recent)),
            "window":    window_label,
            "healthy":   len(recent) < cfg["limit"] * 0.9,
        }
    return result


# ─── Per-Hour IOC Rate Limiter (your own cap) ──────────────────────────────────
_RATE_LIMIT_PER_HOUR = 200
_rate_counters: dict = defaultdict(list)


def _check_rate_limit(ioc_type: str) -> Tuple[bool, int, int]:
    now = time.time()
    hour_ago = now - 3600
    _rate_counters[ioc_type] = [t for t in _rate_counters[ioc_type] if t > hour_ago]
    used = len(_rate_counters[ioc_type])
    remaining = max(0, _RATE_LIMIT_PER_HOUR - used)
    return used < _RATE_LIMIT_PER_HOUR, used, remaining


def _consume_rate(ioc_type: str):
    _rate_counters[ioc_type].append(time.time())


def get_rate_status() -> dict:
    now = time.time()
    hour_ago = now - 3600
    result = {}
    for ioc_type in ["ip", "domain", "hash", "url"]:
        clean = [t for t in _rate_counters[ioc_type] if t > hour_ago]
        _rate_counters[ioc_type] = clean
        used = len(clean)
        next_reset = 3600 - (now - clean[0]) if clean else 0
        result[ioc_type] = {
            "used": used,
            "limit": _RATE_LIMIT_PER_HOUR,
            "remaining": max(0, _RATE_LIMIT_PER_HOUR - used),
            "next_reset_seconds": int(max(0, next_reset)),
        }
    return result


# ─── Async Semaphores ──────────────────────────────────────────────────────────
_SEMAPHORE       = None  # Global enrichment semaphore
_IPAPI_SEMAPHORE = None  # ip-api.com specific (45/min limit)


def _get_sem():
    global _SEMAPHORE
    if _SEMAPHORE is None:
        _SEMAPHORE = asyncio.Semaphore(8)
    return _SEMAPHORE


def _get_ipapi_sem():
    global _IPAPI_SEMAPHORE
    if _IPAPI_SEMAPHORE is None:
        _IPAPI_SEMAPHORE = asyncio.Semaphore(2)  # Max 2 concurrent ip-api calls
    return _IPAPI_SEMAPHORE


# ─── Retry helper ──────────────────────────────────────────────────────────────
async def _get_with_retry(client: httpx.AsyncClient, url: str, **kwargs) -> Optional[httpx.Response]:
    """GET with exponential backoff on 429 / 5xx. Max 3 retries."""
    delays = [1.0, 2.0, 4.0]
    for attempt, delay in enumerate(delays):
        try:
            r = await client.get(url, **kwargs)
            if r.status_code == 429:
                logger.debug(f"Rate limited on {url}, waiting {delay}s (attempt {attempt+1})")
                await asyncio.sleep(delay)
                continue
            if r.status_code >= 500:
                await asyncio.sleep(delay)
                continue
            return r
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            if attempt < len(delays) - 1:
                await asyncio.sleep(delay)
            else:
                logger.debug(f"Request failed after retries: {url} — {e}")
    return None


async def _post_with_retry(client: httpx.AsyncClient, url: str, **kwargs) -> Optional[httpx.Response]:
    """POST with exponential backoff on 429 / 5xx. Max 2 retries."""
    delays = [1.0, 3.0]
    for attempt, delay in enumerate(delays):
        try:
            r = await client.post(url, **kwargs)
            if r.status_code in (429, 503):
                await asyncio.sleep(delay)
                continue
            return r
        except Exception:
            if attempt < len(delays) - 1:
                await asyncio.sleep(delay)
    return None


# ─── Score helpers ─────────────────────────────────────────────────────────────
def _risk_label(score: float) -> str:
    if score >= 85: return "critical"
    if score >= 65: return "high"
    if score >= 40: return "medium"
    if score >= 15: return "low"
    return "safe"


def _clamp(v: float) -> float:
    return max(0.0, min(100.0, v))


# ─── Enricher: Shodan InternetDB ───────────────────────────────────────────────
async def _enrich_shodan(ip: str, client: httpx.AsyncClient) -> dict:
    out = {"source": "Shodan", "score_delta": 0.0, "found": False, "data": {}}
    if not _is_plain_ip(ip) or not _budget_check("Shodan"):
        return out
    _budget_consume("Shodan")
    r = await _get_with_retry(client, f"https://internetdb.shodan.io/{ip}", timeout=10)
    if r and r.status_code == 200:
        try:
            d = r.json()
            vulns = d.get("vulns", [])
            tags  = d.get("tags",  [])
            ports = d.get("ports", [])
            out.update(found=True, data={"ports": ports[:10], "vulns": vulns[:5], "tags": tags})
            out["score_delta"] += min(len(vulns) * 8, 30)
            if any(t in tags for t in ["c2", "compromised", "malware", "eol-os"]):
                out["score_delta"] += 25
            if any(t in tags for t in ["self-signed", "honeypot"]):
                out["score_delta"] += 10
            sus_ports = {21, 22, 23, 25, 445, 1433, 3306, 3389, 4444, 8080, 8888, 9001}
            out["score_delta"] += len(set(ports) & sus_ports) * 5
            out["summary"] = f"{len(ports)} open ports · {len(vulns)} CVEs · tags: {', '.join(tags[:4]) or 'none'}"
        except Exception:
            pass
    return out


# ─── Enricher: AbuseIPDB ───────────────────────────────────────────────────────
async def _enrich_abuseipdb(ip: str, client: httpx.AsyncClient) -> dict:
    out = {"source": "AbuseIPDB", "score_delta": 0.0, "found": False, "data": {}}
    api_key = getattr(settings, "ABUSEIPDB_API_KEY", None) if settings else None
    if not _is_plain_ip(ip) or not api_key or not _budget_check("AbuseIPDB"):
        return out
    _budget_consume("AbuseIPDB")
    r = await _get_with_retry(
        client,
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": "90"},
        timeout=10,
    )
    if r and r.status_code == 200:
        try:
            d = r.json().get("data", {})
            score   = float(d.get("abuseConfidenceScore", 0))
            reports = d.get("totalReports", 0)
            out.update(found=score > 0, data={
                "abuse_score": score, "total_reports": reports,
                "usage_type": d.get("usageType", ""), "isp": d.get("isp", ""),
                "is_tor": d.get("isTor", False), "country": d.get("countryCode", ""),
            })
            out["score_delta"] = score * 0.8
            out["summary"] = f"Abuse score: {score:.0f}% · {reports} reports · {d.get('usageType','')}"
        except Exception:
            pass
    return out


# ─── Enricher: GreyNoise ───────────────────────────────────────────────────────
async def _enrich_greynoise(ip: str, client: httpx.AsyncClient) -> dict:
    out = {"source": "GreyNoise", "score_delta": 0.0, "found": False, "data": {}}
    if not _is_plain_ip(ip) or not _budget_check("GreyNoise"):
        return out
    _budget_consume("GreyNoise")
    r = await _get_with_retry(client, f"https://api.greynoise.io/v3/community/{ip}", timeout=8)
    if r and r.status_code == 200:
        try:
            d = r.json()
            cls = d.get("classification", "unknown")
            out.update(found=True, data={
                "classification": cls, "noise": d.get("noise", False),
                "riot": d.get("riot", False), "name": d.get("name", ""),
            })
            out["score_delta"] = 35 if cls == "malicious" else (-20 if cls == "benign" else 5)
            out["summary"] = f"GreyNoise: {cls} · noise={d.get('noise')} · riot={d.get('riot')}"
        except Exception:
            pass
    return out


# ─── Enricher: ip-api.com ─────────────────────────────────────────────────────
async def _enrich_ipapi(ip: str, client: httpx.AsyncClient) -> dict:
    out = {"source": "ip-api", "score_delta": 0.0, "found": False, "data": {}}
    if not _is_plain_ip(ip) or not _budget_check("ip-api"):
        return out
    _budget_consume("ip-api")
    sem = _get_ipapi_sem()
    async with sem:
        r = await _get_with_retry(
            client,
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,proxy,hosting",
            timeout=8,
        )
    if r and r.status_code == 200:
        try:
            d = r.json()
            if d.get("status") == "success":
                out.update(found=True, data={
                    "country": d.get("country", ""), "country_code": d.get("countryCode", ""),
                    "city": d.get("city", ""), "isp": d.get("isp", ""),
                    "org": d.get("org", ""), "is_proxy": d.get("proxy", False),
                    "is_hosting": d.get("hosting", False),
                })
                if d.get("proxy"):    out["score_delta"] += 15
                if d.get("hosting"):  out["score_delta"] += 8
                out["summary"] = (
                    f"{d.get('country','?')} · ISP: {d.get('isp','?')} · "
                    f"{'Proxy ' if d.get('proxy') else ''}{'Hosting' if d.get('hosting') else ''}"
                ).strip(" ·")
        except Exception:
            pass
    return out


# ─── Enricher: MalwareBazaar ──────────────────────────────────────────────────
async def _enrich_malwarebazaar(value: str, client: httpx.AsyncClient) -> dict:
    out = {"source": "MalwareBazaar", "score_delta": 0.0, "found": False, "data": {}}
    if not _budget_check("MalwareBazaar"):
        return out
    _budget_consume("MalwareBazaar")
    headers = {}
    if settings and getattr(settings, "MALWAREBAZAAR_AUTH_KEY", None):
        headers["API-KEY"] = settings.MALWAREBAZAAR_AUTH_KEY

    r = await _post_with_retry(
        client, "https://mb-api.abuse.ch/api/v1/",
        data={"query": "get_info", "hash": value}, timeout=10, headers=headers
    )
    if r and r.status_code == 200:
        try:
            d = r.json()
            if d.get("query_status") == "ok" and d.get("data"):
                s = d["data"][0]
                out.update(found=True, data={
                    "signature": s.get("signature", "Unknown"),
                    "file_type": s.get("file_type_mime", ""),
                    "tags": s.get("tags") or [],
                    "sha256": s.get("sha256_hash", ""),
                })
                out["score_delta"] = 75
                out["summary"] = f"MalwareBazaar: {s.get('signature','Unknown')} · {s.get('file_type_mime','')}"
        except Exception:
            pass
    return out


# ─── Enricher: AlienVault OTX ─────────────────────────────────────────────────
async def _enrich_otx(value: str, ioc_type: str, client: httpx.AsyncClient) -> dict:
    out = {"source": "OTX", "score_delta": 0.0, "found": False, "data": {}}
    api_key = getattr(settings, "ALIENVAULT_OTX_API_KEY", None) if settings else None
    if not api_key or not _budget_check("OTX"):
        return out
    _budget_consume("OTX")
    section_map = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "url"}
    section = section_map.get(ioc_type, "IPv4")
    r = await _get_with_retry(
        client,
        f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
        headers={"X-OTX-API-KEY": api_key},
        timeout=10,
    )
    if r and r.status_code == 200:
        try:
            d = r.json()
            pulse_count = d.get("pulse_info", {}).get("count", 0)
            tags = d.get("tags", [])
            out.update(found=pulse_count > 0, data={"pulse_count": pulse_count, "tags": tags[:5]})
            out["score_delta"] = min(pulse_count * 6, 40)
            out["summary"] = f"OTX: {pulse_count} threat pulses · tags: {', '.join(tags[:3]) or 'none'}"
        except Exception:
            pass
    return out


# ─── Enricher: ThreatFox ──────────────────────────────────────────────────────
async def _enrich_threatfox(value: str, client: httpx.AsyncClient) -> dict:
    out = {"source": "ThreatFox", "score_delta": 0.0, "found": False, "data": {}}
    if not _budget_check("ThreatFox"):
        return out
    _budget_consume("ThreatFox")
    headers = {}
    if settings and getattr(settings, "THREATFOX_AUTH_KEY", None):
        headers["API-KEY"] = settings.THREATFOX_AUTH_KEY

    r = await _post_with_retry(
        client, "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "search_ioc", "search_term": value}, timeout=10, headers=headers
    )
    if r and r.status_code == 200:
        try:
            d = r.json()
            if d.get("query_status") == "ok" and d.get("data"):
                item = d["data"][0]
                out.update(found=True, data={
                    "threat_type": item.get("threat_type"),
                    "malware": item.get("malware_printable"),
                    "confidence": item.get("confidence_level"),
                })
                # ThreatFox is highly deterministic
                out["score_delta"] = 99
                out["summary"] = f"ThreatFox: {item.get('malware_printable')} ({item.get('threat_type')})"
        except Exception:
            pass
    return out


# ─── Enricher: Pulsedive ──────────────────────────────────────────────────────
async def _enrich_pulsedive(value: str, client: httpx.AsyncClient) -> dict:
    out = {"source": "Pulsedive", "score_delta": 0.0, "found": False, "data": {}}
    if not _budget_check("Pulsedive"):
        return out
    _budget_consume("Pulsedive")
    import base64
    encoded_ioc = base64.b64encode(value.encode()).decode()
    url = f"https://pulsedive.com/api/info.php?indicator={encoded_ioc}"
    if settings and getattr(settings, "PULSEDIVE_API_KEY", None):
        url += f"&key={settings.PULSEDIVE_API_KEY}"
        
    r = await _get_with_retry(client, url, timeout=10)
    if r and r.status_code == 200:
        try:
            d = r.json()
            if "error" not in d:
                risk = d.get("risk", "none")
                out.update(found=risk != "none", data={
                    "risk": risk,
                    "properties": d.get("properties", {}),
                    "threats": d.get("threats", [])
                })
                if risk == "critical": out["score_delta"] = 80
                elif risk == "high": out["score_delta"] = 50
                elif risk == "medium": out["score_delta"] = 20
                out["summary"] = f"Pulsedive Risk: {risk}"
        except Exception:
            pass
    return out


# ─── Enricher: urlscan.io ─────────────────────────────────────────────────────
async def _enrich_urlscan(url: str, client: httpx.AsyncClient) -> dict:
    out = {"source": "urlscan.io", "score_delta": 0.0, "found": False, "data": {}}
    if not _budget_check("urlscan"):
        return out
    _budget_consume("urlscan")
    # Using community search
    r = await _get_with_retry(
        client, f"https://urlscan.io/api/v1/search/?q=page.url:\"{url}\"", timeout=10
    )
    if r and r.status_code == 200:
        try:
            d = r.json()
            if d.get("total", 0) > 0:
                result = d["results"][0]
                score = result.get("result", {}).get("score", 0)
                out.update(found=True, data={
                    "score": score,
                    "task_url": result.get("task", {}).get("url"),
                })
                out["score_delta"] = min(score, 80)
                out["summary"] = f"urlscan score: {score}"
        except Exception:
            pass
    return out


# ─── Master enrichment for a single IOC ───────────────────────────────────────
async def score_ioc(value: str, ioc_type: str, base_severity: str = "low") -> dict:
    """
    Enriches a single IOC. Checks cache first — if cached, returns instantly.
    CIDR ranges are skipped. Uses budget tracking per source.
    """
    # Skip CIDR blocks
    if ioc_type == "ip" and _is_cidr(value):
        return {
            "value": value, "ioc_type": ioc_type, "risk_score": None,
            "risk_label": "skip", "skip_reason": "cidr_block",
            "confirmed_malicious": False, "confirmation_count": 0,
            "source_details": [], "sources_confirmed": [], "sources_checked": [],
            "detection_ratio": "0/0 sources",
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }

    # Check cache first
    cache_key = (value.lower().strip(), ioc_type)
    cached = _cache_get(cache_key)
    if cached:
        return {**cached, "from_cache": True}

    # Enrich
    sem = _get_sem()
    async with sem:
        base_scores = {"critical": 70, "high": 55, "medium": 35, "low": 15}
        base_score  = base_scores.get(base_severity, 15)
        source_results = []

        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            if ioc_type == "ip":
                tasks = [
                    _enrich_shodan(value, client),
                    _enrich_abuseipdb(value, client),
                    _enrich_greynoise(value, client),
                    _enrich_ipapi(value, client),
                    _enrich_threatfox(value, client),
                    _enrich_pulsedive(value, client),
                ]
            elif ioc_type == "domain":
                tasks = [
                    _enrich_otx(value, ioc_type, client),
                    _enrich_threatfox(value, client),
                    _enrich_pulsedive(value, client),
                ]
            elif ioc_type == "hash":
                tasks = [
                    _enrich_malwarebazaar(value, client),
                    _enrich_otx(value, ioc_type, client),
                    _enrich_threatfox(value, client),
                ]
            elif ioc_type == "url":
                tasks = [
                    _enrich_otx(value, ioc_type, client),
                    _enrich_pulsedive(value, client),
                    _enrich_urlscan(value, client),
                ]
            else:
                tasks = []

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, Exception):
                    logger.debug(f"Enricher exception for {value}: {res}")
                    continue
                source_results.append(res)

        # Aggregated Risk Score Logic
        total_delta = sum(r.get("score_delta", 0) for r in source_results)
        
        # Immediate High Confidence deterministic hits override base calculation
        max_override = max([r.get("score_delta", 0) for r in source_results] + [0])
        if max_override >= 90:
            final_score = _clamp(max_override)
        else:
            final_score = _clamp(base_score + total_delta)
            
        # GreyNoise benign reducer check
        gn_result = next((r for r in source_results if r.get("source") == "GreyNoise"), None)
        if gn_result and gn_result.get("data", {}).get("classification") == "benign":
            final_score = _clamp(final_score - 50)
            
        risk_label = _risk_label(final_score)
        sources_found      = [s["source"] for s in source_results if s.get("found")]
        sources_checked    = [s["source"] for s in source_results]
        confirmation_count = len(sources_found)
        detection_ratio    = f"{confirmation_count}/{len(sources_checked)} sources"

        result = {
            "value":               value,
            "ioc_type":            ioc_type,
            "risk_score":          round(final_score, 1),
            "risk_label":          risk_label,
            "base_severity":       base_severity,
            "sources_checked":     sources_checked,
            "sources_confirmed":   sources_found,
            "confirmation_count":  confirmation_count,
            "detection_ratio":     detection_ratio,
            "confirmed_malicious": confirmation_count >= 1,
            "from_cache":          False,
            "source_details": [
                {
                    "source":  s["source"],
                    "found":   s.get("found", False),
                    "summary": s.get("summary", ""),
                    "data":    s.get("data", {}),
                }
                for s in source_results
            ],
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }

        # Store in cache
        _cache_set(cache_key, result)
        return result


# ─── Production batch enrichment ──────────────────────────────────────────────
async def enrich_batch(iocs: List[dict], max_per_type: int = 200, cached_only: bool = False) -> dict:
    """
    Production-grade batch enrichment:
    1. CIDR filter    — skip network ranges
    2. Deduplication  — enrich each unique IOC value only once
    3. Rate limit     — respect 200/type/hour self-limit
    4. Cache check    — cached IOCs don't hit any external API
    5. Filter output  — only confirmed malicious with score >= 30
    """
    enriched      = []
    rate_limited  = []
    skipped       = []
    cache_hits    = 0

    # Fast path: if cached_only, just return everything currently in the cache
    if cached_only:
        all_cached = []
        if _HAS_CACHETOOLS:
            with _cache_lock:
                all_cached = list(_enrichment_cache.values())
        else:
            all_cached = list(_enrichment_cache.values())
            
        confirmed = [
            r for r in all_cached
            if r.get("risk_label") not in ("skip", "error")
            and r.get("confirmed_malicious", False)
            and (r.get("risk_score") or 0) >= 30
        ]
        confirmed.sort(key=lambda x: (x.get("risk_score") or 0), reverse=True)
        return {
            "enriched": confirmed,
            "enriched_count": len(confirmed),
            "checked_count": len(all_cached),
            "cache_hits": len(all_cached),
            "fresh_enriched": 0,
            "false_positives_removed": 0,
            "rate_limited_count": 0,
            "skipped_cidr_count": 0,
            "rate_status": get_rate_status(),
            "api_budget_status": get_budget_status(),
            "cache_stats": get_cache_stats(),
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }

    # Step 1: CIDR filter
    valid_iocs = []
    for ioc in iocs:
        if ioc.get("ioc_type") == "ip" and _is_cidr(ioc.get("value", "")):
            skipped.append({**ioc, "skip_reason": "cidr_block"})
        else:
            valid_iocs.append(ioc)

    # Step 2: Deduplicate by (value, type) — keep highest severity if duplicate
    SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    seen_keys: dict = {}
    for ioc in valid_iocs:
        key = (ioc["value"].lower().strip(), ioc.get("ioc_type", ""))
        existing = seen_keys.get(key)
        if not existing:
            seen_keys[key] = ioc
        else:
            # Keep the one with higher severity
            if SEV_ORDER.get(ioc.get("severity", "low"), 0) > SEV_ORDER.get(existing.get("severity", "low"), 0):
                seen_keys[key] = ioc

    deduped = list(seen_keys.values())

    # Step 3: Check cache immediately — cache hits bypass rate limit
    to_enrich   = []
    from_cache  = []
    for ioc in deduped:
        cache_key = (ioc["value"].lower().strip(), ioc.get("ioc_type", ""))
        cached = _cache_get(cache_key)
        if cached:
            from_cache.append({**ioc, **cached, "from_cache": True})
            cache_hits += 1
        else:
            to_enrich.append(ioc)

    # Step 4: Rate limit for non-cached IOCs only
    by_type: dict = {"ip": [], "domain": [], "hash": [], "url": []}
    for ioc in to_enrich:
        t = ioc.get("ioc_type", "")
        if t in by_type:
            by_type[t].append(ioc)

    selected = []
    for ioc_type, items in by_type.items():
        allowed, used, remaining = _check_rate_limit(ioc_type)
        can_take = min(len(items), remaining, max_per_type)
        for item in items[:can_take]:
            selected.append(item)
            _consume_rate(ioc_type)
        for item in items[can_take:]:
            rate_limited.append({**item, "skip_reason": "rate_limit"})

    # Step 5: Enrich selected IOCs concurrently
    fresh_results = []
    if not cached_only:
        sem = asyncio.Semaphore(8)

        async def _bounded(ioc):
            async with sem:
                try:
                    return await score_ioc(
                        ioc["value"], ioc.get("ioc_type", ""), ioc.get("severity", "low")
                    )
                except Exception as e:
                    logger.warning(f"score_ioc failed for {ioc['value']}: {e}")
                    return None

        if selected:
            raw = await asyncio.gather(*[_bounded(ioc) for ioc in selected])
            for ioc, result in zip(selected, raw):
                if result:
                    fresh_results.append({**ioc, **result})

    # Step 6: Merge fresh + cache hits, then filter
    all_results = fresh_results + from_cache
    confirmed   = [
        r for r in all_results
        if (
            r.get("risk_label") not in ("skip", "error")
            and r.get("confirmed_malicious", False)
            and (r.get("risk_score") or 0) >= 30
        )
    ]

    # Sort: risk_score DESC, then cache hits first (they're free)
    confirmed.sort(key=lambda x: (x.get("risk_score") or 0), reverse=True)

    total_checked   = len(selected) + cache_hits
    fp_removed      = len(all_results) - len(confirmed)

    return {
        "enriched":               confirmed,
        "enriched_count":         len(confirmed),
        "checked_count":          total_checked,
        "cache_hits":             cache_hits,
        "fresh_enriched":         len(fresh_results),
        "false_positives_removed": fp_removed,
        "rate_limited_count":     len(rate_limited),
        "skipped_cidr_count":     len(skipped),
        "rate_status":            get_rate_status(),
        "api_budget_status":      get_budget_status(),
        "cache_stats":            get_cache_stats(),
        "enriched_at":            datetime.now(timezone.utc).isoformat(),
    }
