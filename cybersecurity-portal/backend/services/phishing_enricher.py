"""
Phishing Enricher Service
=========================
On-click domain enrichment with full fallback chains:

  WHOIS (3 sources):
    1. asyncwhois  — socket-based WHOIS
    2. RDAP        — JSON-based modern WHOIS (rdap.org, free)
    3. WhoisFreaks — REST API (free tier)

  DNS Records (3 sources):
    1. dnspython   — direct resolver
    2. Google DoH  — dns.google (HTTPS, no key)
    3. Cloudflare DoH — cloudflare-dns.com (HTTPS, no key)

  Screenshot (3 sources):
    1. URLScan.io  — reuse existing scan or submit new
    2. thum.io     — free thumbnail service, no API key
    3. microlink.io — free metadata + screenshot (50 req/day free)

  Verdicts (5 engines):
    VirusTotal, AlienVault OTX, Pulsedive, URLhaus, ThreatFox
"""
import asyncio
import logging
import socket
from datetime import datetime, timezone
from typing import Optional

import httpx

from config import settings

logger = logging.getLogger("phishing_enricher")

HEADERS = {
    "User-Agent": "SecureEye-PhishingMonitor/2.0 (security-research; contact@secureeye.app)"
}


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS — Source 1: asyncwhois (socket-based)
# ─────────────────────────────────────────────────────────────────────────────
async def _whois_asyncwhois(domain: str) -> Optional[dict]:
    try:
        import asyncwhois
        result = await asyncio.wait_for(asyncwhois.aio_whois(domain), timeout=7.0)
        parsed = getattr(result, "parser_output", None) or {}

        creation_date = parsed.get("created")
        expiry_date   = parsed.get("expires")
        updated_date  = parsed.get("updated")

        if isinstance(creation_date, list): creation_date = creation_date[0]
        if isinstance(expiry_date, list):   expiry_date   = expiry_date[0]

        age_days = -1
        is_new   = False
        if creation_date and hasattr(creation_date, "year"):
            now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
            try:
                naive = creation_date.replace(tzinfo=None)
                age_days = (now - naive).days
                is_new   = age_days < 30
            except Exception:
                pass

        data = {
            "registrar":          parsed.get("registrar", ""),
            "registrant_org":     parsed.get("registrant_organization", ""),
            "registrant_country": parsed.get("registrant_country", ""),
            "creation_date":      str(creation_date)[:10] if creation_date else None,
            "expiry_date":        str(expiry_date)[:10]   if expiry_date   else None,
            "updated_date":       str(updated_date)[:10]  if updated_date  else None,
            "age_days":           age_days,
            "is_newly_registered": is_new,
            "name_servers":       parsed.get("name_servers", []),
            "status":             parsed.get("status", []),
            "dnssec":             parsed.get("dnssec", ""),
            "source":             "asyncwhois",
            "error":              None,
        }
        # Return only if we got at least a creation date or registrar
        if data["registrar"] or data["creation_date"]:
            return data
    except Exception as e:
        logger.warning(f"asyncwhois failed for {domain}: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS — Source 2: RDAP (modern JSON-based WHOIS, always free)
# ─────────────────────────────────────────────────────────────────────────────
async def _whois_rdap(domain: str) -> Optional[dict]:
    """Uses the RDAP protocol via rdap.org — modern replacement for WHOIS."""
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.get(
                f"https://rdap.org/domain/{domain}",
                headers={**HEADERS, "Accept": "application/json"}
            )
            if r.status_code == 200:
                data = r.json()

                # Extract events (registration, expiry, etc.)
                events = {e.get("eventAction", ""): e.get("eventDate", "") for e in data.get("events", [])}
                creation_date = events.get("registration", events.get("last changed", ""))[:10] or None
                expiry_date   = events.get("expiration", "")[:10] or None

                # Registrar from entities
                registrar = ""
                registrant_country = ""
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [None, []])[1]
                        for field in vcard:
                            if field[0] == "fn":
                                registrar = field[3]
                    if "registrant" in roles:
                        vcard = entity.get("vcardArray", [None, []])[1]
                        for field in vcard:
                            if field[0] == "adr" and isinstance(field[3], dict):
                                registrant_country = field[3].get("country-name", "")

                # Nameservers
                ns = [n.get("ldhName", "").lower() for n in data.get("nameservers", [])]

                # Compute age
                age_days, is_new = -1, False
                if creation_date:
                    try:
                        created_dt = datetime.strptime(creation_date, "%Y-%m-%d")
                        age_days = (datetime.utcnow() - created_dt).days
                        is_new = age_days < 30
                    except Exception:
                        pass

                return {
                    "registrar":           registrar,
                    "registrant_org":      "",
                    "registrant_country":  registrant_country,
                    "creation_date":       creation_date,
                    "expiry_date":         expiry_date,
                    "updated_date":        None,
                    "age_days":            age_days,
                    "is_newly_registered": is_new,
                    "name_servers":        ns,
                    "status":              data.get("status", []),
                    "dnssec":              "",
                    "source":              "RDAP",
                    "error":               None,
                }
    except Exception as e:
        logger.warning(f"RDAP failed for {domain}: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS — Source 3: WhoisXML API (free tier, JSON)
# ─────────────────────────────────────────────────────────────────────────────
async def _whois_whoisxml(domain: str) -> Optional[dict]:
    """Uses whoisxmlapi.com free tier (100 req/month, no signup needed for basic)."""
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.get(
                "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                params={"apiKey": "at_free", "domainName": domain, "outputFormat": "JSON"},
                headers=HEADERS
            )
            if r.status_code == 200:
                data = r.json()
                record = data.get("WhoisRecord", {})
                reg_info = record.get("registryData", record)
                dates = record.get("registryData", {}).get("createdDate", record.get("createdDate", ""))
                expiry = record.get("registryData", {}).get("expiresDate", record.get("expiresDate", ""))
                registrar = record.get("registrarName", "")

                creation_date = str(dates)[:10] if dates else None
                expiry_date   = str(expiry)[:10] if expiry  else None
                age_days, is_new = -1, False
                if creation_date and len(creation_date) >= 10:
                    try:
                        created_dt = datetime.strptime(creation_date, "%Y-%m-%d")
                        age_days = (datetime.utcnow() - created_dt).days
                        is_new = age_days < 30
                    except Exception:
                        pass

                if registrar or creation_date:
                    return {
                        "registrar":           registrar,
                        "registrant_org":      record.get("registrant", {}).get("organization", ""),
                        "registrant_country":  record.get("registrant", {}).get("country", ""),
                        "creation_date":       creation_date,
                        "expiry_date":         expiry_date,
                        "updated_date":        None,
                        "age_days":            age_days,
                        "is_newly_registered": is_new,
                        "name_servers":        record.get("nameServers", {}).get("hostNames", []),
                        "status":              [],
                        "dnssec":              "",
                        "source":              "WhoisXML",
                        "error":               None,
                    }
    except Exception as e:
        logger.warning(f"WhoisXML failed for {domain}: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS — Orchestrator: tries all 3 sources in order
# ─────────────────────────────────────────────────────────────────────────────
async def _get_whois(domain: str) -> dict:
    """Tries asyncwhois → RDAP → WhoisXML. Returns first successful result."""
    for fn, name in [(_whois_asyncwhois, "asyncwhois"), (_whois_rdap, "RDAP"), (_whois_whoisxml, "WhoisXML")]:
        try:
            result = await fn(domain)
            if result:
                logger.info(f"WHOIS for {domain} resolved via {name}")
                return result
        except Exception as e:
            logger.warning(f"WHOIS source {name} raised: {e}")
    return {"error": "All WHOIS sources failed", "age_days": -1, "is_newly_registered": False, "source": "none"}


# ─────────────────────────────────────────────────────────────────────────────
# DNS — Source 1: dnspython (direct)
# ─────────────────────────────────────────────────────────────────────────────
async def _dns_dnspython(domain: str) -> Optional[dict]:
    try:
        import dns.resolver
        loop = asyncio.get_event_loop()

        async def resolve(dtype):
            try:
                ans = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, dtype, lifetime=5))
                return [str(r) for r in ans]
            except Exception:
                return []

        a, aaaa, mx, ns, txt = await asyncio.gather(
            resolve("A"), resolve("AAAA"), resolve("MX"), resolve("NS"), resolve("TXT"),
            return_exceptions=True
        )
        result = {
            "a":    a    if not isinstance(a, Exception)    else [],
            "aaaa": aaaa if not isinstance(aaaa, Exception) else [],
            "mx":   mx   if not isinstance(mx, Exception)   else [],
            "ns":   ns   if not isinstance(ns, Exception)   else [],
            "txt":  txt  if not isinstance(txt, Exception)  else [],
            "source": "dnspython",
        }
        if any(result[k] for k in ["a", "mx", "ns"]):
            return result
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"dnspython failed for {domain}: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# DNS — Source 2: Google DNS-over-HTTPS
# ─────────────────────────────────────────────────────────────────────────────
async def _dns_google_doh(domain: str) -> Optional[dict]:
    """Uses Google's DNS-over-HTTPS API — no API key, free, global."""
    async def resolve(dtype: str) -> list:
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(
                    "https://dns.google/resolve",
                    params={"name": domain, "type": dtype},
                    headers={"Accept": "application/dns-json"}
                )
                if r.status_code == 200:
                    return [a.get("data", "") for a in r.json().get("Answer", [])]
        except Exception:
            pass
        return []

    a, aaaa, mx, ns, txt = await asyncio.gather(
        resolve("A"), resolve("AAAA"), resolve("MX"), resolve("NS"), resolve("TXT"),
        return_exceptions=True
    )
    result = {
        "a":    a    if not isinstance(a, Exception)    else [],
        "aaaa": aaaa if not isinstance(aaaa, Exception) else [],
        "mx":   mx   if not isinstance(mx, Exception)   else [],
        "ns":   ns   if not isinstance(ns, Exception)   else [],
        "txt":  txt  if not isinstance(txt, Exception)  else [],
        "source": "Google DoH",
    }
    if any(result[k] for k in ["a", "mx", "ns"]):
        return result
    return None


# ─────────────────────────────────────────────────────────────────────────────
# DNS — Source 3: Cloudflare DNS-over-HTTPS
# ─────────────────────────────────────────────────────────────────────────────
async def _dns_cloudflare_doh(domain: str) -> Optional[dict]:
    """Uses Cloudflare's 1.1.1.1 DoH API — no API key, free, privacy-focused."""
    async def resolve(dtype: str) -> list:
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(
                    "https://cloudflare-dns.com/dns-query",
                    params={"name": domain, "type": dtype},
                    headers={"Accept": "application/dns-json"}
                )
                if r.status_code == 200:
                    return [a.get("data", "") for a in r.json().get("Answer", [])]
        except Exception:
            pass
        return []

    a, aaaa, mx, ns, txt = await asyncio.gather(
        resolve("A"), resolve("AAAA"), resolve("MX"), resolve("NS"), resolve("TXT"),
        return_exceptions=True
    )
    result = {
        "a":    a    if not isinstance(a, Exception)    else [],
        "aaaa": aaaa if not isinstance(aaaa, Exception) else [],
        "mx":   mx   if not isinstance(mx, Exception)   else [],
        "ns":   ns   if not isinstance(ns, Exception)   else [],
        "txt":  txt  if not isinstance(txt, Exception)  else [],
        "source": "Cloudflare DoH",
    }
    if any(result[k] for k in ["a", "mx", "ns"]):
        return result
    return None


# ─────────────────────────────────────────────────────────────────────────────
# DNS — Orchestrator: tries all 3 sources
# ─────────────────────────────────────────────────────────────────────────────
async def _get_dns(domain: str) -> dict:
    """Tries dnspython → Google DoH → Cloudflare DoH. Returns first successful result."""
    for fn, name in [(_dns_dnspython, "dnspython"), (_dns_google_doh, "Google DoH"), (_dns_cloudflare_doh, "Cloudflare DoH")]:
        try:
            result = await fn(domain)
            if result:
                logger.info(f"DNS for {domain} resolved via {name}")
                return result
        except Exception as e:
            logger.warning(f"DNS source {name} raised: {e}")
    # Final fallback: basic socket
    try:
        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
        return {"a": [ip], "aaaa": [], "mx": [], "ns": [], "txt": [], "source": "socket"}
    except Exception:
        pass
    return {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "source": "none"}


# ─────────────────────────────────────────────────────────────────────────────
# SCREENSHOT — Source 1: URLScan.io (reuse existing or trigger new scan)
# ─────────────────────────────────────────────────────────────────────────────
async def _screenshot_urlscan(domain: str) -> Optional[dict]:
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            # Search for existing scan first
            search_r = await client.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"page.domain:{domain}", "size": 1},
                headers=HEADERS
            )
            if search_r.status_code == 200:
                results = search_r.json().get("results", [])
                if results:
                    scan_id = results[0].get("_id", "")
                    page = results[0].get("page", {})
                    return {
                        "status": "ready",
                        "screenshot_url": f"https://urlscan.io/screenshots/{scan_id}.png",
                        "scan_url": f"https://urlscan.io/result/{scan_id}/",
                        "scan_date": results[0].get("task", {}).get("time", ""),
                        "page_title": page.get("title", ""),
                        "page_status": page.get("status", ""),
                        "scan_id": scan_id,
                        "provider": "URLScan.io",
                    }

            # Submit new scan
            submit_r = await client.post(
                "https://urlscan.io/api/v1/scan/",
                json={"url": f"http://{domain}", "visibility": "public"},
                headers={**HEADERS, "Content-Type": "application/json"},
            )
            if submit_r.status_code == 200:
                data = submit_r.json()
                return {
                    "status": "pending",
                    "scan_id": data.get("uuid", ""),
                    "result_url": data.get("result", ""),
                    "message": "Scan submitted. Ready in ~30 seconds.",
                    "provider": "URLScan.io",
                }
    except Exception as e:
        logger.warning(f"URLScan screenshot failed for {domain}: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SCREENSHOT — Source 2: thum.io (free, no API key, instant)
# ─────────────────────────────────────────────────────────────────────────────
async def _screenshot_thumio(domain: str) -> Optional[dict]:
    """
    thum.io renders real website thumbnails for free with no API key.
    URL format: https://image.thum.io/get/width/1280/crop/800/http://{domain}
    """
    try:
        url = f"https://image.thum.io/get/width/1280/crop/800/http://{domain}"
        # Verify it actually returns an image (HEAD check)
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.head(url, headers=HEADERS)
            if r.status_code == 200 and "image" in r.headers.get("content-type", ""):
                return {
                    "status": "ready",
                    "screenshot_url": url,
                    "scan_url": f"http://{domain}",
                    "provider": "thum.io",
                }
    except Exception as e:
        logger.warning(f"thum.io failed for {domain}: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SCREENSHOT — Source 3: microlink.io (free tier, 50 req/day, instant)
# ─────────────────────────────────────────────────────────────────────────────
async def _screenshot_microlink(domain: str) -> Optional[dict]:
    """
    microlink.io metadata + screenshot API. Free tier: 50 requests/day.
    Returns screenshot URL if page is reachable.
    """
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            r = await client.get(
                "https://api.microlink.io/",
                params={"url": f"http://{domain}", "screenshot": "true", "meta": "false"},
                headers=HEADERS
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    screenshot = data.get("data", {}).get("screenshot", {})
                    if screenshot.get("url"):
                        return {
                            "status": "ready",
                            "screenshot_url": screenshot["url"],
                            "scan_url": f"http://{domain}",
                            "page_title": data.get("data", {}).get("title", ""),
                            "provider": "microlink.io",
                        }
    except Exception as e:
        logger.warning(f"microlink.io failed for {domain}: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SCREENSHOT — Orchestrator: tries all 3 sources
# ─────────────────────────────────────────────────────────────────────────────
async def _get_screenshot(domain: str) -> dict:
    """
    Tries URLScan.io → thum.io → microlink.io.
    URLScan is tried first (may also have malicious verdict context).
    thum.io is instant and free with no rate limit.
    microlink.io is a backup with 50 free/day.
    """
    for fn, name in [
        (_screenshot_urlscan, "URLScan.io"),
        (_screenshot_thumio, "thum.io"),
        (_screenshot_microlink, "microlink.io"),
    ]:
        try:
            result = await fn(domain)
            if result:
                logger.info(f"Screenshot for {domain} via {name}")
                return result
        except Exception as e:
            logger.warning(f"Screenshot source {name} raised: {e}")
    return {"status": "unavailable", "screenshot_url": None, "provider": "none"}


# ─────────────────────────────────────────────────────────────────────────────
# VERDICT ENGINES (5 sources, unchanged)
# ─────────────────────────────────────────────────────────────────────────────
async def _verdict_virustotal(domain: str) -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}
            )
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) or 1
                return {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": total,
                    "verdict": "malicious" if malicious > 2 else ("suspicious" if suspicious > 0 else "clean"),
                    "reputation": attrs.get("reputation", 0),
                    "categories": list(attrs.get("categories", {}).values())[:3],
                    "tags": attrs.get("tags", [])[:5],
                }
    except Exception as e:
        logger.warning(f"VirusTotal failed for {domain}: {e}")
    return {}


async def _verdict_alienvault(domain: str) -> dict:
    if not settings.ALIENVAULT_OTX_API_KEY:
        return {}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": settings.ALIENVAULT_OTX_API_KEY}
            )
            if r.status_code == 200:
                data = r.json()
                pulse_info = data.get("pulse_info", {})
                pulses = pulse_info.get("count", 0)
                return {
                    "pulses": pulses,
                    "tags": list(set(pulse_info.get("tags", [])))[:8],
                    "verdict": "malicious" if pulses > 5 else ("suspicious" if pulses > 0 else "clean"),
                    "country": data.get("country_name", ""),
                    "asn": data.get("asn", ""),
                }
    except Exception as e:
        logger.warning(f"AlienVault failed for {domain}: {e}")
    return {}


async def _verdict_pulsedive(domain: str) -> dict:
    if not settings.PULSEDIVE_API_KEY:
        return {}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://pulsedive.com/api/info.php",
                params={"indicator": domain, "key": settings.PULSEDIVE_API_KEY}
            )
            if r.status_code == 200:
                data = r.json()
                risk = data.get("risk", "unknown")
                threats = [t.get("name", "") for t in data.get("threats", []) if t.get("name")]
                return {
                    "risk": risk,
                    "threats": threats[:5],
                    "verdict": "malicious" if risk in ["high", "critical"] else ("suspicious" if risk == "medium" else "clean"),
                    "seen_first": data.get("stamp_seen", ""),
                }
    except Exception as e:
        logger.warning(f"Pulsedive failed for {domain}: {e}")
    return {}


async def _verdict_urlhaus(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                json={"host": domain},
                headers=HEADERS
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "ok":
                    urls = data.get("urls", [])
                    return {
                        "hit": True,
                        "count": len(urls),
                        "tags": list({tag for u in urls for tag in (u.get("tags") or [])})[:5],
                        "verdict": "malicious",
                        "threat_types": list({u.get("threat", "") for u in urls if u.get("threat")})[:3],
                    }
    except Exception as e:
        logger.warning(f"URLhaus failed for {domain}: {e}")
    return {"hit": False, "verdict": "clean"}


async def _verdict_threatfox(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": domain},
                headers=HEADERS
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "ok":
                    iocs = data.get("data", [])
                    return {
                        "hit": True,
                        "ioc_count": len(iocs),
                        "malware_families": list({i.get("malware", "") for i in iocs if i.get("malware")})[:3],
                        "verdict": "malicious",
                        "confidence": max((i.get("confidence_level", 0) for i in iocs), default=0),
                    }
    except Exception as e:
        logger.warning(f"ThreatFox failed for {domain}: {e}")
    return {"hit": False, "verdict": "clean"}


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENRICHMENT FUNCTION
# ─────────────────────────────────────────────────────────────────────────────
async def enrich_domain(domain: str) -> dict:
    """
    Full on-click enrichment. All sources run in parallel.
    Each category (WHOIS, DNS, Screenshot) has 3 fallbacks internally.
    """
    logger.info(f"[Enricher v2] Enriching: {domain}")

    whois_data, dns_data, vt_data, otx_data, pd_data, uh_data, tf_data, screenshot_data = await asyncio.gather(
        _get_whois(domain),
        _get_dns(domain),
        _verdict_virustotal(domain),
        _verdict_alienvault(domain),
        _verdict_pulsedive(domain),
        _verdict_urlhaus(domain),
        _verdict_threatfox(domain),
        _get_screenshot(domain),
        return_exceptions=True
    )

    def safe(r, default):
        return default if isinstance(r, Exception) else (r or default)

    whois_data      = safe(whois_data,      {"error": "Lookup failed", "age_days": -1})
    dns_data        = safe(dns_data,        {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": []})
    vt_data         = safe(vt_data,         {})
    otx_data        = safe(otx_data,        {})
    pd_data         = safe(pd_data,         {})
    uh_data         = safe(uh_data,         {"hit": False})
    tf_data         = safe(tf_data,         {"hit": False})
    screenshot_data = safe(screenshot_data, {"status": "unavailable"})

    # Compute overall verdict
    verdicts = []
    for d, key in [(vt_data, "verdict"), (otx_data, "verdict"), (pd_data, "verdict"), (uh_data, "verdict"), (tf_data, "verdict")]:
        v = d.get(key)
        if v:
            verdicts.append(v)

    if "malicious" in verdicts:
        overall_verdict, overall_color = "malicious", "red"
    elif "suspicious" in verdicts:
        overall_verdict, overall_color = "suspicious", "orange"
    else:
        overall_verdict, overall_color = "clean", "green"

    return {
        "domain":          domain,
        "enriched_at":     datetime.utcnow().isoformat() + "Z",
        "overall_verdict": overall_verdict,
        "overall_color":   overall_color,
        "whois":           whois_data,
        "dns":             dns_data,
        "verdict": {
            "virustotal": vt_data,
            "alienvault": otx_data,
            "pulsedive":  pd_data,
            "urlhaus":    uh_data,
            "threatfox":  tf_data,
        },
        "screenshot": screenshot_data,
    }
