"""
Phishing Monitor Service — Clean Two-Stream Engine
===================================================

Stream A — Lookalike Domain Generators:
  1. dnstwist  — Typosquatting / homoglyph / keyboard-fat permutations (local lib)
  2. crt.sh    — SSL Certificate Transparency logs (brand-name lookup)

Stream B — Known Phishing URL Intelligence Feeds:
  3. PhishTank       — Cisco community-verified phishing DB
  4. OpenPhish       — Active phishing URLs feed
  5. PhishStats      — Real-time phishing stats API
  6. Phishing.Database (GitHub) — 1.8M+ active phishing domains list
  7. URLScan.io      — Scanned malicious pages + screenshots
"""
import asyncio
import hashlib
import logging
import socket
from datetime import datetime, timezone
from typing import Optional

import httpx

from config import settings

logger = logging.getLogger("phishing_monitor")

HEADERS = {
    "User-Agent": "SecureEye-PhishingMonitor/2.0 (security-research; contact@secureeye.app)"
}

# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────
def _hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:10]


def normalize_domain(domain: str) -> str:
    cleaned = domain.strip().lower()
    cleaned = cleaned.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0]
    # Strip www.
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    return cleaned


def risk_label(score: int) -> str:
    if score >= 75: return "critical"
    if score >= 50: return "high"
    if score >= 25: return "medium"
    return "low"


# ─────────────────────────────────────────────────────────────────────────────
# STREAM A-1: dnstwist — Local Typosquatting Permutations
# ─────────────────────────────────────────────────────────────────────────────
async def _stream_a_dnstwist(domain: str) -> list:
    """
    Generates typosquatting domain permutations via dnstwist library.
    dnstwist already resolves DNS internally. Returns ALL permutations
    (resolved and unresolved) sorted by risk.
    """
    try:
        import dnstwist
        loop = asyncio.get_event_loop()

        def run():
            try:
                # No format param — returns list of dicts with dns_a, dns_mx, dns_ns
                return dnstwist.run(domain=domain) or []
            except Exception as e:
                logger.warning(f"dnstwist inner failed: {e}")
                return []

        raw = await loop.run_in_executor(None, run)

        results = []
        for r in raw:
            perm_domain = r.get("domain", "")
            fuzzer = r.get("fuzzer", "unknown")

            # Skip the original domain entry
            if perm_domain == domain or fuzzer == "*original":
                continue

            # dnstwist already resolved DNS — use those results directly
            dns_a  = r.get("dns_a",  [])
            dns_mx = r.get("dns_mx", [])
            dns_ns = r.get("dns_ns", [])

            resolved = bool(dns_a)
            ip  = dns_a[0]  if dns_a  else None
            mx  = dns_mx[0] if dns_mx else None
            ns  = dns_ns[0] if dns_ns else None

            # Risk scoring
            score = 10
            if resolved:                                             score += 30
            if dns_mx:                                               score += 20  # Mail-ready = phishing risk!
            if fuzzer in ("homoglyph", "punycode", "cyrillic"):     score += 25
            if fuzzer in ("transposition", "omission", "repetition"): score += 10

            results.append({
                "id":         f"dt-{_hash(perm_domain)}",
                "domain":     perm_domain,
                "source":     "dnstwist",
                "fuzzer":     fuzzer,
                "ip":         ip,
                "mx":         mx,
                "ns":         ns,
                "resolved":   resolved,
                "has_ssl":    bool(r.get("ssdeep_score") or r.get("geoip_country")),
                "risk_score": min(score, 99),
                "risk_label": risk_label(min(score, 99)),
            })

        # Sort: resolved+MX first, then by risk score descending
        results.sort(key=lambda x: (not x["resolved"], -x.get("risk_score", 0)))
        logger.info(f"dnstwist: {len(results)} permutations ({sum(1 for r in results if r['resolved'])} resolved, {sum(1 for r in results if r.get('mx'))} with MX)")
        return results

    except ImportError:
        logger.warning("dnstwist not installed")
        return []
    except Exception as e:
        logger.error(f"dnstwist stream failed: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# STREAM A-2: crt.sh — SSL Certificate Transparency Lookalikes
# ─────────────────────────────────────────────────────────────────────────────
_crtsh_cache: dict = {}

async def _stream_a_crtsh(domain: str) -> list:
    """
    SSL Certificate Transparency lookalike search.
    Primary: crt.sh → Fallback 1: HackerTarget DNS → Fallback 2: SecurityTrails-style search
    """
    cache_key = domain
    if cache_key in _crtsh_cache:
        age = (datetime.utcnow() - _crtsh_cache[cache_key]["ts"]).total_seconds()
        if age < 3600:
            return _crtsh_cache[cache_key]["data"]

    brand = domain.rsplit(".", 1)[0]
    results = []
    seen = set()
    source_used = "none"

    def _process_name(clean: str, issued: str = "", issuer: str = "", src: str = "cert") -> None:
        """Add a domain to results if it's a valid lookalike."""
        if (
            clean and "." in clean and clean not in seen
            and clean != domain and brand in clean
            and not clean.endswith(f".{domain}")
        ):
            seen.add(clean)
            results.append({
                "id":          f"crt-{_hash(clean)}",
                "domain":      clean,
                "source":      src,
                "issued_date": issued,
                "has_ssl":     True,
                "resolved":    False,
                "ip":          None,
                "issuer":      issuer,
                "risk_score":  35,
                "risk_label":  "medium",
            })

    # ── Source 1: crt.sh ────────────────────────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            for q in [f"%{brand}%", f"%.{brand}.%"]:
                r = await client.get(
                    "https://crt.sh/",
                    params={"q": q, "output": "json"},
                    headers=HEADERS
                )
                if r.status_code == 200 and r.text.strip().startswith("["):
                    certs = r.json()
                    logger.info(f"crt.sh returned {len(certs)} certs for {domain}")
                    for cert in certs[:500]:
                        for raw_name in cert.get("name_value", "").split("\n"):
                            _process_name(
                                raw_name.strip().lower().lstrip("*."),
                                cert.get("not_before", "")[:10],
                                cert.get("issuer_name", ""),
                                "crt.sh"
                            )
                    source_used = "crt.sh"
                    break
    except Exception as e:
        logger.warning(f"crt.sh failed: {e}")

    # ── Source 2: HackerTarget DNS search (free, no key) ─────────────────────
    if not results:
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                r = await client.get(
                    f"https://api.hackertarget.com/hostsearch/?q={brand}",
                    headers=HEADERS
                )
                if r.status_code == 200 and "error" not in r.text.lower():
                    for line in r.text.strip().split("\n"):
                        parts = line.split(",")
                        if len(parts) >= 2:
                            found_domain = parts[0].strip().lower()
                            ip = parts[1].strip()
                            _process_name(found_domain, src="HackerTarget")
                            # Add IP info if we already processed it
                            if found_domain in seen:
                                results[-1]["ip"]      = ip
                                results[-1]["resolved"] = True
                    source_used = "HackerTarget"
                    logger.info(f"HackerTarget: {len(results)} domains for {brand}")
        except Exception as e:
            logger.warning(f"HackerTarget failed: {e}")

    # ── Source 3: URLScan.io search (reuse B-5 output) ───────────────────────
    if not results:
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                r = await client.get(
                    "https://urlscan.io/api/v1/search/",
                    params={"q": f"page.domain:*{brand}* AND NOT page.domain:{domain}", "size": 50},
                    headers=HEADERS
                )
                if r.status_code == 200:
                    for res in r.json().get("results", []):
                        found_domain = res.get("page", {}).get("domain", "")
                        _process_name(found_domain.lower(), src="URLScan-Cert")
                    source_used = "URLScan-Cert"
        except Exception as e:
            logger.warning(f"URLScan cert search failed: {e}")

    logger.info(f"crt.sh stream: {len(results)} unique lookalikes via {source_used}")
    _crtsh_cache[cache_key] = {"data": results[:100], "ts": datetime.utcnow()}
    return results[:100]


# ─────────────────────────────────────────────────────────────────────────────
# STREAM B-1: PhishTank — Cisco Verified Phishing DB
# ─────────────────────────────────────────────────────────────────────────────
_phishtank_cache: dict = {"data": [], "fetched_at": None}

async def _load_phishtank() -> list:
    now = datetime.utcnow()
    if _phishtank_cache["data"] and _phishtank_cache["fetched_at"]:
        if (now - _phishtank_cache["fetched_at"]).total_seconds() < 3600:
            return _phishtank_cache["data"]
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            r = await client.get("http://data.phishtank.com/data/online-valid.csv", headers=HEADERS)
            if r.status_code == 200:
                urls = [
                    line.split(",")[1].strip('"')
                    for line in r.text.strip().split("\n")[1:]
                    if "," in line
                ]
                _phishtank_cache["data"] = urls
                _phishtank_cache["fetched_at"] = now
                logger.info(f"PhishTank: loaded {len(urls)} URLs")
                return urls
    except Exception as e:
        logger.warning(f"PhishTank load failed: {e}")
    return _phishtank_cache.get("data", [])


async def _stream_b_phishtank(domain: str) -> list:
    brand = domain.rsplit(".", 1)[0]
    urls = await _load_phishtank()
    hits = []
    for url in urls:
        if brand in url.lower():
            extracted = url.split("/")[2] if "//" in url else url[:60]
            hits.append({
                "id": f"pt-{_hash(url)}",
                "domain": extracted,
                "url": url,
                "source": "PhishTank",
                "has_ssl": url.startswith("https"),
                "risk_score": 95,
                "risk_label": "critical",
            })
        if len(hits) >= 20:
            break
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# STREAM B-2: OpenPhish
# ─────────────────────────────────────────────────────────────────────────────
async def _stream_b_openphish(domain: str) -> list:
    brand = domain.rsplit(".", 1)[0]
    hits = []
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            r = await client.get("https://openphish.com/feed.txt", headers=HEADERS)
            if r.status_code == 200:
                for url in r.text.strip().split("\n"):
                    if brand in url.lower():
                        extracted = url.split("/")[2] if "//" in url else url[:60]
                        hits.append({
                            "id": f"op-{_hash(url)}",
                            "domain": extracted,
                            "url": url,
                            "source": "OpenPhish",
                            "has_ssl": url.startswith("https"),
                            "risk_score": 90,
                            "risk_label": "critical",
                        })
                    if len(hits) >= 15:
                        break
    except Exception as e:
        logger.warning(f"OpenPhish failed: {e}")
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# STREAM B-3: PhishStats
# ─────────────────────────────────────────────────────────────────────────────
async def _stream_b_phishstats(domain: str) -> list:
    brand = domain.rsplit(".", 1)[0]
    hits = []
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            r = await client.get(
                "https://phishstats.info:2096/api/phishing",
                params={"_where": f"(url,like,~{brand}~)", "_size": 20},
                headers=HEADERS
            )
            if r.status_code == 200:
                for item in r.json()[:15]:
                    url = item.get("url", "")
                    extracted = url.split("/")[2] if "//" in url else url[:60]
                    hits.append({
                        "id": f"ps-{_hash(url)}",
                        "domain": extracted,
                        "url": url,
                        "source": "PhishStats",
                        "has_ssl": url.startswith("https"),
                        "risk_score": 80,
                        "risk_label": "critical",
                        "date": (item.get("date") or "")[:10],
                        "ip": item.get("ip", ""),
                    })
    except Exception as e:
        logger.warning(f"PhishStats failed: {e}")
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# STREAM B-4: Phishing.Database (GitHub)
# ─────────────────────────────────────────────────────────────────────────────
_phishdb_cache: dict = {"data": set(), "fetched_at": None}

async def _load_phishdb() -> set:
    now = datetime.utcnow()
    if _phishdb_cache["data"] and _phishdb_cache["fetched_at"]:
        if (now - _phishdb_cache["fetched_at"]).total_seconds() < 7200:
            return _phishdb_cache["data"]
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(
                "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
            )
            if r.status_code == 200:
                domains = set(d.strip().lower() for d in r.text.strip().split("\n") if d.strip())
                _phishdb_cache["data"] = domains
                _phishdb_cache["fetched_at"] = now
                logger.info(f"Phishing.Database: loaded {len(domains)} domains")
                return domains
    except Exception as e:
        logger.warning(f"Phishing.Database load failed: {e}")
    return _phishdb_cache.get("data", set())


async def _stream_b_phishdb(domain: str) -> list:
    brand = domain.rsplit(".", 1)[0]
    db = await _load_phishdb()
    hits = []
    for d in db:
        if brand in d and d != domain:
            hits.append({
                "id": f"pdb-{_hash(d)}",
                "domain": d,
                "url": f"http://{d}",
                "source": "Phishing.Database",
                "has_ssl": False,
                "risk_score": 85,
                "risk_label": "critical",
            })
        if len(hits) >= 20:
            break
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# STREAM B-5: URLScan.io — Scanned Malicious Pages
# ─────────────────────────────────────────────────────────────────────────────
async def _stream_b_urlscan(domain: str) -> list:
    brand = domain.rsplit(".", 1)[0]
    hits = []
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(
                "https://urlscan.io/api/v1/search/",
                params={
                    "q": f"page.domain:*{brand}* AND NOT page.domain:{domain} AND verdicts.malicious:true",
                    "size": 20
                },
                headers=HEADERS
            )
            if r.status_code == 200:
                for res in r.json().get("results", [])[:15]:
                    page = res.get("page", {})
                    scan_id = res.get("_id", "")
                    phish_domain = page.get("domain", "")
                    hits.append({
                        "id": f"us-{_hash(phish_domain + scan_id)}",
                        "domain": phish_domain,
                        "url": page.get("url", ""),
                        "source": "URLScan.io",
                        "has_ssl": page.get("url", "").startswith("https"),
                        "screenshot_url": f"https://urlscan.io/screenshots/{scan_id}.png" if scan_id else None,
                        "scan_url": f"https://urlscan.io/result/{scan_id}/" if scan_id else None,
                        "risk_score": 85,
                        "risk_label": "critical",
                    })
    except Exception as e:
        logger.warning(f"URLScan stream failed: {e}")
    return hits

# ─────────────────────────────────────────────────────────────────────────────
# STREAM B-6: SURBL — DNS-based spam/phishing blocklist (billions of entries)
# Queried via DNS lookup: {domain}.multi.surbl.org
# Positive result (resolves) = domain is on SURBL blacklist
# ─────────────────────────────────────────────────────────────────────────────
async def _stream_b_surbl(domain: str) -> list:
    """Check domain against SURBL via DNS. Returns hit if blacklisted."""
    # SURBL uses the registerable domain (2LD only)
    import tldextract
    extracted = tldextract.extract(domain)
    lookup = f"{extracted.domain}.{extracted.suffix}.multi.surbl.org"
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(None, socket.gethostbyname, lookup)
        # SURBL returns 127.0.0.x if listed. E.g., 127.0.0.2 up to 127.0.0.128
        # Make sure to ignore 127.255.x.x which are public/cloud DNS block error codes
        if ip.startswith("127.0.0."):
            return [{
                "id": f"surbl-{_hash(domain)}",
                "domain": domain,
                "url": f"http://{domain}",
                "source": "SURBL",
                "has_ssl": False,
                "risk_score": 92,
                "risk_label": "critical",
                "surbl_code": ip,
            }]
    except Exception:
        pass  # Domain not in SURBL = clean
    return []


# ─────────────────────────────────────────────────────────────────────────────
# STREAM B-7: Spamhaus DBL — Domain Block List (real-time DNS, enterprise-grade)
# ─────────────────────────────────────────────────────────────────────────────
async def _stream_b_spamhaus_dbl(domain: str) -> list:
    """Check domain against Spamhaus DBL via DNS."""
    import tldextract
    extracted = tldextract.extract(domain)
    lookup = f"{extracted.domain}.{extracted.suffix}.dbl.spamhaus.org"
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(None, socket.gethostbyname, lookup)
        # 127.0.1.2 = spam domain, 127.0.1.4 = phishing domain, 127.0.1.5 = malware
        codes = {"127.0.1.2": "spam", "127.0.1.4": "phishing", "127.0.1.5": "malware", "127.0.1.6": "botnet C&C"}
        
        # Spamhaus returns 127.255.255.x if the DNS query is blocked (e.g., from Oracle Cloud IPs or public DNS)
        if ip.startswith("127.0.1."):
            threat_type = codes.get(ip, "blacklisted")
            return [{
                "id": f"dbl-{_hash(domain)}",
                "domain": domain,
                "url": f"http://{domain}",
                "source": "Spamhaus DBL",
                "has_ssl": False,
                "risk_score": 96,
                "risk_label": "critical",
                "threat_type": threat_type,
            }]
    except Exception:
        pass
    return []


# ─────────────────────────────────────────────────────────────────────────────
# STREAM B-8: DNS-BH Malware Domain List (daily-updated, free)
# ─────────────────────────────────────────────────────────────────────────────
_dnsbh_cache: dict = {"data": set(), "fetched_at": None}

async def _load_dnsbh() -> set:
    now = datetime.utcnow()
    if _dnsbh_cache["data"] and _dnsbh_cache["fetched_at"]:
        if (now - _dnsbh_cache["fetched_at"]).total_seconds() < 3600:
            return _dnsbh_cache["data"]
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(
                "https://mirror1.malwaredomains.com/files/justdomains",
                headers=HEADERS
            )
            if r.status_code == 200:
                domains = set(d.strip().lower() for d in r.text.strip().split("\n") if d.strip() and not d.startswith("#"))
                _dnsbh_cache["data"] = domains
                _dnsbh_cache["fetched_at"] = now
                logger.info(f"DNS-BH: loaded {len(domains)} malware domains")
                return domains
    except Exception as e:
        logger.warning(f"DNS-BH load failed: {e}")
    # Fallback: Hagezi Pro list (1M+ entries)
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
                headers=HEADERS
            )
            if r.status_code == 200:
                domains = set(
                    d.strip().lower() for d in r.text.strip().split("\n")
                    if d.strip() and not d.startswith("#") and not d.startswith("!")
                )
                _dnsbh_cache["data"] = domains
                _dnsbh_cache["fetched_at"] = now
                logger.info(f"Hagezi Pro (fallback): loaded {len(domains)} domains")
                return domains
    except Exception as e:
        logger.warning(f"Hagezi fallback failed: {e}")
    return _dnsbh_cache.get("data", set())


async def _stream_b_dnsbh(domain: str) -> list:
    brand = domain.rsplit(".", 1)[0]
    db = await _load_dnsbh()
    hits = []
    for d in db:
        if brand in d and d != domain:
            hits.append({
                "id": f"dnsbh-{_hash(d)}",
                "domain": d,
                "url": f"http://{d}",
                "source": "DNS-BH/Hagezi",
                "has_ssl": False,
                "risk_score": 88,
                "risk_label": "critical",
            })
        if len(hits) >= 15:
            break
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# STREAM B-9: Emerging Threats (Proofpoint) — compromised/malicious domains
# ─────────────────────────────────────────────────────────────────────────────
_et_cache: dict = {"data": set(), "fetched_at": None}

async def _load_emerging_threats() -> set:
    now = datetime.utcnow()
    if _et_cache["data"] and _et_cache["fetched_at"]:
        if (now - _et_cache["fetched_at"]).total_seconds() < 3600:
            return _et_cache["data"]
    urls_to_try = [
        "https://rules.emergingthreats.net/blockrules/emerging-botcc.rules",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ]
    for url in urls_to_try:
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                r = await client.get(url, headers=HEADERS)
                if r.status_code == 200:
                    domains = set()
                    for line in r.text.split("\n"):
                        line = line.strip()
                        if line.startswith("0.0.0.0 ") or line.startswith("127.0.0.1 "):
                            parts = line.split()
                            if len(parts) >= 2:
                                d = parts[1].strip().lower()
                                if d and d != "localhost" and "." in d:
                                    domains.add(d)
                    if domains:
                        _et_cache["data"] = domains
                        _et_cache["fetched_at"] = now
                        logger.info(f"Emerging Threats/StevenBlack: loaded {len(domains)} domains")
                        return domains
        except Exception as e:
            logger.warning(f"ET source {url} failed: {e}")
    return _et_cache.get("data", set())


async def _stream_b_emerging_threats(domain: str) -> list:
    brand = domain.rsplit(".", 1)[0]
    db = await _load_emerging_threats()
    hits = []
    for d in db:
        if brand in d and d != domain:
            hits.append({
                "id": f"et-{_hash(d)}",
                "domain": d,
                "url": f"http://{d}",
                "source": "StevenBlack/ET Hosts",
                "has_ssl": False,
                "risk_score": 82,
                "risk_label": "critical",
            })
        if len(hits) >= 15:
            break
    return hits



async def run_phishing_scan(domain: str) -> dict:
    domain = normalize_domain(domain)
    brand = domain.rsplit(".", 1)[0]
    logger.info(f"[PhishMonitor v2] Starting scan for: {domain}")

    # Run all streams in parallel
    (
        dnstwist_results,
        crtsh_results,
        phishtank_hits,
        openphish_hits,
        phishstats_hits,
        phishdb_hits,
        urlscan_hits,
        surbl_hits,
        spamhaus_hits,
        dnsbh_hits,
        et_hits,
    ) = await asyncio.gather(
        _stream_a_dnstwist(domain),
        _stream_a_crtsh(domain),
        _stream_b_phishtank(domain),
        _stream_b_openphish(domain),
        _stream_b_phishstats(domain),
        _stream_b_phishdb(domain),
        _stream_b_urlscan(domain),
        _stream_b_surbl(domain),
        _stream_b_spamhaus_dbl(domain),
        _stream_b_dnsbh(domain),
        _stream_b_emerging_threats(domain),
        return_exceptions=True
    )

    def safe(r, default):
        return default if isinstance(r, Exception) else (r or default)

    dnstwist_results = safe(dnstwist_results, [])
    crtsh_results    = safe(crtsh_results, [])
    phishtank_hits   = safe(phishtank_hits, [])
    openphish_hits   = safe(openphish_hits, [])
    phishstats_hits  = safe(phishstats_hits, [])
    phishdb_hits     = safe(phishdb_hits, [])
    urlscan_hits     = safe(urlscan_hits, [])
    surbl_hits       = safe(surbl_hits, [])
    spamhaus_hits    = safe(spamhaus_hits, [])
    dnsbh_hits       = safe(dnsbh_hits, [])
    et_hits          = safe(et_hits, [])

    # Merge lookalikes from both generators, deduplicate by domain
    lookalike_map: dict[str, dict] = {}
    for item in dnstwist_results + crtsh_results:
        d = item["domain"]
        if d not in lookalike_map:
            lookalike_map[d] = item
        else:
            # Merge: keep higher risk score and SSL info
            existing = lookalike_map[d]
            if item.get("has_ssl"):
                existing["has_ssl"] = True
            if item.get("resolved") and not existing.get("resolved"):
                existing["resolved"] = True
                existing["ip"] = item.get("ip")
            if item.get("risk_score", 0) > existing.get("risk_score", 0):
                existing["risk_score"] = item["risk_score"]
                existing["risk_label"] = item["risk_label"]

    # Merge all confirmed phishing feeds, deduplicate by domain
    confirmed_map: dict[str, dict] = {}
    all_confirmed_hits = phishtank_hits + openphish_hits + phishstats_hits + phishdb_hits + urlscan_hits + surbl_hits + spamhaus_hits + dnsbh_hits + et_hits
    for item in all_confirmed_hits:
        d = item.get("domain", "")
        if not d:
            continue
        if d not in confirmed_map:
            confirmed_map[d] = item
        else:
            # Keep the highest risk score entry as primary, merge sources
            existing = confirmed_map[d]
            existing_sources = existing.get("sources", [existing.get("source", "")])
            new_source = item.get("source", "")
            if new_source not in existing_sources:
                existing_sources.append(new_source)
            existing["sources"] = existing_sources
            if item.get("screenshot_url") and not existing.get("screenshot_url"):
                existing["screenshot_url"] = item["screenshot_url"]

    lookalikes = sorted(lookalike_map.values(), key=lambda x: (not x.get("resolved"), -x.get("risk_score", 0)))
    confirmed = sorted(confirmed_map.values(), key=lambda x: -x.get("risk_score", 0))

    resolved_count = sum(1 for x in lookalikes if x.get("resolved"))

    return {
        "domain": domain,
        "brand": brand,
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "lookalike_count": len(lookalikes),
            "resolved_lookalikes": resolved_count,
            "confirmed_phishing": len(confirmed),
            "total_threats": len(lookalikes) + len(confirmed),
        },
        "sources_run": [
            "dnstwist", "crt.sh", "PhishTank",
            "OpenPhish", "PhishStats",
            "Phishing.Database", "URLScan.io",
            "SURBL", "Spamhaus DBL",
            "DNS-BH/Hagezi", "StevenBlack/ET"
        ],
        "lookalikes": lookalikes,
        "confirmed_phishing": confirmed[:50],
    }
