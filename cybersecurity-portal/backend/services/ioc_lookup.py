"""
IOC Live Lookup Service — Production-grade, uses free + keyed sources.
Routes lookups to the correct APIs based on IOC type:
  ip     → AbuseIPDB, VirusTotal, Shodan InternetDB, ip-api, IPInfo, Greynoise, AlienVault OTX, ThreatFox, FeodoTracker
  domain → VirusTotal, URLHaus, MalwareBazaar, ThreatFox, PhishTank, RDAP, AlienVault OTX
  hash   → MalwareBazaar, VirusTotal, ThreatFox, URLHaus payload
  url    → URLHaus, VirusTotal, ThreatFox, PhishTank, Google Safe Browsing
"""

import asyncio
import logging
import os
import re
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse, quote

import httpx

logger = logging.getLogger("ioc_lookup")

# ── Load API keys from config (with fallback to env vars) ──────────────────────
def _load_keys():
    try:
        from config import settings
        return (
            settings.VIRUSTOTAL_API_KEY or "",
            settings.ABUSEIPDB_API_KEY  or "",
            settings.GREYNOISE_API_KEY  or "",
            settings.ALIENVAULT_OTX_API_KEY or "",
            settings.THREATFOX_AUTH_KEY or "",
        )
    except Exception:
        pass
    # Try loading .env manually (dotenv or raw parse)
    try:
        from dotenv import load_dotenv
        import pathlib
        env_path = pathlib.Path(__file__).parent.parent / ".env"
        load_dotenv(dotenv_path=env_path)
    except Exception:
        # Manual .env parse as last resort
        try:
            import pathlib
            env_path = pathlib.Path(__file__).parent.parent / ".env"
            for line in env_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())
        except Exception:
            pass
    return (
        os.getenv("VIRUSTOTAL_API_KEY", ""),
        os.getenv("ABUSEIPDB_API_KEY",  ""),
        os.getenv("GREYNOISE_API_KEY",  ""),
        os.getenv("ALIENVAULT_OTX_API_KEY", ""),
        os.getenv("THREATFOX_AUTH_KEY", ""),
    )

_VIRUSTOTAL_KEY, _ABUSEIPDB_KEY, _GREYNOISE_KEY, _OTX_KEY, _THREATFOX_KEY = _load_keys()


# ──────────────────────── helpers ────────────────────────

IP_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$"
)
HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
URL_RE = re.compile(r"^https?://", re.I)


def infer_ioc_type(value: str) -> str:
    v = value.strip()
    if IP_RE.match(v):
        return "ip"
    if HASH_RE.match(v):
        return "hash"
    if URL_RE.match(v):
        return "url"
    if DOMAIN_RE.match(v):
        return "domain"
    return "unknown"


def _now_str() -> str:
    return datetime.utcnow().isoformat()


def _make_result(
    value: str,
    ioc_type: str,
    source_name: str,
    source_url: str,
    display_url: str,
    title: str,
    description: str,
    tags: List[str],
    malicious: Optional[bool] = None,
    confidence: Optional[int] = None,
    country: Optional[str] = None,
    asn: Optional[str] = None,
    extra: Optional[dict] = None,
) -> dict:
    badge = "🔴 MALICIOUS" if malicious is True else ("🟡 SUSPICIOUS" if malicious is None else "🟢 CLEAN")
    return {
        "value": value,
        "ioc_type": ioc_type,
        "source_name": source_name,
        "source_url": source_url,
        "display_url": display_url,
        "title": title,
        "description": description,
        "tags": [t for t in tags if t],
        "malicious": malicious,
        "confidence": confidence,
        "country": country,
        "asn": asn,
        "badge": badge,
        "extra": extra or {},
        "fetched_at": _now_str(),
    }


# ──────────────────────── IP LOOKUPS ────────────────────────

async def _lookup_ip_shodan_internetdb(ip: str) -> Optional[dict]:
    """Shodan InternetDB — 100% free, no key, returns open ports, CVEs, tags."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"https://internetdb.shodan.io/{ip}")
        if r.status_code != 200:
            return None
        d = r.json()
        tags = d.get("tags", [])
        cves = d.get("cves", [])
        ports = d.get("ports", [])
        hostnames = d.get("hostnames", [])
        malicious = any(t in tags for t in ["honeypot", "scanner", "malware", "vpn"])
        desc_parts = []
        if ports:
            desc_parts.append(f"Open ports: {', '.join(str(p) for p in ports[:10])}")
        if cves:
            desc_parts.append(f"CVEs: {', '.join(cves[:5])}")
        if hostnames:
            desc_parts.append(f"Hostnames: {', '.join(hostnames[:3])}")
        if tags:
            desc_parts.append(f"Tags: {', '.join(tags)}")
        return _make_result(
            value=ip, ioc_type="ip",
            source_name="Shodan InternetDB",
            source_url=f"https://www.shodan.io/host/{ip}",
            display_url="shodan.io",
            title=f"Shodan scan for {ip}",
            description=" | ".join(desc_parts) or "No data found.",
            tags=tags + (["cve"] if cves else []),
            malicious=malicious if tags else None,
            confidence=85 if malicious else 50,
            extra={"ports": ports, "cves": cves, "hostnames": hostnames},
        )
    except Exception as e:
        logger.warning(f"Shodan InternetDB failed for {ip}: {e}")
        return None


async def _lookup_ip_abuseipdb(ip: str) -> Optional[dict]:
    """AbuseIPDB — uses real API key, 1000 req/day free tier."""
    if not _ABUSEIPDB_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": _ABUSEIPDB_KEY, "Accept": "application/json"},
            )
        if r.status_code != 200:
            logger.warning(f"AbuseIPDB returned {r.status_code} for {ip}")
            return None
        d = r.json().get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        total_reports = d.get("totalReports", 0)
        isp = d.get("isp", "Unknown")
        usage = d.get("usageType", "Unknown")
        country = d.get("countryCode", "")
        hostnames = d.get("hostnames", [])
        malicious = score >= 25
        tags = []
        if score >= 75:
            tags.append("high_abuse")
        if usage and "data center" in usage.lower():
            tags.append("datacenter")
        if usage and "vpn" in usage.lower():
            tags.append("vpn")
        desc = (
            f"Abuse Score: {score}% | "
            f"Total Reports: {total_reports} | "
            f"ISP: {isp} | "
            f"Usage: {usage} | "
            f"Country: {d.get('countryName', country)} | "
            f"Hostnames: {', '.join(hostnames[:2]) if hostnames else 'N/A'}"
        )
        return _make_result(
            value=ip, ioc_type="ip",
            source_name="AbuseIPDB",
            source_url=f"https://www.abuseipdb.com/check/{ip}",
            display_url="abuseipdb.com",
            title=f"AbuseIPDB: {ip} — {score}% abuse confidence",
            description=desc,
            tags=tags,
            malicious=True if score >= 25 else (None if score > 0 else False),
            confidence=score,
            country=d.get("countryName", country),
            asn=f"AS{d.get('asnNumber', '')}" if d.get("asnNumber") else None,
        )
    except Exception as e:
        logger.warning(f"AbuseIPDB failed for {ip}: {e}")
        return None


async def _lookup_ip_virustotal(ip: str) -> Optional[dict]:
    """VirusTotal IP lookup — uses API key."""
    if not _VIRUSTOTAL_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": _VIRUSTOTAL_KEY},
            )
        if r.status_code != 200:
            return None
        d = r.json().get("data", {}).get("attributes", {})
        stats = d.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        harmless_count = stats.get("harmless", 0)
        total = sum(stats.values()) or 1
        malicious = malicious_count > 0
        country = d.get("country", "")
        asn = d.get("asn", "")
        as_owner = d.get("as_owner", "")
        tags = d.get("tags", [])
        if malicious_count > 0:
            tags.append("malicious")
        desc = (
            f"Detections: {malicious_count} malicious, {suspicious_count} suspicious / {total} engines | "
            f"Country: {country} | "
            f"ASN: AS{asn} ({as_owner}) | "
            f"Reputation: {d.get('reputation', 'N/A')}"
        )
        return _make_result(
            value=ip, ioc_type="ip",
            source_name="VirusTotal",
            source_url=f"https://www.virustotal.com/gui/ip-address/{ip}",
            display_url="virustotal.com",
            title=f"VirusTotal: {ip} — {malicious_count}/{total} engines flagged",
            description=desc,
            tags=tags,
            malicious=True if malicious_count > 0 else (None if suspicious_count > 0 else False),
            confidence=int((malicious_count / total) * 100) if malicious_count else 0,
            country=country,
            asn=f"AS{asn}" if asn else None,
        )
    except Exception as e:
        logger.warning(f"VirusTotal IP lookup failed for {ip}: {e}")
        return None


async def _lookup_ip_greynoise(ip: str) -> Optional[dict]:
    """GreyNoise Community API — identifies internet scanners and noise."""
    if not _GREYNOISE_KEY:
        # Try community endpoint (no key needed for basic check)
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(
                    f"https://api.greynoise.io/v3/community/{ip}",
                    headers={"Accept": "application/json"},
                )
            if r.status_code != 200:
                return None
            d = r.json()
            noise = d.get("noise", False)
            riot = d.get("riot", False)
            classification = d.get("classification", "unknown")
            tags = []
            if noise:
                tags.append("scanner")
            if riot:
                tags.append("benign_service")
            if classification:
                tags.append(classification)
            malicious = classification == "malicious"
            desc = (
                f"Noise: {'Yes' if noise else 'No'} | "
                f"RIOT (Benign): {'Yes' if riot else 'No'} | "
                f"Classification: {classification.title()} | "
                f"Name: {d.get('name', 'N/A')} | "
                f"Message: {d.get('message', 'N/A')}"
            )
            return _make_result(
                value=ip, ioc_type="ip",
                source_name="GreyNoise",
                source_url=f"https://viz.greynoise.io/ip/{ip}",
                display_url="greynoise.io",
                title=f"GreyNoise: {ip} — {classification.title()}",
                description=desc,
                tags=tags,
                malicious=True if malicious else (False if riot else None),
                confidence=80 if malicious else (90 if riot else 50),
            )
        except Exception as e:
            logger.warning(f"GreyNoise community lookup failed for {ip}: {e}")
            return None
    else:
        try:
            async with httpx.AsyncClient(timeout=12) as c:
                r = await c.get(
                    f"https://api.greynoise.io/v2/noise/context/{ip}",
                    headers={"key": _GREYNOISE_KEY, "Accept": "application/json"},
                )
            if r.status_code == 404:
                # IP not seen by GreyNoise
                return None
            if r.status_code != 200:
                return None
            d = r.json()
            classification = d.get("classification", "unknown")
            tags = d.get("tags", [])
            malicious = classification == "malicious"
            desc = (
                f"Classification: {classification.title()} | "
                f"Last Seen: {d.get('last_seen', 'N/A')} | "
                f"ASN: {d.get('asn', 'N/A')} | "
                f"Country: {d.get('country', 'N/A')} | "
                f"OS: {d.get('os', 'N/A')} | "
                f"Bot: {'Yes' if d.get('bot') else 'No'}"
            )
            return _make_result(
                value=ip, ioc_type="ip",
                source_name="GreyNoise",
                source_url=f"https://viz.greynoise.io/ip/{ip}",
                display_url="greynoise.io",
                title=f"GreyNoise: {ip} — {classification.title()}",
                description=desc,
                tags=tags + [classification],
                malicious=True if malicious else None,
                confidence=85 if malicious else 50,
                country=d.get("country"),
                asn=d.get("asn"),
            )
        except Exception as e:
            logger.warning(f"GreyNoise full lookup failed for {ip}: {e}")
            return None


async def _lookup_ip_ipapi(ip: str) -> Optional[dict]:
    """ip-api.com — truly free, no key, up to 45 req/min."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,region,city,isp,org,as,reverse,mobile,proxy,hosting,query"},
            )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("status") != "success":
            return None
        tags = []
        if d.get("proxy"):
            tags.append("proxy")
        if d.get("hosting"):
            tags.append("hosting")
        if d.get("mobile"):
            tags.append("mobile")
        desc = (
            f"ISP: {d.get('isp', 'Unknown')} | "
            f"Org: {d.get('org', 'Unknown')} | "
            f"Location: {d.get('city', '')}, {d.get('country', '')} | "
            f"ASN: {d.get('as', '')} | "
            f"Proxy/VPN: {'Yes' if d.get('proxy') else 'No'} | "
            f"Hosting: {'Yes' if d.get('hosting') else 'No'}"
        )
        return _make_result(
            value=ip, ioc_type="ip",
            source_name="ip-api.com",
            source_url=f"https://ip-api.com/#{ip}",
            display_url="ip-api.com",
            title=f"Geo Intelligence: {ip} -> {d.get('country', 'Unknown')}",
            description=desc,
            tags=tags,
            malicious=True if (d.get("proxy") or d.get("hosting")) else None,
            confidence=70,
            country=d.get("country"),
            asn=d.get("as"),
        )
    except Exception as e:
        logger.warning(f"ip-api.com failed for {ip}: {e}")
        return None


async def _lookup_ip_ipinfo(ip: str) -> Optional[dict]:
    """ipinfo.io — free tier 50k req/month."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"https://ipinfo.io/{ip}/json")
        if r.status_code != 200:
            return None
        d = r.json()
        tags = []
        if "vpn" in (d.get("privacy", {}) or {}).get("service", "").lower():
            tags.append("vpn")
        desc = (
            f"Hostname: {d.get('hostname', 'N/A')} | "
            f"City: {d.get('city', 'N/A')} | "
            f"Region: {d.get('region', 'N/A')} | "
            f"Country: {d.get('country', 'N/A')} | "
            f"Org: {d.get('org', 'N/A')} | "
            f"Timezone: {d.get('timezone', 'N/A')}"
        )
        return _make_result(
            value=ip, ioc_type="ip",
            source_name="IPInfo",
            source_url=f"https://ipinfo.io/{ip}",
            display_url="ipinfo.io",
            title=f"Network Intel: {ip}",
            description=desc,
            tags=tags,
            malicious=None,
            confidence=60,
            country=d.get("country"),
            asn=d.get("org"),
        )
    except Exception as e:
        logger.warning(f"ipinfo.io failed for {ip}: {e}")
        return None


async def _lookup_ip_threatfox(ip: str) -> Optional[dict]:
    """ThreatFox (abuse.ch) — free IOC API."""
    try:
        headers = {"API-KEY": _THREATFOX_KEY} if _THREATFOX_KEY else {}
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ip},
                headers=headers,
            )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("query_status") != "ok" or not d.get("data"):
            return None
        iocs = d["data"]
        first = iocs[0]
        malware_printable = first.get("malware_printable", "Unknown Malware")
        confidence = first.get("confidence_level", 50)
        tags = [first.get("threat_type", "malware"), first.get("malware_alias", "")]
        desc = (
            f"Malware: {malware_printable} | "
            f"Threat Type: {first.get('threat_type', 'N/A')} | "
            f"Confidence: {confidence}% | "
            f"Reporter: {first.get('reporter', 'anonymous')} | "
            f"First Seen: {first.get('first_seen', 'N/A')}"
        )
        return _make_result(
            value=ip, ioc_type="ip",
            source_name="ThreatFox",
            source_url=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ip}",
            display_url="threatfox.abuse.ch",
            title=f"ThreatFox Match: {ip} — {malware_printable}",
            description=desc,
            tags=tags,
            malicious=True,
            confidence=confidence,
        )
    except Exception as e:
        logger.warning(f"ThreatFox lookup failed for {ip}: {e}")
        return None


async def _lookup_ip_feodotracker(ip: str) -> Optional[dict]:
    """FeodoTracker (abuse.ch) — free botnet C2 IP blocklist."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
        if r.status_code != 200:
            return None
        data = r.json()
        for entry in data:
            if entry.get("ip_address") == ip:
                tags = ["c2", "botnet", entry.get("malware", "").lower()]
                return _make_result(
                    value=ip, ioc_type="ip",
                    source_name="FeodoTracker",
                    source_url=f"https://feodotracker.abuse.ch/browse/host/{ip}/",
                    display_url="feodotracker.abuse.ch",
                    title=f"C2 Botnet Server: {ip} — {entry.get('malware', 'Unknown')}",
                    description=(
                        f"Malware Family: {entry.get('malware', 'N/A')} | "
                        f"Status: {entry.get('status', 'N/A')} | "
                        f"First Seen: {entry.get('first_seen', 'N/A')} | "
                        f"Last Online: {entry.get('last_online', 'N/A')} | "
                        f"AS: {entry.get('as_number', 'N/A')} — {entry.get('as_name', 'N/A')} | "
                        f"Country: {entry.get('country', 'N/A')}"
                    ),
                    tags=tags,
                    malicious=True,
                    confidence=95,
                    country=entry.get("country"),
                    asn=f"AS{entry.get('as_number', '')}",
                )
        return None
    except Exception as e:
        logger.warning(f"FeodoTracker failed for {ip}: {e}")
        return None


async def _lookup_ip_otx(ip: str) -> Optional[dict]:
    """AlienVault OTX — uses API key."""
    if not _OTX_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": _OTX_KEY},
            )
        if r.status_code != 200:
            return None
        d = r.json()
        pulse_count = d.get("pulse_info", {}).get("count", 0)
        malicious = pulse_count > 0
        tags = []
        for pulse in d.get("pulse_info", {}).get("pulses", [])[:3]:
            tags += pulse.get("tags", [])[:3]
        tags = list(set(tags))[:6]
        reputation = d.get("reputation", 0)
        desc = (
            f"Pulse Count: {pulse_count} threat reports | "
            f"Reputation: {reputation} | "
            f"Country: {d.get('country_name', 'N/A')} | "
            f"ASN: {d.get('asn', 'N/A')}"
        )
        return _make_result(
            value=ip, ioc_type="ip",
            source_name="AlienVault OTX",
            source_url=f"https://otx.alienvault.com/indicator/ip/{ip}",
            display_url="otx.alienvault.com",
            title=f"OTX: {ip} — {pulse_count} pulse(s)",
            description=desc,
            tags=tags + (["otx_threat"] if malicious else []),
            malicious=True if malicious else None,
            confidence=min(pulse_count * 15, 95) if malicious else 30,
            country=d.get("country_name"),
            asn=d.get("asn"),
        )
    except Exception as e:
        logger.warning(f"OTX IP lookup failed for {ip}: {e}")
        return None


# ──────────────────────── DOMAIN LOOKUPS ────────────────────────

async def _lookup_domain_virustotal(domain: str) -> Optional[dict]:
    """VirusTotal domain lookup."""
    if not _VIRUSTOTAL_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": _VIRUSTOTAL_KEY},
            )
        if r.status_code != 200:
            return None
        d = r.json().get("data", {}).get("attributes", {})
        stats = d.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        tags = d.get("tags", [])
        categories = list(d.get("categories", {}).values())[:3]
        registrar = d.get("registrar", "N/A")
        creation_date = d.get("creation_date", "N/A")
        desc = (
            f"Detections: {malicious_count} malicious, {suspicious_count} suspicious / {total} engines | "
            f"Registrar: {registrar} | "
            f"Categories: {', '.join(categories) if categories else 'N/A'} | "
            f"Reputation: {d.get('reputation', 'N/A')}"
        )
        return _make_result(
            value=domain, ioc_type="domain",
            source_name="VirusTotal",
            source_url=f"https://www.virustotal.com/gui/domain/{domain}",
            display_url="virustotal.com",
            title=f"VirusTotal: {domain} — {malicious_count}/{total} flagged",
            description=desc,
            tags=tags + categories,
            malicious=True if malicious_count > 0 else (None if suspicious_count > 0 else False),
            confidence=int((malicious_count / total) * 100) if malicious_count else 0,
        )
    except Exception as e:
        logger.warning(f"VirusTotal domain lookup failed for {domain}: {e}")
        return None


async def _lookup_domain_threatfox(domain: str) -> Optional[dict]:
    """ThreatFox domain search."""
    try:
        headers = {"API-KEY": _THREATFOX_KEY} if _THREATFOX_KEY else {}
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": domain},
                headers=headers,
            )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("query_status") != "ok" or not d.get("data"):
            return None
        first = d["data"][0]
        return _make_result(
            value=domain, ioc_type="domain",
            source_name="ThreatFox",
            source_url=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{domain}",
            display_url="threatfox.abuse.ch",
            title=f"Malicious Domain: {domain} — {first.get('malware_printable', 'Unknown Malware')}",
            description=(
                f"Malware: {first.get('malware_printable', 'N/A')} | "
                f"Type: {first.get('threat_type', 'N/A')} | "
                f"Confidence: {first.get('confidence_level', 0)}% | "
                f"Reporter: {first.get('reporter', 'N/A')}"
            ),
            tags=[first.get("threat_type", "malware"), first.get("malware_alias", "")],
            malicious=True,
            confidence=first.get("confidence_level", 80),
        )
    except Exception as e:
        logger.warning(f"ThreatFox domain lookup failed: {e}")
        return None


async def _lookup_domain_urlhaus(domain: str) -> Optional[dict]:
    """URLHaus host lookup (abuse.ch) — free."""
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
            )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("query_status") == "no_results":
            return None
        urls = d.get("urls", [])
        url_count = len(urls)
        online = sum(1 for u in urls if u.get("url_status") == "online")
        tags = list({u.get("tags", [None])[0] for u in urls if u.get("tags")} - {None})[:5]
        return _make_result(
            value=domain, ioc_type="domain",
            source_name="URLHaus",
            source_url=f"https://urlhaus.abuse.ch/host/{domain}/",
            display_url="urlhaus.abuse.ch",
            title=f"URLHaus Threat: {domain} — {url_count} malicious URL(s)",
            description=(
                f"Total malicious URLs: {url_count} | "
                f"Currently online: {online} | "
                f"Tags: {', '.join(tags) if tags else 'N/A'} | "
                f"First Seen: {d.get('first_seen', 'N/A')}"
            ),
            tags=tags + ["malware_hosting"],
            malicious=url_count > 0,
            confidence=90,
        )
    except Exception as e:
        logger.warning(f"URLHaus domain lookup failed: {e}")
        return None


async def _lookup_domain_rdap(domain: str) -> Optional[dict]:
    """RDAP (ICANN) — free WHOIS replacement."""
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as c:
            r = await c.get(f"https://rdap.org/domain/{domain}")
        if r.status_code != 200:
            return None
        d = r.json()
        registrar = None
        for entity in d.get("entities", []):
            for role in entity.get("roles", []):
                if role == "registrar":
                    vcard = entity.get("vcardArray", [None, []])[1]
                    for field in vcard:
                        if field[0] == "fn":
                            registrar = field[3]
        events = {e["eventAction"]: e["eventDate"] for e in d.get("events", [])}
        reg_date = events.get("registration", "N/A")
        exp_date = events.get("expiration", "N/A")
        status = d.get("status", [])
        return _make_result(
            value=domain, ioc_type="domain",
            source_name="RDAP / ICANN",
            source_url=f"https://lookup.icann.org/lookup?name={domain}",
            display_url="rdap.org",
            title=f"Domain Registration: {domain}",
            description=(
                f"Registrar: {registrar or 'N/A'} | "
                f"Registered: {reg_date} | "
                f"Expires: {exp_date} | "
                f"Status: {', '.join(status) if status else 'N/A'}"
            ),
            tags=["whois", "domain_info"],
            malicious=None,
            confidence=60,
        )
    except Exception as e:
        logger.warning(f"RDAP lookup failed for {domain}: {e}")
        return None


async def _lookup_domain_phishtank(domain: str) -> Optional[dict]:
    """PhishTank domain check."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                "https://checkurl.phishtank.com/checkurl/",
                params={"url": f"http://{domain}/", "format": "json"},
                headers={"User-Agent": "phishtank/SecureEye"},
            )
        if r.status_code != 200:
            return None
        d = r.json()
        result = d.get("results", {})
        in_db = result.get("in_database", False)
        verified = result.get("verified", False)
        if not in_db:
            return None
        return _make_result(
            value=domain, ioc_type="domain",
            source_name="PhishTank",
            source_url=result.get("phish_detail_page", "https://phishtank.org/"),
            display_url="phishtank.org",
            title=f"PhishTank: {domain} — {'Verified Phish' if verified else 'Unverified Submission'}",
            description=(
                f"Phishing Verified: {'Yes' if verified else 'No'} | "
                f"In Database: {'Yes' if in_db else 'No'} | "
                f"Phish ID: {result.get('phish_id', 'N/A')}"
            ),
            tags=["phishing"],
            malicious=verified,
            confidence=95 if verified else 60,
        )
    except Exception as e:
        logger.warning(f"PhishTank lookup failed for {domain}: {e}")
        return None


async def _lookup_domain_otx(domain: str) -> Optional[dict]:
    """AlienVault OTX domain lookup."""
    if not _OTX_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": _OTX_KEY},
            )
        if r.status_code != 200:
            return None
        d = r.json()
        pulse_count = d.get("pulse_info", {}).get("count", 0)
        malicious = pulse_count > 0
        tags = []
        for pulse in d.get("pulse_info", {}).get("pulses", [])[:3]:
            tags += pulse.get("tags", [])[:3]
        tags = list(set(tags))[:6]
        desc = (
            f"Pulse Count: {pulse_count} threat reports | "
            f"Alexa Rank: {d.get('alexa', 'N/A')} | "
            f"Whois: {d.get('whois', 'N/A')[:60] if d.get('whois') else 'N/A'}"
        )
        if not malicious:
            return None  # Skip if no threat reports to avoid noise
        return _make_result(
            value=domain, ioc_type="domain",
            source_name="AlienVault OTX",
            source_url=f"https://otx.alienvault.com/indicator/domain/{domain}",
            display_url="otx.alienvault.com",
            title=f"OTX: {domain} — {pulse_count} pulse(s)",
            description=desc,
            tags=tags + ["otx_threat"],
            malicious=True,
            confidence=min(pulse_count * 15, 95),
        )
    except Exception as e:
        logger.warning(f"OTX domain lookup failed for {domain}: {e}")
        return None


# ──────────────────────── HASH LOOKUPS ────────────────────────

async def _lookup_hash_malwarebazaar(hash_val: str) -> Optional[dict]:
    """MalwareBazaar (abuse.ch) — free hash lookup."""
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": hash_val},
            )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("query_status") != "ok" or not d.get("data"):
            return None
        sample = d["data"][0]
        tags = sample.get("tags") or []
        signature = sample.get("signature") or "Unknown"
        file_type = sample.get("file_type_mime", "")
        return _make_result(
            value=hash_val, ioc_type="hash",
            source_name="MalwareBazaar",
            source_url=f"https://bazaar.abuse.ch/sample/{hash_val}/",
            display_url="bazaar.abuse.ch",
            title=f"Malware Sample: {signature} ({file_type})",
            description=(
                f"Malware Family: {signature} | "
                f"File Type: {file_type} | "
                f"File Size: {sample.get('file_size', 'N/A')} bytes | "
                f"First Seen: {sample.get('first_seen', 'N/A')} | "
                f"Delivery Method: {sample.get('delivery_method', 'N/A')} | "
                f"Origin Country: {sample.get('origin_country', 'N/A')}"
            ),
            tags=tags + ["malware"],
            malicious=True,
            confidence=99,
        )
    except Exception as e:
        logger.warning(f"MalwareBazaar hash lookup failed: {e}")
        return None


async def _lookup_hash_virustotal(hash_val: str) -> Optional[dict]:
    """VirusTotal hash lookup — uses API key."""
    if not _VIRUSTOTAL_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                f"https://www.virustotal.com/api/v3/files/{hash_val}",
                headers={"x-apikey": _VIRUSTOTAL_KEY},
            )
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            return None
        d = r.json().get("data", {}).get("attributes", {})
        stats = d.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        name = (d.get("names") or [hash_val[:16]])[0]
        file_type = d.get("type_description", d.get("magic", "Unknown"))
        tags = d.get("tags", [])
        popular_family = ""
        for engine_result in list(d.get("last_analysis_results", {}).values())[:10]:
            if engine_result.get("result"):
                popular_family = engine_result["result"]
                break
        desc = (
            f"Detections: {malicious_count}/{total} engines | "
            f"File: {name} | "
            f"Type: {file_type} | "
            f"Family: {popular_family or 'N/A'} | "
            f"Size: {d.get('size', 'N/A')} bytes | "
            f"First Seen: {d.get('first_submission_date', 'N/A')}"
        )
        return _make_result(
            value=hash_val, ioc_type="hash",
            source_name="VirusTotal",
            source_url=f"https://www.virustotal.com/gui/file/{hash_val}",
            display_url="virustotal.com",
            title=f"VirusTotal: {malicious_count}/{total} engines — {name}",
            description=desc,
            tags=tags + (["malware"] if malicious_count > 0 else []),
            malicious=True if malicious_count > 0 else (None if suspicious_count > 0 else False),
            confidence=int((malicious_count / total) * 100) if malicious_count else 0,
        )
    except Exception as e:
        logger.warning(f"VirusTotal hash lookup failed for {hash_val}: {e}")
        return None


async def _lookup_hash_threatfox(hash_val: str) -> Optional[dict]:
    """ThreatFox hash search."""
    try:
        headers = {"API-KEY": _THREATFOX_KEY} if _THREATFOX_KEY else {}
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_hash", "hash": hash_val},
                headers=headers,
            )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("query_status") != "ok" or not d.get("data"):
            return None
        first = d["data"][0]
        return _make_result(
            value=hash_val, ioc_type="hash",
            source_name="ThreatFox",
            source_url=f"https://threatfox.abuse.ch/browse.php?search=hash%3A{hash_val}",
            display_url="threatfox.abuse.ch",
            title=f"ThreatFox: {first.get('malware_printable', 'Malware')} hash match",
            description=(
                f"Malware: {first.get('malware_printable', 'N/A')} | "
                f"Threat Type: {first.get('threat_type', 'N/A')} | "
                f"Confidence: {first.get('confidence_level', 0)}% | "
                f"First Seen: {first.get('first_seen', 'N/A')}"
            ),
            tags=[first.get("threat_type", "malware")],
            malicious=True,
            confidence=first.get("confidence_level", 90),
        )
    except Exception as e:
        logger.warning(f"ThreatFox hash lookup failed: {e}")
        return None


async def _lookup_hash_urlhaus_payload(hash_val: str) -> Optional[dict]:
    """URLHaus payload lookup by hash (MD5 or SHA256 only)."""
    # URLHaus supports md5 (32 chars) and sha256 (64 chars), NOT sha1 (40 chars)
    if len(hash_val) not in (32, 64):
        return None
    try:
        payload = {"sha256_hash": hash_val} if len(hash_val) == 64 else {"md5_hash": hash_val}
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(
                "https://urlhaus-api.abuse.ch/v1/payload/",
                data=payload,
            )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("query_status") == "no_results":
            return None
        return _make_result(
            value=hash_val, ioc_type="hash",
            source_name="URLHaus",
            source_url=f"https://urlhaus.abuse.ch/payload/{hash_val}/",
            display_url="urlhaus.abuse.ch",
            title=f"Malware Payload: {d.get('file_type', 'Unknown')} — {d.get('signature', 'Unknown')}",
            description=(
                f"File Type: {d.get('file_type', 'N/A')} | "
                f"Signature: {d.get('signature', 'N/A')} | "
                f"First Seen: {d.get('firstseen', 'N/A')} | "
                f"URL Count: {d.get('url_count', 0)} delivery URLs"
            ),
            tags=["malware_payload", d.get("file_type", "").lower()],
            malicious=True,
            confidence=95,
        )
    except Exception as e:
        logger.warning(f"URLHaus payload lookup failed: {e}")
        return None


async def _lookup_hash_otx(hash_val: str) -> Optional[dict]:
    """AlienVault OTX file hash lookup."""
    if not _OTX_KEY:
        return None
    # OTX supports MD5, SHA1, SHA256
    hash_type = {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(hash_val))
    if not hash_type:
        return None
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(
                f"https://otx.alienvault.com/api/v1/indicators/file/{hash_val}/general",
                headers={"X-OTX-API-KEY": _OTX_KEY},
            )
        if r.status_code != 200:
            return None
        d = r.json()
        pulse_count = d.get("pulse_info", {}).get("count", 0)
        if not pulse_count:
            return None
        tags = []
        for pulse in d.get("pulse_info", {}).get("pulses", [])[:3]:
            tags += pulse.get("tags", [])[:3]
        tags = list(set(tags))[:6]
        desc = (
            f"Pulse Count: {pulse_count} threat reports | "
            f"Hash Type: {hash_type} | "
            f"File Size: {d.get('size', 'N/A')}"
        )
        return _make_result(
            value=hash_val, ioc_type="hash",
            source_name="AlienVault OTX",
            source_url=f"https://otx.alienvault.com/indicator/file/{hash_val}",
            display_url="otx.alienvault.com",
            title=f"OTX File: {hash_val[:16]}... — {pulse_count} pulse(s)",
            description=desc,
            tags=tags + ["otx_threat", "malware"],
            malicious=True,
            confidence=min(pulse_count * 15, 95),
        )
    except Exception as e:
        logger.warning(f"OTX hash lookup failed for {hash_val}: {e}")
        return None


# ──────────────────────── URL LOOKUPS ────────────────────────

async def _lookup_url_urlhaus(url: str) -> Optional[dict]:
    """URLHaus URL lookup."""
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
            )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("query_status") == "no_results":
            return None
        tags = d.get("tags") or []
        return _make_result(
            value=url, ioc_type="url",
            source_name="URLHaus",
            source_url=d.get("urlhaus_reference", "https://urlhaus.abuse.ch/"),
            display_url="urlhaus.abuse.ch",
            title=f"Malicious URL: {d.get('threat', 'Malware')} — {d.get('url_status', 'Unknown')}",
            description=(
                f"Status: {d.get('url_status', 'N/A')} | "
                f"Threat: {d.get('threat', 'N/A')} | "
                f"Added: {d.get('date_added', 'N/A')} | "
                f"Tags: {', '.join(tags) if tags else 'N/A'}"
            ),
            tags=tags + ["malware_url"],
            malicious=True,
            confidence=95,
        )
    except Exception as e:
        logger.warning(f"URLHaus URL lookup failed: {e}")
        return None


async def _lookup_url_virustotal(url: str) -> Optional[dict]:
    """VirusTotal URL lookup."""
    if not _VIRUSTOTAL_KEY:
        return None
    try:
        import base64
        # VT requires URL-safe base64 encoded URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": _VIRUSTOTAL_KEY},
            )
        if r.status_code == 404:
            # Try submitting for analysis first
            async with httpx.AsyncClient(timeout=15) as c:
                submit = await c.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": _VIRUSTOTAL_KEY},
                    data={"url": url},
                )
            if submit.status_code != 200:
                return None
            analysis_id = submit.json().get("data", {}).get("id", "")
            if not analysis_id:
                return None
            # Wait briefly then fetch
            await asyncio.sleep(2)
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers={"x-apikey": _VIRUSTOTAL_KEY},
                )
            if r.status_code != 200:
                return None
            d = r.json().get("data", {}).get("attributes", {})
            stats = d.get("stats", {})
        elif r.status_code != 200:
            return None
        else:
            d = r.json().get("data", {}).get("attributes", {})
            stats = d.get("last_analysis_stats", {})

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        tags = d.get("tags", [])
        categories = list(d.get("categories", {}).values())[:3]
        desc = (
            f"Detections: {malicious_count} malicious, {suspicious_count} suspicious / {total} engines | "
            f"Categories: {', '.join(categories) if categories else 'N/A'} | "
            f"Reputation: {d.get('reputation', 'N/A')}"
        )
        return _make_result(
            value=url, ioc_type="url",
            source_name="VirusTotal",
            source_url=f"https://www.virustotal.com/gui/url/{url_id}",
            display_url="virustotal.com",
            title=f"VirusTotal URL: {malicious_count}/{total} engines flagged",
            description=desc,
            tags=tags + categories,
            malicious=True if malicious_count > 0 else (None if suspicious_count > 0 else False),
            confidence=int((malicious_count / total) * 100) if malicious_count else 0,
        )
    except Exception as e:
        logger.warning(f"VirusTotal URL lookup failed: {e}")
        return None


async def _lookup_url_threatfox(url: str) -> Optional[dict]:
    """ThreatFox URL search."""
    try:
        headers = {"API-KEY": _THREATFOX_KEY} if _THREATFOX_KEY else {}
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": url},
                headers=headers,
            )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("query_status") != "ok" or not d.get("data"):
            return None
        first = d["data"][0]
        return _make_result(
            value=url, ioc_type="url",
            source_name="ThreatFox",
            source_url=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote(url)}",
            display_url="threatfox.abuse.ch",
            title=f"ThreatFox URL Match: {first.get('malware_printable', 'Malware')}",
            description=(
                f"Malware: {first.get('malware_printable', 'N/A')} | "
                f"Type: {first.get('threat_type', 'N/A')} | "
                f"Confidence: {first.get('confidence_level', 0)}%"
            ),
            tags=[first.get("threat_type", "malware")],
            malicious=True,
            confidence=first.get("confidence_level", 85),
        )
    except Exception as e:
        logger.warning(f"ThreatFox URL lookup failed: {e}")
        return None


async def _lookup_url_phishtank(url: str) -> Optional[dict]:
    """PhishTank URL check."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                "https://checkurl.phishtank.com/checkurl/",
                params={"url": url, "format": "json"},
                headers={"User-Agent": "phishtank/SecureEye"},
            )
        if r.status_code != 200:
            return None
        d = r.json()
        result = d.get("results", {})
        in_db = result.get("in_database", False)
        if not in_db:
            return None
        verified = result.get("verified", False)
        return _make_result(
            value=url, ioc_type="url",
            source_name="PhishTank",
            source_url=result.get("phish_detail_page", "https://phishtank.org/"),
            display_url="phishtank.org",
            title=f"PhishTank: {'Verified Phishing URL' if verified else 'Reported Phishing URL'}",
            description=f"Verified Phish: {'Yes' if verified else 'No'} | In Database: Yes | ID: {result.get('phish_id', 'N/A')}",
            tags=["phishing", "url"],
            malicious=verified,
            confidence=95 if verified else 65,
        )
    except Exception as e:
        logger.warning(f"PhishTank URL check failed: {e}")
        return None


async def _lookup_url_gsb(url: str) -> Optional[dict]:
    """Google Safe Browsing — free public transparency lookup."""
    try:
        encoded = quote(url, safe="")
        gsb_url = f"https://transparencyreport.google.com/safe-browsing/search?url={encoded}"
        return _make_result(
            value=url, ioc_type="url",
            source_name="Google Safe Browsing",
            source_url=gsb_url,
            display_url="transparencyreport.google.com",
            title=f"Google Safe Browsing Report: {url[:60]}",
            description="Click to view the full Google Safe Browsing transparency report for this URL.",
            tags=["safe_browsing"],
            malicious=None,
            confidence=None,
        )
    except Exception as e:
        logger.warning(f"GSB lookup failed: {e}")
        return None


# ──────────────────────── MAIN DISPATCHER ────────────────────────

async def enrich_ioc(value: str, ioc_type: Optional[str] = None) -> List[dict]:
    """
    Main IOC enrichment dispatcher.
    Auto-infers type if not provided.
    Runs all relevant lookups in parallel.
    Always returns results (empty list if nothing found).
    """
    value = value.strip()
    detected_type = ioc_type or infer_ioc_type(value)
    results: List[Optional[dict]] = []

    if detected_type == "ip":
        tasks = [
            _lookup_ip_abuseipdb(value),          # keyed (AbuseIPDB)
            _lookup_ip_virustotal(value),          # keyed (VirusTotal)
            _lookup_ip_greynoise(value),           # keyed or community
            _lookup_ip_otx(value),                 # keyed (OTX)
            _lookup_ip_shodan_internetdb(value),   # free, no key
            _lookup_ip_ipapi(value),               # free, no key
            _lookup_ip_ipinfo(value),              # free, no key
            _lookup_ip_threatfox(value),           # free
            _lookup_ip_feodotracker(value),        # free
        ]
    elif detected_type == "domain":
        tasks = [
            _lookup_domain_virustotal(value),      # keyed
            _lookup_domain_otx(value),             # keyed
            _lookup_domain_urlhaus(value),         # free
            _lookup_domain_threatfox(value),       # free
            _lookup_domain_rdap(value),            # free
            _lookup_domain_phishtank(value),       # free
        ]
    elif detected_type == "hash":
        tasks = [
            _lookup_hash_malwarebazaar(value),     # free
            _lookup_hash_virustotal(value),        # keyed
            _lookup_hash_threatfox(value),         # free
            _lookup_hash_urlhaus_payload(value),   # free (MD5/SHA256 only)
            _lookup_hash_otx(value),               # keyed
        ]
    elif detected_type == "url":
        parsed = urlparse(value)
        domain = parsed.netloc

        async def _noop(): return None

        tasks = [
            _lookup_url_urlhaus(value),            # free
            _lookup_url_virustotal(value),         # keyed
            _lookup_url_threatfox(value),          # free
            _lookup_url_phishtank(value),          # free
            _lookup_url_gsb(value),                # free (link only)
            _lookup_domain_urlhaus(domain) if domain else _noop(),
        ]
    else:
        # Unknown type: try most likely sources
        tasks = [
            _lookup_ip_shodan_internetdb(value),
            _lookup_hash_malwarebazaar(value),
            _lookup_domain_urlhaus(value),
        ]

    raw = await asyncio.gather(*tasks, return_exceptions=True)
    for item in raw:
        if isinstance(item, Exception):
            logger.warning(f"IOC lookup task failed: {item}")
            continue
        if item is not None:
            results.append(item)

    return results
