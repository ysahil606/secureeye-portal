"""
IOC Enrichment Service — Production-Grade Multi-Source Intelligence
Sources:
  1. ip-api.com         — Free IP geolocation (no key, 45/min)
  2. AbuseIPDB          — Free IP reputation (key, 1000/day)
  3. AlienVault OTX     — Multi-IOC context (free key)
  4. VirusTotal v3      — Domain/Hash/IP/URL reputation (free key, 4/min)
  5. Shodan InternetDB  — IP ports/vulns/hostnames (no key, unlimited)
  6. GreyNoise Community— IP noise classification (no key)
  7. URLhaus API        — URL/domain/IP/hash malware lookup (no key)
"""
import logging
from datetime import datetime
import httpx
from sqlalchemy.orm import Session
from models import IOC
from config import settings

logger = logging.getLogger("enrichment")


async def _enrich_ip_geolocation(client: httpx.AsyncClient, ioc: IOC):
    """Tier 1: ip-api.com — Free, no key, 45 req/min."""
    try:
        r = await client.get(f"http://ip-api.com/json/{ioc.value}")
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                ioc.country = data.get("country")
                ioc.country_code = data.get("countryCode")
                ioc.latitude = data.get("lat")
                ioc.longitude = data.get("lon")
                ioc.enrichment_data["isp"] = data.get("isp")
                ioc.enrichment_data["org"] = data.get("org")
                ioc.enrichment_data["as"] = data.get("as")
                ioc.enrichment_data["city"] = data.get("city")
                ioc.enrichment_data["region"] = data.get("regionName")
    except Exception as e:
        logger.error(f"Geo-enrichment failed for {ioc.value}: {e}")


async def _enrich_abuseipdb(client: httpx.AsyncClient, ioc: IOC):
    """Tier 2: AbuseIPDB — Free key, 1000/day."""
    if not settings.ABUSEIPDB_API_KEY:
        return
    try:
        headers = {
            "Key": settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {"ipAddress": ioc.value, "maxAgeInDays": "90"}
        ar = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
        if ar.status_code == 200:
            abuse_data = ar.json().get("data", {})
            ioc.threat_score = float(abuse_data.get("abuseConfidenceScore", 0))
            ioc.enrichment_data["abuse_score"] = abuse_data.get("abuseConfidenceScore")
            ioc.enrichment_data["usage_type"] = abuse_data.get("usageType")
            ioc.enrichment_data["total_reports"] = abuse_data.get("totalReports")
            ioc.enrichment_data["last_reported"] = abuse_data.get("lastReportedAt")
            ioc.enrichment_data["is_tor"] = abuse_data.get("isTor", False)
            ioc.enrichment_data["is_whitelisted"] = abuse_data.get("isWhitelisted", False)
    except Exception as e:
        logger.error(f"AbuseIPDB enrichment failed for {ioc.value}: {e}")


async def _enrich_shodan_internetdb(client: httpx.AsyncClient, ioc: IOC):
    """Tier 3: Shodan InternetDB — Completely free, no key, no rate limit.
    Returns open ports, known vulns, hostnames, CPEs, and tags for any IP.
    """
    try:
        r = await client.get(f"https://internetdb.shodan.io/{ioc.value}")
        if r.status_code == 200:
            data = r.json()
            ioc.enrichment_data["shodan_ports"] = data.get("ports", [])
            ioc.enrichment_data["shodan_vulns"] = data.get("vulns", [])
            ioc.enrichment_data["shodan_hostnames"] = data.get("hostnames", [])
            ioc.enrichment_data["shodan_cpes"] = data.get("cpes", [])
            ioc.enrichment_data["shodan_tags"] = data.get("tags", [])

            # Boost threat score if vulns or suspicious tags found
            vulns = data.get("vulns", [])
            tags = data.get("tags", [])
            if vulns and (ioc.threat_score or 0) < 70:
                ioc.threat_score = min((ioc.threat_score or 0) + len(vulns) * 10, 95)
            if any(t in tags for t in ["self-signed", "c2", "compromised", "eol-os"]):
                ioc.threat_score = min((ioc.threat_score or 0) + 20, 95)
    except Exception as e:
        logger.error(f"Shodan InternetDB enrichment failed for {ioc.value}: {e}")


async def _enrich_greynoise_community(client: httpx.AsyncClient, ioc: IOC):
    """Tier 4: GreyNoise Community — Completely free, no key required.
    Classifies IPs as benign/malicious/unknown based on internet scanning activity.
    """
    try:
        headers = {"Accept": "application/json"}
        r = await client.get(f"https://api.greynoise.io/v3/community/{ioc.value}", headers=headers)
        if r.status_code == 200:
            data = r.json()
            ioc.enrichment_data["greynoise_noise"] = data.get("noise", False)
            ioc.enrichment_data["greynoise_riot"] = data.get("riot", False)
            ioc.enrichment_data["greynoise_classification"] = data.get("classification", "unknown")
            ioc.enrichment_data["greynoise_name"] = data.get("name", "")
            ioc.enrichment_data["greynoise_link"] = data.get("link", "")
            ioc.enrichment_data["greynoise_message"] = data.get("message", "")

            classification = data.get("classification", "")
            if classification == "malicious" and (ioc.threat_score or 0) < 80:
                ioc.threat_score = max(ioc.threat_score or 0, 80)
            elif classification == "benign" and (ioc.threat_score or 0) > 30:
                ioc.enrichment_data["greynoise_benign_note"] = "Known benign scanner"
    except Exception as e:
        logger.error(f"GreyNoise enrichment failed for {ioc.value}: {e}")


async def _enrich_urlhaus(client: httpx.AsyncClient, ioc: IOC):
    """Tier 5: URLhaus by abuse.ch — Completely free, no key, no limit.
    Supports URL, domain, IP, and hash lookups for malware distribution.
    """
    try:
        if ioc.ioc_type == "url":
            r = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": ioc.value})
        elif ioc.ioc_type == "domain":
            r = await client.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": ioc.value})
        elif ioc.ioc_type == "ip":
            r = await client.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": ioc.value})
        elif ioc.ioc_type == "hash":
            hash_type = "sha256_hash" if len(ioc.value) == 64 else "md5_hash"
            r = await client.post("https://urlhaus-api.abuse.ch/v1/payload/", data={hash_type: ioc.value})
        else:
            return

        if r.status_code == 200:
            data = r.json()
            query_status = data.get("query_status", "")
            if query_status in ("ok", "no_results"):
                ioc.enrichment_data["urlhaus_status"] = query_status
                ioc.enrichment_data["urlhaus_threat"] = data.get("threat", "")
                ioc.enrichment_data["urlhaus_tags"] = data.get("tags") or []
                urls_count = data.get("urls_count", data.get("url_count", 0))
                ioc.enrichment_data["urlhaus_urls_count"] = urls_count

                if query_status == "ok" and urls_count:
                    # Confirmed malware distribution
                    ioc.threat_score = max(ioc.threat_score or 0, 85)
                    ioc.enrichment_data["urlhaus_blacklists"] = data.get("blacklists", {})
    except Exception as e:
        logger.error(f"URLhaus enrichment failed for {ioc.value}: {e}")


async def _enrich_virustotal(client: httpx.AsyncClient, ioc: IOC):
    """Tier 6: VirusTotal v3 — Free key, 4 req/min, 500/day.
    Supports IP, domain, hash, and URL lookups.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return
    try:
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        vt_type_map = {
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc.value}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{ioc.value}",
            "hash": f"https://www.virustotal.com/api/v3/files/{ioc.value}",
            "url": None,  # URL requires base64 encoding, handled below
        }

        url = vt_type_map.get(ioc.ioc_type)
        if ioc.ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        if not url:
            return

        r = await client.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)
            total_engines = malicious + suspicious + undetected + harmless

            ioc.enrichment_data["vt_malicious"] = malicious
            ioc.enrichment_data["vt_suspicious"] = suspicious
            ioc.enrichment_data["vt_undetected"] = undetected
            ioc.enrichment_data["vt_harmless"] = harmless
            ioc.enrichment_data["vt_total_engines"] = total_engines
            ioc.enrichment_data["vt_reputation"] = data.get("reputation", 0)
            ioc.enrichment_data["vt_link"] = f"https://www.virustotal.com/gui/{ioc.ioc_type}/{ioc.value}"

            # Compute VT-based threat score
            if total_engines > 0:
                detection_ratio = (malicious + suspicious) / total_engines
                vt_score = int(detection_ratio * 100)
                ioc.threat_score = max(ioc.threat_score or 0, vt_score)

            # Extra info for specific types
            if ioc.ioc_type == "domain":
                ioc.enrichment_data["vt_categories"] = data.get("categories", {})
                ioc.enrichment_data["vt_registrar"] = data.get("registrar", "")
            elif ioc.ioc_type == "ip":
                ioc.enrichment_data["vt_as_owner"] = data.get("as_owner", "")
                ioc.enrichment_data["vt_network"] = data.get("network", "")
                if not ioc.country:
                    ioc.country = data.get("country", "")
            elif ioc.ioc_type == "hash":
                ioc.enrichment_data["vt_type_description"] = data.get("type_description", "")
                ioc.enrichment_data["vt_popular_threat_name"] = data.get("popular_threat_classification", {}).get("suggested_threat_label", "")
                ioc.enrichment_data["vt_size"] = data.get("size", 0)

        elif r.status_code == 404:
            ioc.enrichment_data["vt_status"] = "not_found"
    except Exception as e:
        logger.error(f"VirusTotal enrichment failed for {ioc.value}: {e}")


async def _enrich_otx(client: httpx.AsyncClient, ioc: IOC):
    """Tier 7: AlienVault OTX — Free key, generous limits."""
    if not settings.ALIENVAULT_OTX_API_KEY:
        return
    try:
        otx_headers = {"X-OTX-API-KEY": settings.ALIENVAULT_OTX_API_KEY}
        otx_section = "IPv4" if ioc.ioc_type == "ip" else "domain" if ioc.ioc_type == "domain" else "file"
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/{otx_section}/{ioc.value}/general"

        or_res = await client.get(otx_url, headers=otx_headers)
        if or_res.status_code == 200:
            otx_data = or_res.json()
            ioc.enrichment_data["otx_pulse_count"] = otx_data.get("pulse_info", {}).get("count", 0)
            ioc.enrichment_data["otx_tags"] = [t for t in otx_data.get("tags", [])[:5]]

            # Boost score if no other source provided one
            if (ioc.threat_score or 0) == 0:
                pulse_count = otx_data.get("pulse_info", {}).get("count", 0)
                ioc.threat_score = min(pulse_count * 10, 95)
    except Exception as e:
        logger.error(f"AlienVault OTX enrichment failed for {ioc.value}: {e}")


async def _enrich_threatminer(client: httpx.AsyncClient, ioc: IOC):
    """Tier 8: ThreatMiner — Completely free, no key.
    Great for IP and Domain historical WHOIS, URIs, and related samples.
    """
    try:
        if ioc.ioc_type == "ip":
            r = await client.get(f"https://api.threatminer.org/v2/host.php?q={ioc.value}&rt=1")
        elif ioc.ioc_type == "domain":
            r = await client.get(f"https://api.threatminer.org/v2/domain.php?q={ioc.value}&rt=1")
        elif ioc.ioc_type == "hash":
            r = await client.get(f"https://api.threatminer.org/v2/sample.php?q={ioc.value}&rt=1")
        else:
            return
            
        if r.status_code == 200:
            data = r.json()
            if data.get("status_code") == "200" and data.get("results"):
                results = data["results"][0]
                ioc.enrichment_data["threatminer_whois"] = results.get("whois", {})
                if ioc.ioc_type == "domain" and "is_malicious" in str(results).lower():
                    ioc.threat_score = max(ioc.threat_score or 0, 75)
    except Exception as e:
        logger.error(f"ThreatMiner enrichment failed for {ioc.value}: {e}")


async def _enrich_crtsh(client: httpx.AsyncClient, ioc: IOC):
    """Tier 9: crt.sh Certificate Transparency — Free, no key.
    For domains: discovers subdomains via certificate transparency logs.
    """
    if ioc.ioc_type != "domain":
        return
    try:
        r = await client.get(f"https://crt.sh/?q=%25.{ioc.value}&output=json", timeout=20)
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "").lower()
                for n in name.split('\\n'):
                    if n.endswith(ioc.value) and "*" not in n:
                        subdomains.add(n)
            
            ioc.enrichment_data["crtsh_subdomains"] = list(subdomains)[:50]  # Limit to 50
    except Exception as e:
        logger.error(f"crt.sh enrichment failed for {ioc.value}: {e}")


async def enrich_ioc(ioc: IOC, db: Session):
    """
    Master enrichment pipeline — runs all applicable free sources for the IOC.
    IP addresses get the richest enrichment (7 sources).
    Domains, hashes, and URLs get 3-4 sources.
    """
    if not ioc.value:
        return

    if ioc.enrichment_data is None:
        ioc.enrichment_data = {}

    async with httpx.AsyncClient(timeout=15) as client:
        # IP-specific enrichments
        if ioc.ioc_type == "ip":
            await _enrich_ip_geolocation(client, ioc)
            await _enrich_abuseipdb(client, ioc)
            await _enrich_shodan_internetdb(client, ioc)
            await _enrich_greynoise_community(client, ioc)

        # Universal enrichments (all IOC types)
        await _enrich_urlhaus(client, ioc)
        await _enrich_virustotal(client, ioc)
        await _enrich_otx(client, ioc)
        await _enrich_threatminer(client, ioc)
        await _enrich_crtsh(client, ioc)

    ioc.enrichment_data["last_enriched"] = datetime.utcnow().isoformat()
    ioc.enrichment_data["enrichment_sources"] = _get_enrichment_sources(ioc)
    db.commit()


def _get_enrichment_sources(ioc: IOC) -> list:
    """Returns list of sources that contributed data for this IOC."""
    sources = []
    data = ioc.enrichment_data or {}
    if data.get("isp"):
        sources.append("ip-api.com")
    if data.get("abuse_score") is not None:
        sources.append("AbuseIPDB")
    if data.get("shodan_ports") is not None:
        sources.append("Shodan InternetDB")
    if data.get("greynoise_classification"):
        sources.append("GreyNoise Community")
    if data.get("urlhaus_status"):
        sources.append("URLhaus")
    if data.get("vt_total_engines") is not None:
        sources.append("VirusTotal")
    if data.get("otx_pulse_count") is not None:
        sources.append("AlienVault OTX")
    if data.get("threatminer_whois") is not None:
        sources.append("ThreatMiner")
    if data.get("crtsh_subdomains") is not None:
        sources.append("crt.sh")
    return sources
