"""
Raw IOC Feed Service â€” Pulls live IOC feeds from multiple free sources in real-time.

Sources (15 total):
  Abuse.ch suite:
    1.  URLHaus         â€” Malware URLs
    2.  ThreatFox       â€” Multi-type IOC feed
    3.  FeodoTracker    â€” Botnet C2 IPs (JSON)
    4.  FeodoDomains    â€” Botnet C2 Domains
    5.  MalwareBazaar   â€” Recent malware hashes
    6.  SSL Blacklist   â€” C2 SSL certificates

  IP Reputation:
    7.  DShield/SANS    â€” Top attacking IPs (ISC SANS)
    8.  Blocklist.de    â€” Attack IPs from honeypots
    9.  Spamhaus DROP   â€” Hijacked/bogon prefixes
    10. C2 Tracker      â€” C2 IPs from threat actors (GitHub)
    11. Emerging Threats â€” Compromised IPs (ET/Proofpoint)
    12. Tor Exit Nodes  â€” Tor Project exit relays

  Phishing/URL:
    13. OpenPhish       â€” Phishing URLs (free feed)
    14. PhishTank       â€” Verified phishing URLs

  Vulnerability-related:
    15. CISA KEV        â€” Known exploited vulnerabilities

Severity mapping:
  critical â†’ C2, botnet, ransomware, exploit
  high     â†’ malware, trojan, backdoor, stealer
  medium   â†’ phishing, spam, scanner
  low      â†’ informational, tor, general
"""
import asyncio
import csv
import io
import json
import logging
import re
import zipfile
from datetime import datetime, timezone
from typing import List, Optional

import httpx

logger = logging.getLogger("raw_ioc_feed")

# â”€â”€ Source URLs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
URLHAUS_CSV_URL      = "https://urlhaus.abuse.ch/downloads/csv_recent/"        # plain CSV text
FEODO_JSON_URL       = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
FEODO_DOMAIN_URL     = "https://feodotracker.abuse.ch/blocklist/?download=domainblocklist"  # plain text
BAZAAR_DAILY_URL     = "https://bazaar.abuse.ch/export/csv/recent/"              # plain CSV, no header
THREATFOX_CSV_URL    = "https://threatfox.abuse.ch/export/csv/recent/"           # plain CSV text
CINSSCORE_URL        = "http://cinsscore.com/list/ci-badguys.txt"                # CINS Score Badguys IP list
DSHIELD_TOP_URL      = "https://isc.sans.edu/api/sources/attacks/999/"           # XML (1000 was discontinued)
BLOCKLIST_DE_URL     = "https://lists.blocklist.de/lists/all.txt"
SPAMHAUS_DROP_URL    = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL   = "https://www.spamhaus.org/drop/edrop.txt"                 # Extended DROP for C2 Tracker
EMERGING_THREATS_URL = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
TOR_EXIT_URL         = "https://check.torproject.org/torbulkexitlist"
OPENPHISH_URL        = "https://openphish.com/feed.txt"
PHISHTANK_CSV_URL    = "https://data.phishtank.com/data/online-valid.csv"        # CSV

# â”€â”€ Severity classification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_CRITICAL_KEYWORDS = {
    "c2", "command and control", "ransomware", "cryptolocker", "exploit",
    "emotet", "qbot", "qakbot", "trickbot", "cobalt strike", "metasploit",
    "botnet", "revil", "lockbit", "conti", "darkside", "ryuk", "maze",
    "blackcat", "hive", "alphv", "blackbasta", "royal", "play ransomware",
    "dridex", "ursnif", "icedid", "bazarloader", "bumblebee", "gootloader",
}
_HIGH_KEYWORDS = {
    "trojan", "backdoor", "rat", "stealer", "infostealer", "loader",
    "dropper", "downloader", "keylogger", "rootkit", "miner", "cryptominer",
    "agent tesla", "formbook", "asyncrat", "remcos", "njrat", "dcrat",
    "redline", "vidar", "raccoon", "lokibot", "azorult", "nanocore",
    "warzone", "quasar", "xworm", "stealc", "rhadamanthys", "strrat",
    "blackguard", "whitesnake", "aurora", "lumma", "orcus", "limerat",
}
_MEDIUM_KEYWORDS = {
    "phishing", "spam", "scam", "credential", "harvesting", "fake",
    "adware", "pup", "potentially unwanted", "browser hijacker",
    "spear-phishing", "smishing", "vishing",
}
_LOW_KEYWORDS = {
    "scanner", "tor", "proxy", "vpn", "exit node", "sinkhole", "honeypot",
    "brute force", "ssh scan", "rdp scan",
}

_IP_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _classify_severity(text: str, malware_family: str = "") -> str:
    combined = f"{text} {malware_family}".lower()
    if any(k in combined for k in _CRITICAL_KEYWORDS):
        return "critical"
    if any(k in combined for k in _HIGH_KEYWORDS):
        return "high"
    if any(k in combined for k in _MEDIUM_KEYWORDS):
        return "medium"
    return "low"


def _severity_score(severity: str) -> float:
    return {"critical": 95.0, "high": 75.0, "medium": 50.0, "low": 20.0}.get(severity, 20.0)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_date(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return value


# â”€â”€ Source 1: URLHaus CSV (ZIP download â€” no auth required) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def fetch_urlhaus(limit: int = 200) -> List[dict]:
    """URLHaus recent malicious URLs â€” ZIP CSV, no auth, updated every 5 minutes."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=True) as c:
            r = await c.get(URLHAUS_CSV_URL)
        if r.status_code != 200:
            logger.warning(f"URLHaus HTTP {r.status_code}")
            return results
        # Response is plain CSV text (not a ZIP despite the /csv_recent/ path)
        lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
        reader = csv.DictReader(lines, fieldnames=[
            "id", "dateadded", "url", "url_status", "last_online",
            "threat", "tags", "urlhaus_link", "reporter"
        ])
        count = 0
        for row in reader:
            if count >= limit:
                break
            url = row.get("url", "").strip().strip('"')
            if not url or not url.startswith("http"):
                continue
            threat = row.get("threat", "").strip().strip('"')
            tags_raw = row.get("tags", "").strip().strip('"')
            tags = [t.strip() for t in tags_raw.split(",") if t.strip() and t.strip() not in ("None", "")]
            severity = _classify_severity(threat + " " + tags_raw)
            results.append({
                "value": url,
                "ioc_type": "url",
                "source": "URLHaus",
                "source_url": row.get("urlhaus_link", "https://urlhaus.abuse.ch/").strip().strip('"'),
                "severity": severity,
                "threat_score": _severity_score(severity),
                "tags": ["malware_url"] + tags,
                "threat": threat or "malware",
                "status": row.get("url_status", "").strip().strip('"'),
                "reporter": row.get("reporter", "").strip().strip('"'),
                "first_seen": _parse_date(row.get("dateadded", "").strip().strip('"')),
                "fetched_at": _now_iso(),
                "feed": "URLHaus",
            })
            count += 1
    except Exception as e:
        logger.warning(f"URLHaus feed failed: {e}")
    return results


# â”€â”€ Source 2: FeodoTracker C2 IPs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def fetch_feodotracker(limit: int = 300) -> List[dict]:
    """FeodoTracker â€” Active botnet C2 IP blocklist."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(FEODO_JSON_URL)
        if r.status_code != 200:
            return results
        data = r.json()
        for entry in data[:limit]:
            malware = entry.get("malware", "Unknown")
            severity = _classify_severity(malware + " c2 botnet", malware)
            tags = ["c2", "botnet", malware.lower().replace(" ", "_")]
            port = entry.get("port")
            results.append({
                "value": entry.get("ip_address", ""),
                "ioc_type": "ip",
                "source": "FeodoTracker",
                "source_url": f"https://feodotracker.abuse.ch/browse/host/{entry.get('ip_address', '')}/",
                "severity": severity,
                "threat_score": _severity_score(severity),
                "tags": tags,
                "threat": f"{malware} C2 Server",
                "status": entry.get("status", ""),
                "country": entry.get("country", ""),
                "asn": f"AS{entry.get('as_number', '')}" if entry.get("as_number") else "",
                "port": str(port) if port else "",
                "first_seen": _parse_date(entry.get("first_seen")),
                "last_seen": _parse_date(entry.get("last_online")),
                "fetched_at": _now_iso(),
                "feed": "FeodoTracker",
            })
    except Exception as e:
        logger.warning(f"FeodoTracker IP feed failed: {e}")
    return results


# â”€â”€ Source 3: FeodoTracker C2 Domains (plain text) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def fetch_feodo_domains(limit: int = 200) -> List[dict]:
    """FeodoTracker â€” Botnet C2 domain blocklist (plain text, no JSON endpoint)."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
            r = await c.get(FEODO_DOMAIN_URL)
        if r.status_code != 200:
            logger.warning(f"FeodoDomains HTTP {r.status_code}")
            return results
        count = 0
        for line in r.text.splitlines():
            if count >= limit:
                break
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Each line is a plain domain
            domain = line.split()[0] if " " in line else line
            if not domain or "." not in domain:
                continue
            results.append({
                "value": domain,
                "ioc_type": "domain",
                "source": "FeodoTracker",
                "source_url": "https://feodotracker.abuse.ch/",
                "severity": "critical",
                "threat_score": 95.0,
                "tags": ["c2", "botnet", "feodo"],
                "threat": "Botnet C2 Domain",
                "status": "active",
                "first_seen": _now_iso(),
                "fetched_at": _now_iso(),
                "feed": "FeodoDomains",
            })
            count += 1
    except Exception as e:
        logger.warning(f"FeodoTracker domain feed failed: {e}")
    return results


# â”€â”€ Source 4: MalwareBazaar (ZIP CSV â€” no auth) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def fetch_malwarebazaar(limit: int = 100) -> List[dict]:
    """MalwareBazaar â€” Recent malware hashes via daily CSV export (no auth required)."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
            r = await c.get(BAZAAR_DAILY_URL)
        if r.status_code != 200:
            logger.warning(f"MalwareBazaar HTTP {r.status_code}")
            return results
        # MalwareBazaar CSV has NO header row
        import csv as _csv
        count = 0
        for row in _csv.reader(io.StringIO(r.text)):
            if count >= limit:
                break
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 9:
                continue
            sha256 = row[1].strip().strip('"')
            if not sha256 or len(sha256) != 64:
                continue
            sig       = row[8].strip().strip('"') or "Unknown"
            file_type = row[7].strip().strip('"')  # mime type
            severity  = _classify_severity(sig)
            results.append({
                "value": sha256,
                "ioc_type": "hash",
                "source": "MalwareBazaar",
                "source_url": f"https://bazaar.abuse.ch/sample/{sha256}/",
                "severity": severity,
                "threat_score": _severity_score(severity),
                "tags": ["malware", sig.lower().replace(" ", "_")],
                "threat": sig,
                "status": "malicious",
                "file_type": file_type,
                "first_seen": _parse_date(row[0].strip().strip('"')),
                "fetched_at": _now_iso(),
                "feed": "MalwareBazaar",
            })
            count += 1
    except Exception as e:
        logger.warning(f"MalwareBazaar feed failed: {e}")
    return results


# â”€â”€ Source 5: ThreatFox CSV (ZIP â€” no auth) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def fetch_threatfox(days: int = 3, limit: int = 300) -> List[dict]:
    """ThreatFox â€” Multi-type IOC feed via CSV ZIP export (no auth required)."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
            r = await c.get(THREATFOX_CSV_URL)
        if r.status_code != 200:
            logger.warning(f"ThreatFox HTTP {r.status_code}")
            return results
        # Response is plain CSV text
        lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
        reader = csv.DictReader(lines)
        type_map = {
            "ip:port": "ip", "domain": "domain",
            "url": "url", "md5_hash": "hash",
            "sha1_hash": "hash", "sha256_hash": "hash",
        }
        count = 0
        for row in reader:
            if count >= limit:
                break
            ioc_type_raw = row.get("ioc_type", "").strip().strip('"').lower()
            ioc_type = type_map.get(ioc_type_raw, "unknown")
            if ioc_type == "unknown":
                continue
            value = row.get("ioc", "").strip().strip('"')
            if ioc_type_raw == "ip:port" and ":" in value:
                value = value.split(":")[0]
            if not value:
                continue
            malware = row.get("malware", "").strip().strip('"')
            threat_type = row.get("threat_type", "").strip().strip('"')
            confidence = int(row.get("confidence_level", 50) or 50)
            severity = _classify_severity(malware + " " + threat_type, malware)
            tags = [t for t in [threat_type, malware.lower().replace(" ", "_")] if t][:5]
            results.append({
                "value": value,
                "ioc_type": ioc_type,
                "source": "ThreatFox",
                "source_url": "https://threatfox.abuse.ch/",
                "severity": severity,
                "threat_score": float(confidence),
                "tags": tags,
                "threat": malware or threat_type,
                "status": "malicious",
                "confidence": confidence,
                "first_seen": _parse_date(row.get("first_seen", "").strip().strip('"')),
                "fetched_at": _now_iso(),
                "feed": "ThreatFox",
            })
            count += 1
    except Exception as e:
        logger.warning(f"ThreatFox feed failed: {e}")
    return results

# ── Source 6: CINSSCORE CI Badguys (IP list) ───────────────────────────────────
async def fetch_cinsscore(limit: int = 200) -> List[dict]:
    """CINSSCORE CI Badguys — IPs with poor reputation / botnet / scanning activity."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            r = await c.get(CINSSCORE_URL)
        if r.status_code != 200:
            logger.warning(f"CINSSCORE HTTP {r.status_code}")
            return results
        count = 0
        for line in r.text.splitlines():
            if count >= limit:
                break
            ip = line.strip()
            if not ip or ip.startswith("#") or not _IP_REGEX.match(ip):
                continue
            severity = "high"
            results.append({
                "value": ip,
                "ioc_type": "ip",
                "source": "CINSSCORE",
                "source_url": "http://cinsscore.com/",
                "severity": severity,
                "threat_score": _severity_score(severity),
                "tags": ["c2", "scanner", "botnet", "cinsscore"],
                "threat": "CI Badguys - Poor Reputation IP",
                "status": "malicious",
                "first_seen": _now_iso(),
                "fetched_at": _now_iso(),
                "feed": "CINSSCORE",
            })
            count += 1
    except Exception as e:
        logger.warning(f"CINSSCORE feed failed: {e}")
    return results


# â”€â”€ Source 7: DShield / SANS ISC (XML API) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def fetch_dshield(limit: int = 500) -> List[dict]:
    """SANS ISC DShield â€” Daily top attacking IPs from global honeypot network."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            r = await c.get(DSHIELD_TOP_URL)
        if r.status_code != 200:
            logger.warning(f"DShield HTTP {r.status_code}")
            return results
        # Response is XML; /999/ endpoint returns active data (1000 was discontinued)
        import xml.etree.ElementTree as ET
        root = ET.fromstring(r.text)
        for source in list(root)[:limit]:
            ip      = (source.findtext("ip") or "").strip()
            count   = int(source.findtext("count") or 0)
            attacks = int(source.findtext("attacks") or 0)
            if not ip or not _IP_REGEX.match(ip):
                continue
            threat_level = "high" if count > 500 else "medium"
            results.append({
                "value": ip,
                "ioc_type": "ip",
                "source": "DShield/SANS",
                "source_url": f"https://isc.sans.edu/ipinfo/{ip}",
                "severity": threat_level,
                "threat_score": _severity_score(threat_level),
                "tags": ["attacker", "scanner", "dshield", "honeypot"],
                "threat": f"Active attacker ({count} reports, {attacks} attacks)",
                "status": "active",
                "reports": count,
                "attacks": attacks,
                "first_seen": _now_iso(),
                "fetched_at": _now_iso(),
                "feed": "DShield/SANS",
            })
    except Exception as e:
        logger.warning(f"DShield feed failed: {e}")
    return results


# â”€â”€ Source 8: Blocklist.de â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def fetch_blocklistde(limit: int = 300) -> List[dict]:
    """Blocklist.de â€” IPs reported by fail2ban-based honeypots worldwide."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(BLOCKLIST_DE_URL)
        if r.status_code != 200:
            return results
        count = 0
        for line in r.text.splitlines():
            if count >= limit:
                break
            ip = line.strip()
            if not ip or ip.startswith("#") or not _IP_REGEX.match(ip):
                continue
            results.append({
                "value": ip,
                "ioc_type": "ip",
                "source": "Blocklist.de",
                "source_url": f"https://www.blocklist.de/en/search.html?ip={ip}",
                "severity": "medium",
                "threat_score": 50.0,
                "tags": ["attacker", "honeypot", "fail2ban", "brute_force"],
                "threat": "Repeated attack attempts",
                "status": "active",
                "first_seen": _now_iso(),
                "fetched_at": _now_iso(),
                "feed": "Blocklist.de",
            })
            count += 1
    except Exception as e:
        logger.warning(f"Blocklist.de feed failed: {e}")
    return results


# ── Source 9: Spamhaus DROP ────────────────────────────────────────────────────────
async def fetch_spamhaus_drop(limit: int = 200) -> List[dict]:
    """Spamhaus DROP — Hijacked IP space used for spam/attacks."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(SPAMHAUS_DROP_URL)
        if r.status_code != 200:
            return results
        count = 0
        for line in r.text.splitlines():
            if count >= limit:
                break
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            parts = line.split(";")
            cidr = parts[0].strip()
            sbl  = parts[1].strip() if len(parts) > 1 else ""
            ip   = cidr.split("/")[0]
            if not ip or not _IP_REGEX.match(ip):
                continue
            results.append({
                "value": cidr,
                "ioc_type": "ip",
                "source": "Spamhaus DROP",
                "source_url": f"https://www.spamhaus.org/sbl/query/{sbl.strip()}" if sbl else "https://www.spamhaus.org/drop/",
                "severity": "high",
                "threat_score": 75.0,
                "tags": ["spam", "hijacked", "bogon", "drop_list"],
                "threat": f"Hijacked IP space ({sbl})",
                "status": "blacklisted",
                "sbl_ref": sbl,
                "first_seen": _now_iso(),
                "fetched_at": _now_iso(),
                "feed": "Spamhaus DROP",
            })
            count += 1
    except Exception as e:
        logger.warning(f"Spamhaus DROP feed failed: {e}")
    return results


# ── Source 10: C2 Tracker (Emerging Threats compromised IPs) ────────────────────
async def fetch_c2_tracker(limit: int = 300) -> List[dict]:
    """
    C2 Tracker — Emerging Threats compromised-ips.txt (1500+ confirmed C2/compromised IPs).
    The original montysecurity/C2-Tracker GitHub repo is offline; this replaces it.
    """
    results = []
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            r = await c.get("https://rules.emergingthreats.net/blockrules/compromised-ips.txt")
        if r.status_code != 200:
            logger.warning(f"C2 Tracker (ET) HTTP {r.status_code}")
            return results
        count = 0
        for line in r.text.splitlines():
            if count >= limit:
                break
            ip = line.strip()
            if not ip or ip.startswith("#") or not _IP_REGEX.match(ip):
                continue
            results.append({
                "value": ip,
                "ioc_type": "ip",
                "source": "C2 Tracker",
                "source_url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "severity": "high",
                "threat_score": 80.0,
                "tags": ["c2", "compromised", "emerging_threats", "command_control"],
                "threat": "C2 / Compromised Infrastructure",
                "status": "active",
                "first_seen": _now_iso(),
                "fetched_at": _now_iso(),
                "feed": "C2 Tracker",
            })
            count += 1
    except Exception as e:
        logger.warning(f"C2 Tracker feed failed: {e}")
    return results


async def fetch_emerging_threats(limit: int = 300) -> List[dict]:
    """Emerging Threats (Proofpoint) â€” Compromised/malicious IP list."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(EMERGING_THREATS_URL)
        if r.status_code != 200:
            return results
        count = 0
        for line in r.text.splitlines():
            if count >= limit:
                break
            ip = line.strip()
            if not ip or ip.startswith("#") or not _IP_REGEX.match(ip):
                continue
            results.append({
                "value": ip,
                "ioc_type": "ip",
                "source": "Emerging Threats",
                "source_url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "severity": "high",
                "threat_score": 75.0,
                "tags": ["compromised", "malware", "emerging_threats"],
                "threat": "Compromised host",
                "status": "compromised",
                "first_seen": _now_iso(),
                "fetched_at": _now_iso(),
                "feed": "Emerging Threats",
            })
            count += 1
    except Exception as e:
        logger.warning(f"Emerging Threats feed failed: {e}")
    return results


# â”€â”€ Source 12: Tor Exit Nodes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def fetch_tor_exits(limit: int = 300) -> List[dict]:
    """Tor Project â€” Official exit relay IP list."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(TOR_EXIT_URL)
        if r.status_code != 200:
            return results
        count = 0
        for line in r.text.splitlines():
            if count >= limit:
                break
            ip = line.strip()
            if not ip or ip.startswith("#") or not _IP_REGEX.match(ip):
                continue
            results.append({
                "value": ip,
                "ioc_type": "ip",
                "source": "Tor Project",
                "source_url": "https://check.torproject.org/torbulkexitlist",
                "severity": "low",
                "threat_score": 20.0,
                "tags": ["tor", "exit_node", "anonymizer", "proxy"],
                "threat": "Tor Exit Node",
                "status": "active",
                "first_seen": _now_iso(),
                "fetched_at": _now_iso(),
                "feed": "Tor Exits",
            })
            count += 1
    except Exception as e:
        logger.warning(f"Tor exit nodes feed failed: {e}")
    return results


# â”€â”€ Source 13: OpenPhish â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def fetch_openphish(limit: int = 200) -> List[dict]:
    """OpenPhish â€” Community phishing URLs feed (updated 24h)."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(OPENPHISH_URL)
        if r.status_code != 200:
            return results
        count = 0
        for line in r.text.splitlines():
            if count >= limit:
                break
            url = line.strip()
            if not url or not url.startswith("http"):
                continue
            results.append({
                "value": url,
                "ioc_type": "url",
                "source": "OpenPhish",
                "source_url": "https://openphish.com/",
                "severity": "medium",
                "threat_score": 65.0,
                "tags": ["phishing", "credential_harvesting", "openphish"],
                "threat": "Active Phishing URL",
                "status": "active",
                "first_seen": _now_iso(),
                "fetched_at": _now_iso(),
                "feed": "OpenPhish",
            })
            count += 1
    except Exception as e:
        logger.warning(f"OpenPhish feed failed: {e}")
    return results


# â”€â”€ Source 14: PhishTank (CSV) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def fetch_phishtank(limit: int = 200) -> List[dict]:
    """PhishTank â€” Verified phishing URLs via CSV export."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=45, follow_redirects=True) as c:
            r = await c.get(
                PHISHTANK_CSV_URL,
                headers={"User-Agent": "phishtank/secureeye-portal"},
            )
        if r.status_code != 200:
            logger.warning(f"PhishTank HTTP {r.status_code}")
            return results
        lines = r.text.splitlines()
        reader = csv.DictReader(lines)
        count = 0
        for entry in reader:
            if count >= limit:
                break
            url = entry.get("url", "").strip()
            if not url or not url.startswith("http"):
                continue
            verified = entry.get("verified", "no").strip().lower() == "yes"
            target   = entry.get("target", "Other").strip()
            detail   = entry.get("phish_detail_url", "").strip()
            results.append({
                "value": url,
                "ioc_type": "url",
                "source": "PhishTank",
                "source_url": detail or "https://phishtank.org/",
                "severity": "medium",
                "threat_score": 70.0 if verified else 55.0,
                "tags": ["phishing", "verified" if verified else "unverified", "phishtank"],
                "threat": f"Phishing â€” Target: {target}",
                "status": "active",
                "verified": verified,
                "target_brand": target,
                "first_seen": _parse_date(entry.get("submission_time", "")),
                "fetched_at": _now_iso(),
                "feed": "PhishTank",
            })
            count += 1
    except Exception as e:
        logger.warning(f"PhishTank feed failed: {e}")
    return results


# â”€â”€ Source 15: CISA KEV â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def fetch_cisa_kev(limit: int = 200) -> List[dict]:
    """CISA Known Exploited Vulnerabilities â€” CVE IDs actively exploited in the wild."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(CISA_KEV_URL)
        if r.status_code != 200:
            return results
        data = r.json()
        for vuln in (data.get("vulnerabilities") or [])[:limit]:
            cve_id = vuln.get("cveID", "")
            product = vuln.get("product", "")
            vendor = vuln.get("vendorProject", "")
            name = vuln.get("vulnerabilityName", "")
            desc = vuln.get("shortDescription", "")
            action = vuln.get("requiredAction", "")
            # CVE IDs as hash-type IOCs (unique identifiers)
            try:
                cvss = float(vuln.get("cvssScore", 0) or 0)
            except (TypeError, ValueError):
                cvss = 0.0
            severity = "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium" if cvss >= 4.0 else "low"
            results.append({
                "value": cve_id,
                "ioc_type": "hash",   # Using hash type to display as identifier
                "source": "CISA KEV",
                "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "severity": severity,
                "threat_score": cvss * 10 if cvss else 70.0,
                "tags": ["kev", "exploit", "actively_exploited", vendor.lower().replace(" ", "_")],
                "threat": f"{name} â€” {vendor} {product}",
                "status": "actively_exploited",
                "cvss": cvss,
                "vendor": vendor,
                "product": product,
                "required_action": action[:100] if action else "",
                "first_seen": _parse_date(vuln.get("dateAdded")),
                "due_date": _parse_date(vuln.get("dueDate")),
                "fetched_at": _now_iso(),
                "feed": "CISA KEV",
            })
    except Exception as e:
        logger.warning(f"CISA KEV feed failed: {e}")
    return results


# â”€â”€ Master Feed Aggregator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def fetch_all_raw_iocs(
    limit_per_source: int = 200,
    ioc_type_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    source_filter: Optional[str] = None,
) -> dict:
    """
    Fetches raw IOCs from all 15 sources in parallel.
    Returns structured response with per-source metadata.
    """
    all_tasks = {
        # abuse.ch suite
        "URLHaus":          fetch_urlhaus(limit_per_source),
        "FeodoTracker":     fetch_feodotracker(limit_per_source),
        "FeodoDomains":     fetch_feodo_domains(min(limit_per_source, 200)),
        "MalwareBazaar":    fetch_malwarebazaar(min(limit_per_source, 100)),
        "ThreatFox":        fetch_threatfox(days=3, limit=limit_per_source),
        "CINSSCORE":        fetch_cinsscore(limit_per_source),
        # IP reputation
        "DShield/SANS":     fetch_dshield(min(limit_per_source, 500)),
        "Blocklist.de":     fetch_blocklistde(limit_per_source),
        "Spamhaus DROP":    fetch_spamhaus_drop(min(limit_per_source, 200)),
        "C2 Tracker":       fetch_c2_tracker(limit_per_source),
        "Emerging Threats": fetch_emerging_threats(limit_per_source),
        "Tor Exits":        fetch_tor_exits(min(limit_per_source, 300)),
        # Phishing/URL
        "OpenPhish":        fetch_openphish(min(limit_per_source, 200)),
        "PhishTank":        fetch_phishtank(min(limit_per_source, 200)),
    }

    # Filter by source if requested (case-insensitive partial match)
    if source_filter:
        sf = source_filter.lower()
        all_tasks = {k: v for k, v in all_tasks.items() if sf in k.lower()}

    raw = await asyncio.gather(*all_tasks.values(), return_exceptions=True)

    source_results = {}
    all_iocs = []
    for source_name, result in zip(all_tasks.keys(), raw):
        if isinstance(result, Exception):
            logger.warning(f"Feed {source_name} failed: {result}")
            source_results[source_name] = {"count": 0, "status": "error", "error": str(result)}
            continue
        source_results[source_name] = {"count": len(result), "status": "ok"}
        all_iocs.extend(result)

    # Apply filters
    if ioc_type_filter:
        all_iocs = [i for i in all_iocs if i["ioc_type"] == ioc_type_filter]
    if severity_filter:
        all_iocs = [i for i in all_iocs if i["severity"] == severity_filter]

    # Sort: critical first, then high, medium, low
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_iocs.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 4))

    # Summary stats
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    type_counts = {"ip": 0, "domain": 0, "hash": 0, "url": 0}
    for ioc in all_iocs:
        sev = ioc.get("severity", "low")
        if sev in severity_counts:
            severity_counts[sev] += 1
        t = ioc.get("ioc_type", "")
        if t in type_counts:
            type_counts[t] += 1

    return {
        "total": len(all_iocs),
        "iocs": all_iocs,
        "sources": source_results,
        "severity_counts": severity_counts,
        "type_counts": type_counts,
        "source_count": len([s for s in source_results.values() if s["status"] == "ok"]),
        "fetched_at": _now_iso(),
    }
