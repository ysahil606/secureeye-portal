import re
import socket
import ssl
import io
from datetime import datetime, timedelta
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, or_
from sqlalchemy.orm import Session

from auth import get_current_active_user
from database import get_db
from models import Advisory, AdvisoryStatus, IOC, Sector, SeverityLevel

router = APIRouter(prefix="/advanced", tags=["Advanced Security"])


class ThreatAnalystRequest(BaseModel):
    query: str = Field(..., min_length=2)
    context: Optional[str] = None


class DomainRequest(BaseModel):
    domain: str = Field(..., min_length=3)


class WatchlistRequest(BaseModel):
    keywords: List[str] = Field(default_factory=list)


class LeakCheckRequest(BaseModel):
    keyword: str = Field(..., min_length=2)


class AdvancedTextRequest(BaseModel):
    text: str = Field(..., min_length=2)
    context: Optional[str] = None


class PatchPlanRequest(BaseModel):
    cves: List[str] = Field(default_factory=list)
    asset_exposure: str = "internet"
    business_criticality: str = "medium"


class ExecutiveReportRequest(BaseModel):
    title: str = "SecureEye Executive Threat Report"
    summary: str = ""
    business_impact: str = ""
    affected_assets: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)


SEVERITY_WEIGHT = {
    SeverityLevel.critical: 40,
    SeverityLevel.high: 30,
    SeverityLevel.medium: 18,
    SeverityLevel.low: 8,
    SeverityLevel.informational: 3,
}

MITRE_RULES = [
    ("phishing", "TA0001", "T1566", "Phishing"),
    ("credential", "TA0006", "T1110", "Brute Force / Credential Access"),
    ("password", "TA0006", "T1555", "Credentials from Password Stores"),
    ("powershell", "TA0002", "T1059.001", "PowerShell"),
    ("ransomware", "TA0040", "T1486", "Data Encrypted for Impact"),
    ("lateral", "TA0008", "T1021", "Remote Services"),
    ("c2", "TA0011", "T1071", "Application Layer Protocol"),
    ("exfil", "TA0010", "T1041", "Exfiltration Over C2 Channel"),
    ("persistence", "TA0003", "T1053", "Scheduled Task/Job"),
    ("macro", "TA0002", "T1204", "User Execution"),
]

ACTOR_RULES = [
    ("ransomware", "FIN7 / ransomware affiliate", "Financially motivated intrusion"),
    ("bank", "FIN7", "Payment and retail intrusion patterns"),
    ("healthcare", "Cl0p-style extortion operator", "Data theft/extortion targeting"),
    ("vpn", "Initial-access broker", "Perimeter access harvesting"),
    ("exchange", "APT-style email server operator", "Email infrastructure exploitation"),
    ("cloud", "Cloud credential theft actor", "Identity and token abuse"),
    ("c2", "Commodity malware operator", "Command-and-control infrastructure"),
    ("phishing", "Credential phishing operator", "Social engineering access"),
]


def normalize_domain(value: str) -> str:
    text = value.strip()
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    parsed = urlparse(text)
    return (parsed.netloc or parsed.path).split("/")[0].lower()


def advisory_score(advisory: Advisory) -> int:
    score = SEVERITY_WEIGHT.get(advisory.severity, 10)
    if advisory.cvss_score:
        score += int(advisory.cvss_score * 4)
    if advisory.is_kev:
        score += 25
    if advisory.is_zero_day:
        score += 20
    if advisory.is_critical_alert:
        score += 15
    if advisory.published_at and advisory.published_at >= datetime.utcnow() - timedelta(days=14):
        score += 10
    return min(score, 100)


def compact_advisory(advisory: Advisory) -> dict:
    return {
        "id": advisory.id,
        "title": advisory.title,
        "severity": advisory.severity.value if advisory.severity else "medium",
        "cvss_score": advisory.cvss_score,
        "is_kev": advisory.is_kev,
        "is_zero_day": advisory.is_zero_day,
        "published_at": advisory.published_at,
        "score": advisory_score(advisory),
    }


def extract_indicators(text: str) -> dict:
    return {
        "cves": sorted({item.upper() for item in re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)}),
        "ips": sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))),
        "urls": sorted(set(re.findall(r"https?://[^\s,]+", text))),
        "hashes": sorted(set(re.findall(r"\b[a-fA-F0-9]{32,64}\b", text))),
        "domains": sorted(set(re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text)))[:20],
    }


def map_mitre(text: str) -> list[dict]:
    lowered = text.lower()
    matches = []
    for keyword, tactic, technique, name in MITRE_RULES:
        if keyword in lowered:
            matches.append({"keyword": keyword, "tactic": tactic, "technique": technique, "name": name})
    if not matches:
        matches.append({"keyword": "triage", "tactic": "TA0001", "technique": "T1595", "name": "Active Scanning"})
    return matches


def match_actors(text: str) -> list[dict]:
    lowered = text.lower()
    matches = [
        {"actor": actor, "reason": reason, "confidence": "Medium"}
        for keyword, actor, reason in ACTOR_RULES
        if keyword in lowered
    ]
    return matches or [{"actor": "Unknown opportunistic actor", "reason": "Insufficient actor-specific TTPs", "confidence": "Low"}]


def exploit_status(text: str, advisories: list[Advisory]) -> dict:
    lowered = text.lower()
    status = "Unknown"
    if any(item.is_kev for item in advisories) or "kev" in lowered or "actively exploited" in lowered:
        status = "Actively exploited"
    elif any(word in lowered for word in ["poc", "exploit-db", "github exploit", "metasploit"]):
        status = "PoC available"
    elif any(word in lowered for word in ["weaponized", "ransomware", "exploitation in the wild"]):
        status = "Weaponized"
    return {
        "status": status,
        "free_sources": ["CISA KEV", "NVD references", "GitHub Advisory feed", "Local SecureEye intelligence"],
    }


@router.get("/overview")
async def overview(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    now = datetime.utcnow()
    week_start = now - timedelta(days=7)

    total = db.query(Advisory).count()
    critical = db.query(Advisory).filter(Advisory.severity == SeverityLevel.critical).count()
    kev = db.query(Advisory).filter(Advisory.is_kev == True).count()
    zero_days = db.query(Advisory).filter(Advisory.is_zero_day == True).count()
    new_this_week = db.query(Advisory).filter(Advisory.created_at >= week_start).count()
    ioc_total = db.query(IOC).count()

    top_sector = (
        db.query(Sector.name, func.count(Advisory.id).label("count"))
        .outerjoin(Advisory, Advisory.sector_id == Sector.id)
        .group_by(Sector.id)
        .order_by(desc("count"))
        .first()
    )

    top_advisories = (
        db.query(Advisory)
        .filter(Advisory.status != AdvisoryStatus.archived)
        .order_by(desc(Advisory.is_kev), desc(Advisory.cvss_score), desc(Advisory.created_at))
        .limit(8)
        .all()
    )

    risk_level = "Low"
    if critical or kev or zero_days:
        risk_level = "High"
    if critical >= 5 or kev >= 5:
        risk_level = "Critical"

    return {
        "risk_level": risk_level,
        "total_advisories": total,
        "critical": critical,
        "kev": kev,
        "zero_days": zero_days,
        "new_this_week": new_this_week,
        "ioc_total": ioc_total,
        "top_sector": top_sector.name if top_sector else "General",
        "top_advisories": [compact_advisory(item) for item in top_advisories],
        "recommended_actions": [
            "Review KEV and zero-day advisories first.",
            "Prioritize internet-facing assets with CVSS 8.5 or higher.",
            "Run IOC checks against recent firewall, DNS, EDR, and proxy logs.",
            "Generate an executive report after feed ingestion completes.",
        ],
    }


@router.get("/patch-priority")
async def patch_priority(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    advisories = (
        db.query(Advisory)
        .filter(Advisory.status != AdvisoryStatus.archived)
        .order_by(desc(Advisory.is_kev), desc(Advisory.cvss_score), desc(Advisory.created_at))
        .limit(50)
        .all()
    )
    ranked = sorted(advisories, key=advisory_score, reverse=True)[:15]
    return [
        {
            **compact_advisory(item),
            "affected_vendors": item.affected_vendors or [],
            "cve_ids": item.cve_ids or [],
            "why": [
                reason for reason in [
                    "Known exploited" if item.is_kev else None,
                    "Zero-day" if item.is_zero_day else None,
                    "Critical alert" if item.is_critical_alert else None,
                    "High CVSS" if item.cvss_score and item.cvss_score >= 8.5 else None,
                ] if reason
            ],
        }
        for item in ranked
    ]


@router.post("/threat-analyst")
async def threat_analyst(
    data: ThreatAnalystRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    query = data.query.strip()
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", query, flags=re.IGNORECASE)
    hashes = re.findall(r"\b[a-fA-F0-9]{32,64}\b", query)
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", query)
    urls = re.findall(r"https?://[^\s]+", query)

    search_terms = [query, *cves, *hashes, *ips, *urls]
    advisory_matches = []
    for term in search_terms[:8]:
        advisory_matches.extend(
            db.query(Advisory)
            .filter(or_(Advisory.title.ilike(f"%{term}%"), Advisory.description.ilike(f"%{term}%")))
            .limit(5)
            .all()
        )

    unique = {item.id: item for item in advisory_matches}.values()
    top = sorted(unique, key=advisory_score, reverse=True)[:5]

    max_score = max([advisory_score(item) for item in top], default=25)
    verdict = "Low"
    if max_score >= 75:
        verdict = "Critical"
    elif max_score >= 55:
        verdict = "High"
    elif max_score >= 35:
        verdict = "Medium"

    return {
        "verdict": verdict,
        "confidence": "High" if top else "Medium",
        "detected": {
            "cves": list({c.upper() for c in cves}),
            "hashes": hashes,
            "ips": ips,
            "urls": urls,
        },
        "summary": (
            f"{query} is rated {verdict} based on local SecureEye intelligence, "
            f"known exploitation flags, CVSS, and recent advisory matches."
        ),
        "recommended_actions": [
            "Check affected assets and exposure immediately.",
            "Search logs for related IOCs and authentication anomalies.",
            "Apply vendor mitigation or patch according to patch priority.",
            "Create a war room if exploitation is suspected.",
        ],
        "matches": [compact_advisory(item) for item in top],
    }


@router.post("/attack-surface")
async def attack_surface(
    data: DomainRequest,
    current_user=Depends(get_current_active_user),
):
    """
    Performs real-world subdomain discovery and SSL analysis 
    using HackerTarget and crt.sh (Certificate Transparency).
    """
    domain = normalize_domain(data.domain)
    result = {
        "domain": domain,
        "ip": None,
        "https": False,
        "ssl_expires_at": None,
        "days_to_ssl_expiry": None,
        "open_ports": [],
        "subdomains_checked": [],
        "risks": [],
        "intel_source": "OSINT Aggregator"
    }

    # 1. Resolve Primary IP
    try:
        result["ip"] = socket.gethostbyname(domain)
    except OSError:
        result["risks"].append("Primary domain did not resolve")

    # 2. Real-World Subdomain Discovery (crt.sh & HackerTarget)
    discovered_hosts = set()
    async with httpx.AsyncClient(timeout=15) as client:
        # A. Check HackerTarget (Fast & Reliable)
        try:
            r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.splitlines():
                    if "," in line:
                        host = line.split(",")[0]
                        discovered_hosts.add(host)
        except Exception as e:
            logger.error(f"HackerTarget discovery failed: {e}")

        # B. Check crt.sh if few hosts found (Deep Certificate Search)
        if len(discovered_hosts) < 5:
            try:
                cr = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
                if cr.status_code == 200:
                    for entry in cr.json():
                        name = entry.get("name_value", "").lower()
                        # Handle wildcard and multi-name certs
                        for n in name.split('\n'):
                            if n.endswith(domain) and "*" not in n:
                                discovered_hosts.add(n)
            except Exception as e:
                logger.error(f"crt.sh discovery failed: {e}")

    # 3. Verify and Resolve Discovered Subdomains (Limit to top 20 for performance)
    for host in list(discovered_hosts)[:20]:
        try:
            # We don't resolve every one synchronously to keep it fast, 
            # but we'll flag interesting ones
            result["subdomains_checked"].append({
                "host": host,
                "type": "production" if any(x in host for x in ["api", "portal", "www"]) else "discovered"
            })
            if any(x in host for x in ["dev", "staging", "test", "vpn", "admin", "internal"]):
                result["risks"].append(f"Potentially sensitive endpoint discovered: {host}")
        except:
            continue

    # 4. Port & SSL Check on Primary
    for port in [80, 443, 8080, 8443]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.5)
            if sock.connect_ex((domain, port)) == 0:
                result["open_ports"].append(port)

    if 443 in result["open_ports"]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            result["https"] = True
            result["ssl_expires_at"] = expires.isoformat()
            result["days_to_ssl_expiry"] = (expires - datetime.utcnow()).days
            if result["days_to_ssl_expiry"] <= 14:
                result["risks"].append("SSL certificate expires soon")
        except Exception:
            result["risks"].append("SSL certificate could not be verified")
    
    if 80 in result["open_ports"] and 443 not in result["open_ports"]:
        result["risks"].append("HTTP is exposed without secure HTTPS alternative")

    return result


@router.post("/watchlist/preview")
async def watchlist_preview(
    data: WatchlistRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    keywords = [item.strip() for item in data.keywords if item.strip()]
    matches = []
    for keyword in keywords[:10]:
        advisories = (
            db.query(Advisory)
            .filter(or_(Advisory.title.ilike(f"%{keyword}%"), Advisory.description.ilike(f"%{keyword}%")))
            .order_by(desc(Advisory.created_at))
            .limit(5)
            .all()
        )
        iocs = db.query(IOC).filter(IOC.value.ilike(f"%{keyword}%")).limit(5).all()
        matches.append({
            "keyword": keyword,
            "advisories": [compact_advisory(item) for item in advisories],
            "iocs": [{"id": item.id, "value": item.value, "type": item.ioc_type} for item in iocs],
        })
    return {"keywords": keywords, "matches": matches}


@router.post("/leak-check")
async def leak_check(
    data: LeakCheckRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    keyword = data.keyword.strip()
    advisory_hits = (
        db.query(Advisory)
        .filter(or_(Advisory.title.ilike(f"%{keyword}%"), Advisory.description.ilike(f"%{keyword}%")))
        .order_by(desc(Advisory.created_at))
        .limit(10)
        .all()
    )
    ioc_hits = db.query(IOC).filter(IOC.value.ilike(f"%{keyword}%")).limit(10).all()

    signals = []
    if "@" in keyword:
        signals.append("Email identity format detected")
    if "." in keyword and " " not in keyword:
        signals.append("Domain or hostname format detected")
    if advisory_hits or ioc_hits:
        signals.append("Keyword appears in local threat intelligence")

    return {
        "keyword": keyword,
        "exposure_level": "Elevated" if advisory_hits or ioc_hits else "Watch",
        "signals": signals or ["No direct local matches"],
        "advisories": [compact_advisory(item) for item in advisory_hits],
        "iocs": [{"id": item.id, "value": item.value, "type": item.ioc_type} for item in ioc_hits],
    }


@router.post("/incident-copilot")
async def incident_copilot(
    data: AdvancedTextRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    text = data.text.strip()
    indicators = extract_indicators(text)
    terms = [text, *indicators["cves"], *indicators["ips"], *indicators["domains"]][:10]
    matches = []
    for term in terms:
        matches.extend(
            db.query(Advisory)
            .filter(or_(Advisory.title.ilike(f"%{term}%"), Advisory.description.ilike(f"%{term}%")))
            .limit(5)
            .all()
        )
    unique = list({item.id: item for item in matches}.values())
    score = max([advisory_score(item) for item in unique], default=25)
    if indicators["hashes"] or indicators["urls"]:
        score += 15
    if any(word in text.lower() for word in ["ransomware", "admin", "domain controller", "exfil", "data leak"]):
        score += 25
    score = min(score, 100)
    severity = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 35 else "Low"
    mitre = map_mitre(text)
    actors = match_actors(text)
    attack_path = [
        {"id": "entry", "label": "Initial Access", "detail": "Phishing, exposed service, or malicious file"},
        {"id": "execution", "label": "Execution", "detail": "Script, payload, exploit, or user execution"},
        {"id": "persistence", "label": "Persistence", "detail": "Scheduled task, service, token, or credential reuse"},
        {"id": "lateral", "label": "Lateral Movement", "detail": "Remote service, VPN, SMB, RDP, or cloud session"},
        {"id": "impact", "label": "Impact", "detail": "Data theft, encryption, outage, or account takeover"},
    ]
    return {
        "severity": severity,
        "score": score,
        "summary": f"SecureEye rates this incident as {severity} based on indicators, local advisories, MITRE mapping, and exploitation signals.",
        "indicators": indicators,
        "likely_attack_path": attack_path,
        "mitre": mitre,
        "actors": actors,
        "exploit": exploit_status(text, unique),
        "containment_steps": [
            "Isolate impacted endpoint, account, or workload.",
            "Block related IPs, domains, URLs, and hashes at perimeter and EDR.",
            "Reset exposed credentials and revoke active sessions.",
            "Search SIEM, EDR, DNS, firewall, VPN, and proxy logs for matching indicators.",
            "Apply vendor patch or mitigation for matched CVEs.",
        ],
        "report_draft": {
            "title": f"{severity} Security Incident Triage",
            "business_impact": "Potential exposure depends on affected asset criticality, privilege level, and confirmed lateral movement.",
            "next_update": "Provide an update after containment validation and log sweep completion.",
        },
        "matches": [compact_advisory(item) for item in sorted(unique, key=advisory_score, reverse=True)[:8]],
    }


@router.post("/mitre-map")
async def mitre_map(data: AdvancedTextRequest, current_user=Depends(get_current_active_user)):
    return {"items": map_mitre(data.text), "indicators": extract_indicators(data.text)}


@router.post("/actor-match")
async def actor_profile_match(data: AdvancedTextRequest, current_user=Depends(get_current_active_user)):
    return {"actors": match_actors(data.text), "indicators": extract_indicators(data.text)}


@router.post("/exploit-tracker")
async def exploit_tracker(
    data: AdvancedTextRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    indicators = extract_indicators(data.text)
    advisories = []
    for cve in indicators["cves"]:
        advisories.extend(
            db.query(Advisory)
            .filter(or_(Advisory.title.ilike(f"%{cve}%"), Advisory.description.ilike(f"%{cve}%")))
            .limit(5)
            .all()
        )
    unique = list({item.id: item for item in advisories}.values())
    return {**exploit_status(data.text, unique), "cves": indicators["cves"], "matches": [compact_advisory(item) for item in unique[:8]]}


@router.post("/rule-builder")
async def rule_builder(data: AdvancedTextRequest, current_user=Depends(get_current_active_user)):
    indicators = extract_indicators(data.text)
    strings = [item for item in re.findall(r"[A-Za-z0-9_./:-]{6,}", data.text) if not item.startswith("http")][:8]
    yara_strings = indicators["hashes"] + indicators["domains"][:5] + strings[:5]
    yara = "rule SecureEye_Generated_Detection {\n  meta:\n    author = \"SecureEye\"\n    generated = \"%s\"\n  strings:\n%s\n  condition:\n    any of them\n}" % (
        datetime.utcnow().isoformat(),
        "\n".join([f"    $s{i} = \"{value[:120]}\" nocase" for i, value in enumerate(yara_strings or ["suspicious"], 1)]),
    )
    sigma = {
        "title": "SecureEye Generated Detection",
        "status": "experimental",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"CommandLine|contains": yara_strings or ["suspicious"]},
            "condition": "selection",
        },
        "level": "high" if indicators["hashes"] or indicators["urls"] else "medium",
    }
    return {"yara": yara, "sigma": sigma, "indicators": indicators}


@router.post("/patch-planner")
async def patch_planner(
    data: PatchPlanRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    cves = [item.strip().upper() for item in data.cves if item.strip()]
    rows = []
    for cve in cves[:30]:
        advisories = (
            db.query(Advisory)
            .filter(or_(Advisory.title.ilike(f"%{cve}%"), Advisory.description.ilike(f"%{cve}%")))
            .limit(5)
            .all()
        )
        base = max([advisory_score(item) for item in advisories], default=35)
        if data.asset_exposure == "internet":
            base += 20
        if data.business_criticality == "high":
            base += 20
        score = min(base, 100)
        rows.append({
            "cve": cve,
            "priority": "P0" if score >= 85 else "P1" if score >= 65 else "P2" if score >= 40 else "P3",
            "score": score,
            "sla": "24 hours" if score >= 85 else "72 hours" if score >= 65 else "14 days" if score >= 40 else "30 days",
            "reason": ["Local match" if advisories else "No local match", data.asset_exposure, data.business_criticality],
        })
    return {"items": sorted(rows, key=lambda item: item["score"], reverse=True)}


@router.get("/zero-day-watch")
async def zero_day_watch(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    keywords = ["zero-day", "zero day", "actively exploited", "under investigation", "no patch", "unpatched"]
    filters = [Advisory.description.ilike(f"%{keyword}%") for keyword in keywords] + [Advisory.title.ilike(f"%{keyword}%") for keyword in keywords]
    rows = (
        db.query(Advisory)
        .filter(or_(Advisory.is_zero_day == True, *filters))
        .order_by(desc(Advisory.created_at))
        .limit(30)
        .all()
    )
    return {"items": [compact_advisory(item) for item in rows]}


@router.get("/feed-health")
async def feed_health(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    from models import FeedLog

    rows = (
        db.query(FeedLog)
        .order_by(desc(FeedLog.run_at))
        .limit(50)
        .all()
    )
    latest = {}
    for row in rows:
        if row.feed_source not in latest:
            latest[row.feed_source] = {
                "source": row.feed_source,
                "status": row.status,
                "started_at": row.run_at,
                "items_new": row.items_new,
                "items_fetched": row.items_fetched,
                "error": row.error_msg,
            }
    free_sources = [
        {"source": "CISA_KEV", "access": "free/no key", "endpoint": "CISA KEV JSON"},
        {"source": "NVD_CVE", "access": "free/no key, optional key", "endpoint": "NVD CVE API 2.0"},
        {"source": "URLHaus", "access": "free/no key", "endpoint": "abuse.ch URLHaus CSV"},
        {"source": "Feodo Tracker", "access": "free/no key", "endpoint": "abuse.ch Feodo JSON"},
        {"source": "ThreatFox", "access": "free auth key required", "endpoint": "ThreatFox export"},
    ]
    return {"latest": list(latest.values()), "free_sources": free_sources}


@router.post("/executive-report")
async def executive_report(
    data: ExecutiveReportRequest,
    current_user=Depends(get_current_active_user),
):
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    except Exception:
        content = f"{data.title}\n\n{data.summary}\n\nBusiness Impact:\n{data.business_impact}\n\nActions:\n" + "\n".join(data.recommended_actions)
        return Response(content=content.encode(), media_type="text/plain")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [
        Paragraph(data.title, styles["Title"]),
        Spacer(1, 12),
        Paragraph(data.summary or "No summary provided.", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Business Impact", styles["Heading2"]),
        Paragraph(data.business_impact or "To be assessed.", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Affected Assets", styles["Heading2"]),
        *[Paragraph(f"- {asset}", styles["BodyText"]) for asset in (data.affected_assets or ["Not specified"])],
        Spacer(1, 12),
        Paragraph("Recommended Actions", styles["Heading2"]),
        *[Paragraph(f"- {action}", styles["BodyText"]) for action in (data.recommended_actions or ["Continue investigation"])],
    ]
    doc.build(story)
    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="SecureEye_Executive_Report.pdf"'},
    )
