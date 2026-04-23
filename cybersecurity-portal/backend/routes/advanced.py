import re
import socket
import ssl
from datetime import datetime, timedelta
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
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


SEVERITY_WEIGHT = {
    SeverityLevel.critical: 40,
    SeverityLevel.high: 30,
    SeverityLevel.medium: 18,
    SeverityLevel.low: 8,
    SeverityLevel.informational: 3,
}


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
    }

    try:
        result["ip"] = socket.gethostbyname(domain)
    except OSError:
        result["risks"].append("Domain did not resolve")
        return result

    for port in [80, 443]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            if sock.connect_ex((domain, port)) == 0:
                result["open_ports"].append(port)

    if 443 in result["open_ports"]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=4) as sock:
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
    else:
        result["risks"].append("HTTPS is not reachable")

    for prefix in ["www", "api", "admin", "portal", "mail", "vpn"]:
        subdomain = f"{prefix}.{domain}"
        try:
            result["subdomains_checked"].append({"host": subdomain, "ip": socket.gethostbyname(subdomain)})
        except OSError:
            continue

    if 80 in result["open_ports"] and 443 not in result["open_ports"]:
        result["risks"].append("HTTP is exposed without HTTPS")
    if any(item["host"].startswith(("admin.", "vpn.")) for item in result["subdomains_checked"]):
        result["risks"].append("Sensitive subdomain discovered")

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
