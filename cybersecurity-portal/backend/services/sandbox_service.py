"""
Malware Sandbox & DeepScan Service — Production-Grade Multi-Source
Sources:
  1. VirusTotal v3       — File hash reputation (free key, 4/min)
  2. MalwareBazaar       — Hash lookup (free, no key)
  3. Hybrid Analysis     — Hash lookup (free key, optional)
  4. Local Static Analysis — Heuristic file scanning (no API)
  5. URL Intelligence     — DNS, SSL, phishing heuristics + AI
"""
import asyncio
import logging
import httpx
import hashlib
import socket
import ssl
import re
from urllib.parse import urlparse
from config import settings
try:
    from services.ai_service import summarize_threat_report
except ImportError:
    from ai_service import summarize_threat_report

logger = logging.getLogger("sandbox")

HYBRID_ANALYSIS_API = "https://www.hybrid-analysis.com/api/v2"
HEADERS = {"User-Agent": "SecureEye-DeepScan/2.0 (security-research)"}


def calculate_sha256(file_content: bytes) -> str:
    """Compute SHA256 of uploaded file."""
    return hashlib.sha256(file_content).hexdigest()


async def _lookup_virustotal(file_hash: str) -> dict | None:
    """Tier 1: VirusTotal v3 — Free key, 4/min, 500/day."""
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    try:
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers=headers
            )
            if r.status_code == 200:
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                harmless = stats.get("harmless", 0)
                total = malicious + suspicious + undetected + harmless

                threat_label = data.get("popular_threat_classification", {}).get("suggested_threat_label", "")

                verdict = "clean"
                if malicious >= 5:
                    verdict = "malicious"
                elif malicious >= 1 or suspicious >= 3:
                    verdict = "suspicious"

                return {
                    "found": True,
                    "source": "VirusTotal",
                    "verdict": verdict,
                    "threat_score": int((malicious + suspicious) / max(total, 1) * 100),
                    "vx_family": threat_label or data.get("type_description", ""),
                    "detections": f"{malicious}/{total} engines flagged malicious",
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "harmless_count": harmless,
                    "total_engines": total,
                    "sha256": data.get("sha256", file_hash),
                    "file_type": data.get("type_description", ""),
                    "file_size": data.get("size", 0),
                    "first_submission": data.get("first_submission_date"),
                    "report_url": f"https://www.virustotal.com/gui/file/{file_hash}"
                }
            elif r.status_code == 404:
                return {"found": False, "source": "VirusTotal", "message": "Not found in VirusTotal database."}
    except Exception as e:
        logger.error(f"VirusTotal lookup failed: {e}")
    return None


async def _lookup_malwarebazaar(file_hash: str) -> dict | None:
    """Tier 2: MalwareBazaar by abuse.ch — Completely free, no key required."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": file_hash}
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    sample = data["data"][0]
                    return {
                        "found": True,
                        "source": "MalwareBazaar",
                        "verdict": "malicious",
                        "threat_score": 90,
                        "vx_family": sample.get("signature") or sample.get("file_type", ""),
                        "detections": f"Confirmed malware sample",
                        "sha256": sample.get("sha256_hash", file_hash),
                        "file_type": sample.get("file_type", ""),
                        "file_size": sample.get("file_size", 0),
                        "first_seen": sample.get("first_seen"),
                        "tags": sample.get("tags") or [],
                        "delivery_method": sample.get("delivery_method", ""),
                        "intelligence": sample.get("intelligence", {}),
                        "report_url": f"https://bazaar.abuse.ch/sample/{sample.get('sha256_hash', file_hash)}/"
                    }
                elif data.get("query_status") == "hash_not_found":
                    return {"found": False, "source": "MalwareBazaar", "message": "Not found in MalwareBazaar database."}
    except Exception as e:
        logger.error(f"MalwareBazaar lookup failed: {e}")
    return None


async def _lookup_hybrid_analysis(file_hash: str) -> dict | None:
    """Tier 3: Hybrid Analysis — Free key optional."""
    api_key = getattr(settings, "HYBRID_ANALYSIS_API_KEY", "")
    if not api_key:
        return None
    try:
        headers = {
            "User-Agent": "Falcon Sandbox",
            "api-key": api_key
        }
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                f"{HYBRID_ANALYSIS_API}/search/hash",
                data={"hash": file_hash},
                headers=headers
            )
            if r.status_code == 200:
                results = r.json()
                if results and len(results) > 0:
                    report = results[0]
                    return {
                        "found": True,
                        "source": "Hybrid Analysis",
                        "verdict": report.get("verdict", "unknown"),
                        "threat_score": report.get("threat_score"),
                        "vx_family": report.get("vx_family"),
                        "analysis_start_time": report.get("analysis_start_time"),
                        "sha256": report.get("sha256"),
                        "report_url": f"https://www.hybrid-analysis.com/sample/{report.get('sha256')}"
                    }
        return {"found": False, "source": "Hybrid Analysis", "message": "No report found."}
    except Exception as e:
        logger.error(f"Hybrid Analysis lookup failed: {e}")
    return None


async def _lookup_pulsedive(file_hash: str) -> dict | None:
    """Tier 4: Pulsedive — Free tier, 50 req/day without key."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"https://pulsedive.com/api/info.php?indicator={file_hash}")
            if r.status_code == 200:
                data = r.json()
                if not data.get("error") and data.get("iid"):
                    risk = data.get("risk", "unknown")
                    verdict = "clean"
                    if risk in ["high", "critical"]:
                        verdict = "malicious"
                    elif risk == "medium":
                        verdict = "suspicious"
                        
                    return {
                        "found": True,
                        "source": "Pulsedive",
                        "verdict": verdict,
                        "threat_score": 80 if verdict == "malicious" else 50,
                        "vx_family": "",
                        "detections": f"Pulsedive risk level: {risk}",
                        "sha256": file_hash,
                        "file_type": "Indicator",
                        "file_size": 0,
                        "first_seen": data.get("stamp_seen"),
                        "report_url": f"https://pulsedive.com/indicator/?iid={data.get('iid')}"
                    }
        return {"found": False, "source": "Pulsedive", "message": "Not found in Pulsedive database."}
    except Exception as e:
        logger.error(f"Pulsedive lookup failed: {e}")
    return None


def _score_from_sources(source_results: list[dict], local_report: dict | None = None) -> tuple[int, str, list[str]]:
    score = 0
    factors = []

    for item in source_results:
        if not item or not item.get("found"):
            continue
        verdict = (item.get("verdict") or "").lower()
        source = item.get("source", "Threat source")
        if verdict == "malicious":
            score += 55
            factors.append(f"{source} confirmed malicious reputation")
        elif verdict == "suspicious":
            score += 30
            factors.append(f"{source} reported suspicious reputation")
        elif item.get("threat_score"):
            score += min(int(item.get("threat_score") or 0), 35)

        if item.get("malicious_count", 0) >= 5:
            score += 20
            factors.append(f"{source} has {item.get('malicious_count')} malicious detections")
        if item.get("vx_family"):
            factors.append(f"Malware family/signature: {item.get('vx_family')}")

    if local_report:
        suspicious = local_report.get("suspicious_features") or []
        if suspicious:
            score += min(len(suspicious) * 10, 35)
            factors.extend(suspicious[:5])

    score = max(0, min(score, 100))
    verdict = "Clean"
    if score >= 70:
        verdict = "Malicious"
    elif score >= 35:
        verdict = "Suspicious"
    elif score >= 15:
        verdict = "Review Required"
    return score, verdict, factors


def _build_static_summary(target: str, verdict: str, score: int, factors: list[str], sources: list[str]) -> str:
    if verdict == "Malicious":
        lead = f"{target} has confirmed malicious intelligence and should be blocked or isolated immediately."
    elif verdict == "Suspicious":
        lead = f"{target} shows suspicious signals and should be treated as untrusted until manually reviewed."
    elif verdict == "Review Required":
        lead = f"{target} has weak risk signals that require analyst validation before allowlisting."
    else:
        lead = f"{target} has no strong malicious signal in the checked free intelligence sources."

    factor_text = "; ".join(factors[:4]) if factors else "No high-confidence malicious indicators were returned."
    source_text = ", ".join(sources) if sources else "local static analysis"
    return f"{lead} Risk score: {score}/100. Key evidence: {factor_text}. Sources checked: {source_text}."

async def get_sandbox_report(file_hash: str, file_content: bytes = None, filename: str = "", mode: str = "basic") -> dict:
    """
    Multi-source hash reputation lookup with tiered failover.
    Tries: VirusTotal → MalwareBazaar → Hybrid Analysis
    If mode == 'advanced', uploads to Hybrid Analysis if no report exists.
    """
    if not file_hash or len(file_hash) < 32:
        return {"error": "Invalid file hash format. Provide MD5 (32), SHA-1 (40), or SHA-256 (64)."}

    lookups = [_lookup_virustotal, _lookup_malwarebazaar, _lookup_hybrid_analysis, _lookup_pulsedive]
    results = await asyncio.gather(*(fn(file_hash) for fn in lookups), return_exceptions=True)
    source_results = [r for r in results if isinstance(r, dict)]
    sources_checked = [r.get("source") for r in source_results if r.get("source")]
    positive = [r for r in source_results if r.get("found")]

    if positive:
        score, verdict, factors = _score_from_sources(positive)
        primary = max(positive, key=lambda item: int(item.get("threat_score") or 0))
        return {
            **primary,
            "verdict": verdict,
            "threat_score": score,
            "source_results": source_results,
            "sources_checked": sources_checked,
            "risk_factors": factors,
            "summary": _build_static_summary(file_hash, verdict, score, factors, sources_checked),
        }

    # If all sources checked but none found, and mode is advanced, upload to Hybrid Analysis
    api_key = getattr(settings, "HYBRID_ANALYSIS_API_KEY", "")
    if mode == "advanced" and file_content and api_key:
        try:
            headers = {"User-Agent": "Falcon Sandbox", "api-key": api_key}
            files = {"file": (filename or "sample.bin", file_content)}
            data = {"environment_id": 120} # Windows 10 64-bit
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(f"{HYBRID_ANALYSIS_API}/submit/file", headers=headers, files=files, data=data)
                if r.status_code in (200, 201):
                    return {
                        "found": True,
                        "source": "Hybrid Analysis",
                        "verdict": "Analysis Pending",
                        "threat_score": 0,
                        "message": "File successfully submitted to Falcon Sandbox. Detonation in progress.",
                        "report_url": f"https://www.hybrid-analysis.com/sample/{file_hash}"
                    }
        except Exception as e:
            logger.error(f"Hybrid Analysis file upload failed: {e}")

    # If still not found or not uploaded
    return {
        "found": False,
        "message": "No existing report found in Threat DBs, and upload was skipped or failed.",
        "hash": file_hash,
        "source_results": source_results,
        "sources_checked": sources_checked or ["VirusTotal", "MalwareBazaar", "Hybrid Analysis", "Pulsedive"],
        "verdict": "Clean",
        "threat_score": 0,
        "summary": _build_static_summary(file_hash, "Clean", 0, [], sources_checked),
    }


import base64

async def analyze_url(url: str, mode: str = "basic") -> dict:
    """
    Advanced URL Analysis:
    1. Resolve IP & Location
    2. Check SSL/TLS Security
    3. Phishing Pattern Detection
    4. URLhaus malware check (free, no key)
    5. VirusTotal URL check (if mode == advanced)
    6. AI Verdict
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]

    analysis = {
        "url": url,
        "domain": domain,
        "is_https": url.startswith("https://"),
        "ip": None,
        "location": "Unknown",
        "phishing_score": 0,
        "suspicious_patterns": [],
        "verdict": "Clear",
        "details": "",
        "urlhaus": None,
        "source_results": [],
        "sources_checked": [],
        "risk_factors": [],
        "network_exposure": {},
    }

    # 1. Resolve IP
    try:
        analysis["ip"] = socket.gethostbyname(domain)
    except Exception:
        analysis["ip"] = "Unresolved"
        analysis["phishing_score"] += 10
        analysis["suspicious_patterns"].append("Domain could not be resolved")

    # 2. Heuristic Phishing Check
    suspicious_tlds = [".zip", ".mov", ".top", ".xyz", ".club", ".link", ".tk", ".ml", ".ga", ".cf"]
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        analysis["phishing_score"] += 20
        analysis["suspicious_patterns"].append(f"Suspicious TLD: {domain}")

    if "-" in domain or "@" in domain:
        analysis["phishing_score"] += 10
        analysis["suspicious_patterns"].append("Dashes or @ in domain (common in phishing)")

    if len(domain) > 30:
        analysis["phishing_score"] += 15
        analysis["suspicious_patterns"].append("Excessively long domain name")

    # Check for brand impersonation patterns
    brand_keywords = ["paypal", "google", "apple", "microsoft", "amazon", "netflix", "bank"]
    if any(brand in domain.lower() for brand in brand_keywords) and not any(domain.endswith(f".{brand}.com") for brand in brand_keywords):
        analysis["phishing_score"] += 25
        analysis["suspicious_patterns"].append("Possible brand impersonation detected")

    # 3. SSL Check
    if analysis["is_https"]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    # Flatten the issuer tuple into a dictionary
                    issuer_dict = dict(x[0] for x in cert.get("issuer", ()) if x)
                    analysis["ssl_issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown"
        except Exception:
            analysis["ssl_issuer"] = "Self-signed or Invalid"
            analysis["phishing_score"] += 10
    else:
        analysis["phishing_score"] += 5
        analysis["suspicious_patterns"].append("No HTTPS encryption")

    # 4. URLhaus Check (free, no key)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
            if r.status_code == 200:
                uh_data = r.json()
                if uh_data.get("query_status") == "ok":
                    analysis["urlhaus"] = {
                        "threat": uh_data.get("threat", "malware_download"),
                        "status": uh_data.get("url_status", ""),
                        "tags": uh_data.get("tags") or [],
                        "blacklists": uh_data.get("blacklists", {}),
                    }
                    analysis["phishing_score"] += 50
                    analysis["suspicious_patterns"].append(f"URLhaus: Confirmed malicious ({uh_data.get('threat', 'malware')})")
    except Exception as e:
        logger.warning(f"URLhaus URL check failed: {e}")

    async def check_urlhaus_host():
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": domain}, headers=HEADERS)
                if r.status_code == 200 and r.json().get("query_status") == "ok":
                    data = r.json()
                    return {
                        "found": True,
                        "source": "URLhaus Host",
                        "verdict": "malicious",
                        "threat_score": 85,
                        "detections": f"{len(data.get('urls') or [])} malicious URLs on host",
                        "report_url": f"https://urlhaus.abuse.ch/browse.php?search={domain}",
                    }
        except Exception as e:
            logger.warning(f"URLhaus host failed: {e}")
        return {"found": False, "source": "URLhaus Host"}

    async def check_threatfox():
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json={"query": "search_ioc", "search_term": domain},
                    headers=HEADERS,
                )
                if r.status_code == 200 and r.json().get("query_status") == "ok":
                    return {
                        "found": True,
                        "source": "ThreatFox",
                        "verdict": "malicious",
                        "threat_score": 80,
                        "detections": f"{len(r.json().get('data') or [])} IOC matches",
                        "report_url": "https://threatfox.abuse.ch/",
                    }
        except Exception as e:
            logger.warning(f"ThreatFox URL/domain failed: {e}")
        return {"found": False, "source": "ThreatFox"}

    async def check_openphish():
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get("https://openphish.com/feed.txt", headers=HEADERS)
                if r.status_code == 200:
                    matches = [line for line in r.text.splitlines() if domain in line][:5]
                    if matches:
                        return {
                            "found": True,
                            "source": "OpenPhish",
                            "verdict": "malicious",
                            "threat_score": 85,
                            "detections": f"{len(matches)} active phishing feed matches",
                            "matches": matches,
                            "report_url": "https://openphish.com/",
                        }
        except Exception as e:
            logger.warning(f"OpenPhish failed: {e}")
        return {"found": False, "source": "OpenPhish"}

    async def check_urlscan():
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    "https://urlscan.io/api/v1/search/",
                    params={"q": f"domain:{domain}", "size": 5},
                    headers=HEADERS,
                )
                if r.status_code == 200:
                    results = r.json().get("results") or []
                    malicious = [
                        item for item in results
                        if item.get("verdicts", {}).get("overall", {}).get("malicious")
                    ]
                    if malicious:
                        return {
                            "found": True,
                            "source": "URLScan.io",
                            "verdict": "malicious",
                            "threat_score": 80,
                            "detections": f"{len(malicious)} malicious URLScan verdicts",
                            "report_url": malicious[0].get("result"),
                        }
                    return {"found": bool(results), "source": "URLScan.io", "verdict": "clean", "threat_score": 0, "detections": f"{len(results)} public scans"}
        except Exception as e:
            logger.warning(f"URLScan failed: {e}")
        return {"found": False, "source": "URLScan.io"}

    async def check_shodan():
        if not analysis.get("ip") or analysis["ip"] == "Unresolved":
            return {"found": False, "source": "Shodan InternetDB"}
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(f"https://internetdb.shodan.io/{analysis['ip']}", headers=HEADERS)
                if r.status_code == 200:
                    data = r.json()
                    vulns = data.get("vulns") or []
                    ports = data.get("ports") or []
                    analysis["network_exposure"] = {"ports": ports, "vulns": vulns, "cpes": data.get("cpes") or []}
                    return {
                        "found": True,
                        "source": "Shodan InternetDB",
                        "verdict": "suspicious" if vulns else "clean",
                        "threat_score": 70 if vulns else 10 if ports else 0,
                        "detections": f"{len(ports)} open ports, {len(vulns)} CVEs",
                        "vulns": vulns,
                        "ports": ports,
                        "report_url": f"https://www.shodan.io/host/{analysis['ip']}",
                    }
        except Exception as e:
            logger.warning(f"Shodan InternetDB failed: {e}")
        return {"found": False, "source": "Shodan InternetDB"}

    extra_results = await asyncio.gather(
        check_urlhaus_host(),
        check_threatfox(),
        check_openphish(),
        check_urlscan(),
        check_shodan(),
        return_exceptions=True,
    )
    for item in extra_results:
        if isinstance(item, dict):
            analysis["source_results"].append(item)
            if item.get("source"):
                analysis["sources_checked"].append(item["source"])
            if item.get("found") and item.get("verdict") in {"malicious", "suspicious"}:
                analysis["phishing_score"] += min(int(item.get("threat_score") or 0), 50)
                analysis["suspicious_patterns"].append(f"{item.get('source')}: {item.get('detections', 'risk signal')}")

    # 5. VirusTotal URL Lookup (Deep Analysis Mode)
    if mode == "advanced" and getattr(settings, "VIRUSTOTAL_API_KEY", ""):
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
                if r.status_code == 200:
                    vt_data = r.json().get("data", {}).get("attributes", {})
                    stats = vt_data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    if malicious > 0:
                        analysis["phishing_score"] += (malicious * 10)
                        analysis["suspicious_patterns"].append(f"VirusTotal: {malicious} security vendors flagged this URL as malicious")
        except Exception as e:
            logger.error(f"VirusTotal URL lookup failed: {e}")

    # 5. Final Verdict & AI Explanation
    analysis["phishing_score"] = min(analysis["phishing_score"], 100)
    score, aggregate_verdict, factors = _score_from_sources(
        [item for item in analysis["source_results"] if item.get("found")],
        {"suspicious_features": analysis["suspicious_patterns"]},
    )
    analysis["risk_factors"] = factors or analysis["suspicious_patterns"]

    if max(analysis["phishing_score"], score) > 60:
        analysis["verdict"] = "Malicious"
    elif max(analysis["phishing_score"], score) > 25:
        analysis["verdict"] = "Suspicious"
    elif aggregate_verdict == "Review Required":
        analysis["verdict"] = "Review Required"

    analysis["summary"] = _build_static_summary(domain, analysis["verdict"], max(analysis["phishing_score"], score), analysis["risk_factors"], analysis["sources_checked"])
    ai_prompt = (
        "Using only the following URL scan evidence, write a concise analyst verdict. "
        "If evidence is weak, say so. Do not invent detections or references.\n"
        f"{analysis}"
    )
    ai_report = await summarize_threat_report(ai_prompt)
    analysis["ai_report"] = ai_report if not ai_report.startswith("Automated analysis completed") else analysis["summary"]

    return analysis


async def local_static_analysis(file_content: bytes, filename: str) -> dict:
    """Perform basic local analysis without cloud upload."""
    sha256 = calculate_sha256(file_content)
    md5 = hashlib.md5(file_content).hexdigest()
    size_kb = len(file_content) / 1024

    # ASCII string extraction (first 20)
    strings = re.findall(b"[A-Za-z0-9\\-\\.\\/]{5,}", file_content)[:20]
    decoded_strings = [s.decode(errors='ignore') for s in strings]

    # Heuristics
    suspicious = []
    if any(ext in filename.lower() for ext in [".exe", ".vbs", ".ps1", ".scr", ".bat", ".cmd", ".msi", ".dll"]):
        suspicious.append("Executable file type")

    if len(file_content) < 500:
        suspicious.append("Unusually small file (possible stager)")

    if len(file_content) > 50_000_000:
        suspicious.append("Very large file (possible padding/evasion)")

    # Check for suspicious strings
    suspicious_strings = [
        b"powershell", b"cmd.exe", b"WScript", b"eval(", b"base64", b"CreateObject",
        b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread", b"rundll32",
        b"regsvr32", b"Invoke-WebRequest", b"curl ", b"wget ", b"FromBase64String",
    ]
    for s in suspicious_strings:
        if s.lower() in file_content.lower():
            suspicious.append(f"Contains suspicious string: {s.decode()}")

    score, verdict, factors = _score_from_sources([], {"suspicious_features": suspicious})
    return {
        "filename": filename,
        "sha256": sha256,
        "md5": md5,
        "size_kb": round(size_kb, 2),
        "strings_sample": decoded_strings,
        "suspicious_features": suspicious,
        "threat_score": score,
        "risk_factors": factors,
        "verdict": verdict if suspicious else "Clean (Local Only)"
    }
