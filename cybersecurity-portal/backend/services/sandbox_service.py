"""
Malware Sandbox & DeepScan Service
Integrates with Cloud APIs (Hybrid Analysis) + Local Static Analysis + URL Intelligence.
"""
import logging
import httpx
import hashlib
import socket
import ssl
from urllib.parse import urlparse
from config import settings
try:
    from services.ai_service import summarize_threat_report
except ImportError:
    from ai_service import summarize_threat_report

logger = logging.getLogger("sandbox")

HYBRID_ANALYSIS_API = "https://www.hybrid-analysis.com/api/v2"

def calculate_sha256(file_content: bytes) -> str:
    """Compute SHA256 of uploaded file."""
    return hashlib.sha256(file_content).hexdigest()

async def analyze_url(url: str) -> dict:
    """
    Advanced URL Analysis:
    1. Resolve IP & Location
    2. Check SSL/TLS Security
    3. Phishing Pattern Detection
    4. AI Verdict
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
        "details": ""
    }

    # 1. Resolve IP
    try:
        analysis["ip"] = socket.gethostbyname(domain)
    except:
        analysis["ip"] = "Unresolved"

    # 2. Heuristic Phishing Check
    suspicious_tlds = [".zip", ".mov", ".top", ".xyz", ".club", ".link"]
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        analysis["phishing_score"] += 20
        analysis["suspicious_patterns"].append(f"Suspicious TLD: {domain}")

    if "-" in domain or "@" in domain:
         analysis["phishing_score"] += 10
         analysis["suspicious_patterns"].append("Dashes or @ in domain (common in phishing)")

    if len(domain) > 30:
        analysis["phishing_score"] += 15
        analysis["suspicious_patterns"].append("Excessively long domain name")

    # 3. SSL Check (Simple)
    if analysis["is_https"]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    analysis["ssl_issuer"] = cert.get("issuer", [([("commonName", "Unknown")],)])[0][0][0][1]
        except:
            analysis["ssl_issuer"] = "Self-signed or Invalid"
            analysis["phishing_score"] += 10

    # 4. Final Verdict & AI Explanation
    if analysis["phishing_score"] > 40:
        analysis["verdict"] = "Malicious"
    elif analysis["phishing_score"] > 20:
        analysis["verdict"] = "Suspicious"

    # AI context for Gemini
    ai_prompt = f"Analyze this URL and its metadata: {analysis}. Provide a 2-sentence expert cybersecurity warning."
    analysis["ai_report"] = await summarize_threat_report(ai_prompt)

    return analysis

async def get_sandbox_report(file_hash: str) -> dict:
    """
    Search for an existing malware analysis report using a file hash.
    Uses Hybrid Analysis Public API.
    """
    if not file_hash or len(file_hash) < 32:
        return {"error": "Invalid file hash format"}

    headers = {
        "User-Agent": "Falcon Sandbox",
        "api-key": getattr(settings, "HYBRID_ANALYSIS_API_KEY", "")
    }

    async with httpx.AsyncClient(timeout=15) as client:
        try:
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
                        "verdict": report.get("verdict", "unknown"),
                        "threat_score": report.get("threat_score"),
                        "vx_family": report.get("vx_family"),
                        "analysis_start_time": report.get("analysis_start_time"),
                        "sha256": report.get("sha256"),
                        "report_url": f"https://www.hybrid-analysis.com/sample/{report.get('sha256')}"
                    }
            
            return {"found": False, "message": "No existing report found for this hash."}
        except Exception as e:
            logger.error(f"Sandbox lookup failed: {e}")
            return {"error": "Connection to sandbox service failed."}

async def local_static_analysis(file_content: bytes, filename: str) -> dict:
    """Perform basic local analysis without cloud upload."""
    sha256 = calculate_sha256(file_content)
    size_kb = len(file_content) / 1024
    
    # Simple ASCII string extraction (first 20)
    import re
    strings = re.findall(b"[A-Za-z0-9\-\.\/]{5,}", file_content)[:20]
    decoded_strings = [s.decode(errors='ignore') for s in strings]

    # Heuristics
    suspicious = []
    if any(ext in filename.lower() for ext in [".exe", ".vbs", ".ps1", ".scr", ".bat"]):
        suspicious.append("Executable file type")
    
    if len(file_content) < 500:
        suspicious.append("Unusually small file (possible stager)")

    return {
        "filename": filename,
        "sha256": sha256,
        "size_kb": round(size_kb, 2),
        "strings_sample": decoded_strings,
        "suspicious_features": suspicious,
        "verdict": "Review Required" if suspicious else "Clean (Local Only)"
    }
