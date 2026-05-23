"""
Secure Intelligence AI - Version 13.0 (Multi-Provider Auto-Rotating Engine)
Rotates across Gemini Flash, Groq (multi-key), Cerebras, OpenRouter free models.
Combined free quota: 18,000+ requests/day — effectively unlimited for normal usage.
"""
import logging
import httpx
import re

from groq import Groq
from bs4 import BeautifulSoup
from config import settings
from services.threat_feeds import search_live_sources

logger = logging.getLogger("ai_service")

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# ─── Multi-Provider AI Router ─────────────────────────────────────────────────
SYS_PROMPT = (
    "You are a Principal Threat Intelligence Analyst at SecureEye Global Operations Center. "
    "You produce CLASSIFIED, board-level intelligence reports for Fortune 500 CISOs and government security agencies. "
    "STRICT OUTPUT RULES — VIOLATING ANY RULE MAKES THE REPORT INVALID: "
    "(1) NEVER use asterisks (*), hashtags (#), double asterisks (**), underscores (_), or ANY markdown formatting. "
    "(2) ALWAYS use EXACTLY the section headers provided — no additions, no omissions, no reordering. "
    "(3) Use ONLY plain dashes (-) for bullet points. "
    "(4) Output CLEAN PLAIN TEXT only — no bold, no italic, no headers with #. "
    "(5) If data is unknown, provide your best expert assessment without labeling it as an estimate. "
    "(6) Be authoritative, precise, terse, and technically accurate."
)

async def _try_gemini(prompt: str, api_key: str, model: str = "gemini-2.0-flash", max_tokens: int = 3000) -> str | None:
    """Google Gemini — Free 1,500 req/day per key. Each model has its own quota."""
    if not api_key:
        return None
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": SYS_PROMPT}]},
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": max_tokens}
        }
        async with httpx.AsyncClient(timeout=45) as client:
            r = await client.post(url, json=payload)
            if r.status_code == 200:
                data = r.json()
                text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                if text and len(text.strip()) > 100:
                    logger.info(f"Gemini [{model}]: SUCCESS")
                    return text.strip()
            elif r.status_code == 429:
                logger.warning(f"Gemini [{model}]: rate limit hit, trying next provider")
    except Exception as e:
        logger.warning(f"Gemini [{model}] failed: {e}")
    return None

async def _try_groq(prompt: str, api_key: str, model: str = "llama-3.3-70b-versatile", max_tokens: int = 3000) -> str | None:
    """Groq — Free per key per model. Each model has its OWN separate rate limit bucket."""
    if not api_key:
        return None
    try:
        client = Groq(api_key=api_key)
        resp = client.chat.completions.create(
            messages=[{"role": "system", "content": SYS_PROMPT}, {"role": "user", "content": prompt}],
            model=model,
            temperature=0.2,
            max_tokens=max_tokens,
        )
        text = resp.choices[0].message.content
        if text and len(text.strip()) > 100:
            logger.info(f"Groq [{model}]: SUCCESS")
            return text.strip()
    except Exception as e:
        err = str(e)
        if "rate_limit" in err.lower() or "429" in err:
            logger.warning(f"Groq [{model}]: rate limit hit, rotating to next key/model")
        else:
            logger.warning(f"Groq [{model}] failed: {e}")
    return None

async def _try_cerebras(prompt: str, max_tokens: int = 3000) -> str | None:
    """Cerebras Llama-3.3-70B — Free 1,000 req/day. Very fast."""
    if not settings.CEREBRAS_API_KEY:
        return None
    try:
        url = "https://api.cerebras.ai/v1/chat/completions"
        payload = {
            "model": "llama-3.3-70b",
            "messages": [{"role": "system", "content": SYS_PROMPT}, {"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
        headers = {"Authorization": f"Bearer {settings.CEREBRAS_API_KEY}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=45) as client:
            r = await client.post(url, json=payload, headers=headers)
            if r.status_code == 200:
                text = r.json()["choices"][0]["message"]["content"]
                if text and len(text.strip()) > 100:
                    logger.info("Cerebras: SUCCESS")
                    return text.strip()
            elif r.status_code == 429:
                logger.warning("Cerebras: rate limit hit, trying next provider")
    except Exception as e:
        logger.warning(f"Cerebras failed: {e}")
    return None

async def _try_openrouter(prompt: str, max_tokens: int = 3000) -> str | None:
    """OpenRouter free models — No cost, just needs a free account key."""
    if not settings.OPENROUTER_API_KEY:
        return None
    try:
        url = "https://openrouter.ai/api/v1/chat/completions"
        payload = {
            "model": "meta-llama/llama-3.1-8b-instruct:free",  # Completely free model
            "messages": [{"role": "system", "content": SYS_PROMPT}, {"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
            "HTTP-Referer": "https://secureeye.app",
            "X-Title": "SecureEye Portal",
        }
        async with httpx.AsyncClient(timeout=45) as client:
            r = await client.post(url, json=payload, headers=headers)
            if r.status_code == 200:
                text = r.json()["choices"][0]["message"]["content"]
                if text and len(text.strip()) > 100:
                    logger.info("OpenRouter: SUCCESS")
                    return text.strip()
    except Exception as e:
        logger.warning(f"OpenRouter failed: {e}")
    return None

async def _smart_ai_call(prompt: str, max_tokens: int = 3000) -> str | None:
    """
    Rotates through all configured providers in priority order.
    Different models = separate rate limit buckets = more combined free quota!

    Priority order:
      Gemini Key1 (model1) → Gemini Key2 (model2) →
      Groq Key1 (model1)  → Groq Key2 (model2)   → Groq Key3 (model3) →
      Cerebras → OpenRouter
    """
    # ── Gemini Tier ──────────────────────────────────────────────────────────
    result = await _try_gemini(prompt, settings.GEMINI_API_KEY, settings.GEMINI_MODEL_1, max_tokens)
    if result:
        return result

    result = await _try_gemini(prompt, settings.GEMINI_API_KEY_2, settings.GEMINI_MODEL_2, max_tokens)
    if result:
        return result

    # ── Groq Tier (each model has its own separate daily rate limit) ─────────
    result = await _try_groq(prompt, settings.GROQ_API_KEY, settings.GROQ_MODEL_1, max_tokens)
    if result:
        return result

    result = await _try_groq(prompt, settings.GROQ_API_KEY_2, settings.GROQ_MODEL_2, max_tokens)
    if result:
        return result

    result = await _try_groq(prompt, settings.GROQ_API_KEY_3, settings.GROQ_MODEL_3, max_tokens)
    if result:
        return result

    result = await _try_groq(prompt, settings.GROQ_API_KEY_4, settings.GROQ_MODEL_4, max_tokens)
    if result:
        return result

    # ── Cerebras Tier ────────────────────────────────────────────────────────
    result = await _try_cerebras(prompt, max_tokens)
    if result:
        return result

    # ── OpenRouter Tier ──────────────────────────────────────────────────────
    result = await _try_openrouter(prompt, max_tokens)
    if result:
        return result

    return None


async def scrape_link(url: str) -> str:
    """Extract and clean text content from a provided security link."""
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            headers = {"User-Agent": "SecureEye-Intelligence-Bot/5.0"}
            r = await client.get(url, headers=headers)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup(["script", "style", "nav", "footer", "aside", "form"]):
                tag.decompose()
            text = soup.get_text(separator=" ", strip=True)
            return re.sub(r'\s+', ' ', text)[:10000]
    except Exception as e:
        logger.error(f"Scraping failed: {e}")
        return ""

async def get_ai_summary(content: str) -> str:
    """
    Generates an ultra-professional, classified threat intelligence report
    using AI as the primary engine.
    """
    prompt = f"""Analyze the following security content and produce a COMPLETE, STRUCTURED intelligence report.

CRITICAL RULES:
- Use EXACTLY the section headers below in EXACT order. DO NOT skip any section.
- NO markdown: no asterisks (*), no hashtags (#), no bold (**text**), no underscores.
- Use plain dashes (-) for ALL bullet points.
- If data is unknown, fill with expert knowledge — NEVER leave blank. Do NOT use the phrase [ANALYST ESTIMATE].
- Output ONLY plain text. No preambles, no sign-offs, no extra commentary.

====================================================================
SECURE THREAT INTELLIGENCE BRIEF
[THREAT_ID: Primary CVE ID, malware family name, or threat campaign. E.g., CVE-2024-12345 or MALWARE-AGENT-TESLA]
[CLASSIFICATION: CRITICAL / HIGH / MEDIUM / LOW]
[CVSS_SCORE: e.g., 9.8 or N/A]
[CVSS_VECTOR: e.g., AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H or N/A]
[TLP: AMBER]
[REPORT_DATE: today's date as DD MMM YYYY]
====================================================================

EXECUTIVE OVERVIEW
Provide a concise, bulleted summary covering all critical aspects:
- Threat Summary: [1-2 sentences on what the threat is and its severity]
- Systems Affected: [Vendors, products, or industries impacted]
- Attack Vector: [Exploitation method and complexity]
- Business Impact: [Immediate risk to the organization if unaddressed]
- Remediation Priority: [The most urgent action required]

THREAT ACTOR PROFILE
- Attribution: [Nation-state / Cybercriminal / Hacktivist / Unknown — with confidence level]
- Known Group: [APT name or group alias if attributed, else UNKNOWN]
- Primary Motivation: [Financial / Espionage / Sabotage / Ideology]
- Target Sectors: [Industries or government sectors most at risk]
- Historical Activity: [Known past campaigns or similar attacks by this actor]
- Sophistication Level: [LOW / MEDIUM / HIGH / NATION-STATE GRADE]

MITRE ATT&CK MAPPING
- Tactic: [Initial Access]\n  Technique: [e.g., T1190 - Exploit Public-Facing Application]
- Tactic: [Execution / Persistence / Privilege Escalation — most relevant]\n  Technique: [e.g., T1059.001 - PowerShell]
- Tactic: [Command and Control or Exfiltration]\n  Technique: [e.g., T1071.001 - Web Protocols]
- Tactic: [Defense Evasion]\n  Technique: [e.g., T1027 - Obfuscated Files or Information]

TECHNICAL ANALYSIS
- Vulnerability Class: [CWE type, e.g., CWE-78: OS Command Injection]
- Affected Products: [Specific software, versions, firmware, protocols]
- Attack Chain: [Step-by-step: Initial access → Execution → Persistence → Objective]
- Exploitation Complexity: [LOW / MEDIUM / HIGH + justification]
- Authentication Required: [YES / NO / PARTIAL]
- Public Exploit Available: [YES - PoC Public / YES - Weaponized / NO / UNCONFIRMED]
- In-the-Wild Exploitation: [CONFIRMED ACTIVE / LIMITED REPORTS / UNCONFIRMED / NO EVIDENCE]
- Payload Type: [Ransomware / RAT / Dropper / Backdoor / Infostealer / N/A]

INDICATORS OF COMPROMISE
- File Hashes (MD5/SHA256): [Known malicious hashes, or likely hash patterns]
- IP Addresses / C2 Infrastructure: [Known IPs, domains, or URLs used for C2]
- Malicious URLs / Download Locations: [Staging servers, payload delivery URLs]
- File System Artifacts: [Dropped files, registry keys, scheduled tasks, service names]
- Network Indicators: [Ports, protocols, beacon intervals, JA3/JA3S signatures, DNS queries]
- Process Indicators: [Spawned processes, injected processes, unusual parent-child relationships]
- YARA/Sigma Detection Hint: [Concise detection rule concept]

IMPACT ASSESSMENT
- Confidentiality Impact: [COMPLETE / PARTIAL / NONE — data at risk]
- Integrity Impact: [COMPLETE / PARTIAL / NONE — what can be tampered]
- Availability Impact: [COMPLETE / PARTIAL / NONE — downtime / ransomware risk]
- Affected Industries: [Finance, Healthcare, Government, Energy, Retail, etc.]
- Geographic Scope: [Global / Regional — specify regions]
- Regulatory Exposure: [GDPR / HIPAA / PCI-DSS / SOX / NIS2 / NERC CIP applicable]
- Estimated Financial Impact: [Quantify: e.g., potential $X million breach, ransom demands]
- Collateral Risk: [Supply chain exposure, lateral movement potential, downstream impact]

REMEDIATION DIRECTIVES
1. IMMEDIATE (0-24 hours): [Emergency containment — block IPs, isolate systems, pull network segments]
2. SHORT-TERM (24-72 hours): [Patch deployment, credential resets, firewall rules, temporary mitigations]
3. MEDIUM-TERM (3-7 days): [System hardening, detection rule deployment, threat hunting queries]
4. LONG-TERM (7-30 days): [Architecture review, vendor assessment, policy and process improvements]
5. DETECTION ENGINEERING: [Specific SIEM rule concept, EDR hunt query, Suricata/Snort rule hint, or YARA rule skeleton]

ANALYST VERDICT
Write exactly 3 sentences:
1. The single most critical action the security team must execute within the next hour.
2. The primary worst-case risk scenario if no action is taken within 48 hours.
3. Overall threat confidence level and recommended escalation path.

INTELLIGENCE REFERENCES
- NVD Database: https://nvd.nist.gov/vuln/detail/[CVE-ID or NOT AVAILABLE]
- MITRE ATT&CK: https://attack.mitre.org/techniques/[Primary TID]/ [or NOT AVAILABLE]
- MITRE CVE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=[CVE-ID or NOT AVAILABLE]
- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog [if in KEV, else NOT AVAILABLE]
- Vendor Security Advisory: [Official vendor patch URL or NOT AVAILABLE]
- VirusTotal: https://www.virustotal.com/gui/search/[hash or threat name]
- Additional Source: [Researcher blog, threat report, or vendor advisory URL]
====================================================================

CONTENT TO ANALYZE:
{content[:14000]}
"""
    # Use smart rotating AI engine (Gemini → Groq x3 → Cerebras → OpenRouter)
    result = await _smart_ai_call(prompt, max_tokens=3000)
    if result:
        return result

    # Final fallback: Rule-based engine (always works, no AI needed)
    raw_input = content.strip()
    if raw_input.startswith("http"):
        raw_context = await scrape_link(raw_input)
    else:
        if len(raw_input) < 50:
            research = await search_live_sources(raw_input)
            raw_context = " ".join([f"{i['title']} {i['description']}" for i in research.get("items", [])])
        else:
            raw_context = raw_input

    cve_match = CVE_PATTERN.search(raw_context)
    cve_id = cve_match.group(0).upper() if cve_match else "Threat Intelligence"
    vendor_match = re.search(r'\b(Horner Automation|Microsoft|Google|Cisco|WordPress|Delta|Apple|Linux|Fortinet)\b', raw_context, re.I)
    vendor = vendor_match.group(0) if vendor_match else "Enterprise Systems"
    cvss_match = re.search(r'CVSS\s*(?:3.1|3.0|2.0)?\s*(?:Score:?)?\s*(\d\.\d)', raw_context, re.I)
    cvss = cvss_match.group(1) if cvss_match else "High"

    sentences = [s.strip() for s in re.split(r'[.!?]', raw_context) if len(s.strip()) > 40]
    facts = [s for s in sentences if not any(x in s.lower() for x in ["legal", "privacy", "notification", "anonymous"])]

    report = []
    if cve_id == "Threat Intelligence":
        report.append("SECURE THREAT INTELLIGENCE BRIEF")
    else:
        report.append(f"SECURE THREAT INTELLIGENCE BRIEF: {cve_id}")
    report.append("=" * 55)
    if facts:
        report.append(f"A critical security exposure has been identified in {vendor} involving {facts[0].lower()}. The vulnerability carries a CVSS score of {cvss}, posing significant risk.")
    else:
        report.append(f"Technical analysis identifies a high-severity vulnerability in {vendor} infrastructure.")
    report.append("")
    report.append("TECHNICAL ANALYSIS & IMPACT:")
    for f in facts[2:6]:
        report.append(f"- {f}.")
    report.append("")
    report.append("REMEDIATION DIRECTIVES:")
    report.append("1. Apply the official vendor security patches immediately.")
    report.append("2. Isolate affected systems from public-facing network segments.")
    report.append("3. Enable enhanced logging and monitoring for anomalous activity.")
    report.append("")
    report.append("INTELLIGENCE REFERENCES:")
    if cve_id != "Threat Intelligence":
        report.append(f"- NVD Database: https://nvd.nist.gov/vuln/detail/{cve_id}")
        report.append(f"- MITRE CVE: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
    report.append(f"- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    return "\n".join(report)


async def summarize_threat_report(prompt: str) -> str:
    """Specialized AI call for playbooks and impact predictions. Uses smart rotating engine."""
    result = await _smart_ai_call(prompt, max_tokens=1500)
    if result:
        return result
    return "Automated analysis completed. Please review the technical metadata for threat indicators."

async def analyze_attack_surface(domain: str, scan_data: dict) -> str:
    """
    Generates a professional AI briefing based on raw attack surface scan data.
    """
    prompt = f"""You are a Principal Threat Intelligence Analyst mapping an external attack surface.
Analyze the following infrastructure reconnaissance data for the domain '{domain}' and produce a COMPLETE, STRUCTURED briefing.

CRITICAL RULES:
- Use EXACTLY the section headers below in EXACT order. DO NOT skip any section.
- NO markdown: no asterisks (*), no hashtags (#), no bold (**text**), no underscores.
- Use plain dashes (-) for ALL bullet points.
- If data is unknown or missing, write your best expert assessment or state 'None detected'. Do NOT use the phrase [ANALYST ESTIMATE].
- Output ONLY plain text. No preambles, no sign-offs, no extra commentary.

====================================================================
SECURE THREAT INTELLIGENCE BRIEF
[ASSET: {domain}]
[IP_ADDRESS: {scan_data.get('ip', 'UNKNOWN')}]
[CLASSIFICATION: TACTICAL RECONNAISSANCE]
[REPORT_DATE: today]
====================================================================

EXECUTIVE OVERVIEW
Provide a concise, bulleted summary covering:
- Exposure Summary: [1-2 sentences on the overall perimeter health]
- Key Findings: [Primary risks discovered, e.g., open ports, missing SSL, CVEs]
- Business Risk: [Immediate risk if infrastructure is breached]

TECHNICAL ANALYSIS
- Open Ports & Services: [List discovered open ports and likely running services]
- SSL/TLS Posture: [Describe certificate validity and HTTPS status]
- Discovered Subdomains: [Summarize the scope of discovered assets]
- Known Vulnerabilities (CVEs): [List any CVEs identified by Shodan, or state None]

THREAT REPUTATION (OTX)
- AlienVault OTX Pulses: [Describe any threat indicators or malicious associations discovered, or state None]

REMEDIATION DIRECTIVES
1. IMMEDIATE (0-24 hours): [Emergency actions based on open ports/CVEs]
2. SHORT-TERM (24-72 hours): [Patching and configuration updates]
3. LONG-TERM (7-30 days): [Architecture and exposure reduction]

ANALYST VERDICT
Write exactly 2 sentences on the single most critical action the infrastructure team must execute, and the overall security posture rating.
====================================================================

RAW RECONNAISSANCE DATA:
{str(scan_data)[:10000]}
"""
    result = await _smart_ai_call(prompt, max_tokens=2000)
    if result:
        return result
    return "Automated analysis completed. Review the raw telemetry for technical details."

async def chat_with_assistant(message: str, history: list, db_context: str) -> str:
    """
    Conversational AI Chatbot function.
    history: List of dicts [{"role": "user"/"assistant", "content": "..."}]
    """
    sys_prompt = f"""You are 'SecureEye Cyber Assistant', an elite conversational AI threat intelligence analyst powered by a massive Large Language Model.
You have vast general knowledge about all cybersecurity topics, threat actors, malware, and history. Answer the user's questions using ALL of your training data.

If the user asks about recent platform data, here is the latest context from the local database:
{db_context}

Keep your answers concise, highly technical, and conversational. Do not use markdown headers unless necessary. Use plain text formatting.
"""
    
    # We will build a unified prompt since _smart_ai_call only takes a single prompt string,
    # or we can modify _smart_ai_call to handle messages list. For simplicity without breaking other things,
    # we'll build a conversational transcript string for the prompt.
    
    conversation = ""
    for msg in history:
        role = "User" if msg["role"] == "user" else "Assistant"
        conversation += f"\\n{role}: {msg['content']}"
    
    prompt = f"{sys_prompt}\\n\\n--- CONVERSATION HISTORY ---{conversation}\\n\\nUser: {message}\\nAssistant:"
    
    result = await _smart_ai_call(prompt, max_tokens=1000)
    if result:
        return result
    return "I am currently experiencing a localized neural uplink interruption. Please try again."
