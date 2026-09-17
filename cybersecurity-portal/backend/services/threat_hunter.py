import json
import re
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models import HuntHypothesis, IOC, Advisory
from services.ai_service import _smart_ai_call
from services.mitre_service import get_mitre_context

logger = logging.getLogger("secureeye.threat_hunter")


class SingleHypothesisSchema(BaseModel):
    title: str = Field(..., description="Actionable title for the threat hunting hypothesis")
    hypothesis: str = Field(..., description="Clear state hypothesis of adversary behavior")
    target_sector: str = Field(default="All Sectors", description="Target industry sector e.g. Financial, Healthcare, Critical Infrastructure")
    severity: str = Field(default="medium", description="Severity level: critical, high, medium, low")
    mitre_technique_id: str = Field(..., description="MITRE ATT&CK technique ID e.g. T1059.001")
    mitre_tactic: str = Field(..., description="MITRE ATT&CK Tactic e.g. Execution, Persistence")
    mitre_name: str = Field(..., description="MITRE ATT&CK technique name e.g. PowerShell")
    data_sources: List[str] = Field(default_factory=list, description="Required data logs e.g. Windows Event ID 4688, Sysmon Event ID 1")
    investigation_steps: List[str] = Field(default_factory=list, description="Step-by-step SOC analyst hunting guide")
    kql_query: str = Field(..., description="Microsoft Sentinel / Defender KQL query")
    spl_query: str = Field(..., description="Splunk SPL query")
    sigma_rule: str = Field(..., description="Standard YAML Sigma rule format")
    trigger_iocs: List[str] = Field(default_factory=list, description="Associated IP, domain, hash, or CVE strings")
    trigger_reason: str = Field(..., description="Why this hypothesis was generated based on recent threat indicators")
    confidence_score: float = Field(default=0.8, ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")


class MultiHypothesisResponse(BaseModel):
    hypotheses: List[SingleHypothesisSchema]


SYSTEM_PROMPT_HUNT = """
You are a Principal Cyber Threat Hunter and Detection Engineer.
Your job is to analyze recent Indicators of Compromise (IOCs), CVE advisories, and MITRE ATT&CK techniques, and produce actionable, production-ready Threat Hunting Hypotheses with detection queries.

CRITICAL INSTRUCTIONS:
1. You MUST respond strictly with a valid JSON array containing hypothesis objects.
2. DO NOT include markdown codeblock fences like ```json or ``` surrounding the JSON array. Output raw JSON array text only.
3. Each object in the array must strictly match this structure:
{
  "title": "Short descriptive title",
  "hypothesis": "Detailed hypothesis statement following format: Adversaries may be using [Technique] via [Vector] to achieve [Objective] in [Sector] environments.",
  "target_sector": "Financial / Healthcare / Government / Tech / All Sectors",
  "severity": "critical / high / medium / low",
  "mitre_technique_id": "T1059.001",
  "mitre_tactic": "Execution",
  "mitre_name": "PowerShell",
  "data_sources": ["Windows Event ID 4688", "Sysmon Event ID 1", "Process Creation Logs"],
  "investigation_steps": [
    "Step 1: Run KQL query against endpoint logs for last 30 days",
    "Step 2: Filter out legitimate administrative scripts by digital signature",
    "Step 3: Correlate parent process trees for anomalous execution"
  ],
  "kql_query": "DeviceProcessEvents | where ProcessCommandLine has_any ('-EncodedCommand', '-w hidden')",
  "spl_query": "index=wineventlog EventCode=4688 | search CommandLine=\"*-EncodedCommand*\" OR CommandLine=\"*-w hidden*\"",
  "sigma_rule": "title: Detect Suspicious PowerShell Execution\\nid: auto-generated\\nstatus: experimental\\ndescription: Detects obfuscated powershell commands\\nlogsource:\\n  category: process_creation\\n  product: windows\\ndetection:\\n  selection:\\n    CommandLine|contains:\\n      - '-EncodedCommand'\\n      - '-w hidden'\\n  condition: selection\\nlevel: high",
  "trigger_iocs": ["CVE-2024-21412", "192.168.1.50", "powershell.exe"],
  "trigger_reason": "Generated due to recent spike in exploit attempts targeting Windows MSHTML vulnerability.",
  "confidence_score": 0.85
}
"""


async def generate_threat_hunting_hypotheses(
    db: Session,
    sector: str = "All Sectors",
    count: int = 5
) -> Dict[str, Any]:
    """
    Core AI Threat Hunting Engine.
    Queries recent active IOCs & Advisories from DB + MITRE ATT&CK context,
    invokes multi-provider AI via _smart_ai_call, parses JSON response,
    deduplicates against existing hypotheses, and saves to DB.
    """
    logger.info(f"Starting Threat Hunting Hypothesis generation for sector '{sector}' (requested count: {count})...")

    # 1. Fetch recent IOCs (top 15 active high threat score)
    recent_iocs = db.query(IOC).filter(IOC.is_active == True)\
        .order_by(IOC.threat_score.desc(), IOC.first_seen.desc()).limit(15).all()
    
    ioc_summary = []
    for i in recent_iocs:
        ioc_type_str = getattr(i, 'ioc_type', getattr(i, 'type', 'IOC'))
        ioc_summary.append(f"- [{str(ioc_type_str).upper()}] {i.value} (Score: {getattr(i, 'threat_score', 0)}, Tags: {getattr(i, 'tags', [])})")

    # 2. Fetch recent advisories/CVEs
    recent_advisories = db.query(Advisory).order_by(Advisory.created_at.desc()).limit(10).all()
    adv_summary = []
    for a in recent_advisories:
        sec_name = a.sector.name if getattr(a, 'sector', None) else "Cross-Sector"
        adv_summary.append(f"- CVE/Advisory: {a.title} (Severity: {a.severity}, Sector: {sec_name})")

    # 3. Get MITRE techniques context
    mitre_context = get_mitre_context(db, limit=12)

    # 4. Construct AI Prompt
    user_prompt = f"""
Target Sector Scope: {sector}
Desired Output Count: {count} hypotheses

=== RECENT IOC THREAT INTELLIGENCE ===
{chr(10).join(ioc_summary) if ioc_summary else "No recent high-score IOCs. Generate based on trending APT TTPs."}

=== RECENT SECURITY ADVISORIES & CVEs ===
{chr(10).join(adv_summary) if adv_summary else "No recent advisories."}

=== MITRE ATT&CK REFERENCE TECHNIQUES ===
{json.dumps(mitre_context, indent=2)}

Produce exactly {count} distinct, highly realistic Threat Hunting Hypotheses targeting {sector}.
Make sure KQL, SPL, and Sigma rules are syntax-valid and production-ready.
Return strictly a JSON array of objects.
"""

    ai_response = await _smart_ai_call(user_prompt, max_tokens=4000, sys_prompt=SYSTEM_PROMPT_HUNT)

    parsed_list = []

    if not ai_response:
        logger.warning("AI service returned empty response. Activating deterministic threat hunt engine fallback...")
        parsed_list = [
            {
                "title": "Detect Obfuscated PowerShell Encoded Script Execution",
                "hypothesis": f"Adversaries may execute obfuscated PowerShell commands with -EncodedCommand or -WindowStyle Hidden to bypass endpoint monitoring in {sector} environments.",
                "target_sector": sector,
                "severity": "high",
                "mitre_technique_id": "T1059.001",
                "mitre_tactic": "Execution",
                "mitre_name": "PowerShell",
                "data_sources": ["Windows Event ID 4688", "Sysmon Event ID 1", "Script Block Logging Event 4104"],
                "investigation_steps": [
                    "Step 1: Execute KQL query against DeviceProcessEvents for past 14 days",
                    "Step 2: Decode Base64 payloads found in ProcessCommandLine strings",
                    "Step 3: Check parent process trees for winword.exe, excel.exe, or mshta.exe"
                ],
                "kql_query": "DeviceProcessEvents | where ProcessCommandLine has_any ('-EncodedCommand', '-w hidden', '-nop -exec bypass') | project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName",
                "spl_query": "index=wineventlog EventCode=4688 | search CommandLine=\"*-EncodedCommand*\" OR CommandLine=\"*-w hidden*\" | table _time, host, user, CommandLine, ParentProcessName",
                "sigma_rule": "title: Detect Encoded PowerShell Execution\nid: auto-generated-t1059\nstatus: stable\ndescription: Detects powershell process launching with obfuscated arguments\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - '-EncodedCommand'\n      - '-w hidden'\n  condition: selection\nlevel: high",
                "trigger_iocs": ["powershell.exe", "T1059.001"],
                "trigger_reason": f"Automated trigger based on active threat intelligence for {sector}.",
                "confidence_score": 0.88
            },
            {
                "title": "Detect LSASS Memory Dumping via Process Access (Sysmon Event ID 10)",
                "hypothesis": f"Threat actors may attempt to dump LSASS process memory using Mimikatz or ProcDump to extract plaintext credentials in {sector} domain networks.",
                "target_sector": sector,
                "severity": "critical",
                "mitre_technique_id": "T1003.001",
                "mitre_tactic": "Credential Access",
                "mitre_name": "LSASS Memory Dumping",
                "data_sources": ["Sysmon Event ID 10 (ProcessAccess)", "Security Event ID 4656"],
                "investigation_steps": [
                    "Step 1: Inspect Sysmon Event 10 logs where TargetImage ends with lsass.exe",
                    "Step 2: Filter for GrantedAccess rights 0x1010 or 0x1F0FFF",
                    "Step 3: Isolate affected host and force kerberos ticket resets"
                ],
                "kql_query": "DeviceEvents | where ActionType == 'ProcessAccess' and TargetProcessName endswith 'lsass.exe' and GrantedAccess in ('0x1010', '0x1F0FFF') | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName",
                "spl_query": "index=sysmon EventCode=10 TargetImage=\"*lsass.exe\" (GrantedAccess=\"0x1010\" OR GrantedAccess=\"0x1F0FFF\") | table _time, Computer, SourceImage, GrantedAccess",
                "sigma_rule": "title: Detect LSASS Memory Access\nid: auto-generated-t1003\nstatus: stable\ndescription: Detects process access targeting lsass.exe with read permissions\nlogsource:\n  category: process_access\n  product: windows\ndetection:\n  selection:\n    TargetImage|endswith: '\\lsass.exe'\n    GrantedAccess:\n      - '0x1010'\n      - '0x1F0FFF'\n  condition: selection\nlevel: critical",
                "trigger_iocs": ["lsass.exe", "procdump.exe", "T1003.001"],
                "trigger_reason": "High-risk credential theft pattern detected across active enterprise environments.",
                "confidence_score": 0.92
            },
            {
                "title": "Detect Unauthorized Scheduled Task Creation for Persistence",
                "hypothesis": f"Adversaries may register malicious scheduled tasks to establish persistent backdoor execution upon system reboot in {sector} endpoints.",
                "target_sector": sector,
                "severity": "medium",
                "mitre_technique_id": "T1053.005",
                "mitre_tactic": "Persistence",
                "mitre_name": "Scheduled Task",
                "data_sources": ["Security Event ID 4698 (Scheduled Task Created)", "Schtasks.exe execution"],
                "investigation_steps": [
                    "Step 1: Audit Event 4698 XML payloads for task actions pointing to AppData or Temp folders",
                    "Step 2: Verify task author user account validity",
                    "Step 3: Remove unrecognized tasks using schtasks /delete"
                ],
                "kql_query": "DeviceProcessEvents | where ProcessCommandLine has 'schtasks' and ProcessCommandLine has '/create' | project Timestamp, DeviceName, AccountName, ProcessCommandLine",
                "spl_query": "index=wineventlog EventCode=4698 | table _time, Computer, TaskName, TaskContent",
                "sigma_rule": "title: Detect Scheduled Task Creation via Command Line\nid: auto-generated-t1053\nstatus: stable\ndescription: Detects creation of scheduled tasks using schtasks utility\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - 'schtasks'\n      - '/create'\n  condition: selection\nlevel: medium",
                "trigger_iocs": ["schtasks.exe", "T1053.005"],
                "trigger_reason": "Automated trigger for persistence mechanism monitoring.",
                "confidence_score": 0.82
            }
        ]
    else:
        # 5. Extract and parse JSON
        cleaned_json_str = ai_response.strip()
        if cleaned_json_str.startswith("```"):
            cleaned_json_str = re.sub(r"^```(?:json)?\n?", "", cleaned_json_str)
            cleaned_json_str = re.sub(r"\n?```$", "", cleaned_json_str)

        try:
            parsed_list = json.loads(cleaned_json_str)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed direct JSON parse: {e}. Attempting regex extraction...")
            match = re.search(r"\[\s*\{.*\}\s*\]", cleaned_json_str, re.DOTALL)
            if match:
                try:
                    parsed_list = json.loads(match.group(0))
                except Exception as ex:
                    logger.error(f"Regex JSON extraction failed: {ex}")
            else:
                logger.error(f"Could not extract JSON array from AI output: {cleaned_json_str[:200]}...")

    if not isinstance(parsed_list, list):
        if isinstance(parsed_list, dict) and "hypotheses" in parsed_list:
            parsed_list = parsed_list["hypotheses"]
        else:
            parsed_list = []

    created_records = []
    skipped_count = 0

    for item in parsed_list:
        try:
            # Validate schema
            hypo_data = SingleHypothesisSchema(**item)

            # Deduplication: Check if an 'open' hypothesis with same technique_id and title already exists
            existing = db.query(HuntHypothesis).filter(
                HuntHypothesis.mitre_technique_id == hypo_data.mitre_technique_id,
                HuntHypothesis.title == hypo_data.title,
                HuntHypothesis.status == "open"
            ).first()

            if existing:
                logger.info(f"Skipping duplicate hypothesis '{hypo_data.title}' for technique {hypo_data.mitre_technique_id}")
                skipped_count += 1
                continue

            new_hypo = HuntHypothesis(
                title=hypo_data.title,
                hypothesis=hypo_data.hypothesis,
                target_sector=hypo_data.target_sector or sector,
                severity=hypo_data.severity.lower(),
                mitre_technique_id=hypo_data.mitre_technique_id,
                mitre_tactic=hypo_data.mitre_tactic,
                mitre_name=hypo_data.mitre_name,
                data_sources=hypo_data.data_sources,
                investigation_steps=hypo_data.investigation_steps,
                kql_query=hypo_data.kql_query,
                spl_query=hypo_data.spl_query,
                sigma_rule=hypo_data.sigma_rule,
                trigger_iocs=hypo_data.trigger_iocs,
                trigger_reason=hypo_data.trigger_reason,
                confidence_score=hypo_data.confidence_score,
                status="open"
            )
            db.add(new_hypo)
            created_records.append(new_hypo)
        except Exception as ve:
            logger.warning(f"Validation error skipping item: {ve}")

    try:
        db.commit()
        for r in created_records:
            db.refresh(r)
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to commit new hypotheses: {e}")
        return {"status": "error", "message": f"Database commit failed: {str(e)}", "created_count": 0}

    logger.info(f"Successfully created {len(created_records)} new threat hunting hypotheses ({skipped_count} skipped).")
    return {
        "status": "success",
        "created_count": len(created_records),
        "skipped_count": skipped_count,
        "hypotheses": [
            {
                "id": r.id,
                "title": r.title,
                "mitre_technique_id": r.mitre_technique_id,
                "severity": r.severity,
                "target_sector": r.target_sector
            } for r in created_records
        ]
    }
