import logging
import httpx
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from models import MitreCache

logger = logging.getLogger("secureeye.mitre_service")

MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Fallback seed techniques if offline/fetch fails
SEED_TECHNIQUES = [
    {
        "technique_id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may use PowerShell to perform commands and scripts for execution.",
        "platforms": ["Windows"],
        "data_sources": ["Process: Process Creation", "Command: Command Execution"],
        "detection_guidance": "Monitor process execution logs (Event ID 4688, Sysmon Event ID 1) for powershell.exe with suspicious arguments like -EncodedCommand, -Nop, -W Hidden."
    },
    {
        "technique_id": "T1003.001",
        "name": "LSASS Memory Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access credentials stored in the Local Security Authority Subsystem Service (LSASS) process memory.",
        "platforms": ["Windows"],
        "data_sources": ["Process: Process Access", "Command: Command Execution"],
        "detection_guidance": "Look for process open events targeting lsass.exe with PROCESS_VM_READ permissions (Sysmon Event ID 10)."
    },
    {
        "technique_id": "T1053.005",
        "name": "Scheduled Task",
        "tactic": "Persistence",
        "description": "Adversaries may use task scheduler to perform task scheduling for initial or recurring execution of malicious code.",
        "platforms": ["Windows"],
        "data_sources": ["Scheduled Task: Task Creation", "Process: Process Creation"],
        "detection_guidance": "Monitor Event ID 4698 (Scheduled task created) and schtasks.exe command executions."
    },
    {
        "technique_id": "T1071.001",
        "name": "Web Protocols C2",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Network Traffic: Network Connection", "Network Traffic: Web Traffic"],
        "detection_guidance": "Inspect HTTP/HTTPS proxy logs for beaconing patterns, abnormal User-Agent strings, or connections to untrusted dynamic DNS domains."
    },
    {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Application Log: Application Crash", "Network Traffic: Network Traffic Content"],
        "detection_guidance": "Monitor web server error logs (500s, stack traces), unusual child processes spawned by web server services (w3wp.exe, apache2, nginx)."
    },
    {
        "technique_id": "T1021.001",
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use RDP to log into remote systems and control them interactively.",
        "platforms": ["Windows"],
        "data_sources": ["Logon: Logon Attempt", "Network Traffic: Network Connection"],
        "detection_guidance": "Monitor Event ID 4624 (Logon Type 10) and internal network RDP connections between non-admin workstations."
    },
    {
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability of system and network resources.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["File: File Modification", "Process: Process Creation"],
        "detection_guidance": "Monitor high-volume file modification events, deletion of shadow copies via vssadmin/PowerShell, and renaming files with ransomware extensions."
    }
]


async def sync_mitre_attack_db(db: Session) -> Dict[str, Any]:
    """
    Fetch Enterprise ATT&CK JSON from MITRE repository, parse techniques, and store/update in DB.
    Falls back to seed techniques if network fails.
    """
    count_added = 0
    count_updated = 0
    parsed_techniques = []

    try:
        logger.info(f"Fetching MITRE ATT&CK dataset from {MITRE_ATTACK_URL}...")
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(MITRE_ATTACK_URL)
            if resp.status_code == 200:
                stix_data = resp.json()
                objects = stix_data.get("objects", [])

                for obj in objects:
                    if obj.get("type") == "attack-pattern" and not obj.get("x_mitre_deprecated") and not obj.get("revoked"):
                        # Extract technique ID (T1059 or T1059.001)
                        ext_refs = obj.get("external_references", [])
                        t_id = None
                        for ref in ext_refs:
                            if ref.get("source_name") == "mitre-attack":
                                t_id = ref.get("external_id")
                                break

                        if not t_id:
                            continue

                        name = obj.get("name", "Unknown Technique")
                        desc = obj.get("description", "")
                        
                        # Extract tactic
                        tactics = []
                        for kill_chain in obj.get("kill_chain_phases", []):
                            if kill_chain.get("kill_chain_name") == "mitre-attack":
                                tactics.append(kill_chain.get("phase_name", "").replace("-", " ").title())
                        tactic_str = ", ".join(tactics) if tactics else "General"

                        platforms = obj.get("x_mitre_platforms", [])
                        data_sources = obj.get("x_mitre_data_sources", [])
                        detection = obj.get("x_mitre_detection", "")

                        parsed_techniques.append({
                            "technique_id": t_id,
                            "name": name,
                            "tactic": tactic_str,
                            "description": desc[:1500], # trim for space
                            "platforms": platforms,
                            "data_sources": data_sources,
                            "detection_guidance": detection[:1500]
                        })

                logger.info(f"Parsed {len(parsed_techniques)} techniques from MITRE STIX JSON.")
            else:
                logger.warning(f"Failed to download MITRE STIX JSON: HTTP {resp.status_code}. Using seed techniques.")
                parsed_techniques = SEED_TECHNIQUES
    except Exception as e:
        logger.error(f"Error fetching MITRE STIX data: {e}. Falling back to seed techniques.")
        parsed_techniques = SEED_TECHNIQUES

    if not parsed_techniques:
        parsed_techniques = SEED_TECHNIQUES

    # Upsert into database
    for t in parsed_techniques:
        existing = db.query(MitreCache).filter(MitreCache.technique_id == t["technique_id"]).first()
        if existing:
            existing.name = t["name"]
            existing.tactic = t["tactic"]
            existing.description = t["description"]
            existing.platforms = t["platforms"]
            existing.data_sources = t["data_sources"]
            existing.detection_guidance = t["detection_guidance"]
            count_updated += 1
        else:
            new_record = MitreCache(
                technique_id=t["technique_id"],
                name=t["name"],
                tactic=t["tactic"],
                description=t["description"],
                platforms=t["platforms"],
                data_sources=t["data_sources"],
                detection_guidance=t["detection_guidance"]
            )
            db.add(new_record)
            count_added += 1

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to commit MITRE cache upserts: {e}")
        raise e

    return {
        "status": "success",
        "total_parsed": len(parsed_techniques),
        "added": count_added,
        "updated": count_updated
    }


def get_mitre_context(db: Session, limit: int = 15) -> List[Dict[str, Any]]:
    """
    Get a list of MITRE techniques from DB to feed into AI threat hunting context.
    If cache is empty, seed it synchronously.
    """
    techniques = db.query(MitreCache).order_by(MitreCache.id.asc()).limit(limit).all()
    
    if not techniques:
        # Seed initial data
        for t in SEED_TECHNIQUES:
            new_record = MitreCache(
                technique_id=t["technique_id"],
                name=t["name"],
                tactic=t["tactic"],
                description=t["description"],
                platforms=t["platforms"],
                data_sources=t["data_sources"],
                detection_guidance=t["detection_guidance"]
            )
            db.add(new_record)
        try:
            db.commit()
            techniques = db.query(MitreCache).limit(limit).all()
        except Exception as e:
            db.rollback()
            logger.error(f"Error seeding MITRE cache: {e}")

    return [
        {
            "technique_id": t.technique_id,
            "name": t.name,
            "tactic": t.tactic,
            "description": (t.description or "")[:300],
            "data_sources": t.data_sources or []
        }
        for t in techniques
    ]
