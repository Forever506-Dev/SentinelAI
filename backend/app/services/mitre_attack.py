"""
MITRE ATT&CK Integration Service

Provides mapping, search, and correlation against the MITRE ATT&CK
Enterprise framework for technique/tactic classification of security events.
"""

import structlog

logger = structlog.get_logger()

# --- MITRE ATT&CK Enterprise Tactics ---
MITRE_TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "description": "Gathering information to plan future adversary operations"},
    {"id": "TA0042", "name": "Resource Development", "description": "Establishing resources to support operations"},
    {"id": "TA0001", "name": "Initial Access", "description": "Trying to get into your network"},
    {"id": "TA0002", "name": "Execution", "description": "Trying to run malicious code"},
    {"id": "TA0003", "name": "Persistence", "description": "Trying to maintain their foothold"},
    {"id": "TA0004", "name": "Privilege Escalation", "description": "Trying to gain higher-level permissions"},
    {"id": "TA0005", "name": "Defense Evasion", "description": "Trying to avoid being detected"},
    {"id": "TA0006", "name": "Credential Access", "description": "Stealing credentials like account names and passwords"},
    {"id": "TA0007", "name": "Discovery", "description": "Trying to figure out your environment"},
    {"id": "TA0008", "name": "Lateral Movement", "description": "Trying to move through your environment"},
    {"id": "TA0009", "name": "Collection", "description": "Gathering data of interest to their goal"},
    {"id": "TA0011", "name": "Command and Control", "description": "Communicating with compromised systems to control them"},
    {"id": "TA0010", "name": "Exfiltration", "description": "Trying to steal data"},
    {"id": "TA0040", "name": "Impact", "description": "Trying to manipulate, interrupt, or destroy systems and data"},
]

# --- Common MITRE ATT&CK Techniques (subset for quick local lookup) ---
MITRE_TECHNIQUES = [
    # Execution
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution",
     "sub_techniques": [
         {"id": "T1059.001", "name": "PowerShell"},
         {"id": "T1059.003", "name": "Windows Command Shell"},
         {"id": "T1059.004", "name": "Unix Shell"},
         {"id": "T1059.005", "name": "Visual Basic"},
         {"id": "T1059.006", "name": "Python"},
         {"id": "T1059.007", "name": "JavaScript"},
     ]},
    {"id": "T1204", "name": "User Execution", "tactic": "Execution", "sub_techniques": []},
    {"id": "T1047", "name": "Windows Management Instrumentation", "tactic": "Execution", "sub_techniques": []},

    # Persistence
    {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence",
     "sub_techniques": [
         {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
         {"id": "T1547.004", "name": "Winlogon Helper DLL"},
     ]},
    {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence", "sub_techniques": []},
    {"id": "T1136", "name": "Create Account", "tactic": "Persistence", "sub_techniques": []},

    # Privilege Escalation
    {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation",
     "sub_techniques": [
         {"id": "T1548.002", "name": "Bypass User Account Control"},
     ]},
    {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "sub_techniques": []},

    # Defense Evasion
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "sub_techniques": []},
    {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion",
     "sub_techniques": [
         {"id": "T1070.001", "name": "Clear Windows Event Logs"},
         {"id": "T1070.004", "name": "File Deletion"},
     ]},
    {"id": "T1218", "name": "System Binary Proxy Execution", "tactic": "Defense Evasion",
     "sub_techniques": [
         {"id": "T1218.005", "name": "Mshta"},
         {"id": "T1218.010", "name": "Regsvr32"},
         {"id": "T1218.011", "name": "Rundll32"},
     ]},
    {"id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion", "sub_techniques": []},
    {"id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion",
     "sub_techniques": [
         {"id": "T1562.001", "name": "Disable or Modify Tools"},
     ]},

    # Credential Access
    {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access",
     "sub_techniques": [
         {"id": "T1003.001", "name": "LSASS Memory"},
         {"id": "T1003.002", "name": "Security Account Manager"},
     ]},
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "sub_techniques": []},
    {"id": "T1056", "name": "Input Capture", "tactic": "Credential Access",
     "sub_techniques": [
         {"id": "T1056.001", "name": "Keylogging"},
     ]},

    # Discovery
    {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "sub_techniques": []},
    {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery", "sub_techniques": []},
    {"id": "T1057", "name": "Process Discovery", "tactic": "Discovery", "sub_techniques": []},
    {"id": "T1049", "name": "System Network Connections Discovery", "tactic": "Discovery", "sub_techniques": []},

    # Lateral Movement
    {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement",
     "sub_techniques": [
         {"id": "T1021.001", "name": "Remote Desktop Protocol"},
         {"id": "T1021.002", "name": "SMB/Windows Admin Shares"},
         {"id": "T1021.004", "name": "SSH"},
     ]},
    {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement", "sub_techniques": []},

    # Command and Control
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control",
     "sub_techniques": [
         {"id": "T1071.001", "name": "Web Protocols"},
         {"id": "T1071.004", "name": "DNS"},
     ]},
    {"id": "T1572", "name": "Protocol Tunneling", "tactic": "Command and Control", "sub_techniques": []},
    {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control", "sub_techniques": []},

    # Exfiltration
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "sub_techniques": []},
    {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "sub_techniques": []},

    # Impact
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "sub_techniques": []},
    {"id": "T1489", "name": "Service Stop", "tactic": "Impact", "sub_techniques": []},
    {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact", "sub_techniques": []},
]


class MitreAttackService:
    """MITRE ATT&CK framework integration for technique mapping and search."""

    def __init__(self) -> None:
        self.tactics = MITRE_TACTICS
        self.techniques = MITRE_TECHNIQUES

    async def search_techniques(
        self, query: str, tactic: str | None = None
    ) -> list[dict]:
        """
        Search techniques by keyword and optional tactic filter.

        Args:
            query: Search keyword (matched against name and ID)
            tactic: Optional tactic name to filter by

        Returns:
            Matching techniques with sub-techniques.
        """
        query_lower = query.lower()
        results = []

        for tech in self.techniques:
            # Filter by tactic
            if tactic and tech["tactic"].lower() != tactic.lower():
                continue

            # Match against name or ID
            if (
                query_lower in tech["name"].lower()
                or query_lower in tech["id"].lower()
            ):
                results.append(tech)
                continue

            # Match against sub-techniques
            for sub in tech.get("sub_techniques", []):
                if (
                    query_lower in sub["name"].lower()
                    or query_lower in sub["id"].lower()
                ):
                    results.append(tech)
                    break

        return results

    async def get_technique_by_id(self, technique_id: str) -> dict | None:
        """Get a specific technique by its MITRE ID (e.g., T1059.001)."""
        for tech in self.techniques:
            if tech["id"] == technique_id:
                return tech
            for sub in tech.get("sub_techniques", []):
                if sub["id"] == technique_id:
                    return {**sub, "parent": tech["name"], "tactic": tech["tactic"]}
        return None

    async def get_all_tactics(self) -> list[dict]:
        """Return all MITRE ATT&CK Enterprise tactics."""
        return self.tactics

    async def map_event_to_techniques(self, event: dict) -> list[str]:
        """
        Map a telemetry event to potential MITRE ATT&CK techniques.

        Uses heuristic rules to identify likely techniques based on
        process names, command lines, and network activity.
        """
        techniques = []
        process = (event.get("process_name") or "").lower()
        cmd = (event.get("command_line") or "").lower()
        event_type = event.get("event_type", "")

        # PowerShell execution
        if "powershell" in process:
            techniques.append("T1059.001")
            if "-encodedcommand" in cmd or "-enc " in cmd:
                techniques.append("T1027")  # Obfuscation

        # cmd.exe
        if "cmd.exe" in process:
            techniques.append("T1059.003")

        # LOLBins → System Binary Proxy Execution
        lolbin_mapping = {
            "mshta": "T1218.005",
            "regsvr32": "T1218.010",
            "rundll32": "T1218.011",
            "certutil": "T1218",
            "wmic": "T1047",
        }
        for binary, tech_id in lolbin_mapping.items():
            if binary in process:
                techniques.append(tech_id)

        # Credential dumping indicators
        if any(x in cmd for x in ["lsass", "sam", "ntds", "mimikatz", "sekurlsa"]):
            techniques.append("T1003.001")

        # Scheduled tasks
        if "schtasks" in process or "at.exe" in process:
            techniques.append("T1053")

        # Network-related
        if event_type == "network":
            dest_port = event.get("dest_port")
            if dest_port == 3389:
                techniques.append("T1021.001")  # RDP
            elif dest_port == 445:
                techniques.append("T1021.002")  # SMB
            elif dest_port == 22:
                techniques.append("T1021.004")  # SSH
            elif event.get("dns_query"):
                techniques.append("T1071.004")  # DNS C2

        return list(set(techniques))

    async def get_kill_chain_coverage(self, technique_ids: list[str]) -> dict:
        """
        Analyze which phases of the kill chain are covered by detected techniques.

        Returns a map of tactic → list of detected techniques.
        """
        coverage: dict[str, list[str]] = {}
        for tech_id in technique_ids:
            tech = await self.get_technique_by_id(tech_id)
            if tech:
                tactic = tech.get("tactic", "Unknown")
                if tactic not in coverage:
                    coverage[tactic] = []
                coverage[tactic].append(tech_id)

        return coverage
