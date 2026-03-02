"""
Rule Engine — Standalone Detection Rules

Fires alerts from telemetry WITHOUT requiring LLM.
Works with the actual data shape from the Rust agent:
  - process events: process_name, exe_path, process_id, parent_process_id,
                    command_line (may be empty), cpu_usage, memory_bytes
  - network/stats:  interface, bytes_received, bytes_transmitted, etc.
  - file events:    file_name, file_path, file_size, file_extension
  - system events:  cpu/memory/disk metrics, os_info

Each rule returns a RuleMatch or None.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

import structlog

logger = structlog.get_logger()


@dataclass
class RuleMatch:
    """Result of a single rule match against an event."""

    rule_id: str
    rule_name: str
    title: str
    description: str
    severity: str  # critical | high | medium | low | informational
    confidence: float  # 0.0 – 1.0
    detection_source: str  # rule_engine
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    raw_event: dict = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════
# Suspicious process lists — tuned for Windows endpoints
# ═══════════════════════════════════════════════════════════════════

# LOLBins that are commonly abused
LOLBINS = {
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "wmic.exe", "cscript.exe", "wscript.exe",
    "msiexec.exe", "cmstp.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "msconfig.exe", "msbuild.exe", "ieexec.exe",
    "control.exe", "presentationhost.exe", "forfiles.exe",
    "pcalua.exe", "hh.exe", "infdefaultinstall.exe",
}

# Hacking / recon tools that should never appear on a corporate endpoint
HACKER_TOOLS = {
    "mimikatz.exe", "psexec.exe", "psexec64.exe",
    "procdump.exe", "procdump64.exe",
    "lazagne.exe", "rubeus.exe", "seatbelt.exe", "sharphound.exe",
    "bloodhound.exe", "covenant.exe", "crackmapexec.exe",
    "impacket", "responder.exe", "hashcat.exe",
    "nmap.exe", "masscan.exe", "wireshark.exe",
    "netcat.exe", "nc.exe", "nc64.exe", "ncat.exe",
    "chisel.exe", "plink.exe", "socat.exe",
    "winpeas.exe", "linpeas.sh", "powerup.ps1",
}

# Processes associated with credential dumping or security tool tampering
CREDENTIAL_TOOLS = {
    "mimikatz.exe", "procdump.exe", "procdump64.exe",
    "lazagne.exe", "rubeus.exe", "nanodump.exe",
    "secretsdump.exe",
}

# Scripting engines that deserve scrutiny
SCRIPT_ENGINES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "cscript.exe",
    "wscript.exe", "python.exe", "python3.exe", "node.exe",
    "mshta.exe", "wmic.exe",
}

# Processes that commonly make outbound connections (legitimate)
LEGITIMATE_NETWORK_PROCS = {
    "svchost.exe", "system", "msedge.exe", "chrome.exe", "firefox.exe",
    "explorer.exe", "searchhost.exe", "backgroundtaskhost.exe",
    "onedrive.exe", "teams.exe", "slack.exe", "discord.exe",
    "code.exe", "windowsterminal.exe", "docker.exe",
}

# Suspicious exe path patterns (non-standard install locations)
SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"(?i)\\temp\\[^\\]+\.exe$"),
    re.compile(r"(?i)\\tmp\\[^\\]+\.exe$"),
    re.compile(r"(?i)\\appdata\\local\\temp\\[^\\]+\.exe$"),
    re.compile(r"(?i)\\downloads\\[^\\]+\.exe$"),
    re.compile(r"(?i)\\public\\[^\\]+\.exe$"),
    re.compile(r"(?i)\\users\\[^\\]+\\desktop\\[^\\]+\.exe$"),
    re.compile(r"(?i)\\recycler\\"),
    re.compile(r"(?i)\\recycle\.bin\\"),
    re.compile(r"(?i)c:\\perflogs\\"),
]

# Suspicious file extensions for file events
SUSPICIOUS_FILE_EXTENSIONS = {
    "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "msi", "msp", "mst",
    "cpl", "com", "pif", "reg", "inf", "lnk",
}

# High-risk locations for file writes
PERSISTENCE_FILE_PATHS = [
    re.compile(r"(?i)\\start menu\\programs\\startup\\"),
    re.compile(r"(?i)\\microsoft\\windows\\start menu\\programs\\startup\\"),
    re.compile(r"(?i)\\currentversion\\run"),
    re.compile(r"(?i)\\currentversion\\runonce"),
    re.compile(r"(?i)\\system32\\tasks\\"),
    re.compile(r"(?i)\\system32\\drivers\\"),
]


class RuleEngine:
    """
    Lightweight rule engine that generates alerts from raw telemetry.

    Does NOT call LLM — all detections are deterministic and fast.
    """

    def evaluate_batch(
        self,
        events: list[dict],
        agent_info: dict,
    ) -> list[RuleMatch]:
        """Evaluate all rules against a batch of events."""
        matches: list[RuleMatch] = []

        for event in events:
            event_matches = self._evaluate_single(event, agent_info)
            matches.extend(event_matches)

        if matches:
            logger.info(
                "Rule engine matches",
                total_events=len(events),
                total_matches=len(matches),
                rules=[m.rule_id for m in matches],
            )

        return matches

    def _evaluate_single(
        self, event: dict, agent_info: dict
    ) -> list[RuleMatch]:
        """Run all applicable rules against a single event."""
        matches: list[RuleMatch] = []
        event_type = event.get("event_type", "")
        event_action = event.get("event_action", "")

        if event_type == "process" and event_action == "create":
            matches.extend(self._rules_process_create(event, agent_info))
        elif event_type == "file":
            matches.extend(self._rules_file_event(event, agent_info))
        elif event_type == "network":
            matches.extend(self._rules_network_event(event, agent_info))
        elif event_type == "system":
            matches.extend(self._rules_system_event(event, agent_info))

        return matches

    # ───────────────────────────────────────────────────────────
    # Process Creation Rules
    # ───────────────────────────────────────────────────────────

    def _rules_process_create(
        self, event: dict, agent_info: dict
    ) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        process_name = (event.get("process_name") or "").lower()
        exe_path = (event.get("exe_path") or "").lower()
        command_line = (event.get("command_line") or "").lower()
        parent_name = (event.get("parent_process_name") or "").lower()

        # ── RULE P001: Known hacking tool detected ──────────────
        if process_name in HACKER_TOOLS:
            matches.append(RuleMatch(
                rule_id="P001",
                rule_name="known_hacker_tool",
                title=f"Known hacking tool executed: {process_name}",
                description=(
                    f"The process '{process_name}' is a known offensive security "
                    f"tool detected on {agent_info.get('hostname', 'unknown')}. "
                    f"Path: {exe_path or 'unknown'}"
                ),
                severity="critical",
                confidence=0.95,
                detection_source="rule_engine",
                mitre_techniques=["T1059", "T1003"],
                mitre_tactics=["Execution", "Credential Access"],
                raw_event=event,
            ))

        # ── RULE P002: LOLBin execution ──────────────────────────
        if process_name in LOLBINS:
            # LOLBins are legitimate but often abused
            confidence = 0.45
            severity = "low"

            # Boost if command line has suspicious flags
            if command_line:
                suspicious_flags = [
                    "-urlcache", "-decode", "-encode", "download",
                    "/transfer", "-executionpolicy bypass", "-enc ",
                    "-encodedcommand", "-windowstyle hidden",
                    "frombase64string", "/s /n /u /i:", "scrobj.dll",
                    "javascript:", "vbscript:",
                ]
                if any(f in command_line for f in suspicious_flags):
                    confidence = 0.85
                    severity = "high"

            # Boost if spawned from Office/unusual parent
            if parent_name and any(p in parent_name for p in [
                "excel", "word", "winword", "outlook", "powerpnt",
                "wscript", "mshta",
            ]):
                confidence = min(confidence + 0.25, 0.95)
                severity = "high"

            # Boost if running from suspicious path
            full_path = exe_path or event.get("exe_path", "")
            if full_path and any(
                pat.search(full_path) for pat in SUSPICIOUS_PATH_PATTERNS
            ):
                confidence = min(confidence + 0.20, 0.95)
                severity = "high" if severity != "critical" else severity

            matches.append(RuleMatch(
                rule_id="P002",
                rule_name="lolbin_execution",
                title=f"LOLBin execution: {process_name}",
                description=(
                    f"Living-off-the-Land Binary '{process_name}' executed on "
                    f"{agent_info.get('hostname', 'unknown')}. "
                    f"These binaries are legitimate Windows tools often abused "
                    f"by attackers for defense evasion. "
                    f"Command: {command_line or '(not captured)'}"
                ),
                severity=severity,
                confidence=confidence,
                detection_source="rule_engine",
                mitre_techniques=["T1218"],
                mitre_tactics=["Defense Evasion"],
                raw_event=event,
            ))

        # ── RULE P003: Executable from suspicious path ───────────
        full_path = exe_path or ""
        if full_path and any(
            pat.search(full_path) for pat in SUSPICIOUS_PATH_PATTERNS
        ):
            # Don't double-fire if already caught as LOLBin
            if process_name not in LOLBINS:
                matches.append(RuleMatch(
                    rule_id="P003",
                    rule_name="suspicious_exe_path",
                    title=f"Executable from suspicious location: {process_name}",
                    description=(
                        f"Process '{process_name}' running from non-standard "
                        f"location: {full_path}. Legitimate software typically "
                        f"installs to Program Files or System32."
                    ),
                    severity="medium",
                    confidence=0.60,
                    detection_source="rule_engine",
                    mitre_techniques=["T1036"],
                    mitre_tactics=["Defense Evasion"],
                    raw_event=event,
                ))

        # ── RULE P004: Encoded PowerShell ────────────────────────
        if "powershell" in process_name or "pwsh" in process_name:
            if command_line and any(x in command_line for x in [
                "-encodedcommand", "-enc ", "frombase64string",
                "-windowstyle hidden", "-w hidden",
                "bypass", "-nop",
            ]):
                matches.append(RuleMatch(
                    rule_id="P004",
                    rule_name="encoded_powershell",
                    title="Encoded/hidden PowerShell execution detected",
                    description=(
                        f"PowerShell executed with suspicious arguments on "
                        f"{agent_info.get('hostname', 'unknown')}: "
                        f"{command_line[:200]}"
                    ),
                    severity="high",
                    confidence=0.85,
                    detection_source="rule_engine",
                    mitre_techniques=["T1059.001", "T1027"],
                    mitre_tactics=["Execution", "Defense Evasion"],
                    raw_event=event,
                ))

        # ── RULE P005: Suspicious parent-child process chain ─────
        suspicious_spawns = {
            "cmd.exe": ["excel.exe", "winword.exe", "outlook.exe", "powerpnt.exe"],
            "powershell.exe": ["excel.exe", "winword.exe", "wscript.exe", "outlook.exe"],
            "pwsh.exe": ["excel.exe", "winword.exe", "wscript.exe", "outlook.exe"],
            "certutil.exe": ["cmd.exe", "powershell.exe", "pwsh.exe"],
            "mshta.exe": ["explorer.exe", "cmd.exe", "powershell.exe"],
            "regsvr32.exe": ["cmd.exe", "powershell.exe"],
            "rundll32.exe": ["cmd.exe", "powershell.exe"],
            "wmic.exe": ["cmd.exe", "powershell.exe"],
            "net.exe": ["excel.exe", "winword.exe", "outlook.exe"],
            "net1.exe": ["excel.exe", "winword.exe", "outlook.exe"],
        }
        if parent_name and process_name:
            for child_proc, bad_parents in suspicious_spawns.items():
                if child_proc in process_name and any(
                    p in parent_name for p in bad_parents
                ):
                    matches.append(RuleMatch(
                        rule_id="P005",
                        rule_name="suspicious_process_chain",
                        title=f"Suspicious process spawn: {parent_name} → {process_name}",
                        description=(
                            f"Process '{process_name}' was spawned by "
                            f"'{parent_name}' on {agent_info.get('hostname', 'unknown')}. "
                            f"This parent-child relationship is commonly seen in "
                            f"malware execution chains (e.g., macro-based attacks)."
                        ),
                        severity="high",
                        confidence=0.85,
                        detection_source="rule_engine",
                        mitre_techniques=["T1204", "T1059"],
                        mitre_tactics=["Execution"],
                        raw_event=event,
                    ))

        # ── RULE P006: Credential tool execution ─────────────────
        if process_name in CREDENTIAL_TOOLS:
            matches.append(RuleMatch(
                rule_id="P006",
                rule_name="credential_tool",
                title=f"Credential access tool detected: {process_name}",
                description=(
                    f"Credential dumping tool '{process_name}' executed on "
                    f"{agent_info.get('hostname', 'unknown')}. "
                    f"Path: {exe_path or 'unknown'}"
                ),
                severity="critical",
                confidence=0.95,
                detection_source="rule_engine",
                mitre_techniques=["T1003", "T1003.001"],
                mitre_tactics=["Credential Access"],
                raw_event=event,
            ))

        # ── RULE P007: High memory usage process (> 2GB) ─────────
        mem_bytes = event.get("memory_bytes", 0)
        if isinstance(mem_bytes, (int, float)) and mem_bytes > 2_000_000_000:
            # Only alert on non-standard high-memory processes
            normal_high_mem = {
                "msedge.exe", "chrome.exe", "firefox.exe", "code.exe",
                "java.exe", "javaw.exe", "docker.exe", "vmware-vmx.exe",
                "svchost.exe", "explorer.exe", "vmmemwsl", "vmmem",
                "memory compression", "system",
            }
            if process_name not in normal_high_mem:
                matches.append(RuleMatch(
                    rule_id="P007",
                    rule_name="high_memory_process",
                    title=f"Abnormal memory usage: {process_name} ({mem_bytes / 1e9:.1f} GB)",
                    description=(
                        f"Process '{process_name}' is consuming "
                        f"{mem_bytes / 1e9:.1f} GB of memory on "
                        f"{agent_info.get('hostname', 'unknown')}. "
                        f"This could indicate memory-resident malware or "
                        f"a cryptominer."
                    ),
                    severity="medium",
                    confidence=0.50,
                    detection_source="rule_engine",
                    mitre_techniques=["T1496"],
                    mitre_tactics=["Impact"],
                    raw_event=event,
                ))

        # ── RULE P008: Event log clearing (T1070.001) ───────────
        if command_line and any(clr in command_line for clr in [
            "wevtutil cl", "wevtutil.exe cl",
            "clear-eventlog", "remove-eventlog",
            "wevtutil sl /e:false",
        ]):
            matches.append(RuleMatch(
                rule_id="P008",
                rule_name="event_log_clearing",
                title=f"Windows event log clearing detected",
                description=(
                    f"A command to clear Windows event logs was executed on "
                    f"{agent_info.get('hostname', 'unknown')}: "
                    f"{command_line[:300]}. "
                    f"Attackers clear event logs to remove evidence of "
                    f"their activity."
                ),
                severity="critical",
                confidence=0.92,
                detection_source="rule_engine",
                mitre_techniques=["T1070.001"],
                mitre_tactics=["Defense Evasion"],
                raw_event=event,
            ))

        # ── RULE P009: Scheduled task creation (persistence) ─────
        if command_line and any(st in command_line for st in [
            "schtasks /create", "schtasks.exe /create",
            "register-scheduledjob", "new-scheduledtask",
        ]):
            matches.append(RuleMatch(
                rule_id="P009",
                rule_name="scheduled_task_creation",
                title=f"Scheduled task created via command line",
                description=(
                    f"A scheduled task was created on "
                    f"{agent_info.get('hostname', 'unknown')}: "
                    f"{command_line[:300]}. "
                    f"Scheduled tasks are commonly used for persistence."
                ),
                severity="medium",
                confidence=0.65,
                detection_source="rule_engine",
                mitre_techniques=["T1053.005"],
                mitre_tactics=["Persistence", "Execution"],
                raw_event=event,
            ))

        # ── RULE P010: Service creation (persistence/priv-esc) ──
        if command_line and any(sc in command_line for sc in [
            "sc create", "sc.exe create",
            "new-service", "install-service",
        ]):
            matches.append(RuleMatch(
                rule_id="P010",
                rule_name="service_creation",
                title=f"Windows service created via command line",
                description=(
                    f"A Windows service was created on "
                    f"{agent_info.get('hostname', 'unknown')}: "
                    f"{command_line[:300]}. "
                    f"Adversaries create services for persistence and "
                    f"privilege escalation."
                ),
                severity="high",
                confidence=0.70,
                detection_source="rule_engine",
                mitre_techniques=["T1543.003"],
                mitre_tactics=["Persistence", "Privilege Escalation"],
                raw_event=event,
            ))

        # ── RULE P011: UAC bypass attempt ────────────────────────
        uac_patterns = [
            "eventvwr.exe", "fodhelper.exe", "computerdefaults.exe",
            "sdclt.exe", "slui.exe",
        ]
        if process_name in uac_patterns and parent_name in ("cmd.exe", "powershell.exe", "pwsh.exe"):
            matches.append(RuleMatch(
                rule_id="P011",
                rule_name="uac_bypass",
                title=f"Possible UAC bypass: {parent_name} → {process_name}",
                description=(
                    f"UAC bypass technique detected on "
                    f"{agent_info.get('hostname', 'unknown')}: "
                    f"'{process_name}' spawned from '{parent_name}'. "
                    f"This is a known UAC bypass vector."
                ),
                severity="high",
                confidence=0.85,
                detection_source="rule_engine",
                mitre_techniques=["T1548.002"],
                mitre_tactics=["Privilege Escalation", "Defense Evasion"],
                raw_event=event,
            ))

        # ── RULE P012: WMI process creation (lateral movement) ──
        if "wmic" in process_name and command_line and "process call create" in command_line:
            matches.append(RuleMatch(
                rule_id="P012",
                rule_name="wmi_process_create",
                title="WMI remote process execution detected",
                description=(
                    f"WMI was used to create a remote process on "
                    f"{agent_info.get('hostname', 'unknown')}: "
                    f"{command_line[:300]}. "
                    f"This is commonly used for lateral movement."
                ),
                severity="high",
                confidence=0.80,
                detection_source="rule_engine",
                mitre_techniques=["T1047"],
                mitre_tactics=["Execution", "Lateral Movement"],
                raw_event=event,
            ))

        # ── RULE P013: Shadow copy deletion (ransomware precursor)
        if command_line and any(vs in command_line for vs in [
            "vssadmin delete shadows",
            "wmic shadowcopy delete",
            "bcdedit /set {default} recoveryenabled no",
            "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        ]):
            matches.append(RuleMatch(
                rule_id="P013",
                rule_name="shadow_copy_delete",
                title="Volume shadow copy deletion / recovery disabled",
                description=(
                    f"Shadow copies or recovery options were deleted/disabled on "
                    f"{agent_info.get('hostname', 'unknown')}: "
                    f"{command_line[:300]}. "
                    f"This is a strong indicator of ransomware preparation."
                ),
                severity="critical",
                confidence=0.95,
                detection_source="rule_engine",
                mitre_techniques=["T1490"],
                mitre_tactics=["Impact"],
                raw_event=event,
            ))

        return matches

    # ───────────────────────────────────────────────────────────
    # File Event Rules
    # ───────────────────────────────────────────────────────────

    def _rules_file_event(
        self, event: dict, agent_info: dict
    ) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        file_path = (event.get("file_path") or "").lower()
        file_name = (event.get("file_name") or "").lower()
        file_ext = (event.get("file_extension") or "").lower().lstrip(".")
        action = event.get("event_action", "")

        # ── RULE F001: Executable written to suspicious location ─
        if action in ("create", "modify") and file_ext in SUSPICIOUS_FILE_EXTENSIONS:
            if any(pat.search(file_path) for pat in SUSPICIOUS_PATH_PATTERNS):
                matches.append(RuleMatch(
                    rule_id="F001",
                    rule_name="suspicious_file_drop",
                    title=f"Executable dropped: {file_name}",
                    description=(
                        f"A file with executable extension '.{file_ext}' was "
                        f"{'created' if action == 'create' else 'modified'} at "
                        f"'{file_path}' on {agent_info.get('hostname', 'unknown')}."
                    ),
                    severity="high",
                    confidence=0.75,
                    detection_source="rule_engine",
                    mitre_techniques=["T1105"],
                    mitre_tactics=["Command and Control"],
                    raw_event=event,
                ))

        # ── RULE F002: Persistence via startup/autorun locations ─
        if action in ("create", "modify"):
            if any(pat.search(file_path) for pat in PERSISTENCE_FILE_PATHS):
                matches.append(RuleMatch(
                    rule_id="F002",
                    rule_name="persistence_file_write",
                    title=f"Persistence mechanism: file written to autorun location",
                    description=(
                        f"File '{file_name}' was written to a persistence "
                        f"location: {file_path} on "
                        f"{agent_info.get('hostname', 'unknown')}."
                    ),
                    severity="high",
                    confidence=0.80,
                    detection_source="rule_engine",
                    mitre_techniques=["T1547.001"],
                    mitre_tactics=["Persistence"],
                    raw_event=event,
                ))

        # ── RULE F003: Large file created (potential staging) ────
        file_size = event.get("file_size", 0)
        if (
            action == "create"
            and isinstance(file_size, (int, float))
            and file_size > 50_000_000  # > 50 MB
        ):
            matches.append(RuleMatch(
                rule_id="F003",
                rule_name="large_file_created",
                title=f"Large file created: {file_name} ({file_size / 1e6:.0f} MB)",
                description=(
                    f"A large file ({file_size / 1e6:.0f} MB) was created at "
                    f"'{file_path}' on {agent_info.get('hostname', 'unknown')}. "
                    f"This could indicate data staging for exfiltration."
                ),
                severity="medium",
                confidence=0.40,
                detection_source="rule_engine",
                mitre_techniques=["T1074"],
                mitre_tactics=["Collection"],
                raw_event=event,
            ))

        return matches

    # ───────────────────────────────────────────────────────────
    # Network Event Rules
    # ───────────────────────────────────────────────────────────

    def _rules_network_event(
        self, event: dict, agent_info: dict
    ) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        action = event.get("event_action", "")

        if action == "stats":
            matches.extend(self._rules_network_stats(event, agent_info))
        elif action == "connection":
            matches.extend(self._rules_network_connection(event, agent_info))

        return matches

    def _rules_network_stats(
        self, event: dict, agent_info: dict
    ) -> list[RuleMatch]:
        """Rules for network interface statistics."""
        matches: list[RuleMatch] = []

        # ── RULE N001: Large data transfer (>5 GB transmitted) ──
        bytes_tx = event.get("bytes_transmitted", 0)
        if isinstance(bytes_tx, (int, float)) and bytes_tx > 5_000_000_000:
            matches.append(RuleMatch(
                rule_id="N001",
                rule_name="large_outbound_transfer",
                title=f"Large outbound transfer: {bytes_tx / 1e9:.1f} GB on {event.get('interface', '?')}",
                description=(
                    f"Network interface '{event.get('interface', 'unknown')}' on "
                    f"{agent_info.get('hostname', 'unknown')} has transmitted "
                    f"{bytes_tx / 1e9:.2f} GB. Investigate for data exfiltration."
                ),
                severity="informational",
                confidence=0.30,
                detection_source="rule_engine",
                mitre_techniques=["T1048"],
                mitre_tactics=["Exfiltration"],
                raw_event=event,
            ))

        # ── RULE N002: High error rate ───────────────────────────
        errors_tx = event.get("errors_transmitted", 0)
        errors_rx = event.get("errors_received", 0)
        total_errors = (errors_tx or 0) + (errors_rx or 0)
        if total_errors > 100:
            matches.append(RuleMatch(
                rule_id="N002",
                rule_name="network_errors",
                title=f"High network error count: {total_errors} on {event.get('interface', '?')}",
                description=(
                    f"Interface '{event.get('interface', 'unknown')}' on "
                    f"{agent_info.get('hostname', 'unknown')} has {total_errors} "
                    f"errors. This could indicate network tampering or scanning."
                ),
                severity="low",
                confidence=0.35,
                detection_source="rule_engine",
                mitre_techniques=["T1049"],
                mitre_tactics=["Discovery"],
                raw_event=event,
            ))

        return matches

    def _rules_network_connection(
        self, event: dict, agent_info: dict
    ) -> list[RuleMatch]:
        """Rules for individual network connections."""
        matches: list[RuleMatch] = []
        dest_port = event.get("dest_port")
        dest_ip = event.get("dest_ip", "")

        # ── RULE N003: Connection to known-bad port ──────────────
        bad_ports = {
            4444: ("Metasploit default", "critical", 0.90),
            5555: ("Common RAT", "high", 0.80),
            8888: ("Common RAT", "medium", 0.60),
            1337: ("Leet port / trojan", "high", 0.75),
            31337: ("Back Orifice", "critical", 0.90),
            6666: ("IRC C2", "high", 0.80),
            6667: ("IRC C2", "high", 0.80),
            9999: ("Common backdoor", "high", 0.75),
            12345: ("NetBus", "high", 0.80),
            54321: ("Reverse shell", "critical", 0.85),
        }
        if dest_port and dest_port in bad_ports:
            name, sev, conf = bad_ports[dest_port]
            matches.append(RuleMatch(
                rule_id="N003",
                rule_name="suspicious_port",
                title=f"Connection to suspicious port {dest_port} ({name})",
                description=(
                    f"Connection from {agent_info.get('hostname', 'unknown')} to "
                    f"{dest_ip}:{dest_port} ({name}). This port is commonly "
                    f"associated with malware command-and-control."
                ),
                severity=sev,
                confidence=conf,
                detection_source="rule_engine",
                mitre_techniques=["T1571"],
                mitre_tactics=["Command and Control"],
                raw_event=event,
            ))

        # ── RULE N004: Lateral movement — RDP (port 3389) ───────
        lateral_ports = {
            3389: ("RDP", "T1021.001", "Remote Desktop"),
            5985: ("WinRM-HTTP", "T1021.006", "WinRM"),
            5986: ("WinRM-HTTPS", "T1021.006", "WinRM"),
            445: ("SMB", "T1021.002", "SMB/Admin Share"),
            135: ("RPC", "T1021", "DCOM/RPC"),
            22: ("SSH", "T1021.004", "SSH"),
        }
        if dest_port and dest_port in lateral_ports:
            name, technique, description = lateral_ports[dest_port]
            # Only alert if dest_ip is an internal IP (lateral movement)
            is_internal = False
            if dest_ip:
                is_internal = (
                    dest_ip.startswith("10.")
                    or dest_ip.startswith("192.168.")
                    or dest_ip.startswith("172.16.")
                    or dest_ip.startswith("172.17.")
                    or dest_ip.startswith("172.18.")
                    or dest_ip.startswith("172.19.")
                    or dest_ip.startswith("172.2")
                    or dest_ip.startswith("172.3")
                )
            if is_internal:
                matches.append(RuleMatch(
                    rule_id="N004",
                    rule_name="lateral_movement_connection",
                    title=f"Lateral movement: {name} connection to {dest_ip}:{dest_port}",
                    description=(
                        f"Internal {description} connection from "
                        f"{agent_info.get('hostname', 'unknown')} to "
                        f"{dest_ip}:{dest_port}. This could indicate "
                        f"lateral movement within the network."
                    ),
                    severity="medium",
                    confidence=0.55,
                    detection_source="rule_engine",
                    mitre_techniques=[technique],
                    mitre_tactics=["Lateral Movement"],
                    raw_event=event,
                ))

        # ── RULE N005: Connection to Tor exit node ports ─────────
        tor_ports = {9001, 9030, 9050, 9051, 9150}
        if dest_port and dest_port in tor_ports:
            matches.append(RuleMatch(
                rule_id="N005",
                rule_name="tor_connection",
                title=f"Possible Tor network connection on port {dest_port}",
                description=(
                    f"Connection to port {dest_port} (commonly used by Tor) "
                    f"from {agent_info.get('hostname', 'unknown')} to "
                    f"{dest_ip}. Tor is used by threat actors to anonymize "
                    f"C2 communications."
                ),
                severity="high",
                confidence=0.70,
                detection_source="rule_engine",
                mitre_techniques=["T1090.003"],
                mitre_tactics=["Command and Control"],
                raw_event=event,
            ))

        return matches

    # ───────────────────────────────────────────────────────────
    # System Event Rules
    # ───────────────────────────────────────────────────────────

    def _rules_system_event(
        self, event: dict, agent_info: dict
    ) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        action = event.get("event_action", "")

        # ── RULE S001: Critical CPU usage (> 95%) ────────────────
        if action == "cpu_metrics":
            cpu = event.get("cpu_usage_percent") or event.get("usage_percent", 0)
            if isinstance(cpu, (int, float)) and cpu > 95:
                matches.append(RuleMatch(
                    rule_id="S001",
                    rule_name="critical_cpu",
                    title=f"Critical CPU usage: {cpu:.0f}%",
                    description=(
                        f"CPU usage on {agent_info.get('hostname', 'unknown')} "
                        f"is at {cpu:.0f}%. Could indicate cryptomining, "
                        f"denial of service, or resource exhaustion attack."
                    ),
                    severity="medium",
                    confidence=0.40,
                    detection_source="rule_engine",
                    mitre_techniques=["T1496"],
                    mitre_tactics=["Impact"],
                    raw_event=event,
                ))

        # ── RULE S002: Critical disk usage (> 95%) ───────────────
        if action == "disk_metrics":
            # Check all mount points in the event
            raw = event
            mount_point = raw.get("mount_point", "")
            usage_pct = raw.get("usage_percent", 0)
            if isinstance(usage_pct, (int, float)) and usage_pct > 95:
                matches.append(RuleMatch(
                    rule_id="S002",
                    rule_name="critical_disk",
                    title=f"Critical disk usage: {usage_pct:.0f}% on {mount_point}",
                    description=(
                        f"Disk usage on {agent_info.get('hostname', 'unknown')} "
                        f"({mount_point}) is at {usage_pct:.0f}%. "
                        f"Could indicate data staging or log bombing."
                    ),
                    severity="low",
                    confidence=0.30,
                    detection_source="rule_engine",
                    mitre_techniques=["T1489"],
                    mitre_tactics=["Impact"],
                    raw_event=event,
                ))

        return matches
