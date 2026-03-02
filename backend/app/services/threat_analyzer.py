"""
Threat Analyzer Service

Multi-stage threat analysis pipeline that combines LOLGlobs intelligence,
NVD vulnerability lookups, heuristic rules, and LLM-powered triage.

Pipeline: Triage → Enrich → LLM Triage → Classify → Respond
"""

import asyncio

import structlog
import httpx

from app.core.config import settings
from app.services.llm_engine import LLMEngine
from app.services.vuln_database import VulnDatabaseService
from app.services.mitre_attack import MitreAttackService
from app.services.lolglobs_service import LOLGlobsService

logger = structlog.get_logger()


class ThreatAnalyzer:
    """
    Central threat analysis engine.

    Detection priority:
    1. High-confidence heuristic rules (encoded PS, LOLBins, suspicious ports)
    2. LOLGlobs pattern matching with MITRE mapping
    3. NVD vulnerability cross-reference
    4. LLM deep-triage for ambiguous / complex events
    """

    def __init__(self) -> None:
        self.llm: LLMEngine | None = None
        self.vuln_db = VulnDatabaseService()
        self.mitre = MitreAttackService()
        self.lolglobs = LOLGlobsService()

    def _get_llm(self) -> LLMEngine:
        """Lazily initialize LLM to keep non-LLM paths available."""
        if self.llm is None:
            self.llm = LLMEngine()
        return self.llm

    async def analyze_event_batch(self, events: list[dict], agent_info: dict) -> list[dict]:
        """
        Analyze a batch of telemetry events for threats.

        Stage 1 — Triage: Quick rule-based checks for known-bad indicators
        Stage 2 — Enrich: Add context from threat intel sources
        Stage 3 — LLM Analysis: Deep behavioral analysis
        Stage 4 — Classify: Assign severity and MITRE mapping
        Stage 5 — Respond: Generate recommended response actions
        """
        alerts = []

        # Stage 1: Triage with heuristic rules
        suspicious_events = self._triage_events(events)

        if not suspicious_events:
            return alerts

        logger.info(
            "Triage flagged events",
            total=len(events),
            suspicious=len(suspicious_events),
        )

        # Stage 2: Enrich each suspicious event
        for event in suspicious_events:
            enriched = await self._enrich_event(event)

            # Stage 3: LLM analysis for complex events
            llm_result = await self._get_llm().analyze_alert({
                "title": enriched.get("triage_reason", "Suspicious activity"),
                "description": str(enriched),
                "detection_source": "behavioral",
                "os_type": agent_info.get("os_type", "unknown"),
                "raw_events": enriched,
                "process_tree": enriched.get("process_tree", {}),
                "network_context": enriched.get("network_context", {}),
            })

            # Stage 4: Classify
            alert = {
                "title": enriched.get("triage_reason", "Suspicious activity detected"),
                "description": llm_result.get("analysis", "No analysis available"),
                "severity": llm_result.get("severity", "medium"),
                "confidence": llm_result.get("confidence", 0.5),
                "detection_source": "behavioral",
                "mitre_techniques": llm_result.get("mitre_techniques", []),
                "llm_analysis": llm_result.get("analysis"),
                "llm_recommendation": str(llm_result.get("recommendations", [])),
                "llm_confidence": llm_result.get("confidence"),
                "raw_events": enriched,
            }

            # Stage 5: Recommended response
            alert["recommended_actions"] = self._generate_response(
                severity=alert["severity"],
                mitre_techniques=alert["mitre_techniques"],
            )

            alerts.append(alert)

        return alerts

    def _triage_events(self, events: list[dict]) -> list[dict]:
        """
        Quick heuristic triage to identify suspicious events.

        High-confidence rules (fires immediately):
        - PowerShell with encoded commands
        - Suspicious parent-child process relationships
        - Connections to known malicious ports
        - DNS queries to suspicious TLDs
        - LOLBin execution (checked via LOLGlobs in async enrichment)
        """
        suspicious = []

        for event in events:
            reasons = []

            cmd = (event.get("command_line") or "").lower()
            process = (event.get("process_name") or "").lower()

            # ── Rule 1: Encoded PowerShell ───────────────────────
            if "powershell" in process and (
                "-encodedcommand" in cmd
                or "-enc " in cmd
                or "frombase64string" in cmd
                or "-windowstyle hidden" in cmd
                or "bypass" in cmd and "executionpolicy" in cmd
            ):
                reasons.append("Encoded/hidden PowerShell command detected")

            # ── Rule 2: Suspicious parent-child spawns ───────────
            suspicious_spawns = {
                "cmd.exe": ["excel.exe", "word.exe", "outlook.exe", "winword.exe"],
                "powershell.exe": ["excel.exe", "word.exe", "wscript.exe", "winword.exe", "outlook.exe"],
                "certutil.exe": ["cmd.exe", "powershell.exe"],
                "mshta.exe": ["explorer.exe", "cmd.exe", "powershell.exe"],
                "regsvr32.exe": ["cmd.exe", "powershell.exe"],
                "rundll32.exe": ["cmd.exe", "powershell.exe", "explorer.exe"],
                "wmic.exe": ["cmd.exe", "powershell.exe"],
                "cscript.exe": ["word.exe", "excel.exe", "outlook.exe"],
                "wscript.exe": ["word.exe", "excel.exe", "outlook.exe"],
            }
            parent = (event.get("parent_process_name") or "").lower()
            for child, parents in suspicious_spawns.items():
                if child in process and any(p in parent for p in parents):
                    reasons.append(f"Suspicious process spawn: {parent} → {process}")

            # ── Rule 3: Suspicious network ports ─────────────────
            dest_port = event.get("dest_port")
            suspicious_ports = {
                4444: "Metasploit default",
                5555: "Common RAT",
                8888: "Common RAT",
                1337: "Leet port",
                31337: "Back Orifice",
                6666: "IRC-based C2",
                6667: "IRC C2",
                9999: "Common backdoor",
                1234: "Common test backdoor",
                12345: "NetBus",
                54321: "Reverse shell",
            }
            if dest_port and dest_port in suspicious_ports:
                reasons.append(f"Connection to suspicious port {dest_port} ({suspicious_ports[dest_port]})")

            # ── Rule 4: Suspicious DNS TLDs ──────────────────────
            dns = event.get("dns_query") or ""
            suspicious_tlds = [
                ".xyz", ".top", ".work", ".click", ".loan", ".tk", ".ml",
                ".ga", ".cf", ".gq", ".buzz", ".icu", ".club", ".online",
            ]
            if any(dns.endswith(tld) for tld in suspicious_tlds):
                reasons.append(f"DNS query to suspicious TLD: {dns}")

            # ── Rule 5: Data exfiltration indicators ─────────────
            if event.get("event_type") == "network" and event.get("bytes_sent"):
                bytes_sent = event.get("bytes_sent", 0)
                if isinstance(bytes_sent, (int, float)) and bytes_sent > 10_000_000:  # >10 MB
                    reasons.append(f"Large outbound transfer: {bytes_sent / 1_000_000:.1f} MB")

            # ── Rule 6: Registry persistence ─────────────────────
            file_path = (event.get("file_path") or "").lower()
            persistence_paths = [
                "\\currentversion\\run",
                "\\currentversion\\runonce",
                "\\currentversion\\runservices",
                "\\startup",
                "\\policies\\explorer\\run",
            ]
            if any(p in file_path for p in persistence_paths):
                reasons.append(f"Registry persistence modification: {file_path}")

            if reasons:
                event["triage_reasons"] = reasons
                event["triage_reason"] = reasons[0]
                event["triage_confidence"] = min(0.5 + 0.15 * len(reasons), 0.95)
                suspicious.append(event)

        return suspicious

    async def _enrich_event(self, event: dict) -> dict:
        """
        Enrich an event with LOLGlobs, NVD, and reputation data.

        Enrichment sources (in priority order):
        1. LOLGlobs — binary + evasion pattern matching
        2. NVD — software vulnerability cross-reference
        3. Reputation feeds — hash, IP, domain (placeholder)
        """
        enriched = {**event}

        # ── LOLGlobs enrichment ──────────────────────────────────
        process_name = event.get("process_name") or ""
        command_line = event.get("command_line") or ""
        if process_name:
            lol_result = await self.lolglobs.check_process(process_name, command_line)
            if lol_result:
                enriched["lolglobs"] = lol_result
                enriched["lolbin_detected"] = True
                # Add MITRE techniques from LOLGlobs
                if lol_result.get("mitre_id"):
                    enriched.setdefault("mitre_techniques_auto", []).append(lol_result["mitre_id"])
                # If evasion patterns matched, boost confidence
                if lol_result.get("evasion_patterns_matched"):
                    event["triage_confidence"] = min(
                        event.get("triage_confidence", 0.5) + 0.2, 0.98
                    )
                    enriched["evasion_detected"] = True

        # ── File path LOLBin check ───────────────────────────────
        file_path = event.get("file_path")
        if file_path:
            path_result = await self.lolglobs.check_file_path(file_path)
            if path_result:
                enriched.setdefault("lolglobs", {}).update(path_result)
                enriched["lolbin_detected"] = True

        # ── MITRE ATT&CK mapping ────────────────────────────────
        mitre_techniques = await self.mitre.map_event_to_techniques(event)
        if mitre_techniques:
            enriched.setdefault("mitre_techniques_auto", []).extend(
                [t["technique_id"] for t in mitre_techniques]
            )

        # ── File hash reputation ─────────────────────────────────
        file_hash = event.get("file_hash_sha256")
        if file_hash:
            enriched["hash_reputation"] = await self._check_hash_reputation(file_hash)

        # ── IP reputation ────────────────────────────────────────
        dest_ip = event.get("dest_ip")
        if dest_ip:
            enriched["ip_reputation"] = await self._check_ip_reputation(dest_ip)

        # ── Domain reputation ────────────────────────────────────
        dns_query = event.get("dns_query")
        if dns_query:
            enriched["domain_reputation"] = await self._check_domain_reputation(dns_query)

        return enriched

    async def _check_hash_reputation(self, file_hash: str) -> dict:
        """Check file hash against threat intelligence feeds."""
        # TODO: Integrate with VirusTotal, MalwareBazaar, etc.
        return {"hash": file_hash, "status": "unknown", "source": "pending_integration"}

    async def _check_ip_reputation(self, ip: str) -> dict:
        """Check IP reputation against threat intelligence feeds."""
        # TODO: Integrate with AbuseIPDB, OTX, etc.
        return {"ip": ip, "status": "unknown", "source": "pending_integration"}

    async def _check_domain_reputation(self, domain: str) -> dict:
        """Check domain reputation against threat intelligence feeds."""
        # TODO: Integrate with URLhaus, PhishTank, etc.
        return {"domain": domain, "status": "unknown", "source": "pending_integration"}

    def _generate_response(
        self, severity: str, mitre_techniques: list[str]
    ) -> list[dict]:
        """Generate recommended response actions based on severity and techniques."""
        actions = []

        if severity == "critical":
            actions.extend([
                {"action": "isolate", "priority": "immediate", "description": "Isolate the endpoint from the network"},
                {"action": "collect_forensics", "priority": "immediate", "description": "Collect forensic artifacts (memory dump, disk image)"},
                {"action": "kill_process", "priority": "high", "description": "Terminate the malicious process"},
            ])
        elif severity == "high":
            actions.extend([
                {"action": "kill_process", "priority": "high", "description": "Terminate the suspicious process"},
                {"action": "scan", "priority": "high", "description": "Run full endpoint scan"},
            ])
        elif severity == "medium":
            actions.extend([
                {"action": "scan", "priority": "medium", "description": "Run targeted scan"},
                {"action": "monitor", "priority": "medium", "description": "Increase monitoring for this endpoint"},
            ])

        return actions

    async def lookup_indicator(
        self, indicator_type: str, indicator_value: str
    ) -> dict:
        """
        Look up a specific threat indicator across all intelligence sources.
        """
        results = {
            "threat_level": "unknown",
            "sources": [],
            "details": {},
            "recommendations": [],
        }

        match indicator_type:
            case "cve":
                cve_data = await self.vuln_db.lookup_cve(indicator_value)
                results["details"]["cve"] = cve_data
                results["sources"].append("NVD")
                if cve_data:
                    cvss = cve_data.get("cvss_score", 0)
                    if cvss >= 9.0:
                        results["threat_level"] = "critical"
                    elif cvss >= 7.0:
                        results["threat_level"] = "high"
                    elif cvss >= 4.0:
                        results["threat_level"] = "medium"
                    else:
                        results["threat_level"] = "low"

            case "ip":
                ip_data = await self._check_ip_reputation(indicator_value)
                results["details"]["ip"] = ip_data
                results["sources"].append("ip_reputation")

            case "domain" | "url" | "email":
                domain_data = await self._check_domain_reputation(indicator_value)
                results["details"]["domain"] = domain_data
                results["sources"].append("domain_reputation")

            case "hash_sha256" | "hash_md5":
                hash_data = await self._check_hash_reputation(indicator_value)
                results["details"]["hash"] = hash_data
                results["sources"].append("hash_reputation")

        # Enrich with LLM analysis
        llm_context = f"Indicator: {indicator_type}={indicator_value}, Known data: {results['details']}"
        try:
            llm_result = await self._get_llm().investigate(
                query=f"What is the threat assessment for {indicator_type}: {indicator_value}?",
                context={"indicator": llm_context},
            )
            results["details"]["llm_analysis"] = llm_result.get("analysis")
            results["recommendations"] = llm_result.get("recommendations", [])
        except Exception as e:
            logger.error("LLM enrichment failed", error=str(e))

        return results
