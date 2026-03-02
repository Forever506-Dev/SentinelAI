"""
Correlation Engine Service

Cross-agent event correlation, temporal pattern matching,
attack chain reconstruction, and alert deduplication.
"""

import uuid
from datetime import datetime, timedelta, timezone

import structlog

from app.services.mitre_attack import MitreAttackService

logger = structlog.get_logger()


class CorrelationEngine:
    """
    Event correlation engine for detecting multi-stage attacks.

    Features:
    - Cross-agent correlation (same attack targeting multiple endpoints)
    - Temporal correlation (events in sequence matching attack patterns)
    - Kill chain progression tracking
    - Alert grouping and deduplication
    """

    def __init__(self) -> None:
        self.mitre = MitreAttackService()
        # In production, these would be backed by Redis/DB
        self._active_correlations: dict[str, dict] = {}
        self._correlation_window = timedelta(hours=4)

    async def correlate_alert(self, alert: dict, recent_alerts: list[dict]) -> dict:
        """
        Attempt to correlate a new alert with existing alerts.

        Checks for:
        1. Same attack technique across multiple agents (lateral movement)
        2. Sequential techniques indicating kill chain progression
        3. Same source indicators (IP, hash, domain) across alerts
        4. Temporal proximity of related events
        """
        correlation = {
            "group_id": None,
            "is_correlated": False,
            "related_alerts": [],
            "attack_chain": [],
            "confidence": 0.0,
        }

        # 1. Check for IOC overlap
        ioc_matches = self._find_ioc_matches(alert, recent_alerts)
        if ioc_matches:
            correlation["related_alerts"].extend(ioc_matches)
            correlation["is_correlated"] = True
            correlation["confidence"] = max(correlation["confidence"], 0.8)

        # 2. Check for kill chain progression
        techniques = alert.get("mitre_techniques", [])
        chain = await self._detect_kill_chain(techniques, recent_alerts)
        if chain:
            correlation["attack_chain"] = chain
            correlation["is_correlated"] = True
            correlation["confidence"] = max(correlation["confidence"], 0.9)

        # 3. Check for cross-agent correlation
        cross_agent = self._find_cross_agent_matches(alert, recent_alerts)
        if cross_agent:
            correlation["related_alerts"].extend(cross_agent)
            correlation["is_correlated"] = True
            correlation["confidence"] = max(correlation["confidence"], 0.85)

        # Assign or create correlation group
        if correlation["is_correlated"]:
            group_id = self._get_or_create_group(alert, correlation["related_alerts"])
            correlation["group_id"] = group_id

        return correlation

    def _find_ioc_matches(self, alert: dict, recent_alerts: list[dict]) -> list[dict]:
        """Find alerts sharing the same IOCs (IPs, hashes, domains)."""
        matches = []
        alert_iocs = alert.get("ioc_indicators", {})
        if not alert_iocs:
            return matches

        alert_ips = set(alert_iocs.get("ips", []))
        alert_hashes = set(alert_iocs.get("hashes", []))
        alert_domains = set(alert_iocs.get("domains", []))

        for other in recent_alerts:
            other_iocs = other.get("ioc_indicators", {})
            if not other_iocs:
                continue

            other_ips = set(other_iocs.get("ips", []))
            other_hashes = set(other_iocs.get("hashes", []))
            other_domains = set(other_iocs.get("domains", []))

            overlap_ips = alert_ips & other_ips
            overlap_hashes = alert_hashes & other_hashes
            overlap_domains = alert_domains & other_domains

            if overlap_ips or overlap_hashes or overlap_domains:
                matches.append({
                    "alert_id": other.get("id"),
                    "match_type": "ioc_overlap",
                    "shared_ips": list(overlap_ips),
                    "shared_hashes": list(overlap_hashes),
                    "shared_domains": list(overlap_domains),
                })

        return matches

    async def _detect_kill_chain(
        self, techniques: list[str], recent_alerts: list[dict]
    ) -> list[dict]:
        """
        Detect kill chain progression across alerts.

        Looks for technique sequences that indicate a multi-stage attack:
        Recon → Initial Access → Execution → Persistence → Priv Esc → etc.
        """
        if not techniques:
            return []

        # Gather all techniques from recent alerts
        all_techniques = set(techniques)
        for alert in recent_alerts:
            for tech in alert.get("mitre_techniques", []):
                all_techniques.add(tech)

        # Map to kill chain phases
        coverage = await self.mitre.get_kill_chain_coverage(list(all_techniques))

        # Check if we see progression (multiple phases covered)
        kill_chain_order = [
            "Reconnaissance", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection",
            "Command and Control", "Exfiltration", "Impact",
        ]

        covered_phases = []
        for phase in kill_chain_order:
            if phase in coverage:
                covered_phases.append({
                    "phase": phase,
                    "techniques": coverage[phase],
                })

        # If 3+ phases are covered, it's likely a multi-stage attack
        if len(covered_phases) >= 3:
            logger.warning(
                "Kill chain progression detected",
                phases=len(covered_phases),
                techniques=list(all_techniques),
            )
            return covered_phases

        return []

    def _find_cross_agent_matches(
        self, alert: dict, recent_alerts: list[dict]
    ) -> list[dict]:
        """Find the same attack technique targeting multiple agents."""
        matches = []
        alert_techniques = set(alert.get("mitre_techniques", []))
        alert_agent = alert.get("agent_id")

        if not alert_techniques or not alert_agent:
            return matches

        for other in recent_alerts:
            other_agent = other.get("agent_id")
            if other_agent == alert_agent:
                continue

            other_techniques = set(other.get("mitre_techniques", []))
            shared = alert_techniques & other_techniques

            if shared:
                matches.append({
                    "alert_id": other.get("id"),
                    "match_type": "cross_agent",
                    "other_agent_id": other_agent,
                    "shared_techniques": list(shared),
                })

        return matches

    def _get_or_create_group(
        self, alert: dict, related_alerts: list[dict]
    ) -> str:
        """Get existing correlation group or create a new one."""
        # Check if any related alert already has a group
        for related in related_alerts:
            alert_id = related.get("alert_id")
            if alert_id and alert_id in self._active_correlations:
                return self._active_correlations[alert_id]["group_id"]

        # Create new group
        group_id = f"CG-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"

        self._active_correlations[alert.get("id", "")] = {
            "group_id": group_id,
            "created_at": datetime.now(timezone.utc),
        }

        logger.info("New correlation group created", group_id=group_id)
        return group_id
