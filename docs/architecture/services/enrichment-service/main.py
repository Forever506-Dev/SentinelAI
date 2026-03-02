"""
SentinelAI Enrichment Service

Consumes normalized telemetry events from NATS, enriches them with:
  - GeoIP data (MaxMind GeoLite2)
  - Threat intelligence (hash/IP/domain reputation)
  - Process tree context (parent chain lookup)
  - MITRE ATT&CK technique mapping
  - Community ID for network flow correlation

Publishes enriched events back to NATS for storage/detection.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# ─── GeoIP Enrichment ───────────────────────────────────────────────────────


@dataclass
class GeoEnrichment:
    country_code: str = ""
    country_name: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    asn: str = ""
    org: str = ""


class GeoIPEnricher:
    """
    Wraps MaxMind GeoLite2 database for IP geolocation.

    In production:
      import geoip2.database
      self.reader = geoip2.database.Reader('GeoLite2-City.mmdb')
      self.asn_reader = geoip2.database.Reader('GeoLite2-ASN.mmdb')
    """

    def __init__(self, city_db_path: str = "", asn_db_path: str = ""):
        self.city_db_path = city_db_path
        self.asn_db_path = asn_db_path
        # self.city_reader = geoip2.database.Reader(city_db_path) if city_db_path else None
        # self.asn_reader = geoip2.database.Reader(asn_db_path) if asn_db_path else None

    def enrich(self, ip: str) -> GeoEnrichment:
        """Look up GeoIP data for an IP address."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return GeoEnrichment()

        # Skip private/reserved IPs
        if addr.is_private or addr.is_reserved or addr.is_loopback:
            return GeoEnrichment()

        # In production: query MaxMind database
        # try:
        #     city = self.city_reader.city(ip)
        #     asn = self.asn_reader.asn(ip)
        #     return GeoEnrichment(
        #         country_code=city.country.iso_code,
        #         country_name=city.country.name,
        #         city=city.city.name,
        #         latitude=city.location.latitude,
        #         longitude=city.location.longitude,
        #         asn=f"AS{asn.autonomous_system_number}",
        #         org=asn.autonomous_system_organization,
        #     )
        # except geoip2.errors.AddressNotFoundError:
        #     return GeoEnrichment()

        return GeoEnrichment()  # Stub


# ─── Community ID ────────────────────────────────────────────────────────────


def compute_community_id(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: int,  # IANA protocol number (6=TCP, 17=UDP)
    seed: int = 0,
) -> str:
    """
    Compute Community ID v1 hash for network flow correlation.
    See: https://github.com/corelight/community-id-spec

    Ensures the same flow produces the same ID regardless of
    which endpoint is source vs destination.
    """
    try:
        src = ipaddress.ip_address(src_ip)
        dst = ipaddress.ip_address(dst_ip)
    except ValueError:
        return ""

    # Normalize direction: lower IP first (or lower port if IPs equal)
    if src > dst or (src == dst and src_port > dst_port):
        src, dst = dst, src
        src_port, dst_port = dst_port, src_port

    # Pack for hashing
    data = struct.pack("!H", seed)  # seed
    data += src.packed
    data += dst.packed
    data += struct.pack("!B", protocol)
    data += b"\x00"  # padding
    data += struct.pack("!HH", src_port, dst_port)

    digest = hashlib.sha1(data).digest()
    import base64
    return "1:" + base64.b64encode(digest).decode()


# ─── Threat Intelligence ────────────────────────────────────────────────────


class ThreatLevel(str, Enum):
    UNKNOWN = "unknown"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class ThreatIntelResult:
    level: ThreatLevel = ThreatLevel.UNKNOWN
    sources: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    confidence: float = 0.0


class ThreatIntelEnricher:
    """
    Checks IOCs against threat intelligence sources.

    Lookup chain (fast → slow):
      1. Local bloom filter (sub-microsecond, ~0.1% FP)
      2. Local Redis cache (sub-millisecond)
      3. Remote TI API (VirusTotal, AbuseIPDB, etc.) — async, cached

    In production, the bloom filter and Redis cache are pre-populated
    from STIX/TAXII feeds and commercial TI providers.
    """

    def __init__(self):
        # self.bloom = load_ioc_bloom_filter()
        # self.redis = aioredis.from_url("redis://redis:6379/1")
        pass

    async def check_hash(self, sha256: str) -> ThreatIntelResult:
        """Check file hash against threat intelligence."""
        # 1. Bloom filter fast negative
        # if not self.bloom.check(sha256):
        #     return ThreatIntelResult(level=ThreatLevel.CLEAN)

        # 2. Redis cache
        # cached = await self.redis.get(f"ti:hash:{sha256}")
        # if cached:
        #     return ThreatIntelResult.from_json(cached)

        # 3. Remote API (rate-limited, async)
        # result = await self._query_vt(sha256)
        # await self.redis.setex(f"ti:hash:{sha256}", 86400, result.to_json())
        # return result

        return ThreatIntelResult()  # Stub

    async def check_ip(self, ip: str) -> ThreatIntelResult:
        """Check IP against threat intelligence."""
        return ThreatIntelResult()  # Stub

    async def check_domain(self, domain: str) -> ThreatIntelResult:
        """Check domain against threat intelligence."""
        return ThreatIntelResult()  # Stub


# ─── Process Tree Context ───────────────────────────────────────────────────


@dataclass
class ProcessContext:
    """Enriches an event with process ancestry information."""
    process_chain: list[str] = field(default_factory=list)  # [grandparent, parent, process]
    tree_depth: int = 0
    is_elevated: bool = False
    parent_is_common: bool = False  # Is parent a known OS process?

    # Common legitimate parents that reduce suspicion when present
    COMMON_PARENTS = {
        "explorer.exe", "services.exe", "svchost.exe", "wininit.exe",
        "csrss.exe", "lsass.exe", "winlogon.exe", "smss.exe",
        "systemd", "init", "bash", "zsh", "sh",
    }


class ProcessTreeEnricher:
    """
    Maintains a sliding window of process create/terminate events
    to build parent-child chains for enrichment.

    Backed by Redis with TTL (processes older than 24h are evicted).
    """

    def __init__(self):
        # self.redis = aioredis.from_url("redis://redis:6379/2")
        pass

    async def get_context(
        self,
        process_guid: str,
        parent_process_guid: str,
    ) -> ProcessContext:
        """Look up process ancestry chain."""
        # In production:
        # 1. Lookup parent_process_guid in Redis
        # 2. Recursively walk parent chain (max depth 10)
        # 3. Build process_chain list
        # 4. Check if parent is in COMMON_PARENTS
        return ProcessContext()  # Stub


# ─── MITRE ATT&CK Mapping ───────────────────────────────────────────────────

# Heuristic technique mapping based on event characteristics.
# In production, this is driven by detection rule metadata.

TECHNIQUE_INDICATORS: dict[str, list[dict]] = {
    "T1059.001": [  # PowerShell
        {"field": "process_name", "values": ["powershell.exe", "pwsh.exe"]},
    ],
    "T1059.003": [  # Windows Command Shell
        {"field": "process_name", "values": ["cmd.exe"]},
    ],
    "T1003.001": [  # LSASS Memory
        {"field": "process_name", "values": ["mimikatz.exe", "procdump.exe"]},
    ],
    "T1547.001": [  # Registry Run Keys
        {"field": "registry_key_path", "contains": ["\\Run", "\\RunOnce"]},
    ],
    "T1071.001": [  # Web Protocols
        {"field": "dest_port", "values": [80, 443, 8080, 8443]},
    ],
    "T1048": [  # Exfiltration Over Alternative Protocol
        {"field": "dest_port", "values": [53, 443, 8443]},
        {"field": "bytes_sent", "greater_than": 1_000_000},
    ],
}


def suggest_mitre_techniques(event_fields: dict) -> list[str]:
    """Suggest MITRE ATT&CK techniques based on event fields."""
    matches = []

    for technique_id, indicators in TECHNIQUE_INDICATORS.items():
        for indicator in indicators:
            field_name = indicator["field"]
            if field_name not in event_fields:
                continue

            value = event_fields[field_name]

            if "values" in indicator:
                if isinstance(value, str) and value.lower() in [
                    v.lower() if isinstance(v, str) else v
                    for v in indicator["values"]
                ]:
                    matches.append(technique_id)
                elif isinstance(value, (int, float)) and value in indicator["values"]:
                    matches.append(technique_id)

            if "contains" in indicator and isinstance(value, str):
                if any(c.lower() in value.lower() for c in indicator["contains"]):
                    matches.append(technique_id)

            if "greater_than" in indicator:
                if isinstance(value, (int, float)) and value > indicator["greater_than"]:
                    matches.append(technique_id)

    return list(set(matches))


# ─── Enrichment Pipeline ────────────────────────────────────────────────────


class EnrichmentPipeline:
    """
    Orchestrates all enrichment steps for a single event.

    Consumed from: NATS telemetry.normalized.>
    Published to:  NATS telemetry.enriched.{tenant_id}.{category}
    """

    def __init__(self):
        self.geoip = GeoIPEnricher()
        self.threat_intel = ThreatIntelEnricher()
        self.process_tree = ProcessTreeEnricher()

    async def enrich(self, event: dict) -> dict:
        """
        Apply all enrichment steps to a normalized event.

        Enrichment is additive — original fields are never modified,
        only new fields are added.
        """
        enriched = dict(event)  # shallow copy

        # 1. GeoIP enrichment for destination IPs
        if dest_ip := event.get("dest_ip"):
            geo = self.geoip.enrich(dest_ip)
            enriched["dest_country_code"] = geo.country_code
            enriched["dest_country_name"] = geo.country_name
            enriched["dest_city"] = geo.city
            enriched["dest_asn"] = geo.asn
            enriched["dest_org"] = geo.org
            if geo.latitude and geo.longitude:
                enriched["dest_location"] = {
                    "lat": geo.latitude,
                    "lon": geo.longitude,
                }

        # 2. Community ID for network events
        if all(k in event for k in ("source_ip", "dest_ip", "source_port", "dest_port")):
            protocol_num = {"tcp": 6, "udp": 17, "icmp": 1}.get(
                event.get("protocol", "").lower(), 0
            )
            enriched["community_id"] = compute_community_id(
                event["source_ip"],
                event["dest_ip"],
                event.get("source_port", 0),
                event.get("dest_port", 0),
                protocol_num,
            )

        # 3. Threat intelligence lookups (parallel)
        # In production, use asyncio.gather for parallel lookups:
        #   hash_result, ip_result, domain_result = await asyncio.gather(
        #       self.threat_intel.check_hash(event.get("sha256", "")),
        #       self.threat_intel.check_ip(event.get("dest_ip", "")),
        #       self.threat_intel.check_domain(event.get("dns_query_name", "")),
        #   )

        # 4. Process tree context
        if process_guid := event.get("process_guid"):
            ctx = await self.process_tree.get_context(
                process_guid,
                event.get("parent_process_guid", ""),
            )
            if ctx.process_chain:
                enriched["process_chain"] = ctx.process_chain
                enriched["tree_depth"] = ctx.tree_depth

        # 5. MITRE ATT&CK technique suggestions
        techniques = suggest_mitre_techniques(event)
        if techniques:
            enriched["mitre_techniques"] = techniques

        # 6. Risk score computation
        enriched["risk_score"] = self._compute_risk_score(enriched)

        return enriched

    def _compute_risk_score(self, event: dict) -> int:
        """
        Compute a 0-100 risk score based on enrichment signals.

        Scoring factors:
          +30: Malicious TI hit (hash/IP/domain)
          +20: Suspicious process ancestry
          +15: Known MITRE technique match
          +10: High-value target (LSASS, SAM, etc.)
          +10: Elevated integrity level
          +5:  Unsigned module load
          -10: Common/known-good parent process
        """
        score = 0

        if event.get("mitre_techniques"):
            score += 15 * len(event["mitre_techniques"])

        process_name = event.get("process_name", "").lower()
        if process_name in ("mimikatz.exe", "procdump.exe", "rubeus.exe"):
            score += 40

        integrity = event.get("integrity_level", "").lower()
        if integrity in ("system", "high"):
            score += 10

        if event.get("is_sensitive_path"):
            score += 10

        if event.get("module_is_signed") is False:
            score += 5

        parent = event.get("parent_process_name", "").lower()
        if parent in ProcessContext.COMMON_PARENTS:
            score -= 10

        return max(0, min(100, score))


# ─── NATS Consumer (Main Loop) ──────────────────────────────────────────────

# async def main():
#     """
#     Main loop:
#       1. Connect to NATS JetStream
#       2. Create/bind durable consumer on TELEMETRY_NORMALIZED stream
#       3. For each message: deserialize → enrich → publish to telemetry.enriched.*
#     """
#     import nats
#     nc = await nats.connect("nats://nats:4222")
#     js = nc.jetstream()
#
#     pipeline = EnrichmentPipeline()
#
#     # Pull consumer with queue group for horizontal scaling
#     sub = await js.pull_subscribe(
#         "telemetry.normalized.>",
#         durable="enrichment-workers",
#         stream="TELEMETRY_NORMALIZED",
#     )
#
#     while True:
#         try:
#             messages = await sub.fetch(batch=50, timeout=5.0)
#             for msg in messages:
#                 event = json.loads(msg.data)
#                 enriched = await pipeline.enrich(event)
#
#                 # Publish enriched event
#                 tenant_id = event.get("tenant_id", "unknown")
#                 category = event.get("category", "unknown")
#                 await js.publish(
#                     f"telemetry.enriched.{tenant_id}.{category}",
#                     json.dumps(enriched).encode(),
#                 )
#
#                 await msg.ack()
#         except nats.errors.TimeoutError:
#             continue
#         except Exception as e:
#             logger.error(f"enrichment error: {e}")
#             # NAK the message for redelivery
#             continue
