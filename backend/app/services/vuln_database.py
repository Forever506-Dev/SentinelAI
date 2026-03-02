"""
Vulnerability Database Service

Integration with the National Vulnerability Database (NVD) and other
CVE data sources for real-time vulnerability lookup and correlation.
"""

import structlog
import httpx
from datetime import datetime, timedelta, timezone

from app.core.config import settings

logger = structlog.get_logger()


class VulnDatabaseService:
    """
    NVD/CVE vulnerability lookup and caching service.

    Provides:
    - Real-time CVE lookup via NVD API v2.0
    - CVSS score retrieval and severity classification
    - Software/CPE matching against agent inventory
    - Caching to avoid rate limits
    """

    def __init__(self) -> None:
        self.base_url = settings.NVD_BASE_URL
        self.api_key = settings.NVD_API_KEY
        self.cache_ttl = timedelta(hours=settings.NVD_CACHE_TTL_HOURS)
        self._cache: dict[str, tuple[datetime, dict]] = {}

    async def lookup_cve(self, cve_id: str) -> dict | None:
        """
        Look up a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            CVE details including CVSS score, description, affected products,
            and exploit availability. None if not found.
        """
        # Check cache
        cached = self._get_cached(cve_id)
        if cached:
            return cached

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {}
                if self.api_key:
                    headers["apiKey"] = self.api_key

                response = await client.get(
                    self.base_url,
                    params={"cveId": cve_id},
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    return None

                cve_data = vulnerabilities[0].get("cve", {})
                result = self._parse_cve(cve_data)

                # Cache result
                self._set_cached(cve_id, result)

                logger.info("CVE lookup successful", cve_id=cve_id)
                return result

        except httpx.HTTPStatusError as e:
            logger.error("NVD API error", cve_id=cve_id, status=e.response.status_code)
            return None
        except Exception as e:
            logger.error("CVE lookup failed", cve_id=cve_id, error=str(e))
            return None

    async def search_cves(
        self,
        keyword: str | None = None,
        cpe_name: str | None = None,
        cvss_severity: str | None = None,
        days_back: int = 30,
    ) -> list[dict]:
        """
        Search for CVEs matching criteria.

        Args:
            keyword: Search keyword
            cpe_name: CPE name to match (e.g., "cpe:2.3:a:microsoft:windows_10")
            cvss_severity: LOW | MEDIUM | HIGH | CRITICAL
            days_back: How many days back to search

        Returns:
            List of matching CVE records.
        """
        params: dict = {}
        if keyword:
            params["keywordSearch"] = keyword
        if cpe_name:
            params["cpeName"] = cpe_name
        if cvss_severity:
            params["cvssV3Severity"] = cvss_severity

        # Date range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days_back)
        params["pubStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {}
                if self.api_key:
                    headers["apiKey"] = self.api_key

                response = await client.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()

                results = []
                for vuln in data.get("vulnerabilities", []):
                    cve_data = vuln.get("cve", {})
                    results.append(self._parse_cve(cve_data))

                logger.info("CVE search completed", results_count=len(results))
                return results

        except Exception as e:
            logger.error("CVE search failed", error=str(e))
            return []

    async def check_software_vulnerabilities(
        self, software_inventory: list[dict]
    ) -> list[dict]:
        """
        Check an agent's software inventory against known vulnerabilities.

        Args:
            software_inventory: List of installed software with name and version.

        Returns:
            List of matching vulnerabilities with affected software.
        """
        findings = []

        for software in software_inventory:
            name = software.get("name", "")
            version = software.get("version", "")

            if not name:
                continue

            cves = await self.search_cves(keyword=f"{name} {version}")
            if cves:
                findings.append({
                    "software": software,
                    "vulnerabilities": cves[:10],  # Limit to top 10
                    "total_cves": len(cves),
                })

        return findings

    def _parse_cve(self, cve_data: dict) -> dict:
        """Parse raw NVD CVE data into a clean format."""
        cve_id = cve_data.get("id", "Unknown")

        # Extract description (prefer English)
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # Extract CVSS v3.1 score
        metrics = cve_data.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31", [{}])
        cvss_score = 0.0
        cvss_severity = "UNKNOWN"
        cvss_vector = ""
        if cvss_data:
            cvss_info = cvss_data[0].get("cvssData", {})
            cvss_score = cvss_info.get("baseScore", 0.0)
            cvss_severity = cvss_info.get("baseSeverity", "UNKNOWN")
            cvss_vector = cvss_info.get("vectorString", "")

        # Extract affected products (CPE)
        configurations = cve_data.get("configurations", [])
        affected_products = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        affected_products.append(cpe_match.get("criteria", ""))

        # Extract references
        references = [
            {"url": ref.get("url"), "source": ref.get("source")}
            for ref in cve_data.get("references", [])
        ]

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "affected_products": affected_products[:20],
            "references": references[:10],
            "published": cve_data.get("published"),
            "last_modified": cve_data.get("lastModified"),
        }

    def _get_cached(self, key: str) -> dict | None:
        """Get a cached result if still valid."""
        if key in self._cache:
            cached_at, data = self._cache[key]
            if datetime.now(timezone.utc) - cached_at < self.cache_ttl:
                return data
            del self._cache[key]
        return None

    def _set_cached(self, key: str, data: dict) -> None:
        """Cache a result."""
        self._cache[key] = (datetime.now(timezone.utc), data)
