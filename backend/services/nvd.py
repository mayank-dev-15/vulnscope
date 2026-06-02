"""NVD (National Vulnerability Database) Service"""

import aiohttp
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDService:
    """Service for fetching and processing CVE data from NVD."""

    def __init__(self):
        self.base_url = NVD_API_BASE
        self._cache: Dict[str, Any] = {}
        self._cache_ttl = 300  # 5 minutes

    async def get_cves(
        self,
        severity: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
        days: Optional[int] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[Dict], int]:
        """
        Fetch CVEs from NVD API with optional filtering.

        Args:
            severity: Filter by severity level
            limit: Maximum results per page
            offset: Pagination offset
            days: Filter by last N days
            search: Search in description text

        Returns:
            Tuple of (cves_list, total_count)
        """
        params = {
            "resultsPerPage": limit,
            "startIndex": offset,
        }

        if severity:
            params["cvssV3Severity"] = severity.upper()

        if days:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            params["pubStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["pubEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        if search:
            params["keywordSearch"] = search

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.base_url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    if response.status != 200:
                        logger.error(f"NVD API error: {response.status}")
                        return [], 0

                    data = await response.json()

                    cves = []
                    for item in data.get("vulnerabilities", []):
                        cve_data = self._parse_cve_item(item)
                        cves.append(cve_data)

                    total = data.get("totalResults", 0)
                    return cves, total

        except aiohttp.ClientError as e:
            logger.error(f"Error connecting to NVD API: {e}")
            return [], 0
        except Exception as e:
            logger.error(f"Unexpected error fetching CVEs: {e}")
            return [], 0

    async def get_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """Fetch a specific CVE by its ID."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}",
                    params={"cveId": cve_id},
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    if response.status != 200:
                        return None

                    data = await response.json()
                    vulnerabilities = data.get("vulnerabilities", [])

                    if vulnerabilities:
                        return self._parse_cve_item(vulnerabilities[0])
                    return None

        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
            return None

    async def get_trends(self, days: int = 30) -> List[Dict]:
        """Get daily CVE publish trends for the last N days."""
        trends = []
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.base_url,
                    params={
                        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "resultsPerPage": 2000,
                    },
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as response:
                    if response.status != 200:
                        return []

                    data = await response.json()

                    # Aggregate by date
                    daily_counts: Dict[str, Dict[str, int]] = {}
                    for item in data.get("vulnerabilities", []):
                        cve = item.get("cve", {})
                        published = cve.get("published", "")
                        if published:
                            date_key = published[:10]
                            if date_key not in daily_counts:
                                daily_counts[date_key] = {
                                    "critical": 0, "high": 0,
                                    "medium": 0, "low": 0, "total": 0,
                                }
                            severity = cve.get("metrics", {}).get("cvssMetricV31", [{}])
                            if severity:
                                level = severity[0].get("cvssData", {}).get("baseSeverity", "MEDIUM").lower()
                                if level in daily_counts[date_key]:
                                    daily_counts[date_key][level] += 1
                            daily_counts[date_key]["total"] += 1

                    for date_key in sorted(daily_counts.keys()):
                        entry = {"date": date_key, **daily_counts[date_key]}
                        trends.append(entry)

                    return trends

        except Exception as e:
            logger.error(f"Error fetching trends: {e}")
            return []

    async def get_severity_distribution(self) -> Dict[str, int]:
        """Get current severity distribution across all recent CVEs."""
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for severity in distribution.keys():
            _, total = await self.get_cves(severity=severity, limit=1)
            distribution[severity] = total

        return distribution

    @staticmethod
    def _parse_cve_item(item: Dict) -> Dict[str, Any]:
        """Parse a raw NVD CVE item into a clean dictionary."""
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])
        cvss_data = metrics[0].get("cvssData", {}) if metrics else {}

        return {
            "cve_id": cve.get("id", ""),
            "description": cve.get("descriptions", [{}])[0].get("value", ""),
            "severity": cvss_data.get("baseSeverity", "UNKNOWN").lower(),
            "cvss_score": cvss_data.get("baseScore", 0.0),
            "published_date": cve.get("published", ""),
            "modified_date": cve.get("lastModified", ""),
            "references": [
                ref.get("url", "")
                for ref in cve.get("references", [])
            ],
            "affected_products": [
                f"{cp.get('vendor', '')}:{cp.get('product', '')}"
                for config in cve.get("configurations", [])
                for node in config.get("nodes", [])
                for cp in node.get("cpeMatch", [])
                if cp.get("criteria", "")
            ],
            "cwe_ids": [
                weakness.get("description", [{}])[0].get("value", "")
                for weakness in cve.get("weaknesses", [])
                if weakness.get("description")
            ],
        }
