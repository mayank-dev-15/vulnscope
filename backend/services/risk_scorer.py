"""Risk Scoring Service"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class RiskScorer:
    """
    Custom risk scoring engine that combines CVSS base scores with
    environmental factors like exploit availability and age.
    """

    # Weight factors for risk calculation
    CVSS_WEIGHT = 0.5
    EXPLOIT_WEIGHT = 0.3
    AGE_WEIGHT = 0.2

    def calculate(self, cve: Dict[str, Any]) -> float:
        """
        Calculate a composite risk score (0-10) for a CVE.

        Factors:
        - CVSS base score (50%)
        - Exploit availability (30%)
        - CVE age/recency (20%)

        Args:
            cve: CVE data dictionary

        Returns:
            Risk score from 0.0 to 10.0
        """
        try:
            cvss_score = self._cvss_component(cve)
            exploit_score = self._exploit_component(cve)
            age_score = self._age_component(cve)

            composite = (
                cvss_score * self.CVSS_WEIGHT
                + exploit_score * self.EXPLOIT_WEIGHT
                + age_score * self.AGE_WEIGHT
            )

            return round(min(max(composite, 0.0), 10.0), 2)

        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return 0.0

    @staticmethod
    def _cvss_component(cve: Dict[str, Any]) -> float:
        """Normalized CVSS score (already 0-10)."""
        return float(cve.get("cvss_score", 0.0))

    @staticmethod
    def _exploit_component(cve: Dict[str, Any]) -> float:
        """
        Score based on exploit availability.
        More available exploits = higher risk.
        """
        exploits = cve.get("exploits", [])
        if not exploits:
            return 2.0  # Base score: no known exploits

        score = 5.0  # At least one exploit exists

        # Bonus for verified exploits
        verified = sum(1 for e in exploits if e.get("verified", False))
        score += min(verified * 1.5, 3.0)

        # Bonus for multiple exploit sources
        score += min(len(exploits) * 0.5, 2.0)

        return min(score, 10.0)

    @staticmethod
    def _age_component(cve: Dict[str, Any]) -> float:
        """
        Score based on CVE recency.
        Newer CVEs get higher risk scores (more likely to be actively exploited).
        """
        from datetime import datetime

        published = cve.get("published_date", "")
        if not published:
            return 5.0

        try:
            pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
            days_old = (datetime.utcnow() - pub_date.replace(tzinfo=None)).days

            if days_old <= 7:
                return 10.0  # Very recent - highest risk
            elif days_old <= 30:
                return 8.0
            elif days_old <= 90:
                return 6.0
            elif days_old <= 180:
                return 4.0
            elif days_old <= 365:
                return 2.0
            else:
                return 1.0  # Old CVE - lower risk
        except (ValueError, TypeError):
            return 5.0
