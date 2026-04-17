"""
Solidify CVSS Scorer
CVSS 3.1 scoring for vulnerability severity

Author: Peace Stephen (Tech Lead)
Description: CVSS scoring calculator
"""

import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class SeverityLevel(Enum):
    """Severity levels based on CVSS score"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CVSSMetrics:
    """CVSS 3.1 base metrics"""
    attack_vector: str = "N"  # Network, Adjacent, Local, Physical
    attack_complexity: str = "L"  # Low, High
    privileges_required: str = "N"  # None, Low, High
    user_interaction: str = "N"  # None, Required
    scope: str = "U"  # Unchanged, Changed
    confidentiality: str = "H"  # None, Low, High
    integrity: str = "H"  # None, Low, High
    availability: str = "H"  # None, Low, High


# ============================================================================
# CVSS Calculator
# ============================================================================

class CVSSScorer:
    """
    Calculate CVSS 3.1 scores for vulnerabilities
    
    Features:
    - Base score calculation
    - Severity classification
    - Risk scoring normalization
    - Smart contract specific adjustments
    """
    
    # CVSS 3.1 weight vectors
    WEIGHTS = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.50}
        },
        "UI": {"N": 0.85, "R": 0.62},
        "S": {"U": 6.42, "C": 7.52},
        "C": {"N": 0.0, "L": 0.22, "H": 0.56},
        "I": {"N": 0.0, "L": 0.22, "H": 0.56},
        "A": {"N": 0.0, "L": 0.22, "H": 0.56}
    }
    
    # Severity thresholds
    SEVERITY_THRESHOLDS = {
        (9.0, 10.0): SeverityLevel.CRITICAL,
        (7.0, 8.9): SeverityLevel.HIGH,
        (4.0, 6.9): SeverityLevel.MEDIUM,
        (0.1, 3.9): SeverityLevel.LOW,
        (0.0, 0.0): SeverityLevel.INFO
    }
    
    # Smart contract vulnerability severity overrides
    VULN_SEVERITY_OVERRIDES = {
        "reentrancy": 9.1,
        "unprotected-selfdestruct": 9.0,
        "access-control": 8.5,
        "integer-overflow": 8.0,
        "unchecked-call": 7.5,
        "front-running": 6.5,
        "timestamp-dependence": 5.0,
        "tx-origin": 5.5,
        "dos": 6.0,
    }
    
    def __init__(self):
        """Initialize CVSS scorer"""
        self.default_metrics = CVSSMetrics()
        logger.info("✅ CVSS scorer initialized")
    
    def calculate_score(self, vulnerability: Dict[str, Any]) -> float:
        """
        Calculate CVSS score for a vulnerability
        
        Args:
            vulnerability: Vulnerability dictionary
        
        Returns:
            CVSS score (0.0 - 10.0)
        """
        vuln_name = vulnerability.get("name", "").lower()
        
        # Check for smart contract specific overrides
        for key, score in self.VULN_SEVERITY_OVERRIDES.items():
            if key in vuln_name:
                return score
        
        # Use provided CVSS score if available
        if "cvss_score" in vulnerability:
            return float(vulnerability["cvss_score"])
        
        # Calculate from metrics
        try:
            metrics = self._extract_metrics(vulnerability)
            return self._calculate_base_score(metrics)
        except Exception as e:
            logger.warning(f"CVSS calculation failed, using default: {str(e)}")
            return 5.0
    
    def _extract_metrics(self, vulnerability: Dict[str, Any]) -> CVSSMetrics:
        """Extract CVSS metrics from vulnerability data"""
        metrics = CVSSMetrics()
        
        # Map common fields
        if "attack_vector" in vulnerability:
            metrics.attack_vector = vulnerability["attack_vector"][0].upper()
        if "attack_complexity" in vulnerability:
            metrics.attack_complexity = vulnerability["attack_complexity"][0].upper()
        if "privileges_required" in vulnerability:
            metrics.privileges_required = vulnerability["privileges_required"][0].upper()
        if "user_interaction" in vulnerability:
            metrics.user_interaction = vulnerability["user_interaction"][0].upper()
        if "scope" in vulnerability:
            metrics.scope = vulnerability["scope"][0].upper()
        
        return metrics
    
    def _calculate_base_score(self, metrics: CVSSMetrics) -> float:
        """Calculate CVSS base score"""
        try:
            # ISS (Impact Sub Score)
            iss = 1 - (
                (1 - self._impact(metrics.confidentiality)) *
                (1 - self._impact(metrics.integrity)) *
                (1 - self._impact(metrics.availability))
            )
            
            # Impact
            impact = self._impact_factor(metrics.scope, iss)
            
            # Exploitability
            exploitability = (
                self.WEIGHTS["AV"][metrics.attack_vector] *
                self.WEIGHTS["AC"][metrics.attack_complexity] *
                self.WEIGHTS["PR"][metrics.scope][metrics.privileges_required] *
                self.WEIGHTS["UI"][metrics.user_interaction]
            )
            
            # Base score
            if impact <= 0:
                base_score = 0.0
            elif metrics.scope == "U":
                base_score = min(impact + exploitability, 10.0)
            else:
                base_score = min(1.08 * (impact + exploitability), 10.0)
            
            return round(base_score, 1)
            
        except Exception as e:
            logger.warning(f"Score calculation failed: {str(e)}")
            return 5.0
    
    def _impact(self, metric: str) -> float:
        """Get impact value for a metric"""
        return self.WEIGHTS.get("C", {}).get(metric, 0.0)
    
    def _impact_factor(self, scope: str, iss: float) -> float:
        """Calculate impact factor"""
        if scope == "U":
            return 6.42 * iss
        else:
            return 7.52 * iss - 0.029
    
    def get_severity(self, cvss_score: float) -> str:
        """
        Get severity string from CVSS score
        
        Args:
            cvss_score: CVSS score (0.0 - 10.0)
        
        Returns:
            Severity string
        """
        for (low, high), severity in self.SEVERITY_THRESHOLDS.items():
            if low <= cvss_score <= high:
                return severity.value
        return SeverityLevel.INFO.value
    
    def get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            "CRITICAL": "#ff3333",
            "HIGH": "#ff9900",
            "MEDIUM": "#ffcc00",
            "LOW": "#4dba4d",
            "INFO": "#6666cc"
        }
        return colors.get(severity.upper(), "#666666")
    
    def calculate_risk_score(
        self,
        vulnerability: Dict[str, Any],
        normalize: bool = True
    ) -> float:
        """
        Calculate normalized risk score
        
        Args:
            vulnerability: Vulnerability dictionary
            normalize: Whether to normalize to 0-10
        
        Returns:
            Risk score
        """
        cvss = self.calculate_score(vulnerability)
        
        if normalize:
            return cvss
        
        # Convert CVSS to risk percentage
        return (cvss / 10.0) * 100
    
    def get_severity_badge(self, severity: str) -> Dict[str, str]:
        """
        Get severity badge data
        
        Args:
            severity: Severity string
        
        Returns:
            Badge data with color, icon, label
        """
        badges = {
            "CRITICAL": {
                "color": "#ff3333",
                "icon": "🔴",
                "label": "CRITICAL",
                "description": "Immediate action required"
            },
            "HIGH": {
                "color": "#ff9900",
                "icon": "🟠",
                "label": "HIGH",
                "description": "High priority fixes needed"
            },
            "MEDIUM": {
                "color": "#ffcc00",
                "icon": "🟡",
                "label": "MEDIUM",
                "description": "Should be addressed"
            },
            "LOW": {
                "color": "#4dba4d",
                "icon": "🟢",
                "label": "LOW",
                "description": "Minor improvements"
            },
            "INFO": {
                "color": "#6666cc",
                "icon": "🔵",
                "label": "INFO",
                "description": "Informational"
            }
        }
        
        return badges.get(severity.upper(), badges["INFO"])
    
    def score_summary(self, vulnerabilities: list) -> Dict[str, Any]:
        """
        Get summary of scores for multiple vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
        
        Returns:
            Summary with counts and scores
        """
        summary = {
            "total": len(vulnerabilities),
            "by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0
            },
            "average_score": 0.0,
            "max_score": 0.0,
            "risk_distribution": {}
        }
        
        total_score = 0.0
        
        for vuln in vulnerabilities:
            score = self.calculate_score(vuln)
            severity = self.get_severity(score)
            
            summary["by_severity"][severity] += 1
            total_score += score
            
            if score > summary["max_score"]:
                summary["max_score"] = score
        
        if vulnerabilities:
            summary["average_score"] = round(total_score / len(vulnerabilities), 1)
        
        return summary


# ============================================================================
# Factory Functions
# ============================================================================

def create_cvss_scorer() -> CVSSScorer:
    """Create CVSS scorer instance"""
    return CVSSScorer()


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    scorer = CVSSScorer()
    
    # Test vulnerabilities
    test_vulns = [
        {"name": "Reentrancy", "cvss_score": 9.1},
        {"name": "Access Control", "cvss_score": 8.5},
        {"name": "Integer Overflow", "cvss_score": 8.0},
        {"name": "Front Running", "cvss_score": 6.5},
        {"name": "Timestamp Dependence", "cvss_score": 5.0},
    ]
    
    for vuln in test_vulns:
        score = scorer.calculate_score(vuln)
        severity = scorer.get_severity(score)
        badge = scorer.get_severity_badge(severity)
        print(f"{badge['icon']} {vuln['name']}: {score} ({severity})")
    
    # Test summary
    summary = scorer.score_summary(test_vulns)
    print(f"\nSummary: {summary}")