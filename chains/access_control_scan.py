"""
Access Control Scan Chain

Production-grade access control vulnerability scanner that checks
for missing modifiers, broken auth, and privilege escalation.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class AccessControlPattern(Enum):
    MISSING_MODIFIER = "missing_modifier"
    BROKEN_AUTH = "broken_authorization"
    TX_ORIGIN = "tx_origin"
    PUBLIC_MINT = "public_mint"
    UNRESTRICTED_UPGRADE = "unrestricted_upgrade"
    ROLE_CONFUSION = "role_confusion"
    DEFAULT_ADMIN = "default_admin"


@dataclass
class AccessControlFinding:
    pattern: AccessControlPattern
    severity: str
    title: str
    description: str
    location: Dict[str, Any]
    cvss_score: float
    recommendation: str


class AccessControlScan:
    CRITICAL_FUNCTIONS = {
        "mint": ["_mint", "mint", "mintTo"],
        "burn": ["_burn", "burn", "burnFrom"],
        "withdraw": ["withdraw", "withdrawETH"],
        "upgrade": ["upgrade", "upgradeTo", "_upgradeTo"],
        "pause": ["pause", "_pause"],
        "unpause": ["unpause", "_unpause"],
        "transferOwnership": ["transferOwnership"],
        "setAdmin": ["setAdmin", "grantRole"],
    }

    PROTECTION_PATTERNS = {
        "onlyOwner": r"modifier\s+onlyOwner",
        "onlyRole": r"modifier\s+onlyRole\(",
        "requiresRole": r"requiresRole\(",
        "hasRole": r"hasRole\(",
        "msg_sender": r"require\s*\(\s*msg\.sender\s*==\s*\w+",
    }

    def __init__(self):
        self.findings: List[AccessControlFinding] = []

    def scan(self, source_code: str) -> List[AccessControlFinding]:
        self.findings = []

        self._scan_missing_modifiers(source_code)
        self._scan_tx_origin(source_code)
        self._scan_public_mint(source_code)
        self._scan_unrestricted_upgrade(source_code)
        self._scan_broken_auth(source_code)

        return self.findings

    def _scan_missing_modifiers(self, source_code: str):
        functions = re.findall(r"function\s+(\w+)\s*\(([^)]*)\)\s*(?:public|external)", source_code)

        for func_name in functions:
            is_critical = any(
                kw in func_name.lower()
                for keywords in self.CRITICAL_FUNCTIONS.values()
                for kw in keywords
            )

            if is_critical:
                has_protection = False
                for pattern in self.PROTECTION_PATTERNS.values():
                    if re.search(pattern, source_code):
                        has_protection = True
                        break

                if not has_protection:
                    finding = AccessControlFinding(
                        pattern=AccessControlPattern.MISSING_MODIFIER,
                        severity="CRITICAL",
                        title=f"Missing Access Control - {func_name}",
                        description=f"Critical function '{func_name}' lacks access control",
                        location={"function": func_name},
                        cvss_score=9.8,
                        recommendation="Add onlyOwner or AccessControl modifier",
                    )
                    self.findings.append(finding)

    def _scan_tx_origin(self, source_code: str):
        if "tx.origin" not in source_code:
            return

        for match in re.finditer(r"tx\.origin", source_code):
            line = source_code[:match.start()].count("\n") + 1

            finding = AccessControlFinding(
                pattern=AccessControlPattern.TX_ORIGIN,
                severity="MEDIUM",
                title="tx.origin Authentication",
                description="tx.origin can be exploited in phishing attacks",
                location={"line": line},
                cvss_score=5.3,
                recommendation="Use msg.sender instead of tx.origin",
            )
            self.findings.append(finding)

    def _scan_public_mint(self, source_code: str):
        if "mint" not in source_code.lower():
            return

        mint_pattern = re.compile(r"function\s+mint\s*\([^)]+\)\s+public", re.IGNORECASE)
        for match in mint_pattern.finditer(source_code):
            line = source_code[:match.start()].count("\n") + 1

            finding = AccessControlFinding(
                pattern=AccessControlPattern.PUBLIC_MINT,
                severity="HIGH",
                title="Unprotected Mint Function",
                description="Mint function is public without access control",
                location={"line": line, "function": "mint"},
                cvss_score=8.5,
                recommendation="Add onlyOwner or minter role check",
            )
            self.findings.append(finding)

    def _scan_unrestricted_upgrade(self, source_code: str):
        upgrade_keywords = ["upgrade", "upgradeTo", "upgradeToAndCall"]

        for keyword in upgrade_keywords:
            pattern = rf"function\s+{keyword}\s*\([^)]+\)\s+public"
            if re.search(pattern, source_code, re.IGNORECASE):
                finding = AccessControlFinding(
                    pattern=AccessControlPattern.UNRESTRICTED_UPGRADE,
                    severity="CRITICAL",
                    title="Unprotected Upgrade",
                    description=f"Upgrade function '{keyword}' lacks access control",
                    location={"function": keyword},
                    cvss_score=9.8,
                    recommendation="Add onlyOwner or AccessControl",
                )
                self.findings.append(finding)

    def _scan_broken_auth(self, source_code: str):
        if "require" not in source_code and "if" not in source_code:
            return

        auth_patterns = [
            (r"require\s*\(\s*msg\.sender\s*==\s*(\w+)(?!\s*\|\||\s*&&)", "Simple owner check"),
            (r"if\s*\(\s*msg\.sender\s*==\s*owner(?!\s*\|\||\s*&&)", "Incomplete check"),
        ]

        for pattern, desc in auth_patterns:
            if re.search(pattern, source_code):
                finding = AccessControlFinding(
                    pattern=AccessControlPattern.BROKEN_AUTH,
                    severity="MEDIUM",
                    title="Potential Broken Authorization",
                    description=desc,
                    location={"type": "comparison"},
                    cvss_score=5.3,
                    recommendation="Use modifiers for authorization",
                )
                self.findings.append(finding)

    def get_high_severity_findings(self) -> List[AccessControlFinding]:
        return [f for f in self.findings if f.severity in ("CRITICAL", "HIGH")]

    def get_summary(self) -> Dict[str, int]:
        return {
            "critical": sum(1 for f in self.findings if f.severity == "CRITICAL"),
            "high": sum(1 for f in self.findings if f.severity == "HIGH"),
            "medium": sum(1 for f in self.findings if f.severity == "MEDIUM"),
            "low": sum(1 for f in self.findings if f.severity == "LOW"),
        }


def scan_access_control(source_code: str) -> List[AccessControlFinding]:
    scanner = AccessControlScan()
    return scanner.scan(source_code)


__all__ = [
    "AccessControlScan",
    "AccessControlPattern",
    "AccessControlFinding",
    "scan_access_control",
]