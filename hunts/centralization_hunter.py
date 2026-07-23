"""
Solidify Centralization Hunter
Hunt for centralization risks with comprehensive detection

Author: Peace Stephen (Tech Lead)
Description: Specialized hunter for centralization risks and single points of failure in smart contracts
"""

import re
import logging
import json
import hashlib
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class CentralizationPattern(Enum):
    SINGLE_OWNER = "single_owner"
    ADMIN_KEY = "admin_key"
    UPGRADEABLE = "upgradeable"
    PAUSABLE = "pausable"
    MINTABLE = "mintable"
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    LIMIT_SWITCH = "limit_switch"
    FEE_MANAGER = "fee_manager"
    ORACLE_ADMIN = "oracle_admin"
    EMERGENCY_ADMIN = "emergency_admin"
    OWNER_TRANSFER = "owner_transfer"
    BACKDOOR = "backdoor"
    RUG_PULL = "rug_pull"
    CUSTODIAL = "custodial"
    KEY_CUSTODY = "key_custody"
    CENTRALIZED_ORACLE = "centralized_oracle"
    ADMIN_PAUSE = "admin_pause"


class CentralizationSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityStatus(Enum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    FALSE_POSITIVE = "false_positive"
    PENDING = "pending"


@dataclass
class CentralizationFinding:
    pattern: CentralizationPattern
    severity: CentralizationSeverity
    function: str
    description: str
    line_number: int
    risk_vector: str
    recommendation: str
    code_snippet: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    status: VulnerabilityStatus = VulnerabilityStatus.PENDING
    affected_users: int = 0
    owner_address: str = ""


@dataclass
class RoleAnalysis:
    name: str
    address: str = ""
    permissions: List[str] = field(default_factory=list)
    is_singular: bool = True
    can_upgrade: bool = False
    can_pause: bool = False
    can_mint: bool = False
    can_burn: bool = False
    can_set_fee: bool = False
    can_whitelist: bool = False


@dataclass 
class GovernanceRisk:
    mechanism: str = ""
    risk_level: str = "unknown"
    quorum_required: float = 0.0
    voting_period: int = 0
    execution_delay: int = 0
    proposal_threshold: float = 0.0


CENTRALIZATION_PATTERNS = {
    "owner_single_point": {
        "pattern": r"(owner|admin|super)\s*=\s*([^;]{20,})",
        "severity": "critical",
        "description": "Single owner with full control",
        "cwe": "CWE-862",
        "cvss": 8.5,
        "impact": "Owner can unilaterally control all contract functions"
    },
    "admin_upgradeable": {
        "pattern": r"(upgradeTo|upgradeToAndCall|upgrade)\s*\(",
        "severity": "critical",
        "description": "Admin can upgrade contract",
        "cwe": "CWE-754",
        "cvss": 9.0,
        "impact": "Admin can change contract logic arbitrarily"
    },
    "admin_pausable": {
        "pattern": r"(pause|unpause|paused)\s*\(",
        "severity": "high",
        "description": "Admin can pause contract",
        "cwe": "CWE-862",
        "cvss": 7.5,
        "impact": "Admin can halt all transactions"
    },
    "unlimited_minting": {
        "pattern": r"(mint|mintTo)\s*\([^)]*\)",
        "severity": "critical",
        "description": "Unlimited token minting capability",
        "cwe": "CWE-770",
        "cvss": 9.2,
        "impact": "Can inflate supply arbitrarily"
    },
    "admin_set_fee": {
        "pattern": r"(setFee|updateFee|setProtocolFee)\s*\(",
        "severity": "high",
        "description": "Admin can change fees",
        "cwe": "CWE-754",
        "cvss": 7.0,
        "impact": "Fees can be increased arbitrarily"
    },
    "transfer_ownership": {
        "pattern": r"(transferOwnership|renounceOwnership)\s*\(",
        "severity": "medium",
        "description": "Ownership transfer capability exists",
        "cwe": "CWE-362",
        "cvss": 6.5,
        "impact": "Ownership can be transferred without notification"
    },
    "whitelist_admin": {
        "pattern": r"(addToWhitelist|whitelist)\s*\(",
        "severity": "high",
        "description": "Admin controls whitelist",
        "cwe": "CWE-862",
        "cvss": 7.0,
        "impact": "Admin can exclude users from protocol"
    },
    "blacklist_admin": {
        "pattern": r"(addToBlacklist|block|ban)\s*\(",
        "severity": "high",
        "description": "Admin can blacklist users",
        "cwe": "CWE-862",
        "cvss": 7.5,
        "impact": "Admin can freeze user funds"
    },
    "admin_withdraw": {
        "pattern": r"(withdraw|withdrawETH|sweep)\s*\([^)]*owner",
        "severity": "critical",
        "description": "Admin can withdraw all funds",
        "cwe": "CWE-770",
        "cvss": 9.0,
        "impact": "Complete fund control by admin"
    },
    "emergency_admin": {
        "pattern": r"(emergency|execute|emergencyCall)\s*\(",
        "severity": "critical",
        "description": "Emergency admin has elevated privileges",
        "cwe": "CWE-862",
        "cvss": 8.8,
        "impact": "Emergency functions can bypass checks"
    },
    "centralized_oracle": {
        "pattern": r"oracle\s*=\s*([^;]{20,})",
        "severity": "medium",
        "description": "Single oracle source",
        "cwe": "CWE-757",
        "cvss": 6.5,
        "impact": "Oracle failure affects entire protocol"
    },
    "fee_admin": {
        "pattern": r"(setReserveFactor|adjustLoan|adjustRate)\s*\(",
        "severity": "high",
        "description": "Admin controls protocol parameters",
        "cwe": "CWE-754",
        "cvss": 7.5,
        "impact": "Protocol parameters can be manipulated"
    },
    "rug_pull_risk": {
        "pattern": r"(selfdestruct|suicide)\s*\(",
        "severity": "critical",
        "description": "Contract can be destroyed",
        "cwe": "CWE-506",
        "cvss": 9.5,
        "impact": "Complete protocol shutdown possible"
    },
    "upgrade_without_timelock": {
        "pattern": r"upgradeTo\([^)]*\)\s*[^}]{0,50}?(?!timelock|delay|queue)",
        "severity": "critical",
        "description": "Upgrade without timelock",
        "cwe": "CWE-362",
        "cvss": 8.5,
        "impact": "Immediate upgrade without user notice"
    },
    "backdoor_function": {
        "pattern": r"(backdoor|hidden|adminOnly)\s*\(",
        "severity": "critical",
        "description": "Potential backdoor function",
        "cwe": "CWE-698",
        "cvss": 9.8,
        "impact": "Unauthorized access possible"
    },
}


ADMIN_KEYWORDS = [
    "owner",
    "admin",
    "super_admin",
    "governance",
    "manager",
    "controller",
    "operator",
    "guardian",
    "treasurer",
    "executor",
]

DANGEROUS_FUNCTIONS = [
    "upgradeTo",
    "upgradeToAndCall",
    "pause",
    "unpause",
    "mint",
    "mintTo",
    "burn",
    "burnFrom",
    "setFee",
    "setProtocolFee",
    "withdraw",
    "withdrawETH",
    "sweep",
    "execute",
    "governance",
    "kill",
    "selfdestruct",
]


@dataclass
class PermissionAnalysis:
    role_name: str = ""
    can_upgrade: bool = False
    can_pause: bool = False
    can_mint: bool = False
    can_burn: bool = False
    can_withdraw: bool = False
    can_set_fee: bool = False
    can_whitelist: bool = False
    can_blacklist: bool = False
    can_transfer_ownership: bool = False
    risk_score: float = 0.0


@dataclass
class TrustAnalysis:
    trust_level: str = "high"
    centralization_risk_score: float = 0.0
    num_admin_roles: int = 0
    has_timelock: bool = False
    has_multi_sig: bool = False
    has_governance: bool = False
    upgrade_mechanism: str = "none"


class CentralizationHunter:
    def __init__(self):
        self.findings: List[CentralizationFinding] = []
        self.roles: Dict[str, RoleAnalysis] = {}
        self.risks: List[GovernanceRisk] = []
        self.analysis_cache: Dict[str, Any] = {}
        
    def hunt(self, source_code: str, file_name: str = "") -> List[CentralizationFinding]:
        logger.info(f"Hunting for centralization risks in {file_name}")
        
        self.findings.clear()
        self._parse_roles(source_code)
        self._detect_centralization_patterns(source_code)
        self._analyze_permission_risk(source_code)
        self._check_upgrade_mechanism(source_code)
        self._assess_governance_risk(source_code)
        
        return self.findings
    
    def _parse_roles(self, source_code: str) -> None:
        lines = source_code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            for keyword in ADMIN_KEYWORDS:
                if re.search(rf"{keyword}\s*[=:]\s*", line_stripped):
                    self._register_role(line_stripped, keyword, line_num)
                    
    def _register_role(self, line: str, keyword: str, line_num: int) -> None:
        address_match = re.search(r"0x[a-fA-F0-9]{40}", line)
        
        role = RoleAnalysis(
            name=keyword,
            address=address_match.group(0) if address_match else "",
            permissions=[]
        )
        
        self.roles[keyword] = role
        
    def _detect_centralization_patterns(
        self, source_code: str
    ) -> None:
        lines = source_code.split('\n')
        
        for pattern_name, pattern_info in CENTRALIZATION_PATTERNS.items():
            pattern = pattern_info["pattern"]
            severity_str = pattern_info["severity"]
            description = pattern_info["description"]
            cwe = pattern_info["cwe"]
            cvss = pattern_info["cvss"]
            impact = pattern_info["impact"]
            
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    severity = self._parse_severity(severity_str)
                    func_name = self._extract_function_name(line, lines, line_num)
                    
                    finding = CentralizationFinding(
                        pattern=self._get_pattern_type(pattern_name),
                        severity=severity,
                        function=func_name,
                        description=description,
                        line_number=line_num,
                        risk_vector=impact,
                        recommendation=self._generate_recommendation(pattern_name),
                        code_snippet=line.strip(),
                        cvss_score=cvss,
                        cwe_id=cwe,
                        status=VulnerabilityStatus.CONFIRMED
                    )
                    self.findings.append(finding)
                    
    def _analyze_permission_risk(self, source_code: str) -> None:
        permission_analysis = PermissionAnalysis(
            role_name="admin",
            risk_score=0.0
        )
        
        if "upgradeTo" in source_code:
            permission_analysis.can_upgrade = True
            permission_analysis.risk_score += 3.0
            
        if "pause" in source_code:
            permission_analysis.can_pause = True
            permission_analysis.risk_score += 2.5
            
        if "mint" in source_code:
            permission_analysis.can_mint = True
            permission_analysis.risk_score += 3.5
            
        if "setFee" in source_code:
            permission_analysis.can_set_fee = True
            permission_analysis.risk_score += 2.0
            
        if permission_analysis.risk_score > 8.0:
            finding = CentralizationFinding(
                pattern=CentralizationPattern.SINGLE_OWNER,
                severity=CentralizationSeverity.CRITICAL,
                function="admin",
                description="High permission concentration in admin role",
                line_number=0,
                risk_vector="Single point of failure",
                recommendation="Implement multi-signature governance or timelock",
                cvss_score=min(10.0, permission_analysis.risk_score),
                cwe_id="CWE-862",
                status=VulnerabilityStatus.CONFIRMED
            )
            self.findings.append(finding)
            
    def _check_upgrade_mechanism(self, source_code: str) -> None:
        has_proxy = bool(
            re.search(r"(Proxy|Upgradeable|delegateCall)", source_code)
        )
        has_timelock = bool(
            re.search(r"(Timelock|TimelockController|delay)", source_code)
        )
        has_guardian = bool(
            re.search(r"(Guardian|MultiSig)", source_code)
        )
        
        if has_proxy and not has_timelock:
            for line_num, line in enumerate(source_code.split('\n'), 1):
                if "upgradeTo" in line:
                    finding = CentralizationFinding(
                        pattern=CentralizationPattern.UPGRADEABLE,
                        severity=CentralizationSeverity.CRITICAL,
                        function="upgradeTo",
                        description="Upgradeable contract without timelock",
                        line_number=line_num,
                        risk_vector="Immediate upgrade possible",
                        recommendation="Add timelock delay for upgrades",
                        cvss_score=8.5,
                        cwe_id="CWE-754",
                        status=VulnerabilityStatus.CONFIRMED
                    )
                    self.findings.append(finding)
                    break
                    
        if has_proxy and not has_guardian:
            finding = CentralizationFinding(
                pattern=CentralizationPattern.ADMIN_KEY,
                severity=CentralizationSeverity.HIGH,
                function="proxy",
                description="Upgradeable proxy without multi-sig",
                line_number=0,
                risk_vector="Single admin controls upgrades",
                recommendation="Implement multi-signature for upgrades",
                cvss_score=7.5,
                cwe_id="CWE-862",
                status=VulnerabilityStatus.CONFIRMED
            )
            self.findings.append(finding)
            
    def _assess_governance_risk(self, source_code: str) -> None:
        if re.search(r"timelock", source_code, re.IGNORECASE):
            risk = GovernanceRisk(
                mechanism="timelock",
                risk_level="low",
                execution_delay=172800
            )
            self.risks.append(risk)
            
        if re.search(r"multi.?sig|gnosis", source_code, re.IGNORECASE):
            risk = GovernanceRisk(
                mechanism="multi-sig",
                risk_level="low",
                quorum_required=0.51
            )
            self.risks.append(risk)
            
        if re.search(r"D A O|governance", source_code):
            risk = GovernanceRisk(
                mechanism="governance",
                risk_level="medium",
                quorum_required=0.04,
                voting_period=259200,
                execution_delay=172800
            )
            self.risks.append(risk)
            
    def _extract_function_name(
        self, line: str, lines: List[str], line_num: int
    ) -> str:
        search_start = max(0, line_num - 10)
        search_end = min(len(lines), line_num + 5)
        
        for i in range(search_start, search_end):
            func_match = re.search(r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)", lines[i])
            if func_match:
                return func_match.group(1)
                
        return "unknown"
        
    def _parse_severity(self, severity_str: str) -> CentralizationSeverity:
        mapping = {
            "critical": CentralizationSeverity.CRITICAL,
            "high": CentralizationSeverity.HIGH,
            "medium": CentralizationSeverity.MEDIUM,
            "low": CentralizationSeverity.LOW,
            "info": CentralizationSeverity.INFO,
        }
        return mapping.get(severity_str.lower(), CentralizationSeverity.MEDIUM)
        
    def _get_pattern_type(self, pattern_name: str) -> CentralizationPattern:
        mapping = {
            "owner_single_point": CentralizationPattern.SINGLE_OWNER,
            "admin_upgradeable": CentralizationPattern.UPGRADEABLE,
            "admin_pausable": CentralizationPattern.PAUSABLE,
            "unlimited_minting": CentralizationPattern.MINTABLE,
            "admin_set_fee": CentralizationPattern.FEE_MANAGER,
            "transfer_ownership": CentralizationPattern.OWNER_TRANSFER,
            "whitelist_admin": CentralizationPattern.WHITELIST,
            "blacklist_admin": CentralizationPattern.BLACKLIST,
            "admin_withdraw": CentralizationPattern.CUSTODIAL,
            "emergency_admin": CentralizationPattern.EMERGENCY_ADMIN,
            "centralized_oracle": CentralizationPattern.CENTRALIZED_ORACLE,
            "fee_admin": CentralizationPattern.FEE_MANAGER,
            "rug_pull_risk": CentralizationPattern.RUG_PULL,
            "upgrade_without_timelock": CentralizationPattern.UPGRADEABLE,
            "backdoor_function": CentralizationPattern.BACKDOOR,
        }
        return mapping.get(pattern_name, CentralizationPattern.SINGLE_OWNER)
        
    def _generate_recommendation(self, pattern_name: str) -> str:
        recommendations = {
            "owner_single_point": (
                "Implement multi-signature wallet or DAO governance"
            ),
            "admin_upgradeable": (
                "Add timelock delay for upgrades, require multi-sig approval"
            ),
            "admin_pausable": (
                "Add timelock for pause/unpause, consider permanent unpause"
            ),
            "unlimited_minting": (
                "Implement maximum supply cap, use multi-sig for minting"
            ),
            "admin_set_fee": (
                "Make fees adjustable only through governance"
            ),
            "transfer_ownership": (
                "Add delay before ownership transfer takes effect"
            ),
            "whitelist_admin": (
                "Make whitelisting subject to governance vote"
            ),
            "blacklist_admin": (
                "Implement due process for blacklisting"
            ),
            "admin_withdraw": (
                "Add withdrawal limits and multi-sig requirements"
            ),
            "emergency_admin": (
                "Limit emergency powers with timelock"
            ),
            "centralized_oracle": (
                "Use decentralized oracle networks (Chainlink, Band)"
            ),
            "fee_admin": (
                "Use governance-controlled rates with caps"
            ),
            "rug_pull_risk": (
                "Remove selfdestruct or add governance controls"
            ),
            "upgrade_without_timelock": (
                "Implement timelock controller for upgrades"
            ),
            "backdoor_function": (
                "Remove hidden functions, audit thoroughly"
            ),
        }
        return recommendations.get(pattern_name, "Review admin privileges.")
        
    def analyze_trust_score(self) -> TrustAnalysis:
        critical_count = len([f for f in self.findings 
                          if f.severity == CentralizationSeverity.CRITICAL])
        high_count = len([f for f in self.findings 
                        if f.severity == CentralizationSeverity.HIGH])
        
        risk_score = critical_count * 3.0 + high_count * 1.5
        
        trust = TrustAnalysis(
            trust_level="low" if risk_score > 10 else "medium" if risk_score > 5 else "high",
            centralization_risk_score=risk_score,
            num_admin_roles=len(self.roles),
            has_timelock=any(r.execution_delay > 0 for r in self.risks),
            has_multi_sig=any(r.quorum_required > 0 for r in self.risks)
        )
        
        return trust
        
    def generate_report(self) -> Dict[str, Any]:
        severity_counts = Counter(f.severity.value for f in self.findings)
        
        trust_analysis = self.analyze_trust_score()
        
        return {
            "hunter": "Centralization Hunter",
            "total_findings": len(self.findings),
            "severity_breakdown": dict(severity_counts),
            "findings": [
                {
                    "pattern": f.pattern.value,
                    "severity": f.severity.value,
                    "function": f.function,
                    "description": f.description,
                    "line_number": f.line_number,
                    "recommendation": f.recommendation,
                    "cvss_score": f.cvss_score,
                    "cwe_id": f.cwe_id,
                }
                for f in self.findings
            ],
            "trust_analysis": {
                "trust_level": trust_analysis.trust_level,
                "centralization_risk_score": trust_analysis.centralization_risk_score,
                "num_admin_roles": trust_analysis.num_admin_roles,
                "has_timelock": trust_analysis.has_timelock,
                "has_multi_sig": trust_analysis.has_multi_sig,
            },
            "governance_risks": [
                {
                    "mechanism": r.mechanism,
                    "risk_level": r.risk_level,
                    "quorum_required": r.quorum_required,
                    "voting_period": r.voting_period,
                    "execution_delay": r.execution_delay,
                }
                for r in self.risks
            ],
            "roles": [
                {
                    "name": role.name,
                    "address": role.address,
                    "permissions": role.permissions,
                }
                for role in self.roles.values()
            ],
        }
        
    def get_critical_findings(self) -> List[CentralizationFinding]:
        return [f for f in self.findings if f.severity == CentralizationSeverity.CRITICAL]
        
    def get_high_findings(self) -> List[CentralizationFinding]:
        return [f for f in self.findings if f.severity == CentralizationSeverity.HIGH]
        
    def export_findings_json(self, output_path: str) -> None:
        report = self.generate_report()
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"Exported findings to {output_path}")
        
    def export_findings_sarif(self, output_path: str) -> None:
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Solidify Centralization Hunter",
                            "rules": [
                                {
                                    "id": f.cwe_id or f.pattern.value,
                                    "name": f.pattern.value,
                                    "shortDescription": {
                                        "text": f.description
                                    },
                                    "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe_id.replace('CWE-', '')}.html"
                                }
                                for f in self.findings
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.cwe_id or f.pattern.value,
                            "level": "error" if f.severity == CentralizationSeverity.CRITICAL else "warning",
                            "message": {
                                "text": f.description
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": f.function
                                        }
                                    }
                                }
                            ]
                        }
                        for f in self.findings
                    ]
                }
            ]
        }
        
        with open(output_path, 'w') as f:
            json.dump(sarif, f, indent=2)
            
        logger.info(f"Exported SARIF results to {output_path}")