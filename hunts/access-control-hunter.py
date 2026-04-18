"""
Solidify Access Control Hunter
Hunt for access control vulnerabilities with comprehensive patterns
Author: Peace Stephen (Tech Lead)
Description: Specialized hunter for access control vulnerabilities in smart contracts
"""

import re
import logging
import hashlib
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict, OrderedDict

logger = logging.getLogger(__name__)


class AccessControlPattern(Enum):
    MISSING_MODIFIER = "missing_modifier"
    OWNABLE = "ownable"
    ROLE_BASED = "role_based"
    TIMELOCK = "timelock"
    MULTISIG = "multisig"
    PROXY_ADMIN = "proxy_admin"
    UPGRADEABILITY = "upgradeability"
    PAUSABLE = "pausable"
    INITIALIZABLE = "initializable"
    GUARDIAN = "guardian"
    KEEPER = "keeper"
    GOVERNOR = "governor"


class AccessControlSeverity(Enum):
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
class AccessControlFinding:
    pattern: AccessControlPattern
    severity: AccessControlSeverity
    function: str
    description: str
    line_number: int
    expected_modifier: str
    recommendation: str
    cvss_score: float = 0.0
    cwe_id: str = ""
    status: VulnerabilityStatus = VulnerabilityStatus.PENDING
    impact: str = ""
    bypass_complexity: str = "simple"


@dataclass
class RoleAnalysis:
    role_name: str
    role_holder: str
    permissions: List[str] = field(default_factory=list)
    has_admin: bool = False
    is_revocable: bool = False


@dataclass
class ModifierAnalysis:
    modifier_name: str
    associated_functions: List[str] = field(default_factory=list)
    checks_ownership: bool = False
    checks_role: bool = False
    is_pausable: bool = False


ACCESS_PATTERNS = {
    "missing_owner": {
        "pattern": r"function\s+(?!constructor)(?:update|delegate|set|withdraw|mint|burn|pause|unpause|upgrade|initialize|transferOwnership|claim|grant|revoke)[^{]*\{[^}]*(?!onlyOwner|onlyAdmin|onlyGovernance|whenNotPaused)",
        "severity": "critical",
        "description": "Critical function missing onlyOwner access control modifier",
        "modifier": "onlyOwner",
        "cvss": 9.1,
        "cwe": "CWE-284",
        "impact": "Complete protocol compromise possible",
        "bypass": "No special conditions needed"
    },
    "missing_only": {
        "pattern": r"function\s+(transfer|set|mint|burn|grant|revoke)[^{]*public\s*(?:payable)?\s*(?!\s*only|when)",
        "severity": "critical",
        "description": "Sensitive function missing only* modifier - anyone can call",
        "modifier": "onlyOwner/onlyRole",
        "cvss": 9.8,
        "cwe": "CWE-284",
        "impact": "Unauthorized control over assets",
        "bypass": "Direct call without special conditions"
    },
    "anyone_can_withdraw": {
        "pattern": r"function\s+withdraw[^{]*\{[^}]*(?!onlyOwner|onlyAuth|onlyApproved)",
        "severity": "critical",
        "description": "Withdraw function without access control - drains all contract funds",
        "modifier": "onlyOwner",
        "cvss": 9.8,
        "cwe": "CWE-284",
        "impact": "Complete drain of contract funds",
        "bypass": "Simply call withdraw()"
    },
    "anyone_can_mint": {
        "pattern": r"function\s+mint[^{]*\{[^}]*(?!onlyMinter|only MINTER|hasRole\(|require\(msg\.sender",
        "severity": "critical",
        "description": "Unlimited token minting without access control",
        "modifier": "onlyMinter",
        "cvss": 9.8,
        "cwe": "CWE-284",
        "impact": "Unlimited inflation of token supply",
        "bypass": "Call mint() with any amount"
    },
    "anyone_can_pause": {
        "pattern": r"function\s+pause[^{]*\{?\s*(?!whenNotPaused|onlyPauser|require\(.*paused)",
        "severity": "critical",
        "description": "Protocol can be paused by anyone - complete DoS",
        "modifier": "onlyPauser",
        "cvss": 9.5,
        "cwe": "CWE-284",
        "impact": "Denial of service for entire protocol",
        "bypass": "Call pause() function"
    },
    "unprotected_upgrade": {
        "pattern": r"function\s+upgrade[^{]*\{?\s*(?!onlyProxyAdmin|onlyOwner|onlyGovernance)",
        "severity": "critical",
        "description": "Proxy upgrade without strict access control - complete compromise",
        "modifier": "onlyProxyAdmin",
        "cvss": 9.8,
        "cwe": "CWE-284",
        "impact": "Arbitrary code execution via proxy",
        "bypass": "Upgrade contract to malicious implementation"
    },
    "initialize_anyone": {
        "pattern": r"function\s+initialize[^{]*\{?\s*(?!initializer|onlyInitializing|require\(.*initialized)",
        "severity": "critical",
        "description": "Initializable contract callable by anyone after initialization",
        "modifier": "initializer",
        "cvss": 9.5,
        "cwe": "CWE-284",
        "impact": "Can re-initialize with malicious settings",
        "bypass": "Call initialize() directly"
    },
    "unprotected_set_fee": {
        "pattern": r"function\s+setFee[^{]*\{?\s*(?!onlyOwner|onlyFeeManager|require\(.*owner)",
        "severity": "high",
        "description": "Fee setter without access control",
        "modifier": "onlyOwner",
        "cvss": 8.5,
        "cwe": "CWE-284",
        "impact": "Fees can be set arbitrarily",
        "bypass": "Set fee to 100%"
    },
    "transfer_admin_anyone": {
        "pattern": r"function\s+transferAdmin|setPendingAdmin[^{]*\{?\s*(?!onlyOwner|onlyAdmin",
        "severity": "critical",
        "description": "Admin role transfer without restrictions",
        "modifier": "onlyOwner",
        "cvss": 9.5,
        "cwe": "CWE-284",
        "impact": "Can become admin and take full control",
        "bypass": "Call transferAdmin()"
    },
    "default_access": {
        "pattern": r"function\s+\w+\s*\([^)]*\)\s*public\s*(?:payable)?\s*(?:returns)?\s*[^;]*\{?\s*(?!require\(msg\.sender\s*(==|==|!=)\s*(owner|admin)",
        "severity": "high",
        "description": "Public function missing sender verification",
        "modifier": "require(msg.sender == owner)",
        "cvss": 7.5,
        "cwe": "CWE-862",
        "impact": "Anyone can call sensitive functions",
        "bypass": "Direct function call"
    },
    "tx_origin": {
        "pattern": r"tx\.origin\s*==\s*(?!msg\.sender)",
        "severity": "medium",
        "description": "Using tx.origin for authorization - vulnerable to man-in-the-middle",
        "modifier": "Use msg.sender instead",
        "cvss": 5.3,
        "cwe": "CWE-478",
        "impact": "Can be bypassed in certain delegatecall scenarios",
        "bypass": "Deploy malicious contract that calls target"
    },
    "missing_zero_check": {
        "pattern": r"(transfer|send|call)\s*\(\s*address\s*\(0\s*\)",
        "severity": "medium",
        "description": "Missing zero address validation",
        "modifier": "require(addr != address(0))",
        "cvss": 4.0,
        "cwe": "CWE-123",
        "impact": "Can accidentally burn funds or disable functionality",
        "bypass": "Call with zero address"
    },
    "access_anyone_public": {
        "pattern": r"(constructor|init)\s*\([^)]*\)\s*public\s*\{[^}]*\{?\s*(?!Ownable|AccessControl)",
        "severity": "high",
        "description": "Public initializer without proper access control",
        "modifier": "initializer",
        "cvss": 8.0,
        "cwe": "CWE-284",
        "impact": "Can be called multiple times",
        "bypass": "Ensure one-time initialization"
    },
    "unlimited_approval": {
        "pattern": r"approve.*\(.*uint256\(-1\)\)",
        "severity": "medium",
        "description": "Unlimited token approval given",
        "modifier": "Check approval amounts",
        "cvss": 5.3,
        "cwe": "CWE-1289",
        "impact": "Spender can drain full balance",
        "bypass": "Set max approval"
    },
    "role_confusion": {
        "pattern": r"hasRole\([^)]*\).*(?!\s*||.*hasRole)",
        "severity": "medium",
        "description": "Role check may not work as expected with OR logic",
        "modifier": "Use correct role AND/OR logic",
        "cvss": 5.3,
        "cwe": "CWE-1004",
        "impact": "Wrong users may get access",
        "bypass": "Test role combinations"
    },
    "delegatecall_user": {
        "pattern": r"delegatecall.*\(msg\.sender",
        "severity": "critical",
        "description": "Delegatecall with user-provided address - code execution vulnerability",
        "modifier": "Never delegatecall to user-provided addresses",
        "cvss": 9.8,
        "cwe": "CWE-95",
        "impact": "Arbitrary code execution",
        "bypass": "Delegatecall to malicious contract"
    },
    "unprotected_selfdestruct": {
        "pattern": r"selfdestruct|suicide[^{]*\{?\s*(?!onlyOwner|onlyGovernance)",
        "severity": "critical",
        "description": "Contract can be destroyed by anyone",
        "modifier": "onlyOwner",
        "cvss": 9.8,
        "cwe": "CWE-284",
        "impact": "Permanent loss of all funds and functionality",
        "bypass": "Call selfdestruct()"
    },
    "governance_raid": {
        "pattern": r"function\s+execute[^{]*\{?\s*(?!onlyExecutor|onlyGovernance|queue|proposal",
        "severity": "high",
        "description": "Governance execution without proper checks",
        "modifier": "onlyGovernance",
        "cvss": 8.5,
        "cwe": "CWE-284",
        "impact": "Can execute malicious proposals",
        "bypass": "Queue and execute bad proposal"
    },
    "keeper_bypass": {
        "pattern": r"function\s+performUpkeep[^{]*\{?\s*(?!onlyKeeper|checkUpkeep|require\(",
        "severity": "high",
        "description": "Automated keeper functions without access control",
        "modifier": "onlyKeeper",
        "cvss": 8.0,
        "cwe": "CWE-284",
        "impact": "Anyone can trigger automation",
        "bypass": "Call performUpkeep() directly"
    },
    "guardian_escalation": {
        "pattern": r"function\s+grantGuardian|setGuardian[^{]*\{?\s*(?!onlyOwner|onlyAdmin",
        "severity": "critical",
        "description": "Guardian role can be escalated without proper checks",
        "modifier": "onlyOwner + Timelock",
        "cvss": 9.5,
        "cwe": "CWE-284",
        "impact": "Guardian can become owner through escalation",
        "bypass": "Grant guardian to self"
    },
    "upgrade_implementation": {
        "pattern": r"implementation\(\)\.upgradeTo[^{]*\{?\s*(?!onlyProxyAdmin|onlyOwner",
        "severity": "critical",
        "description": "Implementation can be upgraded by anyone",
        "modifier": "onlyProxyAdmin",
        "cvss": 9.8,
        "cwe": "CWE-284",
        "impact": "Complete protocol takeover",
        "bypass": "Call implementation().upgradeTo()"
    }
}


MODIFIER_PATTERNS = {
    "onlyOwner": {
        "pattern": r"modifier\s+onlyOwner\s*\(",
        "checks": ["msg.sender == _owner"],
        "is_standard": True
    },
    "onlyRole": {
        "pattern": r"modifier\s+onlyRole\s*\(",
        "checks": ["hasRole", "msg.sender"],
        "is_standard": True
    },
    "onlyAdmin": {
        "pattern": r"modifier\s+onlyAdmin\s*\(",
        "checks": ["msg.sender == _admin"],
        "is_standard": True
    },
    "onlyGovernance": {
        "pattern": r"modifier\s+onlyGovernance\s*\(",
        "checks": ["_msgSender == _governance"],
        "is_standard": True
    },
    "onlyPauser": {
        "pattern": r"modifier\s+onlyPauser\s*\(",
        "checks": ["hasRole", "pauser"],
        "is_standard": True
    },
    "onlyMinter": {
        "pattern": r"modifier\s+onlyMinter\s*\(",
        "checks": ["hasRole(minter)"],
        "is_standard": True
    },
    "whenNotPaused": {
        "pattern": r"modifier\s+whenNotPaused\s*\(",
        "checks": ["!paused"],
        "is_standard": True
    },
    "initializer": {
        "pattern": r"modifier\s+initializer\s*\(",
        "checks": ["!_initialized"],
        "is_standard": True
    },
    "nonReentrant": {
        "pattern": r"modifier\s+nonReentrant\s*\(",
        "checks": ["_status"],
        "is_standard": True
    },
    "onlyKeeper": {
        "pattern": r"modifier\s+onlyKeeper\s*\(",
        "checks": ["msg.sender == _keeper"],
        "is_standard": True
    }
}

COMMON_SENSITIVE_FUNCTIONS = [
    "withdraw", "transfer", "mint", "burn", "pause", "unpause", "upgrade",
    "initialize", "setFee", "setOwner", "grantRole", "revokeRole",
    "execute", "queue", "cancel", "propose", "vote", "snapshot",
    "liquidate", "seize", "claim", "harvest", "stake", "unstake",
    "performUpkeep", "upkeepNeeded", "setKeeper", "setPrice"
]


class AccessControlDetector:
    """Detect access control vulnerability patterns"""
    
    def __init__(self):
        self.patterns = ACCESS_PATTERNS
        self._findings: List[AccessControlFinding] = []
    
    def detect(self, code: str) -> List[AccessControlFinding]:
        self._findings.clear()
        
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for name, info in self.patterns.items():
                if re.search(info["pattern"], line, re.IGNORECASE):
                    finding = self._create_finding(name, info, line, i)
                    if finding:
                        self._findings.append(finding)
        
        return self._findings
    
    def _create_finding(self, name: str, info: Dict, line: str, line_num: int) -> Optional[AccessControlFinding]:
        severity = AccessControlSeverity[info["severity"].upper()]
        
        return AccessControlFinding(
            pattern=AccessControlPattern[name.upper()],
            severity=severity,
            function=self._extract_function(line),
            description=info["description"],
            line_number=line_num,
            expected_modifier=info["modifier"],
            recommendation=self._get_recommendation(name),
            cvss_score=info.get("cvss", 0.0),
            cwe_id=info.get("cwe", ""),
            status=VulnerabilityStatus.CONFIRMED,
            impact=info.get("impact", ""),
            bypass_complexity=info.get("bypass", "simple")
        )
    
    def _extract_function(self, line: str) -> str:
        match = re.search(r"function\s+(\w+)", line)
        return match.group(1) if match else "unknown"
    
    def _get_recommendation(self, pattern_name: str) -> str:
        recommendations = {
            "missing_owner": "Add 'onlyOwner' modifier from OpenZeppelin Ownable",
            "missing_only": "Add appropriate access control modifier (onlyOwner, onlyRole, etc.)",
            "anyone_can_withdraw": "Add onlyOwner or onlyAuthenticated modifier",
            "anyone_can_mint": "Add onlyMinter role from AccessControl",
            "anyone_can_pause": "Add onlyPauser modifier",
            "unprotected_upgrade": "Add onlyProxyAdmin modifier with timelock",
            "initialize_anyone": "Add initializer modifier and one-time initialization check",
            "unprotected_set_fee": "Add onlyOwner modifier to fee-setting function",
            "transfer_admin_anyone": "Transfer admin through timelock with acceptance",
            "default_access": "Require sender verification in function body or modifier",
            "tx_origin": "Replace tx.origin with msg.sender",
            "missing_zero_check": "Add require(addr != address(0)) validation",
            "access_anyone_public": "Use initializer pattern with initialization flag"
        }
        return recommendations.get(pattern_name, f"Add appropriate access control: {pattern_name}")


class ModifierAnalyzer:
    """Analyze access control modifiers"""
    
    def __init__(self):
        self.modifier_patterns = MODIFIER_PATTERNS
    
    def analyze(self, code: str) -> Dict[str, ModifierAnalysis]:
        modifiers = {}
        
        for mod_name, mod_info in self.modifier_patterns.items():
            if re.search(mod_info["pattern"], code):
                mod_anal = ModifierAnalysis(
                    modifier_name=mod_name,
                    associated_functions=self._find_modifier_usage(mod_name, code),
                    checks_ownership=("owner" in str(mod_info.get("checks", [])).lower()),
                    checks_role=("role" in str(mod_info.get("checks", [])).lower()),
                    is_pausable=mod_name in ["whenNotPaused", "whenPaused"]
                )
                modifiers[mod_name] = mod_anal
        
        return modifiers
    
    def _find_modifier_usage(self, modifier_name: str, code: str) -> List[str]:
        functions = []
        
        for line in code.split('\n'):
            if modifier_name in line and "function" in line:
                match = re.search(r"function\s+(\w+)", line)
                if match:
                    functions.append(match.group(1))
        
        return functions
    
    def check_missing_modifiers(self, code: str) -> List[Dict[str, Any]]:
        missing = []
        
        sensitive_funcs = self._find_sensitive_functions_without_modifier(code)
        
        for func in sensitive_funcs:
            missing.append({
                "function": func,
                "issue": "Sensitive function missing access control",
                "recommendation": "Add appropriate modifier"
            })
        
        return missing
    
    def _find_sensitive_functions_without_modifier(self, code: str) -> List[str]:
        functions_without = []
        
        lines = code.split('\n')
        in_function = False
        current_function = ""
        
        for line in lines:
            if re.search(r"function\s+(\w+)", line):
                match = re.search(r"function\s+(\w+)", line)
                if match:
                    in_function = True
                    current_function = match.group(1)
            
            if in_function and current_function:
                func_name_lower = current_function.lower()
                
                if any(sensitive in func_name_lower for sensitive in COMMON_SENSITIVE_FUNCTIONS):
                    if not any(mod in line for mod in MODIFIER_PATTERNS.keys()):
                        functions_without.append(current_function)
                
                if "returns" in line or "{" not in line:
                    continue
                if line.strip() == "}":
                    in_function = False
                    current_function = ""
        
        return functions_without


class RoleBasedAccessChecker:
    """Check role-based access control implementations"""
    
    def __init__(self):
        self.role_names = [
            "minter", "pauser", "admin", "governor", "operator", 
            "keeper", "fee_manager", "vault", "guardian", "executor",
            "proposer", "voter", "liquidator", "seller", "buyer"
        ]
        self.open_zeppelin_contracts = [
            "AccessControl", "AccessControlEnumerable", "AccessControlMock",
            "Ownable", "OwnableUpgradeable", "Pausable", "PausableUpgradeable",
            "TimelockController", "Governor", "GovernorWithExecution"
        ]
    
    def analyze_roles(self, code: str) -> Dict[str, Any]:
        found_roles = {}
        
        for role in self.role_names:
            role_analysis = self._analyze_role(role, code)
            if role_analysis:
                found_roles[role] = role_analysis
        
        return {
            "roles_found": found_roles,
            "uses_openzeppelin": self._uses_openzeppelin(code),
            "uses_custom": self._uses_custom_roles(code),
            "role_analysis": self._analyze_role_strength(found_roles)
        }
    
    def _analyze_role(self, role: str, code: str) -> Optional[RoleAnalysis]:
        role_patterns = [
            rf"keccak256\('\^{role}'\)",
            rf"^{role.upper()}_ROLE",
            rf"hasRole\(.*{role}",
            rf"only{role.capitalize()}\(\)",
            rf"grant{role.capitalize()}\(",
            rf"revoke{role.capitalize()}\("
        ]
        
        for pattern in role_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return RoleAnalysis(
                    role_name=role,
                    role_holder=self._find_role_holder(role, code),
                    permissions=self._find_role_permissions(role, code),
                    has_admin=self._role_has_admin(role, code),
                    is_revocable=self._role_is_revocable(role, code)
                )
        
        return None
    
    def _find_role_holder(self, role: str, code: str) -> str:
        patterns = [
            rf"{role}_role.*address",
            rf"_grantRole\(.*{role}",
            rf"hasRole\(.*{role}.*msg\.sender"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                return match.group(0)[:50]
        
        return "Unknown"
    
    def _find_role_permissions(self, role: str, code: str) -> List[str]:
        permissions = []
        
        role_functions = {
            "minter": ["mint", "burn", "mintTo"],
            "pauser": ["pause", "unpause"],
            "governor": ["execute", "queue", "propose"],
            "liquidator": ["liquidate", "seize", "foreclose"],
            "keeper": ["performUpkeep", "checkUpkeep"]
        }
        
        if role in role_functions:
            for perm in role_functions[role]:
                if perm in code.lower():
                    permissions.append(perm)
        
        return permissions
    
    def _role_has_admin(self, role: str, code: str) -> bool:
        return f"ADMIN" in code.upper() or f"DEFAULT_ADMIN" in code.upper()
    
    def _role_is_revocable(self, role: str, code: str) -> bool:
        return "revokeRole" in code or "renounceRole" in code
    
    def _uses_openzeppelin(self, code: str) -> bool:
        return any(contract in code for contract in self.open_zeppelin_contracts)
    
    def _uses_custom_roles(self, code: str) -> bool:
        return "mapping(address" in code and "role" in code.lower()
    
    def _analyze_role_strength(self, roles: Dict[str, RoleAnalysis]) -> Dict[str, str]:
        strength = {}
        
        for role_name, role_analysis in roles.items():
            if role_analysis.has_admin and role_analysis.is_revocable:
                strength[role_name] = "strong"
            elif role_analysis.is_revocable:
                strength[role_name] = "medium"
            else:
                strength[role_name] = "weak"
        
        return strength


class FunctionVisibilityChecker:
    """Check function visibility and access patterns"""
    
    def __init__(self):
        self._default_state = ["private", "internal"]
    
    def check_functions(self, code: str) -> List[Dict[str, Any]]:
        issues = []
        
        state_modifying = ["withdraw", "transfer", "mint", "burn", "upgrade", 
                         "set", "pause", "liquidate", "execute", "claim", 
                         "harvest", "stake", "unstake", "performUpkeep"]
        
        for line in code.split('\n'):
            contains_sensitive = any(f"function {func}" in line.lower() 
                                     for func in state_modifying)
            
            if contains_sensitive:
                if "external" not in line and "private" not in line and "internal" not in line:
                    match = re.search(r"function\s+(\w+)", line)
                    if match:
                        issues.append({
                            "function": match.group(1),
                            "recommendation": "Use 'external' for state-modifying functions to save gas"
                        })
                
                elif "public" in line:
                    match = re.search(r"function\s+(\w+)", line)
                    if match:
                        if not any(mod in line for mod in MODIFIER_PATTERNS.keys()):
                            issues.append({
                                "function": match.group(1),
                                "issue": "Public function without access control modifier",
                                "recommendation": "Add visibility modifier"
                            })
        
        return issues
    
    def check_unrestricted_functions(self, code: str) -> List[str]:
        unrestricted = []
        
        functions = self._extract_all_functions(code)
        
        for func_name, func_code in functions.items():
            if not any(mod in func_code for mod in MODIFIER_PATTERNS.keys()):
                if any(sensitive in func_name.lower() for sensitive in COMMON_SENSITIVE_FUNCTIONS):
                    unrestricted.append(func_name)
        
        return unrestricted
    
    def _extract_all_functions(self, code: str) -> Dict[str, str]:
        functions = {}
        current_func = ""
        brace_count = 0
        
        for line in code.split('\n'):
            if "function " in line:
                match = re.search(r"function\s+(\w+)", line)
                if match:
                    current_func = match.group(1)
                    functions[current_func] = line
            elif current_func:
                functions[current_func] += "\n" + line
            
            if current_func:
                brace_count += line.count('{') - line.count('}')
                if brace_count == 0:
                    current_func = ""
        
        return functions


class AccessControlHunter:
    """Main access control vulnerability hunter"""
    
    def __init__(self):
        self.detector = AccessControlDetector()
        self.modifier_analyzer = ModifierAnalyzer()
        self.role_checker = RoleBasedAccessChecker()
        self.visibility_checker = FunctionVisibilityChecker()
        
        logger.info("✅ Access Control Hunter initialized")
    
    def hunt(self, code: str) -> Dict[str, Any]:
        findings = self.detector.detect(code)
        modifier_analysis = self.modifier_analyzer.analyze(code)
        missing_modifiers = self.modifier_analyzer.check_missing_modifiers(code)
        role_analysis = self.role_checker.analyze_roles(code)
        visibility_issues = self.visibility_checker.check_functions(code)
        
        vulnerabilities = []
        
        for finding in findings:
            vulnerabilities.append({
                "type": "access_control",
                "pattern": finding.pattern.value,
                "severity": finding.severity.value,
                "function": finding.function,
                "description": finding.description,
                "line": finding.line_number,
                "expected_modifier": finding.expected_modifier,
                "recommendation": finding.recommendation,
                "cvss": finding.cvss_score,
                "cwe": finding.cwe_id,
                "status": finding.status.value,
                "impact": finding.impact,
                "bypass": finding.bypass_complexity
            })
        
        return {
            "vulnerabilities": vulnerabilities,
            "modifier_analysis": {k: {"name": v.modifier_name, "checks": v.checks_ownership} 
                               for k, v in modifier_analysis.items()},
            "role_analysis": role_analysis,
            "missing_modifiers": missing_modifiers,
            "visibility_issues": visibility_issues,
            "unrestricted_functions": self.visibility_checker.check_unrestricted_functions(code),
            "total_findings": len(findings),
            "risk_score": self._calculate_risk_score(vulnerabilities)
        }
    
    def _calculate_risk_score(self, vulns: List[Dict]) -> float:
        score = 0.0
        
        for vuln in vulns:
            severity = vuln.get("severity")
            if severity == "critical":
                score += 3.0
            elif severity == "high":
                score += 2.0
            elif severity == "medium":
                score += 1.0
        
        return min(10.0, score)
    
    def check_guard(self, code: str) -> bool:
        for mod in MODIFIER_PATTERNS.keys():
            if mod in code:
                return True
        return False
    
    def analyze_roles(self, code: str) -> Dict[str, Any]:
        return self.role_checker.analyze_roles(code)
    
    def analyze_modifiers(self, code: str) -> Dict[str, Any]:
        return self.modifier_analyzer.analyze(code)


def hunt_access_control(code: str) -> Dict[str, Any]:
    """Entry point for access control hunting"""
    hunter = AccessControlHunter()
    return hunter.hunt(code)


def check_access_control(code: str) -> bool:
    """Quick check for access control presence"""
    hunter = AccessControlHunter()
    return hunter.check_guard(code)


def analyze_roles(code: str) -> Dict[str, Any]:
    """Analyze role-based access control"""
    hunter = AccessControlHunter()
    return hunter.analyze_roles(code)