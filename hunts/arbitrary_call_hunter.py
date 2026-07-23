"""
Solidify Arbitrary Call Hunter
Hunt for arbitrary call vulnerabilities with comprehensive detection
Author: Peace Stephen (Tech Lead)
Description: Specialized hunter for arbitrary call and call injection vulnerabilities
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


class ArbitraryCallPattern(Enum):
    RAW_CALL = "raw_call"
    DELEGATE_CALL = "delegate_call"
    FUNCTION_SELECTOR = "function_selector"
    DYNAMIC_CALL = "dynamic_call"
    ADDRESS_CALL = "address_call"
    CONTRACT_CREATION = "contract_creation"
    SELF_DESTRUCT = "self_destruct"
    EXEC_CALL = "exec_call"
    CALLCODE = "callcode"
    STATICCALL = "staticcall"


class ArbitraryCallSeverity(Enum):
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
class ArbitraryCallFinding:
    pattern: ArbitraryCallPattern
    severity: ArbitraryCallSeverity
    function: str
    description: str
    line_number: int
    target_address: str = ""
    call_data: str = ""
    recommendation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    status: VulnerabilityStatus = VulnerabilityStatus.PENDING
    impact: str = ""
    exploit_conditions: str = ""


@dataclass
class CallTarget:
    address: str
    is_verified: bool
    is_contract: bool
    has_code: bool
    is_whitelisted: bool = False


@dataclass
class DelegateAnalysis:
    target: str
    is_safe: bool
    is_immutable: bool
    storage_conflict_risk: bool


ARBITRARY_CALL_PATTERNS = {
    "raw_call": {
        "pattern": r"\.call\s*\(\s*(?:abi\.encodeWithSelector|abi\.encodeWithSignature|bytes|\[[^\]]*\])\s*",
        "severity": "critical",
        "description": "Arbitrary low-level call with dynamic data - dangerous pattern allowing code execution",
        "cvss": 9.8,
        "cwe": "CWE-95",
        "impact": "Attacker can execute arbitrary code in contract context",
        "exploit": "Supply malicious target address or encoded function"
    },
    "raw_call_value": {
        "pattern": r"\.call\{value:\s*[^\}]+\}\s*\(",
        "severity": "critical",
        "description": "Low-level call with value - can send ether to arbitrary address",
        "cvss": 9.8,
        "cwe": "CWE-115",
        "impact": "Can transfer contract balance to arbitrary address",
        "exploit": "Set target to attacker-controlled address"
    },
    "delegate_call": {
        "pattern": r"\.delegatecall\s*\(",
        "severity": "critical",
        "description": "Arbitrary delegatecall - executes code in contract's storage context",
        "cvss": 9.8,
        "cwe": "CWE-829",
        "impact": "Complete storage compromise, can steal all storage values",
        "exploit": "Deploy malicious contract and delegatecall to it"
    },
    "delegate_call_proxy": {
        "pattern": r"function\s+(fallback|receive)\s*\(\s*\)\s*(?:external|public)?\s*(?:payable)?\s*\{[^}]*delegatecall",
        "severity": "critical",
        "description": "Proxy implementation with delegatecall - critical storage layout vulnerability",
        "cvss": 10.0,
        "cwe": "CWE-829",
        "impact": "Storage collision can lead to complete protocol compromise",
        "exploit": "If storage layouts don't match, attacker can overwrite critical values"
    },
    "address_cast": {
        "pattern": r"address\s*\(\s*[a-zA-Z0-9_]+\s*\)(?!\s*\.\s*(?:payable|some|bytes)",
        "severity": "high",
        "description": "Unsafe address type casting removes payable warning",
        "cvss": 8.5,
        "cwe": "CWE-1175",
        "impact": "Can accidentally send ether to non-payable addresses",
        "exploit": "Convert non-payable contract to payable"
    },
    "extcodesize_zero": {
        "pattern": r"(?:extcodesize|extcodehash)\s*\(\s*\w+\s*\)\s*==\s*0(?!\s*\|\||\s*&&)",
        "severity": "high",
        "description": "Missing EOA check - allows calls to both EOA and contracts",
        "cvss": 8.0,
        "cwe": "CWE-1004",
        "impact": "External call to EOA without code can cause transaction failure or enable attack patterns",
        "exploit": "Use EOA as target to avoid execution but pass check"
    },
    "extcodesize_nonzero": {
        "pattern": r"(?:require|assert)\s*\(\s*extcodesize\([^)]+\)\s*>\s*0",
        "severity": "medium",
        "description": "Checking contract exists but not validating target properly",
        "cvss": 5.3,
        "cwe": "CWE-1004",
        "impact": "Limited - only ensures target has code",
        "exploit": "Deploy thin contract to pass check"
    },
    "selfdestruct": {
        "pattern": r"selfdestruct|self\.destroy\s*\(\s*",
        "severity": "critical",
        "description": "Unprotected self-destruct - permanently destroys contract",
        "cvss": 9.8,
        "cwe": "CWE-284",
        "impact": "Complete contract destruction, all funds lost forever",
        "exploit": "Simply call selfdestruct() with any recipient address"
    },
    "suicide": {
        "pattern": r"suicide\s*\(\s*",
        "severity": "critical",
        "description": "Legacy self-destruct (suicide) - same as selfdestruct",
        "cvss": 9.8,
        "cwe": "CWE-284",
        "impact": "Contract can be permanently destroyed by anyone",
        "exploit": "Call suicide()"
    },
    "create_dynamic": {
        "pattern": r"create\s*\(\s*(?:new|msg\.sender|abi\.|bytes|address)",
        "severity": "high",
        "description": "Dynamic contract creation with user-influenced bytecode",
        "cvss": 8.5,
        "cwe": "CWE-94",
        "impact": "Can deploy malicious contracts created from user input",
        "exploit": "Craft bytecode that deploys vulnerable contract"
    },
    "create2_unprotected": {
        "pattern": r"create2\s*\(\s*(?:salt|msg\.sender|abi|bytes)",
        "severity": "high",
        "description": "CREATE2 with predictable salt - can front-run to deploy to same address",
        "cvss": 8.0,
        "cwe": "CWE-400",
        "impact": "Attacker can front-run deployment to take same address",
        "exploit": "Front-run CREATE2 with same salt"
    },
    "function_selector": {
        "pattern": r"bytes4\s*\(\s*keccak256\s*\(\s*[\"\']([^\"\']+)",
        "severity": "medium",
        "description": "Hardcoded function selector can be analyzed",
        "cvss": 3.8,
        "cwe": "CWE-204",
        "impact": "Function selectors are public anyway",
        "exploit": "Just reveals function signatures"
    },
    "abi_encode_dynamic": {
        "pattern": r"abi\.encodeWithSignature\s*\([^,]+\s*(?:,|\))",
        "severity": "medium",
        "description": "Dynamic function encoding enables runtime function selection",
        "cvss": 5.3,
        "cwe": "CWE-94",
        "impact": "Can call any function on target",
        "exploit": "Encode any function selector dynamically"
    },
    "abi_encode_packed": {
        "pattern": r"abi\.encodePacked\s*\(",
        "severity": "medium",
        "description": "abi.encodePacked can cause signature collisions",
        "cvss": 5.3,
        "cwe": "CWE-202",
        "impact": "Hash collisions in packed encoding",
        "exploit": "If signature collision, wrong function called"
    },
    "assembly_call": {
        "pattern": r"assembly\s*\{[^}]*call\s*\(",
        "severity": "high",
        "description": "Inline assembly call - bypasses Solidity safety checks",
        "cvss": 8.5,
        "cwe": "CWE-95",
        "impact": "No type safety or bounds checking",
        "exploit": "Direct assembly call to arbitrary address"
    },
    "assembly_delegatecall": {
        "pattern": r"assembly\s*\{[^}]*delegatecall\s*\(",
        "severity": "critical",
        "description": "Inline assembly delegatecall - same as delegatecall vulnerability",
        "cvss": 9.8,
        "cwe": "CWE-829",
        "impact": "Storage context compromise",
        "exploit": "Delegatecall in assembly"
    },
    "staticcall": {
        "pattern": r"\.staticcall\s*\(",
        "severity": "medium",
        "description": "Staticcall to arbitrary address - read-only but still risky",
        "cvss": 5.3,
        "cwe": "CWE-1004",
        "impact": "Can read arbitrary storage slots",
        "exploit": "Read private storage from other contracts"
    },
    "low_level_call": {
        "pattern": r"address\.call(?!\s*\(\s*\)id)",
        "severity": "high",
        "description": "Using low-level .call() without proper validation",
        "cvss": 8.0,
        "cwe": "CWE-95",
        "impact": "Similar to raw call but slightly safer due to return data availability",
        "exploit": "Call arbitrary address"
    },
    "ecrecover": {
        "pattern": r"ecrecover\s*\(",
        "severity": "medium",
        "description": "Signature recovery via ecrecover - vulnerable to malleability",
        "cvss": 5.3,
        "cwe": "CWE-344",
        "impact": "Signed messages can be replayed or malleated",
        "exploit": "If signature malleability not handled, can replay signatures"
    },
    "signature_verification": {
        "pattern": r"verify\s*\([^)]*signature",
        "severity": "high",
        "description": "Custom signature verification - likely to have vulnerabilities",
        "cvss": 7.5,
        "cwe": "CWE-344",
        "impact": "Custom crypto often has implementation errors",
        "exploit": "Break signature scheme"
    },
    "callcode_inheritance": {
        "pattern": r"callcode\s*\(\s*msg\.sender",
        "severity": "medium",
        "description": "Using callcode to inherit behavior - deprecated and risky",
        "cvss": 5.3,
        "cwe": "CWE-115",
        "impact": "Legacy pattern, limited in newer Solidity",
        "exploit": "Callcode deprecated"
    },
    "variable_target": {
        "pattern": r"\.(call|delegatecall)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\(",
        "severity": "high",
        "description": "Call target from variable - indirect execution path",
        "cvss": 8.0,
        "cwe": "CWE-94",
        "impact": "If variable is controllable, arbitrary code execution possible",
        "exploit": "Modify target variable to malicious address"
    },
    "storage_target": {
        "pattern": r"\.(call|delegatecall)\s*\(\s*\[",
        "severity": "high",
        "description": "Call target from storage array - potential vector",
        "cvss": 8.0,
        "cwe": "CWE-94",
        "impact": "Array index manipulation could lead to arbitrary call",
        "exploit": "Modify storage index to point to attacker address"
    },
    "unrestricted_proxy": {
        "pattern": r"fallback\s*\(\s*\)\s*(?:external)?\s*\{[^}]*\.delegatecall",
        "severity": "critical",
        "description": "Unrestricted proxy fallback enabling delegatecall",
        "cvss": 9.8,
        "cwe": "CWE-287",
        "impact": "Anyone can execute as proxy",
        "exploit": "Simply call contract with data to trigger"
    },
    "eth_sendTransaction": {
        "pattern": r"eth\.sendTransaction\s*\(",
        "severity": "high",
        "description": "External call for sending ether - potential for reentrancy",
        "cvss": 8.0,
        "cwe": "CWE-124",
        "impact": "Can trigger reentrancy or use all gas",
        "exploit": "Use sendTransaction in malicious contract"
    },
    "execute_centralized": {
        "pattern": r"function\s+execute[^{]*\{[^}]*(?!\s*owner|require)",
        "severity": "critical",
        "description": "Execute function without owner check - critical",
        "cvss": 9.8,
        "cwe": "CWE-284",
        "impact": "Anyone can execute arbitrary calls",
        "exploit": "Call execute() directly"
    }
}


SAFE_PRACTICES = {
    "whitelist": "Use contract whitelist for target addresses",
    "immutable": "Make target address immutable after initialization",
    "eoa_check": "Verify extcodesize before call",
    "value_limit": "Limit value transferred per call",
    "events": "Emit events for all calls",
    "owner_check": "Require owner for target setting",
    "timelock": "Add timelock for critical operations",
    "access_control": "Add access control modifiers to target-setting functions"
}


class ArbitraryCallDetector:
    """Detect arbitrary call vulnerability patterns"""
    
    def __init__(self):
        self.patterns = ARBITRARY_CALL_PATTERNS
        self._findings: List[ArbitraryCallFinding] = []
    
    def detect(self, code: str) -> List[ArbitraryCallFinding]:
        self._findings.clear()
        
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for name, info in self.patterns.items():
                if re.search(info["pattern"], line, re.IGNORECASE):
                    finding = self._create_finding(name, info, line, i)
                    if finding:
                        self._findings.append(finding)
        
        return self._findings
    
    def _create_finding(self, name: str, info: Dict, line: str, line_num: int) -> Optional[ArbitraryCallFinding]:
        severity = ArbitraryCallSeverity[info["severity"].upper()]
        
        return ArbitraryCallFinding(
            pattern=ArbitraryCallPattern[name.upper()],
            severity=severity,
            function=self._extract_function(line),
            description=info["description"],
            line_number=line_num,
            target_address=self._extract_address(line),
            call_data=self._extract_call_data(line),
            recommendation=self._get_recommendation(name),
            cvss_score=info.get("cvss", 0.0),
            cwe_id=info.get("cwe", ""),
            status=VulnerabilityStatus.CONFIRMED,
            impact=info.get("impact", ""),
            exploit_conditions=info.get("exploit", "Unknown")
        )
    
    def _extract_function(self, line: str) -> str:
        match = re.search(r"function\s+(\w+)", line)
        return match.group(1) if match else "global"
    
    def _extract_address(self, line: str) -> str:
        patterns = [
            r"\.call\(\s*([^,]+)",
            r"\.delegatecall\(\s*([^,]+)",
            r"\.callvalue\(\s*([^,]+)",
            r"\.staticcall\(\s*([^,]+)"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1).strip()[:30]
        
        return ""
    
    def _extract_call_data(self, line: str) -> str:
        match = re.search(r"\.call\([^,]+,\s*([^)]+)\)", line)
        if match:
            return match.group(1).strip()[:30]
        
        patterns = [r"encodeWithSignature\(([^)]+)", r"encode\(([^)]+)"]
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1).strip()[:30]
        
        return ""
    
    def _get_recommendation(self, pattern_name: str) -> str:
        recommendations = {
            "raw_call": "Use SafePayment or checks-effect-interaction pattern",
            "raw_call_value": "Add address payable validation and amount checks",
            "delegatecall": "Avoid delegatecall to user-provided addresses or use proxy pattern correctly",
            "delegate_call_proxy": "Ensure storage layout compatibility between implementations",
            "address_cast": "Use address payable for transfers or include .payable",
            "extcodesize_zero": "Consider security implications of EOA vs contract",
            "selfdestruct": "Add onlyOwner, onlyGovernance, or timelock to selfdestruct",
            "create_dynamic": "Validate bytecode or use create2 with computed salt",
            "create2_unprotected": "Use CREATE2 with secure salt generation",
            "function_selector": "This is informational - function selectors are public",
            "abi_encode_dynamic": "Use abi.encode instead for clarity",
            "abi_encode_packed": "Use abi.encode for type safety",
            "assembly_call": "Implement proper access controls in assembly",
            "assembly_delegatecall": "Avoid delegating to user-provided addresses",
            "staticcall": "This read-only call is less dangerous but still review",
            "low_level_call": "Validate and whitelist target addresses",
            "ecrecover": "Use OpenZeppelin ECDSA library with malleability protection",
            "signature_verification": "Implement signature replay protection",
            "callcode": "Migrate away from callcode",
            "variable_target": "Validate variable values before use",
            "storage_target": "Ensure storage array is not writable by users",
            "unrestricted_proxy": "Add access control to proxy fallback",
            "eth_sendTransaction": "Avoid direct eth.sendTransaction, use call with limits",
            "execute_centralized": "Add proper access control to execute function"
        }
        
        return recommendations.get(pattern_name, "Review and secure the call pattern")


class DelegateCallAnalyzer:
    """Analyze delegatecall usage for security implications"""
    
    def __init__(self):
        self._patterns = {}
    
    def analyze(self, code: str) -> List[DelegateAnalysis]:
        findings = []
        
        delegate_calls = self._find_delegate_calls(code)
        
        for target, context in delegate_calls:
            analysis = DelegateAnalysis(
                target=target,
                is_safe=self._check_safety(target, code),
                is_immutable=self._check_immutability(target, code),
                storage_conflict_risk=self._check_storage_risk(target, code)
            )
            findings.append(analysis)
        
        return findings
    
    def _find_delegate_calls(self, code: str) -> List[Tuple[str, str]]:
        delegate_calls = []
        
        pattern = r"\.delegatecall\s*\(\s*([^,)+])*(?:,\s*([^,)]+))?"
        matches = re.finditer(pattern, code)
        
        for match in matches:
            if len(match.groups()) >= 1:
                target = match.group(1).strip()
                context = match.group(2).strip() if len(match.groups()) > 1 else ""
                delegate_calls.append((target, context))
        
        return delegate_calls
    
    def _check_safety(self, target: str, code: str) -> bool:
        if "owner" in code.lower() and "immutable" in code.lower():
            return True
        if target in ["implementation", "proxy", "router"]:
            return True
        
        return False
    
    def _check_immutability(self, target: str, code: str) -> bool:
        return "immutable" in code.lower() or target in ["implementation", "proxy"]
    
    def _check_storage_risk(self, target: str, code: str) -> bool:
        return target in code and "storage" in code.lower()


class TargetValidator:
    """Validate call targets for security"""
    
    def __init__(self):
        self._whitelist: Set[str] = set()
        self._blacklist: Set[str] = set()
    
    def add_to_whitelist(self, address: str) -> None:
        self._whitelist.add(address.lower())
    
    def add_to_blacklist(self, address: str) -> None:
        self._blacklist.add(address.lower())
    
    def remove_from_whitelist(self, address: str) -> None:
        self._whitelist.discard(address.lower())
    
    def remove_from_blacklist(self, address: str) -> None:
        self._blacklist.discard(address.lower())
    
    def is_whitelisted(self, address: str) -> bool:
        return address.lower() in self._whitelist
    
    def is_blacklisted(self, address: str) -> bool:
        return address.lower() in self._blacklist
    
    def can_whitelist(self, address: str) -> bool:
        if self._blacklist:
            return False
        return True
    
    def validate_target(self, address: str) -> Dict[str, Any]:
        return {
            "address": address,
            "whitelisted": self.is_whitelisted(address),
            "blacklisted": self.is_blacklisted(address),
            "safe": self.is_whitelisted(address) and not self.is_blacklisted(address)
        }


class FunctionCallAnalyzer:
    """Analyze function call vulnerabilities"""
    
    def __init__(self):
        self._sensitive_functions = {
            "call": "Low-level call",
            "delegatecall": "Delegatecall - executes in contract context",
            "staticcall": "Staticcall - read-only call",
            "create": "Contract creation",
            "create2": "Deterministic contract creation"
        }
    
    def analyze(self, code: str) -> Dict[str, List[str]]:
        findings = defaultdict(list)
        
        for line in code.split('\n'):
            for func_name, description in self._sensitive_functions.items():
                if func_name in line and "(" in line:
                    match = re.search(r"(\w+)\s*\([^)]*\)", line)
                    if match:
                        findings[func_name].append(match.group(1))
        
        return dict(findings)


class ArbitraryCallHunter:
    """Main arbitrary call vulnerability hunter"""
    
    def __init__(self):
        self.detector = ArbitraryCallAnalyzer()
        self.delegate_analyzer = DelegateCallAnalyzer()
        self.validator = TargetValidator()
        self.call_analyzer = FunctionCallAnalyzer()
        
        logger.info("✅ Arbitrary Call Hunter initialized")
    
    def hunt(self, code: str) -> Dict[str, Any]:
        findings = self.detector.detect(code)
        delegate_analysis = self.delegate_analyzer.analyze(code)
        call_analysis = self.call_analyzer.analyze(code)
        
        vulnerabilities = []
        
        for finding in findings:
            vulnerabilities.append({
                "type": "arbitrary_call",
                "pattern": finding.pattern.value,
                "severity": finding.severity.value,
                "function": finding.function,
                "description": finding.description,
                "line": finding.line_number,
                "target": finding.target_address,
                "call_data": finding.call_data,
                "recommendation": finding.recommendation,
                "cvss": finding.cvss_score,
                "cwe": finding.cwe_id,
                "status": finding.status.value,
                "impact": finding.impact,
                "exploit": finding.exploit_conditions
            })
        
        return {
            "vulnerabilities": vulnerabilities,
            "delegate_analysis": [{
                "target": d.target,
                "safe": d.is_safe,
                "immutable": d.is_immutable,
                "storage_risk": d.storage_conflict_risk
            } for d in delegate_analysis],
            "call_patterns": call_analysis,
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
    
    def add_whitelist(self, address: str) -> None:
        self.validator.add_to_whitelist(address)
    
    def add_blacklist(self, address: str) -> None:
        self.validator.add_to_blacklist(address)
    
    def check_target(self, address: str) -> Dict[str, Any]:
        return self.validator.validate_target(address)


def hunt_arbitrary_call(code: str) -> Dict[str, Any]:
    """Entry point for arbitrary call hunting"""
    hunter = ArbitraryCallHunter()
    return hunter.hunt(code)


def analyze_delegate_calls(code: str) -> List[Dict[str, Any]]:
    """Analyze delegatecall vulnerabilities"""
    analyzer = DelegateCallAnalyzer()
    return [{"target": d.target, "safe": d.is_safe} for d in analyzer.analyze(code)]


def validate_call_target(address: str, whitelist: List[str] = None) -> Dict[str, Any]:
    """Validate a call target"""
    validator = TargetValidator()
    
    for addr in whitelist or []:
        validator.add_to_whitelist(addr)
    
    return validator.validate_target(address)