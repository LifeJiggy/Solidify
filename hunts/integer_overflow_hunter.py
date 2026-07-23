"""
Solidify Integer Overflow Hunter
Hunt for integer overflow/underflow vulnerabilities with comprehensive detection
Author: Peace Stephen (Tech Lead)
Description: Specialized hunter for arithmetic vulnerabilities in smart contracts
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


class IntegerPattern(Enum):
    UNCHECKED_ADD = "unchecked_add"
    UNCHECKED_SUB = "unchecked_sub"
    UNCHECKED_MUL = "unchecked_mul"
    UNCHECKED_DIV = "unchecked_div"
    SAFE_MATH = "safe_math"
    CASTING_OVERFLOW = "casting_overflow"
    USER_IMPORT = "user_import"
    UNDERFLOW = "underflow"
    OVERFLOW = "overflow"
    ZERO_DIVISION = "zero_division"
    SIGNED_UNSIGNED = "signed_unsigned"
    SHIFT_OVERFLOW = "shift_overflow"
    EXCESSIVE_PRECISION = "excessive_precision"


class IntegerSeverity(Enum):
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
class IntegerFinding:
    pattern: IntegerPattern
    severity: IntegerSeverity
    function: str
    line_number: int
    description: str
    recommendation: str
    cvss_score: float = 0.0
    cwe_id: str = ""
    status: VulnerabilityStatus = VulnerabilityStatus.PENDING
    impact: str = ""
    vulnerable_expression: str = ""
    suggested_fix: str = ""


@dataclass
class ArithmeticContext:
    operation: str
    operands: List[str] = field(default_factory=list)
    result_variable: str = ""
    line_number: int = 0
    is_in_loop: bool = False
    has_safemath: bool = False


@dataclass
class TypeInfo:
    original_type: str
    target_type: str
    can_overflow: bool
    can_underflow: bool
    bit_length: int = 256


INTEGER_PATTERNS = {
    "unchecked_add": {
        "pattern": r"\.add\s*\([^)]*\)\s*;(?!\s*\/\*)",
        "severity": "high",
        "description": "Unchecked addition using SafeMath - check result manually",
        "cvss": 7.5,
        "cwe": "CWE-190",
        "impact": "Can overflow without revert if result exceeds max uint256"
    },
    "unchecked_sub": {
        "pattern": r"\.sub\s*\([^)]*\)\s*;(?!\s*\/\*)",
        "severity": "high",
        "description": "Unchecked subtraction - can underflow",
        "cvss": 7.5,
        "cwe": "CWE-190",
        "impact": "Will revert on underflow - check before subtraction"
    },
    "unchecked_mul": {
        "pattern": r"\.mul\s*\([^)]*\)\s*;(?!\s*\/\*)",
        "severity": "high",
        "description": "Unchecked multiplication - can overflow",
        "cvss": 7.5,
        "cwe": "CWE-190",
        "impact": "Large values can overflow to unexpected results"
    },
    "unchecked_div": {
        "pattern": r"\.div\s*\([^)]*\)\s*;(?!\s*\/\*)",
        "severity": "medium",
        "description": "Unchecked division - division by zero risk",
        "cvss": 5.3,
        "cwe": "CWE-369",
        "impact": "Should check divisor is non-zero"
    },
    "unprotected_minus": {
        "pattern": r"[a-zA-Z_][a-zA-Z0-9_]*\[[^\]]+\]\s*-=\s*[a-zA-Z_][a-zA-Z0-9_]*",
        "severity": "critical",
        "description": "Direct subtraction from mapping without SafeMath - underflow possible",
        "cvss": 9.1,
        "cwe": "CWE-190",
        "impact": "Can underflow if subtracting more than stored value"
    },
    "unprotected_plus": {
        "pattern": r"[a-zA-Z_][a-zA-Z0-9_]*\[[^\]]+\]\s*\+=\s*[a-zA-Z_][a-zA-Z0-9_]*",
        "severity": "critical",
        "description": "Direct addition to mapping without SafeMath - overflow possible",
        "cvss": 9.1,
        "cwe": "CWE-190",
        "impact": "Can overflow if adding large values"
    },
    "unprotected_minus_assign": {
        "pattern": r"(balance|amount|count|value|shares|reward|debt)\s*-=\s*[a-zA-Z_][a-zA-Z0-9_]*",
        "severity": "critical",
        "description": "Variable subtraction without SafeMath - underflow risk",
        "cvss": 9.1,
        "cwe": "CWE-190",
        "impact": "Underflow can wrap to max uint256"
    },
    "unprotected_plus_assign": {
        "pattern": r"(balance|amount|count|value|shares|reward|debt)\s*\+=\s*[a-zA-Z_][a-zA-Z0-9_]*",
        "severity": "critical",
        "description": "Variable addition without SafeMath - overflow risk",
        "cvss": 9.1,
        "cwe": "CWE-190",
        "impact": "Overflow can wrap to unexpected value"
    },
    "uint256_cast": {
        "pattern": r"uint256\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",
        "severity": "medium",
        "description": "Casting to uint256 - check for negative values",
        "cvss": 5.3,
        "cwe": "CWE-195",
        "impact": "Casting negative int to uint wraps to huge value"
    },
    "int_to_uint": {
        "pattern": r"uint\d*\s*\(\s*int\d*\s*\w+\s*\)",
        "severity": "high",
        "description": "Signed to unsigned conversion - dangerous if value negative",
        "cvss": 8.0,
        "cwe": "CWE-195",
        "impact": "Negative values become huge positive numbers"
    },
    "uint_to_int": {
        "pattern": r"int\d*\s*\(\s*uint\d*\s*\w+\s*\)",
        "severity": "medium",
        "description": "Unsigned to signed conversion - possible overflow",
        "cvss": 5.3,
        "cwe": "CWE-195",
        "impact": "Large uint may exceed int max"
    },
    "downcast": {
        "pattern": r"uint8\s*\(\s*\w+\s*\)|uint16\s*\(\s*\w+\s*\)|uint32\s*\(\s*\w+\s*\)",
        "severity": "high",
        "description": "Downcasting to smaller uint type - overflow possible",
        "cvss": 8.0,
        "cwe": "CWE-190",
        "impact": "Value can overflow when cast to smaller type"
    },
    "loop_counter": {
        "pattern": r"for\s*\([^)]*i\s*\+\+|i\s*<|i\s*-=\s*1\)",
        "severity": "medium",
        "description": "Loop counter manipulation - can cause infinite loop or overflow",
        "cvss": 5.3,
        "cwe": "CWE-834",
        "impact": "Counter can overflow in long-running loops"
    },
    "unbounded_loop": {
        "pattern": r"for\s*\([^)]*;\s*[a-zA-Z_][a-zA-Z0-9_]*\.length\s*\)",
        "severity": "medium",
        "description": "Unbounded loop over array - potential DOS",
        "cvss": 5.3,
        "cwe": "CWE-400",
        "impact": "Gas exhaustion on large arrays"
    },
    "multiplication_before": {
        "pattern": r"\w+\s*\*\s*\w+\s*\/\s*\w+",
        "severity": "medium",
        "description": "Multiplication before division - precision loss",
        "cvss": 4.3,
        "cwe": "CWE-190",
        "impact": "Can lose precision in calculations"
    },
    "addition_overflow": {
        "pattern": r"balance\s*\+\s*amount|value\s*\+\s*reward",
        "severity": "critical",
        "description": "Balance/value addition without SafeMath",
        "cvss": 9.1,
        "cwe": "CWE-190",
        "impact": "Can overflow and lose funds"
    },
    "subtraction_underflow": {
        "pattern": r"balance\s*-\s*amount|available\s*-\s*requested",
        "severity": "critical",
        "description": "Balance subtraction without check - underflow",
        "cvss": 9.1,
        "cwe": "CWE-190",
        "impact": "Can underflow and revert entire transaction"
    },
    "shift_left": {
        "pattern": r"<<\s*\d+|<<\s*\w+",
        "severity": "high",
        "description": "Bit shift without bounds check - overflow",
        "cvss": 8.0,
        "cwe": "CWE-190",
        "impact": "Shift by large amount overflows"
    },
    "shift_right": {
        "pattern": r">>\s*\d+",
        "severity": "medium",
        "description": "Right shift of signed value",
        "cvss": 5.3,
        "cwe": "CWE-197",
        "impact": "Sign extension on signed values"
    },
    "pow_function": {
        "pattern": r"\*\*\s*\d+|pow\s*\(\s*\w+\s*,\s*\d+\s*\)",
        "severity": "high",
        "description": "Exponentiation without overflow check",
        "cvss": 8.0,
        "cwe": "CWE-190",
        "impact": "Exp can cause overflow"
    },
    "max_value": {
        "pattern": r"type\s*\(\s*uint\d+\s*\)\s*\.\s*max",
        "severity": "info",
        "description": "Using type(uintN).max - be aware of overflow",
        "cvss": 1.0,
        "cwe": "CWE-190",
        "impact": "Informational - just need awareness"
    },
    "gas_loop": {
        "pattern": r"while\s*\([^)]*<\s*\w+\.length\s*\)",
        "severity": "high",
        "description": "While loop over dynamic array - gas DOS",
        "cvss": 7.5,
        "cwe": "CWE-400",
        "impact": "Can use all gas on large arrays"
    },
    "array_length": {
        "pattern": r"\.push\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",
        "severity": "medium",
        "description": "Push without bound check - array size limit",
        "cvss": 5.3,
        "cwe": "CWE-190",
        "impact": "Array can grow unbounded"
    },
    "fee_calculation": {
        "pattern": r"fee\s*=\s*\w+\s*\*\s*\d+|amount\s*\*\s*fee\s*\/",
        "severity": "high",
        "description": "Fee calculation without SafeMath - precision loss",
        "cvss": 7.5,
        "cwe": "CWE-190",
        "impact": "Fee calculation can lose precision or overflow"
    },
    "reward_vesting": {
        "pattern": r"released\s*\+=|vested\s*\+=|claimable\s*\+=",
        "severity": "high",
        "description": "Vesting calculation without overflow check",
        "cvss": 8.0,
        "cwe": "CWE-190",
        "impact": "Can overflow total vested amount"
    },
    "division_truncation": {
        "pattern": r"\/\s*\w+|\/\s*\d+",
        "severity": "medium",
        "description": "Integer division truncates - precision loss",
        "cvss": 4.3,
        "cwe": "CWE-190",
        "impact": "Fractional results lost"
    },
    "require_balance": {
        "pattern": r"require\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*>\s*=\s*\w+|require\s*\(\s*\w+\s*>=\s*[a-zA-Z_][a-zA-Z0-9_]*\)",
        "severity": "low",
        "description": "Using require for balance check - good practice",
        "cvss": 0.0,
        "cwe": "",
        "impact": "This is a safe pattern"
    },
    "unchecked_return": {
        "pattern": r"require\s*\(\s*\w+\s*\+",
        "severity": "high",
        "description": "Require with addition inside - overflow in check",
        "cvss": 7.5,
        "cwe": "CWE-190",
        "impact": "Overflow in require can pass invalid states"
    },
    "timestamp": {
        "pattern": r"block\.timestamp\s*\+\s*\d+",
        "severity": "medium",
        "description": "Timestamp addition for deadlines - check overflow",
        "cvss": 5.3,
        "cwe": "CWE-190",
        "impact": "Very large timestamps can overflow"
    },
    "block_gas_limit": {
        "pattern": r"gasleft\s*\(\s*\)\s*<\s*|gas\s*<\s*",
        "severity": "medium",
        "description": "Gas checks for loop termination",
        "cvss": 5.3,
        "cwe": "CWE-400",
        "impact": "Can fail if block fills"
    },
    "proxy_overhead": {
        "pattern": r"data\.length\s*\+\s*\d+",
        "severity": "low",
        "description": "Proxy calldata size calculation",
        "cvss": 2.0,
        "cwe": "",
        "impact": "Should use SafeMath for proxy"
    },
    "allocation": {
        "pattern": r"new\s+\w+\[\s*\w+\s*\*",
        "severity": "critical",
        "description": "Array allocation with multiplication - overflow",
        "cvss": 9.1,
        "cwe": "CWE-190",
        "impact": "Can allocate tiny array or overflow"
    }
}


class IntegerOverflowDetector:
    """Detect integer overflow vulnerability patterns"""
    
    def __init__(self):
        self.patterns = INTEGER_PATTERNS
    
    def detect(self, code: str) -> List[IntegerFinding]:
        findings = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for name, info in self.patterns.items():
                if re.search(info["pattern"], line, re.IGNORECASE):
                    finding = self._create_finding(name, info, line, i)
                    if finding:
                        findings.append(finding)
        
        return findings
    
    def _create_finding(self, name: str, info: Dict, line: str, line_num: int) -> Optional[IntegerFinding]:
        return IntegerFinding(
            pattern=IntegerPattern[name.upper()],
            severity=IntegerSeverity[info["severity"].upper()],
            function=self._extract_function(line),
            line_number=line_num,
            description=info["description"],
            recommendation=self._get_recommendation(name),
            cvss_score=info.get("cvss", 0.0),
            cwe_id=info.get("cwe", ""),
            status=VulnerabilityStatus.CONFIRMED if info.get("cvss", 0) > 0 else VulnerabilityStatus.PENDING,
            impact=info.get("impact", ""),
            vulnerable_expression=line.strip()[:100],
            suggested_fix=self._get_fix(name)
        )
    
    def _extract_function(self, line: str) -> str:
        match = re.search(r"function\s+(\w+)", line)
        return match.group(1) if match else "global"
    
    def _get_recommendation(self, pattern_name: str) -> str:
        recommendations = {
            "unchecked_add": "Use SafeMath.add() or upgrade to Solidity 0.8+",
            "unchecked_sub": "Use SafeMath.sub() or upgrade to Solidity 0.8+",
            "unchecked_mul": "Use SafeMath.mul() or upgrade to Solidity 0.8+",
            "unchecked_div": "Check divisor is non-zero before division",
            "unprotected_minus": "Use SafeMath.sub() with underflow check",
            "unprotected_plus": "Use SafeMath.add() with overflow check",
            "unprotected_minus_assign": "Use -= with SafeMath or Solidity 0.8+",
            "unprotected_plus_assign": "Use += with SafeMath or Solidity 0.8+",
            "uint256_cast": "Add require(value >= 0) before cast",
            "int_to_uint": "Check value is >= 0 before cast",
            "uint_to_int": "Ensure value < 2^255 before cast",
            "downcast": "Verify value fits in target type before cast",
            "loop_counter": "Use checked loop counters",
            "unbounded_loop": "Consider pagination or limits",
            "multiplication_before": "Divide before multiply for precision",
            "addition_overflow": "Use SafeMath.add() for balances",
            "subtraction_underflow": "Check balance >= amount before subtract",
            "shift_left": "Check shift amount < 256",
            "shift_right": "Use unsigned types for right shift",
            "pow_function": "Use SafeMath.pow() or check exponent",
            "max_value": "This is informational - be aware",
            "gas_loop": "Add maximum iteration limits",
            "array_length": "Implement array size limits",
            "fee_calculation": "Use SafeMath for fee calculations",
            "reward_vesting": "Use SafeMath for vesting",
            "division_truncation": "Be aware of truncation or use FixedPoint",
            "unchecked_return": "Move addition outside require",
            "timestamp": "Check deadline doesn't overflow",
            "block_gas_limit": "Account for block gas limits",
            "allocation": "Verify size * element_size won't overflow"
        }
        return recommendations.get(pattern_name, "Use SafeMath or Solidity 0.8+ checked arithmetic")
    
    def _get_fix(self, pattern_name: str) -> str:
        fixes = {
            "unprotected_plus": "balances[user] = balances[user].add(amount);",
            "unprotected_minus": "require(balance >= amount); balances[user] = balances[user].sub(amount);",
            "unchecked_add": "result = a.add(b); // instead of a + b",
            "int_to_uint": "require(intValue >= 0); uint256 u = uint256(intValue);"
        }
        return fixes.get(pattern_name, "Review and fix manually")


class SafeMathChecker:
    """Check for SafeMath usage and Solidity version"""
    
    def __init__(self):
        self.safe_math_patterns = [
            "SafeMath",
            "@openzeppelin/contracts/utils/SafeMath.sol",
            "using SafeMath for uint256;",
            "using SafeMath for uint;",
            ".add(",
            ".sub(",
            ".mul(",
            ".div(",
            ".mod("
        ]
        
        self.solidity_08_patterns = [
            r"pragma\s+solidity\s+\^0\.[89]",
            r"pragma\s+solidity\s+0\.[89]\.",
            r"pragma\s+solidity\s+>=0\.8"
        ]
    
    def check(self, code: str) -> Dict[str, Any]:
        uses_safe_math = any(pattern in code for pattern in self.safe_math_patterns)
        
        uses_08 = any(re.search(pattern, code) for pattern in self.solidity_08_patterns)
        
        solidity_version = self._extract_version(code)
        
        is_safe = uses_safe_math or uses_08 or solidity_version >= (0, 8)
        
        return {
            "uses_safe_math": uses_safe_math,
            "uses_0_8_or_higher": uses_08,
            "solidity_version": f"0.{solidity_version[1]}" if solidity_version else "unknown",
            "is_safe": is_safe,
            "recommendation": self._get_recommendation(is_safe, solidity_version)
        }
    
    def _extract_version(self, code: str) -> Tuple[int, int]:
        match = re.search(r"pragma\s+solidity\s+(\d+)\.(\d+)", code)
        if match:
            try:
                return (int(match.group(1)), int(match.group(2)))
            except ValueError:
                pass
        return (0, 0)
    
    def _get_recommendation(self, is_safe: bool, version: Tuple[int, int]) -> str:
        if is_safe:
            return "Contract appears to use safe arithmetic"
        elif version >= (0, 8):
            return "Upgrade to Solidity 0.8+ for built-in overflow checks"
        else:
            return "Use OpenZeppelin SafeMath library"


class ArithmeticAnalyzer:
    """Analyze arithmetic operations for vulnerabilities"""
    
    def __init__(self):
        self._dangerous_patterns = []
    
    def analyze(self, code: str) -> List[ArithmeticContext]:
        contexts = []
        
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if "+=" in line or "-=" in line or "*=" in line:
                context = self._analyze_operation(line, i + 1)
                if context:
                    contexts.append(context)
        
        return contexts
    
    def _analyze_operation(self, line: str, line_num: int) -> Optional[ArithmeticContext]:
        op = None
        if "+=" in line:
            op = "add"
        elif "-=" in line:
            op = "sub"
        elif "*=" in line:
            op = "mul"
        
        if not op:
            return None
        
        return ArithmeticContext(
            operation=op,
            operands=line.strip().split(op)[1:] if op in line else [],
            line_number=line_num,
            is_in_loop=self._is_in_loop(line),
            has_safemath=".add" in line or ".sub" in line or ".mul" in line
        )
    
    def _is_in_loop(self, line: str) -> bool:
        return "for" in line.lower() or "while" in line.lower()


class TypeBoundsChecker:
    """Check for type boundary issues"""
    
    TYPE_BOUNDS = {
        "uint8": (0, 255),
        "uint16": (0, 65535),
        "uint32": (0, 4294967295),
        "uint64": (0, 2**64 - 1),
        "uint128": (0, 2**128 - 1),
        "uint256": (0, 2**256 - 1),
        "int8": (-128, 127),
        "int16": (-32768, 32767),
        "int32": (-2147483648, 2147483647),
        "int64": (-2**63, 2**63 - 1),
        "int128": (-2**127, 2**127 - 1),
        "int256": (-2**255, 2**255 - 1)
    }
    
    def check_type_cast(self, code: str) -> List[Dict[str, Any]]:
        issues = []
        
        for type_name, (min_val, max_val) in self.TYPE_BOUNDS.items():
            pattern = rf"{type_name}\s*\(\s*(\w+)\s*\)"
            
            for match in re.finditer(pattern, code):
                var_name = match.group(1)
                issues.append({
                    "type": type_name,
                    "variable": var_name,
                    "min": min_val,
                    "max": max_val,
                    "position": match.start()
                })
        
        return issues


class IntegerOverflowHunter:
    """Main integer overflow vulnerability hunter"""
    
    def __init__(self):
        self.detector = IntegerOverflowDetector()
        self.safe_checker = SafeMathChecker()
        self.arithmetic_analyzer = ArithmeticAnalyzer()
        self.type_checker = TypeBoundsChecker()
        
        logger.info("✅ Integer Overflow Hunter initialized")
    
    def hunt(self, code: str) -> Dict[str, Any]:
        findings = self.detector.detect(code)
        safe_status = self.safe_checker.check(code)
        arithmetic_contexts = self.arithmetic_analyzer.analyze(code)
        type_issues = self.type_checker.check_type_cast(code)
        
        vulnerabilities = []
        
        for finding in findings:
            vulnerabilities.append({
                "type": "integer_overflow",
                "pattern": finding.pattern.value,
                "severity": finding.severity.value,
                "function": finding.function,
                "line": finding.line_number,
                "description": finding.description,
                "recommendation": finding.recommendation,
                "cvss": finding.cvss_score,
                "cwe": finding.cwe_id,
                "impact": finding.impact,
                "vulnerable_code": finding.vulnerable_expression,
                "suggested_fix": finding.suggested_fix
            })
        
        return {
            "vulnerabilities": vulnerabilities,
            "safe_math_status": safe_status,
            "arithmetic_contexts": [{
                "operation": ctx.operation,
                "line": ctx.line_number,
                "in_loop": ctx.is_in_loop,
                "has_safemath": ctx.has_safemath
            } for ctx in arithmetic_contexts],
            "type_issues": type_issues,
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
    
    def check_safe_math(self, code: str) -> Dict[str, Any]:
        return self.safe_checker.check(code)


def hunt_integer_overflow(code: str) -> Dict[str, Any]:
    """Entry point for integer overflow hunting"""
    hunter = IntegerOverflowHunter()
    return hunter.hunt(code)


def check_safe_arithmetic(code: str) -> Dict[str, Any]:
    """Quick check for safe arithmetic usage"""
    checker = SafeMathChecker()
    return checker.check(code)


def analyze_arithmetic(code: str) -> List[Dict[str, Any]]:
    """Analyze arithmetic operations"""
    analyzer = ArithmeticAnalyzer()
    return [{"operation": ctx.operation, "line": ctx.line_number} for ctx in analyzer.analyze(code)]