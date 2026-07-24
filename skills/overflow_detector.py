from __future__ import annotations

import re
import logging
from typing import List, Dict, Optional, Tuple, Set

from .skill_registry import Skill, SkillStatus

logger = logging.getLogger(__name__)

__all__ = ["register_skill", "detect", "OverflowDetector"]

PRAGMA_REGEX = re.compile(
    r'pragma\s+solidity\s*\^?([\d.]+)',
    re.MULTILINE
)

FUNCTION_REGEX = re.compile(
    r'function\s+(\w+)\s*\(([^)]*)\)\s*'
    r'((?:public|external|internal|private)\s*)'
    r'((?:view|pure|payable|virtual|override|nonpayable)\s*)*'
    r'((?:\w+\s*)*)',
    re.MULTILINE
)

ARITHMETIC_PATTERNS = {
    'addition': [
        re.compile(r'(\w[\w.]*)\s*\+\s*([^;]+)', re.MULTILINE),
        re.compile(r'(\w[\w.]*)\s*\+=\s*([^;]+)', re.MULTILINE),
    ],
    'subtraction': [
        re.compile(r'(\w[\w.]*)\s*-\s*([^;]+)', re.MULTILINE),
        re.compile(r'(\w[\w.]*)\s*-=\s*([^;]+)', re.MULTILINE),
    ],
    'multiplication': [
        re.compile(r'(\w[\w.]*)\s*\*\s*([^;]+)', re.MULTILINE),
        re.compile(r'(\w[\w.]*)\s*\*=\s*([^;]+)', re.MULTILINE),
    ],
    'division': [
        re.compile(r'(\w[\w.]*)\s*/\s*([^;]+)', re.MULTILINE),
        re.compile(r'(\w[\w.]*)\s*/=\s*([^;]+)', re.MULTILINE),
    ],
    'modulo': [
        re.compile(r'(\w[\w.]*)\s*%\s*([^;]+)', re.MULTILINE),
    ],
}

UNCHECKED_BLOCK_REGEX = re.compile(
    r'unchecked\s*\{',
    re.MULTILINE
)

UNCHECKED_CONTENT_REGEX = re.compile(
    r'unchecked\s*\{([^}]+)\}',
    re.DOTALL
)

SAFEMATH_PATTERNS = [
    re.compile(r'SafeMath', re.MULTILINE),
    re.compile(r'using\s+SafeMath', re.MULTILINE),
    re.compile(r'\.add\(', re.MULTILINE),
    re.compile(r'\.sub\(', re.MULTILINE),
    re.compile(r'\.mul\(', re.MULTILINE),
    re.compile(r'\.div\(', re.MULTILINE),
    re.compile(r'\.mod\(', re.MULTILINE),
]

OVERFLOW_PRONE_VARS = re.compile(
    r'(?:balance|totalSupply|amount|value|credit|debit|debt|reserve|liquidity|reward|stake|deposit|withdrawal)\w*',
    re.IGNORECASE
)

TOKEN_BALANCE_OPS = [
    re.compile(r'balances?\s*\[\s*\w+\s*\]\s*(?:\+|-|\*|/|=\s*\w+\s*(?:\+|-|\*|/))', re.MULTILINE),
    re.compile(r'totalSupply\s*(?:\+|-|\*|/)', re.MULTILINE),
    re.compile(r'_totalSupply\s*(?:\+|-|\*|/)', re.MULTILINE),
    re.compile(r'allowances?\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\]\s*(?:\+|-|\*|/)', re.MULTILINE),
]

LOOP_VAR_PATTERNS = [
    re.compile(r'for\s*\(\s*(?:uint\d*\s+)?(\w+)\s*=', re.MULTILINE),
    re.compile(r'while\s*\([^)]*\)', re.MULTILINE),
]

LOOP_BODY_ARITHMETIC = re.compile(
    r'(?:\w+\s*\+=\s*\w+|\w+\s*-=\s*\w+|\w+\s*\*\=\s*\w+)',
    re.MULTILINE
)

PRECISION_LOSS_PATTERNS = [
    re.compile(r'(\w+)\s*\*\s*(\w+)\s*/\s*(\w+)', re.MULTILINE),
    re.compile(r'(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)', re.MULTILINE),
    re.compile(r'(\w+)\s*\*\s*(\d+)\s*/\s*(\d+)', re.MULTILINE),
]

SAFE_CAST_PATTERNS = [
    re.compile(r'SafeCast', re.MULTILINE),
    re.compile(r'toUint\d+\s*\(', re.MULTILINE),
    re.compile(r'toInt\d+\s*\(', re.MULTILINE),
    re.compile(r'SafeCast256', re.MULTILINE),
    re.compile(r'constrain\s*\(', re.MULTILINE),
]

OVERFLOW_CHECK_PATTERNS = [
    re.compile(r'require\s*\(\s*\w+\s*>=\s*\w+', re.MULTILINE),
    re.compile(r'require\s*\(\s*\w+\s*<=\s*\w+', re.MULTILINE),
    re.compile(r'require\s*\(\s*\w+\s*>\s*\w+', re.MULTILINE),
    re.compile(r'require\s*\(\s*\w+\s*<\s*\w+', re.MULTILINE),
    re.compile(r'assert\s*\(\s*\w+\s*>=', re.MULTILINE),
]

INT_TYPE_REGEX = re.compile(r'\b(?:u?int\d*|uint)\b')

USER_INPUT_PATTERNS = [
    re.compile(r'msg\.value', re.MULTILINE),
    re.compile(r'msg\.data', re.MULTILINE),
    re.compile(r'calldata', re.MULTILINE),
    re.compile(r'block\.\w+', re.MULTILINE),
]


class OverflowDetector:
    def __init__(self):
        self.findings: List[Dict] = []
        self.code_lines: List[str] = []
        self.full_code: str = ''
        self.pragma_version: Optional[str] = None
        self.is_pre_08: bool = False

    def detect(self, code: str, context: dict = None) -> List[Dict]:
        self.findings = []
        self.code_lines = code.split('\n')
        self.full_code = code
        context = context or {}

        self._check_pragma_version(code)
        self._find_unchecked_blocks(code)
        self._analyze_arithmetic_operations(code)
        self._check_safe_math_usage(code)
        self._detect_precision_loss(code)
        self._detect_unchecked_increment(code)

        logger.info(f"Overflow detector found {len(self.findings)} issues")
        return self.findings

    def _check_pragma_version(self, code: str) -> None:
        match = PRAGMA_REGEX.search(code)
        if match:
            version = match.group(1)
            self.pragma_version = version
            major, minor = 0, 0
            parts = version.split('.')
            if len(parts) >= 2:
                major = int(parts[0])
                minor = int(parts[1])
            self.is_pre_08 = major == 0 and minor < 8
        else:
            self.is_pre_08 = True
            self.pragma_version = None

    def _find_unchecked_blocks(self, code: str) -> None:
        for match in UNCHECKED_CONTENT_REGEX.finditer(code):
            block_content = match.group(1)
            block_line = code[:match.start()].count('\n') + 1

            unsafe_ops = []
            for op_type, patterns in ARITHMETIC_PATTERNS.items():
                for pattern in patterns:
                    for op_match in pattern.finditer(block_content):
                        var_name = op_match.group(1)
                        if OVERFLOW_PRONE_VARS.search(var_name):
                            unsafe_ops.append((op_type, op_match.group()))

            if unsafe_ops:
                for op_type, op_text in unsafe_ops:
                    self.findings.append({
                        'type': 'arithmetic',
                        'category': 'arithmetic',
                        'severity': 'high',
                        'cwe_id': 'CWE-190',
                        'cwe_name': 'Integer Overflow or Underflow',
                        'description': f'Unchecked {op_type} on overflow-prone variable: {op_text.strip()}. '
                                       f'Arithmetic in unchecked block bypasses overflow protection.',
                        'location': {
                            'line': block_line,
                            'column': block_content.find(op_text) + 1 if op_text in block_content else 0,
                            'match': op_text.strip(),
                        },
                        'remediation': 'Remove unchecked block or add manual overflow checks. '
                                       'Use Solidity 0.8+ arithmetic without unchecked.',
                        'confidence': 0.85,
                    })

    def _analyze_arithmetic_operations(self, code: str) -> None:
        if not self.is_pre_08:
            has_safemath = any(p.search(code) for p in SAFEMATH_PATTERNS)
            if has_safemath:
                return

        for func_match in FUNCTION_REGEX.finditer(code):
            func_name = func_match.group(1)
            func_start = code[:func_match.start()].count('\n') + 1
            func_body = self._get_function_body(code, func_match)
            if not func_body:
                continue

            func_line_count = func_body.count('\n')
            in_unchecked = self._is_in_unchecked_block(code, func_match.start())

            for op_type, patterns in ARITHMETIC_PATTERNS.items():
                for pattern in patterns:
                    for op_match in pattern.finditer(func_body):
                        var_name = op_match.group(1)
                        op_text = op_match.group()
                        line_in_func = func_body[:op_match.start()].count('\n')
                        actual_line = func_start + line_in_func

                        is_balance_op = bool(OVERFLOW_PRONE_VARS.search(var_name))
                        has_safe_math = self._check_safe_math_in_context(func_body, op_match.start())
                        has_overflow_check = self._check_overflow_guard(func_body, op_match.start())
                        is_user_input = self._has_user_input_nearby(func_body, op_match.start())

                        if in_unchecked:
                            severity = 'high'
                            confidence = 0.88
                        elif self.is_pre_08 and not has_safe_math and is_balance_op:
                            severity = 'critical' if op_type in ('addition', 'subtraction') else 'high'
                            confidence = 0.92
                        elif is_user_input and is_balance_op:
                            severity = 'critical' if self.is_pre_08 else 'high'
                            confidence = 0.90
                        elif is_balance_op and not has_overflow_check:
                            severity = 'high'
                            confidence = 0.75
                        else:
                            continue

                        type_info = self._get_var_type(code, var_name)
                        if type_info and not self._is_safe_type(type_info, op_type):
                            severity = 'critical' if self.is_pre_08 else 'high'
                            confidence = min(confidence + 0.1, 0.99)

                        self.findings.append({
                            'type': 'arithmetic',
                            'category': 'arithmetic',
                            'severity': severity,
                            'cwe_id': 'CWE-190' if 'overflow' in op_type.lower() or op_type in ('addition', 'multiplication') else 'CWE-191',
                            'cwe_name': 'Integer Overflow or Underflow',
                            'description': f'Potential integer {op_type} overflow/underflow in function \'{func_name}\': '
                                           f'{op_text.strip()}. '
                                           f'{"No SafeMath library used. " if self.is_pre_08 and not has_safe_math else ""}'
                                           f'{"In unchecked block. " if in_unchecked else ""}'
                                           f'{"User-controlled value involved. " if is_user_input else ""}',
                            'location': {
                                'line': actual_line,
                                'column': 0,
                                'match': op_text.strip(),
                            },
                            'remediation': f'Use SafeMath for {op_type} or upgrade to Solidity 0.8+. '
                                           f'Add overflow checks before arithmetic.',
                            'confidence': confidence,
                        })

    def _check_safe_math_usage(self, code: str) -> None:
        if not self.is_pre_08:
            return

        has_safemath = any(p.search(code) for p in SAFEMATH_PATTERNS)
        if has_safemath:
            return

        has_any_arithmetic = False
        for patterns in ARITHMETIC_PATTERNS.values():
            for pattern in patterns:
                if pattern.search(code):
                    has_any_arithmetic = True
                    break
            if has_any_arithmetic:
                break

        if has_any_arithmetic:
            self.findings.append({
                'type': 'arithmetic',
                'category': 'arithmetic',
                'severity': 'high',
                'cwe_id': 'CWE-190',
                'cwe_name': 'Integer Overflow or Underflow',
                'description': f'Contract uses Solidity {self.pragma_version or "<0.8.0"} without SafeMath library. '
                               f'All arithmetic operations are vulnerable to overflow/underflow.',
                'location': {
                    'line': 1,
                    'column': 0,
                    'match': f'pragma solidity {self.pragma_version or "^0.7.0"}',
                },
                'remediation': 'Add "using SafeMath for uint256;" or upgrade to Solidity 0.8+ which has built-in overflow checks.',
                'confidence': 0.88,
            })

    def _detect_precision_loss(self, code: str) -> None:
        for pattern in PRECISION_LOSS_PATTERNS:
            for match in pattern.finditer(code):
                line_num = code[:match.start()].count('\n') + 1
                op_text = match.group()

                if '*' in op_text and '/' in op_text:
                    mul_pos = op_text.find('*')
                    div_pos = op_text.find('/')
                    if mul_pos < div_pos:
                        severity = 'medium'
                        confidence = 0.7
                        self.findings.append({
                            'type': 'arithmetic',
                            'category': 'arithmetic',
                            'severity': severity,
                            'cwe_id': 'CWE-190',
                            'cwe_name': 'Integer Overflow or Underflow',
                            'description': f'Precision loss: multiplication before division at line {line_num}. '
                                           f'{op_text.strip()} truncates intermediate result.',
                            'location': {
                                'line': line_num,
                                'column': match.start() - code[:match.start()].rfind('\n'),
                                'match': op_text.strip(),
                            },
                            'remediation': 'Rearrange to divide first or use mulDiv/fixed-point libraries to preserve precision.',
                            'confidence': confidence,
                        })

    def _detect_unchecked_increment(self, code: str) -> None:
        for loop_match in LOOP_VAR_PATTERNS[0].finditer(code):
            var_name = loop_match.group(1)
            loop_start = code[:loop_match.start()].count('\n') + 1
            loop_body = self._get_loop_body(code, loop_match.start())

            if not loop_body:
                continue

            for pattern in LOOP_BODY_ARITHMETIC:
                for op_match in pattern.finditer(loop_body):
                    op_text = op_match.group()
                    if var_name in op_text:
                        has_check = False
                        for cpattern in OVERFLOW_CHECK_PATTERNS:
                            if cpattern.search(loop_body):
                                has_check = True
                                break

                        if not has_check:
                            line_in_loop = loop_body[:op_match.start()].count('\n')
                            self.findings.append({
                                'type': 'arithmetic',
                                'category': 'arithmetic',
                                'severity': 'medium',
                                'cwe_id': 'CWE-190',
                                'cwe_name': 'Integer Overflow or Underflow',
                                'description': f'Loop variable \'{var_name}\' modified without overflow check: '
                                               f'{op_text.strip()}. Potential infinite loop or wrap-around.',
                                'location': {
                                    'line': loop_start + line_in_loop,
                                    'column': 0,
                                    'match': op_text.strip(),
                                },
                                'remediation': 'Add overflow check for loop variable or use Solidity 0.8+ unchecked with bounds validation.',
                                'confidence': 0.72,
                            })

    def _get_function_body(self, code: str, func_match: re.Match) -> str:
        func_start = code.find('{', func_match.start())
        if func_start == -1:
            return ''
        brace_count = 0
        for ci, ch in enumerate(code[func_start:], func_start):
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    return code[func_start:ci + 1]
        return code[func_start:]

    def _get_loop_body(self, code: str, pos: int) -> str:
        brace_start = code.find('{', pos)
        if brace_start == -1:
            return ''
        brace_count = 0
        for ci, ch in enumerate(code[brace_start:], brace_start):
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    return code[brace_start:ci + 1]
        return code[brace_start:]

    def _is_in_unchecked_block(self, code: str, pos: int) -> bool:
        before = code[:pos]
        unchecked_matches = list(UNCHECKED_BLOCK_REGEX.finditer(before))
        for um in reversed(unchecked_matches):
            um_end = code.find('}', um.start())
            if um_end != -1 and um_end >= pos:
                return True
            elif um_end != -1 and um_end < pos:
                continue
        return False

    def _check_safe_math_in_context(self, func_body: str, pos: int) -> bool:
        before = func_body[:pos]
        for pattern in SAFEMATH_PATTERNS:
            if pattern.search(before):
                return True
        return False

    def _check_overflow_guard(self, func_body: str, pos: int) -> bool:
        nearby = func_body[max(0, pos - 200):pos + 200]
        for pattern in OVERFLOW_CHECK_PATTERNS:
            if pattern.search(nearby):
                return True
        return False

    def _has_user_input_nearby(self, func_body: str, pos: int) -> bool:
        nearby = func_body[max(0, pos - 300):pos + 300]
        for pattern in USER_INPUT_PATTERNS:
            if pattern.search(nearby):
                return True
        return False

    def _get_var_type(self, code: str, var_name: str) -> Optional[str]:
        type_patterns = [
            re.compile(rf'(?:uint\d*|int\d*)\s+{re.escape(var_name)}\b', re.MULTILINE),
            re.compile(rf'mapping\s*\([^)]*\)\s*(?:public\s+|private\s+|internal\s+)*{re.escape(var_name)}\b', re.MULTILINE),
        ]
        for pattern in type_patterns:
            match = pattern.search(code)
            if match:
                return match.group()
        return None

    def _is_safe_type(self, type_info: str, op_type: str) -> bool:
        if 'uint256' in type_info or 'uint' in type_info:
            return op_type in ('modulo',)
        if 'uint8' in type_info or 'uint16' in type_info:
            return False
        if 'uint128' in type_info:
            return op_type in ('division', 'modulo')
        return False


def register_skill() -> Skill:
    return Skill(
        name="overflow_detector",
        category="arithmetic",
        severity="high",
        description="Detects integer overflow/underflow vulnerabilities, unchecked arithmetic, "
                    "precision loss, and unsafe loop variable modifications in Solidity contracts.",
        cwe_id="CWE-190",
        cwe_name="Integer Overflow or Underflow",
        patterns=[r'\+\s*\w+', r'-\s*\w+', r'\*\s*\w+', r'unchecked\s*\{', r'SafeMath'],
        sinks=['balance', 'totalSupply', 'amount', 'value', 'credit', 'reserve'],
        guards=['SafeMath', 'unchecked', 'Solidity 0.8+', 'SafeCast'],
        remediation="Use Solidity 0.8+ with built-in overflow checks. If using <0.8.0, use SafeMath library. "
                    "Add manual overflow checks in unchecked blocks. Avoid multiplication before division.",
        references=[
            "https://swcregistry.readthedocs.io/en/latest/SWC-101.html",
            "https://docs.soliditylang.org/en/latest/0.8.0-breaking-changes.html",
            "https://blog.openzeppelin.com/safe-math",
        ],
        status=SkillStatus.ACTIVE,
        version="1.0.0",
        author="Solidify Security Team",
        tags={"arithmetic", "overflow", "underflow", "web3", "solidity", "safemath", "precision-loss"},
    )


def detect(code: str, context: dict = None) -> List[Dict]:
    detector = OverflowDetector()
    return detector.detect(code, context)


if __name__ == '__main__':
    sample_code = '''
pragma solidity ^0.7.0;

import "@openzeppelin/contracts/math/SafeMath.sol";

contract VulnerableToken {
    using SafeMath for uint256;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function unsafeTransfer(address to, uint256 amount) public {
        unchecked {
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }

    function calculateReward(uint256 stake, uint256 rate) public pure returns (uint256) {
        return stake * rate / 10000;
    }

    function mint(uint256 amount) public {
        totalSupply += amount;
    }

    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amounts[i];
        }
    }
}
'''
    results = detect(sample_code)
    for r in results:
        print(f"[{r['severity'].upper()}] {r['description']}")
        print(f"  Location: Line {r['location']['line']}")
        print(f"  Confidence: {r['confidence']}")
        print()
