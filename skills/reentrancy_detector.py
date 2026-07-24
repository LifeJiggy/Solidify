from __future__ import annotations

import re
import logging
from typing import List, Dict, Optional, Tuple

from .skill_registry import Skill, SkillStatus

logger = logging.getLogger(__name__)

__all__ = ["register_skill", "detect", "ReentrancyDetector"]

EXTERNAL_CALL_PATTERNS = [
    re.compile(r'\.call\{value:\s*[^}]*\}\s*\(', re.MULTILINE),
    re.compile(r'\.call\.value\(\s*[^)]*\)\s*\(', re.MULTILINE),
    re.compile(r'\.call\{data:\s*[^}]*\}\s*\(', re.MULTILINE),
    re.compile(r'\.call\(\s*abi\.encode', re.MULTILINE),
    re.compile(r'\.call\(\s*"', re.MULTILINE),
    re.compile(r'msg\.sender\.call\{value:', re.MULTILINE),
]

TRANSFER_PATTERNS = [
    re.compile(r'\.transfer\(\s*[^)]+\)', re.MULTILINE),
    re.compile(r'\.send\(\s*[^)]+\)', re.MULTILINE),
]

GUARD_PATTERNS = [
    re.compile(r'nonReentrant', re.MULTILINE),
    re.compile(r'ReentrancyGuard', re.MULTILINE),
    re.compile(r'reentrancy_guard', re.MULTILINE),
    re.compile(r'modifier\s+noReentry', re.MULTILINE),
    re.compile(r'_guardCounter\s*==', re.MULTILINE),
    re.compile(r'locked\s*==\s*false', re.MULTILINE),
]

CEI_PATTERNS = {
    'checks': [
        re.compile(r'require\s*\(', re.MULTILINE),
        re.compile(r'assert\s*\(', re.MULTILINE),
        re.compile(r'if\s*\([^)]+\)\s*(?:revert|return)', re.MULTILINE),
    ],
    'effects': [
        re.compile(r'\w+\s*=\s*[^;]+;', re.MULTILINE),
        re.compile(r'\w+\s*\+=', re.MULTILINE),
        re.compile(r'\w+\s*-=', re.MULTILINE),
        re.compile(r'\w+\s*\*=', re.MULTILINE),
        re.compile(r'\w+\s*\|=', re.MULTILINE),
        re.compile(r'delete\s+\w+', re.MULTILINE),
        re.compile(r'emit\s+\w+', re.MULTILINE),
    ],
    'interactions': [
        re.compile(r'\.call[\{(]', re.MULTILINE),
        re.compile(r'\.transfer\(', re.MULTILINE),
        re.compile(r'\.send\(', re.MULTILINE),
        re.compile(r'\.delegatecall\(', re.MULTILINE),
        re.compile(r'\.staticcall\(', re.MULTILINE),
        re.compile(r'address\([^)]+\)\.call', re.MULTILINE),
    ],
}

SENSITIVE_FUNCTIONS = [
    'withdraw', 'withdrawal', 'claimReward', 'claimRewards',
    'claim', 'redeem', 'liquidate', 'borrow', 'repay',
    'deposit', 'stake', 'unstake', 'emergencyWithdraw',
    'rescue', 'rescueTokens', 'recover', 'sweep',
    'transferOwnership', 'selfDestruct', 'destroy',
    'execute', 'executeTransaction',
]

ETH_HANDLING_FUNCTIONS = [
    'withdraw', 'withdrawal', 'claimReward', 'claim',
    'redeem', 'deposit', 'stake', 'emergencyWithdraw',
    'receive', 'fallback',
]

FUNCTION_REGEX = re.compile(
    r'function\s+(\w+)\s*\(([^)]*)\)\s*'
    r'((?:public|external|internal|private)\s*)'
    r'((?:view|pure|payable|virtual|override|nonpayable)\s*)*'
    r'((?:\w+\s*)*)',
    re.MULTILINE
)

STATE_VAR_REGEX = re.compile(
    r'(?:mapping\s*\([^)]*\)|uint\d*|int\d*|address|bool|bytes\d*|string)\s+(?:public\s+|private\s+|internal\s+|immutable\s+)*(\w+)',
    re.MULTILINE
)

BALANCE_REGEX = re.compile(
    r'(?:balance|balances|totalSupply|credit|debit|debt|amount|value)\w*',
    re.IGNORECASE
)


class ReentrancyDetector:
    def __init__(self):
        self.findings: List[Dict] = []
        self.code_lines: List[str] = []
        self.full_code: str = ''

    def detect(self, code: str, context: dict = None) -> List[Dict]:
        self.findings = []
        self.code_lines = code.split('\n')
        self.full_code = code
        context = context or {}

        self._detect_direct_reentrancy(code)
        self._detect_transfer_reentrancy(code)
        self._detect_cei_violations(code)
        self._detect_cross_function_reentrancy(code)
        self._detect_nested_external_calls(code)
        self._detect_unprotected_eth_withdrawal(code)

        logger.info(f"Reentrancy detector found {len(self.findings)} issues")
        return self.findings

    def _find_external_calls(self, code: str) -> List[Tuple[int, str, str]]:
        results = []
        for i, line in enumerate(self.code_lines, 1):
            for pattern in EXTERNAL_CALL_PATTERNS:
                for match in pattern.finditer(line):
                    results.append((i, match.group(), 'call'))
            for pattern in TRANSFER_PATTERNS:
                for match in pattern.finditer(line):
                    results.append((i, match.group(), 'transfer'))
        return results

    def _has_reentrancy_guard(self, code: str, func_name: str = '') -> bool:
        for pattern in GUARD_PATTERNS:
            if pattern.search(code):
                return True
        func_match = re.search(
            rf'function\s+{re.escape(func_name)}[^{{]*\{{[^}}]*\}}',
            code, re.DOTALL
        )
        if func_match:
            func_body = func_match.group()
            for pattern in GUARD_PATTERNS:
                if pattern.search(func_body):
                    return True
        return False

    def _check_state_update_order(self, code: str, call_locations: List[Tuple[int, str, str]]) -> List[Dict]:
        violations = []
        for line_num, call_text, call_type in call_locations:
            preceding_lines = self.code_lines[max(0, line_num - 10):line_num - 1]
            has_state_update_before = False
            for pline in preceding_lines:
                for pattern in CEI_PATTERNS['effects']:
                    if pattern.search(pline) and 'emit' not in pline:
                        has_state_update_before = True
                        break
                if has_state_update_before:
                    break

            following_lines = self.code_lines[line_num:min(len(self.code_lines), line_num + 10)]
            has_state_update_after = False
            for fline in following_lines:
                for pattern in CEI_PATTERNS['effects']:
                    if pattern.search(fline) and 'emit' not in fline:
                        has_state_update_after = True
                        break
                if has_state_update_after:
                    break

            if has_state_update_after and not has_state_update_before:
                severity = 'critical'
                if any(tf in call_text.lower() for tf in ['transfer', 'send']):
                    severity = 'high'
                violations.append({
                    'type': 'reentrancy',
                    'category': 'reentrancy',
                    'severity': severity,
                    'cwe_id': 'CWE-362',
                    'cwe_name': 'Concurrent Execution - Race Condition',
                    'description': f'State update after external {call_type} call enables reentrancy. '
                                   f'Attacker can re-enter before state is finalized.',
                    'location': {
                        'line': line_num,
                        'column': self.code_lines[line_num - 1].find(call_text) + 1 if call_text in self.code_lines[line_num - 1] else 0,
                        'match': call_text.strip(),
                    },
                    'remediation': 'Apply checks-effects-interactions pattern: update state before external calls.',
                    'confidence': 0.9,
                })
        return violations

    def _detect_direct_reentrancy(self, code: str) -> None:
        external_calls = self._find_external_calls(code)
        if not external_calls:
            return

        has_guard = self._has_reentrancy_guard(code)
        cei_violations = self._check_state_update_order(code, external_calls)

        for violation in cei_violations:
            if has_guard:
                violation['confidence'] = max(0.3, violation['confidence'] - 0.5)
                violation['description'] += ' [Mitigated by reentrancy guard]'
            self.findings.append(violation)

    def _detect_transfer_reentrancy(self, code: str) -> None:
        for i, line in enumerate(self.code_lines, 1):
            for pattern in TRANSFER_PATTERNS:
                for match in pattern.finditer(line):
                    call_text = match.group()
                    remaining_code = '\n'.join(self.code_lines[i:])
                    state_updates_after = 0
                    for epattern in CEI_PATTERNS['effects'][:5]:
                        for fmatch in epattern.finditer(remaining_code):
                            if 'emit' not in fmatch.group():
                                state_updates_after += 1

                    if state_updates_after > 0:
                        severity = 'high'
                        if '.transfer(' in call_text:
                            severity = 'medium'
                        self.findings.append({
                            'type': 'reentrancy',
                            'category': 'reentrancy',
                            'severity': severity,
                            'cwe_id': 'CWE-362',
                            'cwe_name': 'Concurrent Execution - Race Condition',
                            'description': f'External {call_text.strip()} followed by state updates. '
                                           f'Transfer/send has 2300 gas stipend limiting reentrancy but '
                                           f'cross-function reentrancy may still be possible.',
                            'location': {
                                'line': i,
                                'column': match.start() + 1,
                                'match': call_text.strip(),
                            },
                            'remediation': 'Use nonReentrant modifier or CEI pattern. Consider using call() with gas limit instead of transfer().',
                            'confidence': 0.6 if '.transfer(' in call_text else 0.85,
                        })

    def _detect_cei_violations(self, code: str) -> None:
        function_matches = list(FUNCTION_REGEX.finditer(code))
        for func_match in function_matches:
            func_name = func_match.group(1)
            func_start = code[:func_match.start()].count('\n') + 1

            brace_count = 0
            func_body_start = code.find('{', func_match.start())
            if func_body_start == -1:
                continue

            func_body_end = func_body_start
            for ci, ch in enumerate(code[func_body_start:], func_body_start):
                if ch == '{':
                    brace_count += 1
                elif ch == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        func_body_end = ci
                        break

            func_body = code[func_body_start:func_body_end + 1]
            func_line_count = func_body.count('\n')

            interaction_lines = []
            effect_lines = []

            for pi, pattern in enumerate(CEI_PATTERNS['interactions']):
                for match in pattern.finditer(func_body):
                    line_in_func = func_body[:match.start()].count('\n')
                    interaction_lines.append((line_in_func, match.group(), pi))

            for pi, pattern in enumerate(CEI_PATTERNS['effects']):
                for match in pattern.finditer(func_body):
                    line_in_func = func_body[:match.start()].count('\n')
                    effect_lines.append((line_in_func, match.group(), pi))

            if not interaction_lines:
                continue

            has_guard = self._has_reentrancy_guard(code, func_name)
            if has_guard:
                continue

            interaction_lines.sort(key=lambda x: x[0])
            effect_lines.sort(key=lambda x: x[0])

            for int_line, int_text, _ in interaction_lines:
                for eff_line, eff_text, _ in effect_lines:
                    if eff_line > int_line and 'emit' not in eff_text:
                        balance_affected = bool(BALANCE_REGEX.search(eff_text))
                        if balance_affected:
                            confidence = 0.92
                            severity = 'critical'
                            self.findings.append({
                                'type': 'reentrancy',
                                'category': 'reentrancy',
                                'severity': severity,
                                'cwe_id': 'CWE-362',
                                'cwe_name': 'Concurrent Execution - Race Condition',
                                'description': f'CEI violation in function \'{func_name}\': '
                                               f'state update \'{eff_text.strip()}\' occurs after '
                                               f'external call \'{int_text.strip()}\'.',
                                'location': {
                                    'line': func_start + int_line,
                                    'column': 0,
                                    'match': int_text.strip(),
                                },
                                'remediation': 'Move state updates before external calls. Use checks-effects-interactions pattern.',
                                'confidence': confidence,
                            })
                            break

    def _detect_cross_function_reentrancy(self, code: str) -> None:
        function_matches = list(FUNCTION_REGEX.finditer(code))
        eth_funcs = []
        other_state_funcs = []

        for func_match in function_matches:
            func_name = func_match.group(1)
            func_text = func_match.group(0)
            if any(name in func_name.lower() for name in ETH_HANDLING_FUNCTIONS):
                eth_funcs.append((func_name, func_text, func_match.start()))
            elif any(name in func_name.lower() for name in ['set', 'update', 'change', 'add', 'remove', 'delete', 'mint', 'burn']):
                other_state_funcs.append((func_name, func_text, func_match.start()))

        if not eth_funcs or not other_state_funcs:
            return

        has_guard = self._has_reentrancy_guard(code)
        if has_guard:
            return

        for func_name, func_text, _ in eth_funcs:
            if '.call' in func_text or '.transfer' in func_text:
                for other_name, other_text, _ in other_state_funcs:
                    if 'require' in other_text or 'onlyOwner' in other_text or 'onlyAdmin' in other_text:
                        continue
                    self.findings.append({
                        'type': 'reentrancy',
                        'category': 'reentrancy',
                        'severity': 'high',
                        'cwe_id': 'CWE-362',
                        'cwe_name': 'Concurrent Execution - Race Condition',
                        'description': f'Cross-function reentrancy risk: \'{func_name}\' makes external call '
                                       f'and \'{other_name}\' modifies state without access control. '
                                       f'Attacker can re-enter via \'{other_name}\' during \'{func_name}\' callback.',
                        'location': {
                            'line': code[:func_text.find(func_name)].count('\n') + 1,
                            'column': 0,
                            'match': f'function {func_name}',
                        },
                        'remediation': 'Apply nonReentrant modifier to both functions or use shared reentrancy lock.',
                        'confidence': 0.7,
                    })

    def _detect_nested_external_calls(self, code: str) -> None:
        external_calls = self._find_external_calls(code)
        if len(external_calls) < 2:
            return

        for i, (line_a, call_a, type_a) in enumerate(external_calls):
            for line_b, call_b, type_b in external_calls[i + 1:]:
                if line_b - line_a <= 15:
                    same_func = False
                    for func_match in FUNCTION_REGEX.finditer(code):
                        func_body_start = code.find('{', func_match.start())
                        if func_body_start == -1:
                            continue
                        brace_count = 0
                        for ci, ch in enumerate(code[func_body_start:], func_body_start):
                            if ch == '{':
                                brace_count += 1
                            elif ch == '}':
                                brace_count -= 1
                                if brace_count == 0:
                                    func_body = code[func_body_start:ci + 1]
                                    if call_a in func_body and call_b in func_body:
                                        same_func = True
                                    break
                        if same_func:
                            break

                    if same_func:
                        has_guard = self._has_reentrancy_guard(code)
                        confidence = 0.85 if not has_guard else 0.4
                        self.findings.append({
                            'type': 'reentrancy',
                            'category': 'reentrancy',
                            'severity': 'critical',
                            'cwe_id': 'CWE-362',
                            'cwe_name': 'Concurrent Execution - Race Condition',
                            'description': f'Nested external calls detected within 15 lines. '
                                           f'First: {call_a.strip()}, Second: {call_b.strip()}. '
                                           f'Nested calls create complex reentrancy paths.',
                            'location': {
                                'line': line_a,
                                'column': 0,
                                'match': call_a.strip(),
                            },
                            'remediation': 'Flatten external calls or use reentrancy guard. Ensure each external call is atomic.',
                            'confidence': confidence,
                        })

    def _detect_unprotected_eth_withdrawal(self, code: str) -> None:
        for i, line in enumerate(self.code_lines, 1):
            if '.call{value:' in line or '.call.value(' in line:
                has_require = False
                for j in range(max(0, i - 6), i):
                    check_line = self.code_lines[j]
                    if 'require' in check_line and ('msg.sender' in check_line or 'owner' in check_line.lower()):
                        has_require = True
                        break
                    if 'onlyOwner' in check_line or 'onlyAdmin' in check_line:
                        has_require = True
                        break

                if not has_require:
                    has_balance_op = bool(BALANCE_REGEX.search(line))
                    severity = 'critical' if has_balance_op else 'high'
                    self.findings.append({
                        'type': 'reentrancy',
                        'category': 'reentrancy',
                        'severity': severity,
                        'cwe_id': 'CWE-362',
                        'cwe_name': 'Concurrent Execution - Race Condition',
                        'description': f'Unprotected ETH transfer at line {i} via {line.strip()}. '
                                       f'No sender validation found in preceding 5 lines.',
                        'location': {
                            'line': i,
                            'column': line.find('.call'),
                            'match': line.strip(),
                        },
                        'remediation': 'Add require(msg.sender == owner) or onlyOwner modifier before ETH transfer.',
                        'confidence': 0.95,
                    })


def register_skill() -> Skill:
    return Skill(
        name="reentrancy_detector",
        category="reentrancy",
        severity="critical",
        description="Detects reentrancy vulnerabilities including CEI violations, "
                    "cross-function reentrancy, nested external calls, and unprotected ETH transfers.",
        cwe_id="CWE-362",
        cwe_name="Concurrent Execution - Race Condition",
        patterns=[r'\.call\{value:', r'\.call\.value\(', r'\.transfer\(', r'\.send\(', r'msg\.sender\.call'],
        sinks=['withdraw', 'transfer', 'call', 'claimReward', 'redeem', 'liquidate'],
        guards=['nonReentrant', 'ReentrancyGuard', 'CEI pattern', 'locked'],
        remediation="Apply checks-effects-interactions pattern. Use OpenZeppelin ReentrancyGuard. "
                    "Update state before external calls. Validate all ETH transfer recipients.",
        references=[
            "https://swcregistry.readthedocs.io/en/latest/SWC-107.html",
            "https://blog.openzeppelin.com/reentrancy-after-istanbul",
            "https://medium.com/coinmonks/dao-hack-dao-scam-dao-vulnerability-reentrancy-explained-469f3c1c0e7d",
        ],
        status=SkillStatus.ACTIVE,
        version="1.0.0",
        author="Solidify Security Team",
        tags={"reentrancy", "critical", "web3", "solidity", "cei", "external-calls"},
    )


def detect(code: str, context: dict = None) -> List[Dict]:
    detector = ReentrancyDetector()
    return detector.detect(code, context)


if __name__ == '__main__':
    sample_code = '''
pragma solidity ^0.7.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function withdrawWithTransfer(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }
}

contract SafeBank {
    import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
'''
    results = detect(sample_code)
    for r in results:
        print(f"[{r['severity'].upper()}] {r['description']}")
        print(f"  Location: Line {r['location']['line']}")
        print(f"  Confidence: {r['confidence']}")
        print()
