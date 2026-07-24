from __future__ import annotations

import re
import logging
from typing import List, Dict, Optional, Tuple, Set

from .skill_registry import Skill, SkillStatus

logger = logging.getLogger(__name__)

__all__ = ["register_skill", "detect", "AccessControlDetector"]

FUNCTION_REGEX = re.compile(
    r'function\s+(\w+)\s*\(([^)]*)\)\s*'
    r'((?:public|external|internal|private)\s*)'
    r'((?:view|pure|payable|virtual|override|nonpayable)\s*)*'
    r'((?:\w+\s*)*)',
    re.MULTILINE
)

VISIBILITY_PATTERNS = {
    'public': re.compile(r'\bpublic\b'),
    'external': re.compile(r'\bexternal\b'),
    'internal': re.compile(r'\binternal\b'),
    'private': re.compile(r'\bprivate\b'),
}

ACCESS_MODIFIER_PATTERNS = [
    re.compile(r'\bonlyOwner\b'),
    re.compile(r'\bonlyAdmin\b'),
    re.compile(r'\bonlyRole\b'),
    re.compile(r'\bhasRole\b'),
    re.compile(r'\bonlyAuthorized\b'),
    re.compile(r'\bonlyGovernance\b'),
    re.compile(r'\bonlyController\b'),
    re.compile(r'\bonlyOperator\b'),
    re.compile(r'\bonlyMinter\b'),
    re.compile(r'\bonlyPauser\b'),
    re.compile(r'\bonlyEmergency\b'),
    re.compile(r'\bonlyVault\b'),
    re.compile(r'\bonlyTreasury\b'),
    re.compile(r'\brequireAuth\b'),
    re.compile(r'\bcheckRole\b'),
    re.compile(r'\brequireRole\b'),
]

REQUIRE_SENDER_PATTERNS = [
    re.compile(r'require\s*\(\s*msg\.sender\s*=='),
    re.compile(r'require\s*\(\s*owner\s*==\s*msg\.sender'),
    re.compile(r'require\s*\(\s*msg\.sender\s*==\s*owner'),
    re.compile(r'require\s*\(\s*admin\s*==\s*msg\.sender'),
    re.compile(r'require\s*\(\s*msg\.sender\s*==\s*admin'),
    re.compile(r'require\s*\(\s*_owner\s*==\s*msg\.sender'),
    re.compile(r'require\s*\(\s*msg\.sender\s*==\s*_owner'),
    re.compile(r'require\s*\(\s*controller\s*==\s*msg\.sender'),
    re.compile(r'require\s*\(\s*msg\.sender\s*==\s*controller'),
    re.compile(r'if\s*\(\s*msg\.sender\s*!=\s*\w+\s*\)\s*(?:revert|return|throw)'),
    re.compile(r'if\s*\(\s*msg\.sender\s*==\s*\w+\s*\)'),
]

SENSITIVE_FUNCTION_NAMES = {
    'critical': [
        'selfdestruct', 'suicide', 'delegatecall',
        'upgradeTo', 'upgradeToAndCall', 'initialize',
        'changeAdmin', 'setAdmin', 'transferOwnership',
        'mint', 'burn', 'pause', 'unpause',
        'setFee', 'setFees', 'updateFee',
        'withdraw', 'emergencyWithdraw', 'drain',
        'rescue', 'rescueTokens', 'sweep',
        'execute', 'executeTransaction',
        'setBalance', 'updateBalance', 'setCredit',
        'setWhitelist', 'addToWhitelist', 'removeFromWhitelist',
        'blacklist', 'addToBlacklist', 'removeFromBlacklist',
        'setSwapEnabled', 'setTradingEnabled',
        'setMaxTxAmount', 'setMaxWalletSize',
    ],
    'high': [
        'approve', 'setApprovalForAll',
        'transferFrom', 'safeTransferFrom',
        'addLiquidity', 'removeLiquidity',
        'swap', 'swapExactTokensForTokens',
        'setRewardRate', 'updateRewardRate',
        'setStakingToken', 'setRewardToken',
        'setOracle', 'updateOracle',
        'setPriceFeed', 'updatePriceFeed',
        'setProtocolFee', 'updateProtocolFee',
    ],
    'medium': [
        'setMetadata', 'setName', 'setSymbol',
        'setDecimals', 'setIcon', 'setDescription',
        'setWebsite', 'setLogo',
    ],
}

MODIFIER_DEFINITIONS = re.compile(
    r'modifier\s+(\w+)\s*\([^)]*\)\s*\{',
    re.MULTILINE
)

CONSTRUCTOR_REGEX = re.compile(
    r'constructor\s*\([^)]*\)\s*[^{]*\{',
    re.MULTILINE
)

OWNER_VARIABLES = re.compile(
    r'(?:owner|admin|governance|controller|authority|operator)\s*[:=]',
    re.IGNORECASE
)


class AccessControlDetector:
    def __init__(self):
        self.findings: List[Dict] = []
        self.code_lines: List[str] = []
        self.full_code: str = ''

    def detect(self, code: str, context: dict = None) -> List[Dict]:
        self.findings = []
        self.code_lines = code.split('\n')
        self.full_code = code
        context = context or {}

        self._check_function_visibility(code)
        self._check_unprotected_selfdestruct(code)
        self._check_unprotected_sensitive_functions(code)
        self._check_unprotected_admin_operations(code)
        self._check_missing_role_based_access(code)
        self._check_unprotected_upgrade(code)
        self._check_unprotected_delegatecall(code)

        logger.info(f"Access control detector found {len(self.findings)} issues")
        return self.findings

    def _has_access_modifier(self, func_text: str) -> bool:
        for pattern in ACCESS_MODIFIER_PATTERNS:
            if pattern.search(func_text):
                return True
        for pattern in REQUIRE_SENDER_PATTERNS:
            if pattern.search(func_text):
                return True
        return False

    def _is_sensitive_function(self, name: str) -> Optional[str]:
        name_lower = name.lower()
        for severity, names in SENSITIVE_FUNCTION_NAMES.items():
            for sensitive in names:
                if sensitive.lower() == name_lower or sensitive.lower() in name_lower:
                    return severity
        return None

    def _check_modifier_definition(self, modifier_name: str) -> bool:
        match = MODIFIER_DEFINITIONS.search(
            self.full_code,
            re.MULTILINE
        )
        if match:
            return True
        for mod_match in MODIFIER_DEFINITIONS.finditer(self.full_code):
            if mod_match.group(1) == modifier_name:
                return True
        return False

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

    def _check_function_visibility(self, code: str) -> None:
        for func_match in FUNCTION_REGEX.finditer(code):
            func_name = func_match.group(1)
            visibility = func_match.group(3).strip() if func_match.group(3) else ''
            func_text = func_match.group(0)
            line_num = code[:func_match.start()].count('\n') + 1

            if 'internal' in visibility or 'private' in visibility:
                continue

            has_modifier = self._has_access_modifier(func_text)
            if has_modifier:
                continue

            func_body = self._get_function_body(code, func_match)
            full_func = func_text + func_body

            sensitive_severity = self._is_sensitive_function(func_name)
            if sensitive_severity and ('public' in visibility or 'external' in visibility):
                self.findings.append({
                    'type': 'access_control',
                    'category': 'access_control',
                    'severity': sensitive_severity,
                    'cwe_id': 'CWE-862',
                    'cwe_name': 'Missing Authorization',
                    'description': f'Sensitive function \'{func_name}\' is {visibility} without access control. '
                                   f'Function can be called by anyone.',
                    'location': {
                        'line': line_num,
                        'column': 0,
                        'match': f'function {func_name}',
                    },
                    'remediation': f'Add onlyOwner, AccessControl, or require(msg.sender == owner) to \'{func_name}\'.',
                    'confidence': 0.95,
                })

    def _check_unprotected_selfdestruct(self, code: str) -> None:
        selfdestruct_patterns = [
            re.compile(r'selfdestruct\s*\(\s*[^)]+\)', re.MULTILINE),
            re.compile(r'suicide\s*\(\s*[^)]+\)', re.MULTILINE),
        ]
        for i, line in enumerate(self.code_lines, 1):
            for pattern in selfdestruct_patterns:
                for match in pattern.finditer(line):
                    has_guard = False
                    for j in range(max(0, i - 8), i):
                        check_line = self.code_lines[j]
                        if self._line_has_access_control(check_line):
                            has_guard = True
                            break
                    if not has_guard:
                        self.findings.append({
                            'type': 'access_control',
                            'category': 'access_control',
                            'severity': 'critical',
                            'cwe_id': 'CWE-862',
                            'cwe_name': 'Missing Authorization',
                            'description': f'Unprotected selfdestruct at line {i}. '
                                           f'Anyone can destroy the contract and steal remaining ETH.',
                            'location': {
                                'line': i,
                                'column': match.start() + 1,
                                'match': match.group().strip(),
                            },
                            'remediation': 'Remove selfdestruct or add strict access control (onlyOwner + timelock).',
                            'confidence': 0.98,
                        })

    def _check_unprotected_sensitive_functions(self, code: str) -> None:
        for func_match in FUNCTION_REGEX.finditer(code):
            func_name = func_match.group(1)
            visibility = func_match.group(3).strip() if func_match.group(3) else ''
            func_text = func_match.group(0)
            line_num = code[:func_match.start()].count('\n') + 1

            if 'internal' in visibility or 'private' in visibility:
                continue

            if self._has_access_modifier(func_text):
                continue

            func_body = self._get_function_body(code, func_match)
            full_func = func_text + func_body

            if 'selfdestruct' in full_func or 'suicide' in full_func:
                continue
            if 'delegatecall' in full_func:
                continue

            sensitive_severity = self._is_sensitive_function(func_name)
            if sensitive_severity and func_name in [
                n for names in SENSITIVE_FUNCTION_NAMES.values() for n in names
            ]:
                if 'public' in visibility or 'external' in visibility:
                    is_payable = 'payable' in func_text
                    severity = sensitive_severity
                    if is_payable and severity != 'critical':
                        severity = 'critical'

                    self.findings.append({
                        'type': 'access_control',
                        'category': 'access_control',
                        'severity': severity,
                        'cwe_id': 'CWE-862',
                        'cwe_name': 'Missing Authorization',
                        'description': f'Sensitive function \'{func_name}\' ({visibility}) lacks access control. '
                                       f'{"Payable function " if is_payable else ""}'
                                       f'Anyone can execute this privileged operation.',
                        'location': {
                            'line': line_num,
                            'column': 0,
                            'match': f'function {func_name}',
                        },
                        'remediation': f'Add onlyOwner modifier or require(msg.sender == owner) to \'{func_name}\'.',
                        'confidence': 0.93,
                    })

    def _check_unprotected_admin_operations(self, code: str) -> None:
        admin_operation_patterns = [
            re.compile(r'admin\s*=\s*\w+', re.MULTILINE),
            re.compile(r'owner\s*=\s*\w+', re.MULTILINE),
            re.compile(r'governance\s*=\s*\w+', re.MULTILINE),
            re.compile(r'controller\s*=\s*\w+', re.MULTILINE),
        ]
        for i, line in enumerate(self.code_lines, 1):
            for pattern in admin_operation_patterns:
                for match in pattern.finditer(line):
                    var_name = match.group().split('=')[0].strip()
                    has_guard = False
                    for j in range(max(0, i - 6), i):
                        check_line = self.code_lines[j]
                        if self._line_has_access_control(check_line):
                            has_guard = True
                            break
                        if 'constructor' in check_line:
                            has_guard = True
                            break
                    if not has_guard:
                        self.findings.append({
                            'type': 'access_control',
                            'category': 'access_control',
                            'severity': 'critical',
                            'cwe_id': 'CWE-862',
                            'cwe_name': 'Missing Authorization',
                            'description': f'Unprotected admin/owner state change: {match.group().strip()}. '
                                           f'Anyone can reassign critical roles.',
                            'location': {
                                'line': i,
                                'column': match.start() + 1,
                                'match': match.group().strip(),
                            },
                            'remediation': 'Add onlyOwner modifier or use Ownable.transferOwnership().',
                            'confidence': 0.94,
                        })

    def _check_missing_role_based_access(self, code: str) -> None:
        role_patterns = [
            re.compile(r'_roles?\s*\[', re.MULTILINE),
            re.compile(r'roles?\s*\[', re.MULTILINE),
            re.compile(r'hasRole\s*\(', re.MULTILINE),
            re.compile(r'grantRole\s*\(', re.MULTILINE),
            re.compile(r'revokeRole\s*\(', re.MULTILINE),
        ]
        has_role_management = any(p.search(code) for p in role_patterns)
        if not has_role_management:
            return

        for func_match in FUNCTION_REGEX.finditer(code):
            func_name = func_match.group(1)
            visibility = func_match.group(3).strip() if func_match.group(3) else ''
            func_text = func_match.group(0)
            line_num = code[:func_match.start()].count('\n') + 1

            if 'internal' in visibility or 'private' in visibility:
                continue

            if self._has_access_modifier(func_text):
                continue

            if 'grantRole' in func_name or 'revokeRole' in func_name or 'setRole' in func_name:
                self.findings.append({
                    'type': 'access_control',
                    'category': 'access_control',
                    'severity': 'critical',
                    'cwe_id': 'CWE-862',
                    'cwe_name': 'Missing Authorization',
                    'description': f'Role management function \'{func_name}\' lacks access control. '
                                   f'Anyone can grant/revoke roles.',
                    'location': {
                        'line': line_num,
                        'column': 0,
                        'match': f'function {func_name}',
                    },
                    'remediation': f'Add onlyRole(DEFAULT_ADMIN_ROLE) to \'{func_name}\'.',
                    'confidence': 0.96,
                })

    def _check_unprotected_upgrade(self, code: str) -> None:
        upgrade_patterns = [
            re.compile(r'upgradeTo\s*\(', re.MULTILINE),
            re.compile(r'upgradeToAndCall\s*\(', re.MULTILINE),
            re.compile(r'upgrade\s*\(\s*address', re.MULTILINE),
            re.compile(r'updateImplementation\s*\(', re.MULTILINE),
        ]
        for i, line in enumerate(self.code_lines, 1):
            for pattern in upgrade_patterns:
                for match in pattern.finditer(line):
                    has_guard = False
                    for j in range(max(0, i - 8), i):
                        check_line = self.code_lines[j]
                        if self._line_has_access_control(check_line):
                            has_guard = True
                            break
                    if not has_guard:
                        self.findings.append({
                            'type': 'access_control',
                            'category': 'access_control',
                            'severity': 'critical',
                            'cwe_id': 'CWE-862',
                            'cwe_name': 'Missing Authorization',
                            'description': f'Unprotected upgrade function at line {i}: {match.group().strip()}. '
                                           f'Anyone can replace contract implementation.',
                            'location': {
                                'line': i,
                                'column': match.start() + 1,
                                'match': match.group().strip(),
                            },
                            'remediation': 'Add onlyOwner + timelock to upgrade functions. Use UUPS or TransparentProxy patterns.',
                            'confidence': 0.97,
                        })

    def _check_unprotected_delegatecall(self, code: str) -> None:
        delegatecall_pattern = re.compile(r'\.delegatecall\(', re.MULTILINE)
        for i, line in enumerate(self.code_lines, 1):
            for match in delegatecall_pattern.finditer(line):
                has_guard = False
                for j in range(max(0, i - 8), i):
                    check_line = self.code_lines[j]
                    if self._line_has_access_control(check_line):
                        has_guard = True
                        break
                if not has_guard:
                    self.findings.append({
                        'type': 'access_control',
                        'category': 'access_control',
                        'severity': 'critical',
                        'cwe_id': 'CWE-862',
                        'cwe_name': 'Missing Authorization',
                        'description': f'Unprotected delegatecall at line {i}. '
                                       f'Attacker can redirect execution to malicious contract.',
                        'location': {
                            'line': i,
                            'column': match.start() + 1,
                            'match': line.strip(),
                        },
                        'remediation': 'Add strict access control to delegatecall. Validate target address.',
                        'confidence': 0.96,
                    })

    def _line_has_access_control(self, line: str) -> bool:
        for pattern in ACCESS_MODIFIER_PATTERNS:
            if pattern.search(line):
                return True
        for pattern in REQUIRE_SENDER_PATTERNS:
            if pattern.search(line):
                return True
        if 'require' in line and ('msg.sender' in line or 'owner' in line.lower()):
            return True
        return False


def register_skill() -> Skill:
    return Skill(
        name="access_control_detector",
        category="access_control",
        severity="critical",
        description="Detects missing access control on sensitive functions including "
                    "selfdestruct, upgrade, delegatecall, role management, and admin operations.",
        cwe_id="CWE-862",
        cwe_name="Missing Authorization",
        patterns=[r'function.*public', r'function.*external', r'selfdestruct', r'delegatecall', r'upgradeTo'],
        sinks=['selfdestruct', 'suicide', 'delegatecall', 'upgradeTo', 'mint', 'burn', 'pause'],
        guards=['onlyOwner', 'onlyAdmin', 'require(msg.sender', 'AccessControl', 'Ownable', 'hasRole'],
        remediation="Add Ownable or AccessControl from OpenZeppelin. Use require(msg.sender == owner) "
                    "for critical functions. Implement timelock for upgrade operations.",
        references=[
            "https://swcregistry.readthedocs.io/en/latest/SWC-105.html",
            "https://swcregistry.readthedocs.io/en/latest/SWC-106.html",
            "https://blog.openzeppelin.com/protecting-smart-contracts",
        ],
        status=SkillStatus.ACTIVE,
        version="1.0.0",
        author="Solidify Security Team",
        tags={"access-control", "critical", "web3", "solidity", "authorization", "privilege-escalation"},
    )


def detect(code: str, context: dict = None) -> List[Dict]:
    detector = AccessControlDetector()
    return detector.detect(code, context)


if __name__ == '__main__':
    sample_code = '''
pragma solidity ^0.7.0;

contract VulnerableToken {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 amount) public {
        balances[to] += amount;
    }

    function burn(uint256 amount) public {
        balances[msg.sender] -= amount;
    }

    function withdrawAll() public {
        payable(msg.sender).transfer(address(this).balance);
    }

    function destroy() public {
        selfdestruct(payable(msg.sender));
    }

    function transferOwnership(address newOwner) public {
        owner = newOwner;
    }
}

contract SafeToken {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 amount) public onlyOwner {
        balances[to] += amount;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        owner = newOwner;
    }
}
'''
    results = detect(sample_code)
    for r in results:
        print(f"[{r['severity'].upper()}] {r['description']}")
        print(f"  Location: Line {r['location']['line']}")
        print(f"  Confidence: {r['confidence']}")
        print()
