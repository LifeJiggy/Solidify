"""
Authentication and Authorization Security Rules for Blockchain Smart Contracts

This module provides comprehensive authentication and authorization security rules
specifically designed for Solidity smart contracts and EVM-based blockchain protocols.
Covers access control, role-based permissions, ownership, multisig, timelock, and proxy
authorization patterns for DeFi protocols, NFT marketplaces, DAOs, and Web3 applications.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AuthCategory(Enum):
    """Categories of authentication vulnerabilities in blockchain"""
    ACCESS_CONTROL = "access_control"
    OWNERSHIP = "ownership"
    ROLE_BASED = "role_based"
    MULTISIG = "multisig"
    TIMELOCK = "timelock"
    PROXY = "proxy"
    PAUSABLE = "pausable"
    GOVERNANCE = "governance"
    UPGRADEABLE = "upgradeable"
    TREASURY = "treasury"
    DELEGATION = "delegation"
    PERMISSION_MANAGEMENT = "permission_management"


class AuthSeverity(Enum):
    """Severity levels for authentication vulnerabilities"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


class Exploitability(Enum):
    """Exploitability levels"""
    TRIVIAL = "exploitable"
    EASY = "easy"
    MODERATE = "moderate"
    DIFFICULT = "difficult"
    EXPERT = "expert"


class AuthPatternType(Enum):
    """Types of authorization patterns"""
    MISSING_MODIFIER = "missing_modifier"
    WEAK_MODIFIER = "weak_modifier"
    TYPO_MODIFIER = "typo_modifier"
    BYPASS_MODIFIER = "bypass_modifier"
    CIRCULAR_LOGIC = "circular_logic"
    GAS_LIMITATION = "gas_limitation"
    FRONT_RUNNING = "front_running"

    MISSING_OWNERSHIP_CHECK = "missing_ownership_check"
    MISSING_ROLE_CHECK = "missing_role_check"
    MISSING_SIGNATURE_VERIFICATION = "missing_signature_verification"
    MISSING_TIME_LOCK = "missing_time_lock"

    WEAK_ROLE_ADMIN = "weak_role_admin"
    WEAK_MULTISIG = "weak_multisig"
    MISSING_TIMELOCK = "missing_timelock"

    UNPROTECTED_INITIALIZE = "unprotected_initialize"
    UNPROTECTED_UPGRADE = "unprotected_upgrade"
    UNPROTECTED_PAUSE = "unprotected_pause"
    UNPROTECTED_WITHDRAW = "unprotected_withdraw"

    PUBLIC_INITIALIZE = "public_initialize"
    PUBLIC_MINT = "public_mint"
    PUBLIC_BURN = "public_burn"
    PUBLIC_PAUSE = "public_pause"
    PUBLIC_UPGRADE = "public_upgrade"


@dataclass
class AuthVulnerability:
    """Represents a discovered authentication vulnerability"""
    vulnerability_id: str
    title: str
    category: AuthCategory
    severity: AuthSeverity
    pattern_type: AuthPatternType
    description: str
    impact: str
    attack_vector: str
    cwe_ids: List[str]
    cwss_score: float
    recommendation: str
    code_snippet: str
    function_signature: str
    line_number: int
    exploitability: Exploitability
    remediation_complexity: str
    references: List[str]
    test_cases: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerability_id': self.vulnerability_id,
            'title': self.title,
            'category': self.category.value,
            'severity': self.severity.name,
            'pattern_type': self.pattern_type.value,
            'description': self.description,
            'impact': self.impact,
            'attack_vector': self.attack_vector,
            'cwe_ids': self.cwe_ids,
            'cwss_score': self.cwss_score,
            'recommendation': self.recommendation,
            'code_snippet': self.code_snippet,
            'function_signature': self.function_signature,
            'line_number': self.line_number,
            'exploitability': self.exploitability.value,
            'remediation_complexity': self.remediation_complexity,
            'references': self.references
        }


@dataclass
class AuthRule:
    """Represents an authentication detection rule"""
    rule_id: str
    name: str
    category: AuthCategory
    severity: AuthSeverity
    pattern_type: AuthPatternType
    pattern: str
    description: str
    impact: str
    attack_vector: str
    cwe_ids: List[str]
    cvss_base: float
    exploitability: Exploitability
    recommendation: str
    detection_logic: str
    false_positive_filters: List[str] = field(default_factory=list)
    required_context: List[str] = field(default_factory=list)
    severity_modifiers: Dict[str, float] = field(default_factory=dict)
    remediation_complexity: str = "Medium"
    references: List[str] = field(default_factory=list)
    
    def calculate_cvss(self, context: Dict[str, Any]) -> float:
        """Calculate contextual CVSS score"""
        base = self.cvss_base
        for modifier, value in context.items():
            if modifier in self.severity_modifiers:
                base += self.severity_modifiers[modifier] * value
        return min(10.0, max(0.0, base))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'category': self.category.value,
            'severity': self.severity.name,
            'pattern_type': self.pattern_type.value,
            'pattern': self.pattern,
            'description': self.description,
            'impact': self.impact,
            'attack_vector': self.attack_vector,
            'cwe_ids': self.cwe_ids,
            'cvss_base': self.cvss_base,
            'exploitability': self.exploitability.value,
            'recommendation': self.recommendation,
            'detection_logic': self.detection_logic,
            'false_positive_filters': self.false_positive_filters,
            'references': self.references
        }


class AuthRuleRegistry:
    """Registry of all authentication detection rules"""
    
    def __init__(self):
        self.rules: Dict[str, AuthRule] = {}
        self._register_all_rules()
    
    def _register_all_rules(self) -> None:
        """Register all Web3 authentication rules"""
        self._register_access_control_rules()
        self._register_ownership_rules()
        self._register_role_based_rules()
        self._register_multisig_rules()
        self._register_timelock_rules()
        self._register_proxy_rules()
        self._register_pausable_rules()
        self._register_governance_rules()
        self._register_treasury_rules()
        self._register_delegation_rules()
    
    def _register_access_control_rules(self) -> None:
        """Register access control vulnerability rules"""
        self.rules['AUTH-AC-001'] = AuthRule(
            rule_id='AUTH-AC-001',
            name='Missing Access Control Modifier on Critical Function',
            category=AuthCategory.ACCESS_CONTROL,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+(withdraw|mint|burn|pause|unpause|upgrade|execute)\s*\([^)]*\)\s*(?:public|external)\s*(?:virtual)?\s*(?!onlyOwner|onlyRole|onlyAdmin|onlyMinter|onlyPauser|onlyGovernance|modifier)',
            description='Critical function lacks access control modifier, allowing anyone to execute it',
            impact='Attacker can drain funds, mint tokens, pause protocol, or upgrade contract',
            attack_vector='Directly call vulnerable function without authentication',
            cwe_ids=['CWE-284', 'CWE-862'],
            cvss_base=9.5,
            exploitability=Exploitability.TRIVIAL,
            recommendation='Add onlyOwner modifier or implement role-based access control',
            detection_logic='Scan for functions without authorization modifiers',
            false_positive_filters=['OpenZeppelin Ownable', 'AccessControl', 'Governor'],
            references=['https://docs.openzeppelin.com/contracts/4.x/access-control']
        )
        
        self.rules['AUTH-AC-002'] = AuthRule(
            rule_id='AUTH-AC-002',
            name='Public Owner Assignment',
            category=AuthCategory.ACCESS_CONTROL,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.PUBLIC_MINT,
            pattern=r'function\s+setOwner\([^)]*\)\s*public(?!\s*(?:onlyOwner|auth))',
            description='Owner can be set by any user',
            impact='Attacker can take ownership of contract',
            attack_vector='Call setOwner with attacker address',
            cwe_ids=['CWE-284'],
            cvss_base=9.3,
            exploitability=Exploitability.TRIVIAL,
            recommendation='Add onlyOwner to setOwner function',
            detection_logic='Check setOwner function modifiers',
            references=['Ownership hijacking']
        )
        
        self.rules['AUTH-AC-003'] = AuthRule(
            rule_id='AUTH-AC-003',
            name='Anyone Can Set Fee Parameters',
            category=AuthCategory.ACCESS_CONTROL,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+setFee\([^)]*\)\s*public',
            description='Fee parameters can be set by anyone',
            impact='Attacker can set excessive fees',
            attack_vector='Call setFee to set high fees',
            cwe_ids=['CWE-284'],
            cvss_base=7.8,
            exploitability=Exploitability.EASY,
            recommendation='Restrict setFee to admin role',
            detection_logic='Check fee setter access',
            references=['Fee manipulation']
        )
        
        self.rules['AUTH-AC-004'] = AuthRule(
            rule_id='AUTH-AC-004',
            name='Unprotected Self-Destruct',
            category=AuthCategory.ACCESS_CONTROL,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.UNPROTECTED_UPGRADE,
            pattern=r'selfdestruct\([^)]*\)(?!.*onlyOwner|.*auth)',
            description='Self-destruct callable by anyone',
            impact='Contract can be destroyed by anyone',
            attack_vector='Call selfdestruct to destroy contract',
            cwe_ids=['CWE-284', 'CWE-862'],
            cvss_base=9.4,
            exploitability=Exploitability.TRIVIAL,
            recommendation='Add onlyOwner to self-destruct',
            detection_logic='Check selfdestruct access',
            references=['Self-destruct vulnerability']
        )
        
        self.rules['AUTH-AC-005'] = AuthRule(
            rule_id='AUTH-AC-005',
            name='Unprotected Call to Arbitrary Address',
            category=AuthCategory.ACCESS_CONTROL,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.UNPROTECTED_WITHDRAW,
            pattern=r'(?:call|delegatecall)\([^)]*\)\s*address\([^)]*\)(?!.*require|.*auth|.*onlyOwner)',
            description='Call to arbitrary address without authorization',
            impact='Attacker can call any contract with contract state',
            attack_vector='Call malicious contract via vulnerability',
            cwe_ids=['CWE-284', 'CWE-862'],
            cvss_base=9.2,
            exploitability=Exploitability.EASY,
            recommendation='Validate target address or add access control',
            detection_logic='Check arbitrary call protection',
            false_positive_filters=['Whitelisted targets'],
            references=['Arbitrary call vulnerability']
        )
        
        self.rules['AUTH-AC-006'] = AuthRule(
            rule_id='AUTH-AC-006',
            name='Missing Require on msg.sender',
            category=AuthCategory.ACCESS_CONTROL,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.MISSING_OWNERSHIP_CHECK,
            pattern=r'function\s+\w+\s*\([^)]*\)\s*public\s*\{(?!.*require.*msg\.sender)',
            description='Public function without msg.sender check in function body',
            impact='Can be called by anyone',
            attack_vector='Direct call without authentication',
            cwe_ids=['CWE-284'],
            cvss_base=7.5,
            exploitability=Exploitability.EASY,
            recommendation='Add require(msg.sender == owner)',
            detection_logic='Check require statements',
            references=['Missing authentication']
        )
        
        self.rules['AUTH-AC-007'] = AuthRule(
            rule_id='AUTH-AC-007',
            name='Typosquatting Access Control',
            category=AuthCategory.ACCESS_CONTROL,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.TYPO_MODIFIER,
            pattern=r'modifier\s+(?:onwen|owne|onwer|owner)\s*\(',
            description='Typo in modifier name bypasses access control',
            impact='Access control does not work',
            attack_vector='Call function, modifier name typo prevents execution',
            cwe_ids=['CWE-478'],
            cvss_base=8.0,
            exploitability=Exploitability.MODERATE,
            recommendation='Fix modifier spelling',
            detection_logic='Check modifier names',
            references=['Typo-squatting']
        )
        
        self.rules['AUTH-AC-008'] = AuthRule(
            rule_id='AUTH-AC-008',
            name='Missing Access Control on Callback',
            category=AuthCategory.ACCESS_CONTROL,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+onTokenReceived\([^)]*\)\s*external\s*\{(?!.*require|auth)',
            description='ERC721 receive callback without access control',
            impact='Can receive NFTs without owner verification',
            attack_vector='Send NFT to vulnerable contract',
            cwe_ids=['CWE-284'],
            cvss_base=7.8,
            exploitability=Exploitability.EASY,
            recommendation='Add ownership verification',
            detection_logic='Check callback protection',
            references=['NFT callback vulnerability']
        )

    def _register_ownership_rules(self) -> None:
        """Register ownership vulnerability rules"""
        self.rules['AUTH-OWN-001'] = AuthRule(
            rule_id='AUTH-OWN-001',
            name='Missing Ownership Transfer Verification',
            category=AuthCategory.OWNERSHIP,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.MISSING_OWNERSHIP_CHECK,
            pattern=r'function\s+transferOwnership\([^)]*\)\s*public\s*(?:onlyOwner)?.*\{(?!.*require|newOwner)',
            description='Ownership transfer accepts any address without verification',
            impact='Can transfer ownership to zero address',
            attack_vector='Call transferOwnership',
            cwe_ids=['CWE-20', 'CWE-284'],
            cvss_base=7.5,
            exploitability=Exploitability.EASY,
            recommendation='Verify new owner is not zero address',
            detection_logic='Check ownership transfer logic',
            references=['Ownership verification']
        )
        
        self.rules['AUTH-OWN-002'] = AuthRule(
            rule_id='AUTH-OWN-002',
            name='Renounce Ownership Without Confirmation',
            category=AuthCategory.OWNERSHIP,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+renounceOwnership\([^)]*\)\s*public(?!\s*confirm)',
            description='Renounce ownership callable without confirmation',
            impact='Can permanently lose ownership',
            attack_vector='Call renounceOwnership',
            cwe_ids=['CWE-284'],
            cvss_base=7.0,
            exploitability=Exploitability.EASY,
            recommendation='Add confirmation step',
            detection_logic='Check renounce logic',
            references=['Ownership loss']
        )
        
        self.rules['AUTH-OWN-003'] = AuthRule(
            rule_id='AUTH-OWN-003',
            name='Initial Owner Not Set',
            category=AuthCategory.OWNERSHIP,
            severity=AuthSeverity.MEDIUM,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'constructor\s*\{[^}]*(?!owner\s*=|_owner\s*=)',
            description='Constructor does not set owner',
            impact='Owner is zero address after deployment',
            attack_vector='Deploy contract, owner is zero address',
            cwe_ids=['CWE-665'],
            cvss_base=5.5,
            exploitability=Exploitability.EASY,
            recommendation='Set owner in constructor',
            detection_logic='Check constructor owner',
            references=['Zero address owner']
        )
        
        self.rules['AUTH-OWN-004'] = AuthRule(
            rule_id='AUTH-OWN-004',
            name='Anyone Can Accept Ownership',
            category=AuthCategory.OWNERSHIP,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+acceptOwnership\([^)]*\)\s*public',
            description='Accept ownership callable by anyone',
            impact='Can accept ownership of pending transfers',
            attack_vector='Call acceptOwnership',
            cwe_ids=['CWE-284'],
            cvss_base=7.2,
            exploitability=Exploitability.EASY,
            recommendation='Check pending owner is msg.sender',
            detection_logic='Check acceptOwnership',
            references=['Pending ownership']
        )
        
        self.rules['AUTH-OWN-005'] = AuthRule(
            rule_id='AUTH-OWN-005',
            name='Missing Owner Verification in Modifier',
            category=AuthCategory.OWNERSHIP,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'modifier\s+onlyOwner\s*\([^)]*\)\s*\{(?!require)',
            description='onlyOwner modifier missing require check',
            impact='onlyOwner modifier ineffective',
            attack_vector='Call protected function',
            cwe_ids=['CWE-478'],
            cvss_base=8.0,
            exploitability=Exploitability.MODERATE,
            recommendation='Add require check in modifier',
            detection_logic='Check modifier implementation',
            references=['Broken modifier']
        )

    def _register_role_based_rules(self) -> None:
        """Register role-based access control vulnerability rules"""
        self.rules['AUTH-RBAC-001'] = AuthRule(
            rule_id='AUTH-RBAC-001',
            name='Unrestricted Mint Role',
            category=AuthCategory.ROLE_BASED,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.PUBLIC_MINT,
            pattern=r'function\s+mint\([^)]*\)\s*public\s*(?!onlyMinter|onlyRole|MINTER_ROLE|hasRole)',
            description='Minting function accessible without role check',
            impact='Anyone can mint unlimited tokens',
            attack_vector='Call mint function directly',
            cwe_ids=['CWE-284', 'CWE-862'],
            cvss_base=9.5,
            exploitability=Exploitability.TRIVIAL,
            recommendation='Add onlyMinter modifier or check hasRole',
            detection_logic='Check mint function modifiers',
            false_positive_filters=['OpenZeppelin AccessControl'],
            references=['Unlimited minting']
        )
        
        self.rules['AUTH-RBAC-002'] = AuthRule(
            rule_id='AUTH-RBAC-002',
            name='Unrestricted Burn Role',
            category=AuthCategory.ROLE_BASED,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.PUBLIC_BURN,
            pattern=r'function\s+burn\([^)]*\)\s*public\s*(?!onlyBurner|BURNER_ROLE|hasRole)',
            description='Burn function accessible without role check',
            impact='Anyone can burn tokens',
            attack_vector='Call burn function',
            cwe_ids=['CWE-284'],
            cvss_base=7.8,
            exploitability=Exploitability.EASY,
            recommendation='Add onlyBurner modifier',
            detection_logic='Check burn function protection',
            references=['Unrestricted burning']
        )
        
        self.rules['AUTH-RBAC-003'] = AuthRule(
            rule_id='AUTH-RBAC-003',
            name='Grant Role Without Admin Check',
            category=AuthCategory.ROLE_BASED,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+grantRole\([^)]*\)\s*public(?!\s*onlyRole|hasRole|admin)',
            description='grantRole callable by non-admin',
            impact='Can grant privileged roles to self',
            attack_vector='Call grantRole for admin role',
            cwe_ids=['CWE-284', 'CWE-862'],
            cvss_base=9.2,
            exploitability=Exploitability.TRIVIAL,
            recommendation='Add onlyRole(DEFAULT_ADMIN_ROLE) check',
            detection_logic='Check grantRole protection',
            references=['Role escalation']
        )
        
        self.rules['AUTH-RBAC-004'] = AuthRule(
            rule_id='AUTH-RBAC-004',
            name='Revoke Role Without Admin Check',
            category=AuthCategory.ROLE_BASED,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+revokeRole\([^)]*\)\s*public(?!\s*onlyRole|hasRole)',
            description='revokeRole callable by non-admin',
            impact='Can revoke admin roles to lock out admins',
            attack_vector='Call revokeRole on admin roles',
            cwe_ids=['CWE-284'],
            cvss_base=7.8,
            exploitability=Exploitability.EASY,
            recommendation='Add onlyRole check',
            detection_logic='Check revokeRole access',
            references=['Role revocation']
        )
        
        self.rules['AUTH-RBAC-005'] = AuthRule(
            rule_id='AUTH-RBAC-005',
            name='Default Admin Can Grant Admin Role',
            category=AuthCategory.ROLE_BASED,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.WEAK_ROLE_ADMIN,
            pattern=r'function\s+grantRole\([^)]*\)\s*onlyRole\s*\(\s*DEFAULT_ADMIN_ROLE\s*\)',
            description='Default admin can grant admin role',
            impact='Can escalate to full admin control',
            attack_vector='Grant DEFAULT_ADMIN_ROLE to self',
            cwe_ids=['CWE-284'],
            cvss_base=8.5,
            exploitability=Exploitability.EASY,
            recommendation='Use separate admin role',
            detection_logic='Check role structure',
            references=['Admin role']
        )
        
        self.rules['AUTH-RBAC-006'] = AuthRule(
            rule_id='AUTH-RBAC-006',
            name='Role Assignment Missing Zero Check',
            category=AuthCategory.ROLE_BASED,
            severity=AuthSeverity.MEDIUM,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'grantRole\s*\(\s*[^)]*,\s*address\s*\(\s*0\s*\)\s*\)',
            description='Role can be granted to zero address',
            impact='Role assigned to burn address',
            attack_vector='Call grantRole with zero address',
            cwe_ids=['CWE-20'],
            cvss_base=5.5,
            exploitability=Exploitability.EASY,
            recommendation='Check account is not zero',
            detection_logic='Check grantRole target',
            references=['Zero address role']
        )

    def _register_multisig_rules(self) -> None:
        """Register multisig vulnerability rules"""
        self.rules['AUTH-MULTI-001'] = AuthRule(
            rule_id='AUTH-MULTI-001',
            name='Multisig Threshold Too Low',
            category=AuthCategory.MULTISIG,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.WEAK_MULTISIG,
            pattern=r'uint256\s+public\s+threshold\s*=\s*1',
            description='Multisig threshold set to 1',
            impact='Single point of failure',
            attack_vector='Compromise single signer',
            cwe_ids=['CWE-284'],
            cvss_base=7.0,
            exploitability=Exploitability.EASY,
            recommendation='Set threshold to at least 2',
            detection_logic='Check threshold value',
            references=['Single signer']
        )
        
        self.rules['AUTH-MULTI-002'] = AuthRule(
            rule_id='AUTH-MULTI-002',
            name='MissingConfirmationCheck',
            category=AuthCategory.MULTISIG,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+execute\([^)]*\)\s*public\s*\{(?!.*confirmations|confirmed|required)',
            description='Execute without confirmation check',
            impact='Can execute without required signatures',
            attack_vector='Direct execution',
            cwe_ids=['CWE-284'],
            cvss_base=8.8,
            exploitability=Exploitability.EASY,
            recommendation='Add confirmation tracking',
            detection_logic='Check confirmation logic',
            references=['Missing confirmations']
        )
        
        self.rules['AUTH-MULTI-003'] = AuthRule(
            rule_id='AUTH-MULTI-003',
            name='Duplicate Signer Allowed',
            category=AuthCategory.MULTISIG,
            severity=AuthSeverity.MEDIUM,
            pattern_type=AuthPatternType.WEAK_MULTISIG,
            pattern=r'function\s+addSigner\([^)]*\)\s*public\s*(?!require|onlyOwner)',
            description='Can add same signer multiple times',
            impact='Single signer can have multiple votes',
            attack_vector='Add same address multiple times',
            cwe_ids=['CWE-284'],
            cvss_base=5.5,
            exploitability=Exploitability.EASY,
            recommendation='Check signer not already added',
            detection_logic='Check signer uniqueness',
            references=['Duplicate signer']
        )
        
        self.rules['AUTH-MULTI-004'] = AuthRule(
            rule_id='AUTH-MULTI-004',
            name='Owner Can Remove Themselves',
            category=AuthCategory.MULTISIG,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+removeSigner\([^)]*\)\s*public',
            description='signer can remove themselves',
            impact='Can lock remaining signers',
            attack_vector='Remove self from owners',
            cwe_ids=['CWE-284'],
            cvss_base=6.5,
            exploitability=Exploitability.EASY,
            recommendation='Require multi-signer approval',
            detection_logic='Check remove signer logic',
            references=['Self-removal']
        )

    def _register_timelock_rules(self) -> None:
        """Register timelock vulnerability rules"""
        self.rules['AUTH-TIME-001'] = AuthRule(
            rule_id='AUTH-TIME-001',
            name='Missing Execution Timelock',
            category=AuthCategory.TIMELOCK,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.MISSING_TIME_LOCK,
            pattern=r'function\s+execute\([^)]*\)\s*public\s*(?:onlyGovernance)?.*\{(?!delay|timelock|after|block\.timestamp)',
            description='Execute without timelock delay',
            impact='Can execute immediately after proposal passes',
            attack_vector='Direct execution call',
            cwe_ids=['CWE-293', 'CWE-382'],
            cvss_base=8.8,
            exploitability=Exploitability.EASY,
            recommendation='Implement minimum delay',
            detection_logic='Check timelock in execute',
            references=['No timelock']
        )
        
        self.rules['AUTH-TIME-002'] = AuthRule(
            rule_id='AUTH-TIME-002',
            name='Zero Timelock Delay',
            category=AuthCategory.TIMELOCK,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.MISSING_TIME_LOCK,
            pattern=r'uint256\s+public\s+timelockDelay\s*=\s*0',
            description='Timelock delay set to zero',
            impact='No delay between proposal and execution',
            attack_vector='Execute immediately',
            cwe_ids=['CWE-293'],
            cvss_base=7.5,
            exploitability=Exploitability.EASY,
            recommendation='Set delay to at least 2 days',
            detection_logic='Check timelock value',
            references=['Zero delay']
        )
        
        self.rules['AUTH-TIME-003'] = AuthRule(
            rule_id='AUTH-TIME-003',
            name='Execute Without Grace Period',
            category=AuthCategory.TIMELOCK,
            severity=AuthSeverity.MEDIUM,
            pattern_type=AuthPatternType.MISSING_TIME_LOCK,
            pattern=r'function\s+execute\([^)]*\)\s*public\s*\{(?!gracePeriod|expiry)',
            description='Execution without grace period check',
            impact='Execution can be delayed indefinitely',
            attack_vector='Wait indefinitely',
            cwe_ids=['CWE-293'],
            cvss_base=5.8,
            exploitability=Exploitability.MODERATE,
            recommendation='Add grace period check',
            detection_logic='Check grace period',
            references=['No grace period']
        )

    def _register_proxy_rules(self) -> None:
        """Register proxy upgrade vulnerability rules"""
        self.rules['AUTH-PROXY-001'] = AuthRule(
            rule_id='AUTH-PROXY-001',
            name='Unprotected Proxy Upgrade',
            category=AuthCategory.PROXY,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.UNPROTECTED_UPGRADE,
            pattern=r'function\s+upgradeTo\([^)]*\)\s*public\s*\{(?!onlyProxyAdmin|onlyOwner|admin)',
            description='Proxy upgrade without admin check',
            impact='Can upgrade to malicious implementation',
            attack_vector='Call upgradeTo with malicious logic',
            cwe_ids=['CWE-284', 'CWE-494'],
            cvss_base=9.5,
            exploitability=Exploitability.TRIVIAL,
            recommendation='Add onlyProxyAdmin modifier',
            detection_logic='Check upgradeTo protection',
            references=['Proxy upgrade']
        )
        
        self.rules['AUTH-PROXY-002'] = AuthRule(
            rule_id='AUTH-PROXY-002',
            name='Proxy Initialize Without Access Control',
            category=AuthCategory.PROXY,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.UNPROTECTED_INITIALIZE,
            pattern=r'function\s+initialize\([^)]*\)\s*public\s*(?!initializer|onlyInitializing)',
            description='Proxy initialize callable by anyone',
            impact='Can reinitialize proxy with malicious values',
            attack_vector='Call initialize on proxy',
            cwe_ids=['CWE-284', 'CWE-665'],
            cvss_base=9.3,
            exploitability=Exploitability.TRIVIAL,
            recommendation='Use initializer modifier',
            detection_logic='Check initialize protection',
            references=['Proxy initialize']
        )
        
        self.rules['AUTH-PROXY-003'] = AuthRule(
            rule_id='AUTH-PROXY-003',
            name='Implementation Not Verified',
            category=AuthCategory.PROXY,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+upgradeToAndCall\([^)]*\)\s*\{(?!code|extcodesize|isContract)',
            description='Upgrade does not verify implementation is contract',
            impact='Can upgrade to EOA address',
            attack_vector='Upgrade to non-contract address',
            cwe_ids=['CWE-20'],
            cvss_base=7.8,
            exploitability=Exploitability.EASY,
            recommendation='Verify implementation has code',
            detection_logic='Check code verification',
            references=['Implementation verification']
        )
        
        self.rules['AUTH-PROXY-004'] = AuthRule(
            rule_id='AUTH-PROXY-004',
            name='Transparent Proxy Without Admin Check',
            category=AuthCategory.PROXY,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+admin\([^)]*\)\s*external\s*returns\s*\([^)]*\)\s*\{(?!require.*msg\.sender)',
            description='Proxy admin function missing check',
            impact='Can change admin address',
            attack_vector='Call admin function',
            cwe_ids=['CWE-284'],
            cvss_base=8.5,
            exploitability=Exploitability.EASY,
            recommendation='Add admin verification',
            detection_logic='Check admin function',
            references=['Proxy admin']
        )

    def _register_pausable_rules(self) -> None:
        """Register pausable vulnerability rules"""
        self.rules['AUTH-PAUSE-001'] = AuthRule(
            rule_id='AUTH-PAUSE-001',
            name='Unrestricted Pause',
            category=AuthCategory.PAUSABLE,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.PUBLIC_PAUSE,
            pattern=r'function\s+pause\([^)]*\)\s*public\s*(?!onlyPauser|onlyRole|hasRole)',
            description='Pause function without role check',
            impact='Anyone can pause the protocol',
            attack_vector='Call pause function',
            cwe_ids=['CWE-284'],
            cvss_base=9.0,
            exploitability=Exploitability.TRIVIAL,
            recommendation='Add onlyPauser modifier',
            detection_logic='Check pause protection',
            references=['Unrestricted pause']
        )
        
        self.rules['AUTH-PAUSE-002'] = AuthRule(
            rule_id='AUTH-PAUSE-002',
            name='Unrestricted Unpause',
            category=AuthCategory.PAUSABLE,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.PUBLIC_PAUSE,
            pattern=r'function\s+unpause\([^)]*\)\s*public\s*(?!onlyPauser|onlyRole|hasRole)',
            description='Unpause function without role check',
            impact='Anyone can unpause',
            attack_vector='Call unpause',
            cwe_ids=['CWE-284'],
            cvss_base=9.0,
            exploitability=Exploitability.TRIVIAL,
            recommendation='Add onlyPauser modifier',
            detection_logic='Check unpause protection',
            references=['Unrestricted unpause']
        )
        
        self.rules['AUTH-PAUSE-003'] = AuthRule(
            rule_id='AUTH-PAUSE-003',
            name='Pausable Functions Not Paused',
            category=AuthCategory.PAUSABLE,
            severity=AuthSeverity.MEDIUM,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+\w+\s*\([^)]*\)\s*public\s*(?:whenNotPaused)?.*\{(?!.*paused\(\)|.*require.*paused)',
            description='Critical function does not check paused state',
            impact='Function works even when paused',
            attack_vector='Call function when paused',
            cwe_ids=['CWE-284'],
            cvss_base=5.0,
            exploitability=Exploitability.MODERATE,
            recommendation='Add whenNotPaused modifier',
            detection_logic='Check paused modifier',
            references=['Not pausable']
        )

    def _register_governance_rules(self) -> None:
        """Register governance vulnerability rules"""
        self.rules['AUTH-GOV-001'] = AuthRule(
            rule_id='AUTH-GOV-001',
            name='Proposal Without Quorum Check',
            category=AuthCategory.GOVERNANCE,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+castVote\([^)]*\)\s*external\s*\{(?!require.*quorum|forVotes)',
            description='Vote casting lacks quorum verification',
            impact='Proposal can pass without quorum',
            attack_vector='Vote on proposal',
            cwe_ids=['CWE-1259'],
            cvss_base=7.2,
            exploitability=Exploitability.EASY,
            recommendation='Check quorum reached',
            detection_logic='Check quorum logic',
            references=['Quorum bypass']
        )
        
        self.rules['AUTH-GOV-002'] = AuthRule(
            rule_id='AUTH-GOV-002',
            name='Proposal Without Timelock',
            category=AuthCategory.GOVERNANCE,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.MISSING_TIME_LOCK,
            pattern=r'function\s+queue\([^)]*\)\s*public\s*\{(?!eta|delay|timelock)',
            description='Proposal queued without timelock',
            impact='Can execute immediately',
            attack_vector='Queue and execute immediately',
            cwe_ids=['CWE-293'],
            cvss_base=8.5,
            exploitability=Exploitability.EASY,
            recommendation='Add execution delay',
            detection_logic='Check delay',
            references=['No timelock']
        )
        
        self.rules['AUTH-GOV-003'] = AuthRule(
            rule_id='AUTH-GOV-003',
            name='Vote Manipulation Via Flash Loan',
            category=AuthCategory.GOVERNANCE,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.FRONT_RUNNING,
            pattern=r'function\s+castVote\([^)]*\)\s*external\s*\{(?!block\.timestamp|delay)',
            description='Vote uses current balance without snapshot',
            impact='Can flash loan governance tokens to vote',
            attack_vector='Buy tokens, vote, sell tokens',
            cwe_ids=['CWE-1259'],
            cvss_base=7.8,
            exploitability=Exploitability.EASY,
            recommendation='Use checkpointed voting power',
            detection_logic='Check voting power source',
            references=['Flash loan governance']
        )

    def _register_treasury_rules(self) -> None:
        """Register treasury vulnerability rules"""
        self.rules['AUTH-TREAS-001'] = AuthRule(
            rule_id='AUTH-TREAS-001',
            name='Unprotected Treasury Withdrawal',
            category=AuthCategory.TREASURY,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.UNPROTECTED_WITHDRAW,
            pattern=r'function\s+(withdraw|withdrawETH|sweep)\s*\([^)]*\)\s*public\s*(?!onlyOwner|onlyTreasury)',
            description='Treasury withdrawal without access control',
            impact='Anyone can withdraw treasury funds',
            attack_vector='Call withdraw function',
            cwe_ids=['CWE-284', 'CWE-862'],
            cvss_base=9.5,
            exploitability=Exploitability.TRIVIAL,
            recommendation='Add onlyTreasury or multisig',
            detection_logic='Check withdrawal protection',
            references=['Treasury drain']
        )
        
        self.rules['AUTH-TREAS-002'] = AuthRule(
            rule_id='AUTH-TREAS-002',
            name='Treasury Without Multi-Sig',
            category=AuthCategory.TREASURY,
            severity=AuthSeverity.CRITICAL,
            pattern_type=AuthPatternType.WEAK_MULTISIG,
            pattern=r'function\s+withdraw\([^)]*\)\s*external\s*onlyOwner',
            description='Treasury withdrawal requires single signature',
            impact='Single point of failure',
            attack_vector='Compromise owner',
            cwe_ids=['CWE-284'],
            cvss_base=8.5,
            exploitability=Exploitability.EASY,
            recommendation='Use multi-sig for withdrawals',
            detection_logic='Check signature count',
            references=['Single signer treasury']
        )
        
        self.rules['AUTH-TREAS-003'] = AuthRule(
            rule_id='AUTH-TREAS-003',
            name='Unlimited Treasury Approval',
            category=AuthCategory.TREASURY,
            severity=AuthSeverity.HIGH,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'approve\([^)]*type\(\w+\)\.max',
            description='Unlimited approval to spender',
            impact='Spender can drain all funds',
            attack_vector='Approve and drain',
            cwe_ids=['CWE-649'],
            cvss_base=7.8,
            exploitability=Exploitability.TRIVIAL,
            recommendation='Use exact amounts',
            detection_logic='Check approval limits',
            references=['Unlimited approval']
        )

    def _register_delegation_rules(self) -> None:
        """Register delegation vulnerability rules"""
        self.rules['AUTH-DEL-001'] = AuthRule(
            rule_id='AUTH-DEL-001',
            name='Unrestricted Delegate Assignment',
            category=AuthCategory.DELEGATION,
            severity=AuthSeverity.MEDIUM,
            pattern_type=AuthPatternType.MISSING_MODIFIER,
            pattern=r'function\s+delegate\([^)]*\)\s*public\s*\{(?!require|onlyOwner)',
            description='Can delegate voting power to anyone',
            impact='Can set delegate to attacker',
            attack_vector='Delegate to attacker address',
            cwe_ids=['CWE-284'],
            cvss_base=5.5,
            exploitability=Exploitability.EASY,
            recommendation='Restrict delegate setting',
            detection_logic='Check delegate restrictions',
            references=['Delegate manipulation']
        )


class AuthDetectionContext:
    """Context for authentication detection analysis"""
    
    def __init__(self, source_code: str, contract_name: str = "Unknown"):
        self.source_code = source_code
        self.contract_name = contract_name
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.modifiers: Dict[str, str] = {}
        self.state_variables: Dict[str, str] = {}
        self.imports: Set[str] = set()
        self.inheritance: List[str] = []
        self._analyze_contract()
    
    def _analyze_contract(self) -> None:
        """Extract contract components"""
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*([^{]*)\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        for match in re.finditer(func_pattern, self.source_code, re.MULTILINE | re.DOTALL):
            func_name = match.group(1)
            self.functions[func_name] = {
                'params': match.group(2),
                'modifiers': match.group(3),
                'body': match.group(4)
            }
        
        mod_pattern = r'modifier\s+(\w+)\s*\(([^)]*)\)\s*\{([^}]+)\}'
        for match in re.finditer(mod_pattern, self.source_code, re.MULTILINE | re.DOTALL):
            mod_name = match.group(1)
            self.modifiers[mod_name] = match.group(3)
        
        var_pattern = r'(uint256|address|bool|string|bytes)(\d+)?\s+(\w+)\s*[;=\[]'
        for match in re.finditer(var_pattern, self.source_code):
            var_name = match.group(3)
            var_type = match.group(1)
            self.state_variables[var_name] = var_type
        
        inherit_pattern = r'contract\s+\w+\s+is\s+([^{]+)'
        for match in re.finditer(inherit_pattern, self.source_code):
            self.inheritance = [i.strip() for i in match.group(1).split(',')]
    
    def has_modifier(self, modifier_name: str) -> bool:
        """Check if modifier exists"""
        return modifier_name in self.modifiers
    
    def uses_openzeppelin(self, contract: str) -> bool:
        """Check if contract inherits from OpenZeppelin"""
        oz_contracts = ['Ownable', 'AccessControl', 'ERC20', 'ERC721', 'ERC1155', 
                       'Pausable', 'Governor', 'TimelockController', 'Multisig']
        return any(oc.lower() in contract.lower() for oc in oz_contracts)


class AuthRuleEngine:
    """Main engine for detecting authentication vulnerabilities"""
    
    def __init__(self):
        self.registry = AuthRuleRegistry()
        self.detected_vulnerabilities: List[AuthVulnerability] = []
        self.statistics = defaultdict(int)
    
    def analyze(self, source_code: str, contract_name: str = "Unknown") -> List[Dict[str, Any]]:
        """Analyze source code for authentication vulnerabilities"""
        self.detected_vulnerabilities.clear()
        context = AuthDetectionContext(source_code, contract_name)
        
        results = []
        for rule in self.registry.rules.values():
            matches = self._scan_rule(rule, source_code, context)
            for match in matches:
                vulnerability = self._create_vulnerability(match, rule, context)
                self.detected_vulnerabilities.append(vulnerability)
                results.append(vulnerability.to_dict())
                self.statistics[rule.category.value] += 1
        
        return results
    
    def _scan_rule(self, rule: AuthRule, source_code: str, 
                  context: AuthDetectionContext) -> List[Dict[str, Any]]:
        """Scan for a specific rule"""
        matches = []
        pattern = rule.pattern
        
        try:
            for match in re.finditer(pattern, source_code, re.MULTILINE | re.DOTALL):
                line_num = source_code[:match.start()].count('\n') + 1
                matches.append({
                    'match_text': match.group(0)[:200],
                    'line_number': line_num,
                    'function_signature': self._extract_function_name(match.group(0))
                })
        except re.error as e:
            logger.warning(f"Invalid regex pattern {rule.rule_id}: {e}")
        
        return matches
    
    def _extract_function_name(self, code_snippet: str) -> str:
        """Extract function name from code snippet"""
        match = re.search(r'function\s+(\w+)', code_snippet)
        return match.group(1) if match else code_snippet[:50]
    
    def _create_vulnerability(self, match: Dict[str, Any], rule: AuthRule,
                             context: AuthDetectionContext) -> AuthVulnerability:
        """Create vulnerability object from match"""
        return AuthVulnerability(
            vulnerability_id=f"{rule.rule_id}-{len(self.detected_vulnerabilities) + 1}",
            title=rule.name,
            category=rule.category,
            severity=rule.severity,
            pattern_type=rule.pattern_type,
            description=rule.description,
            impact=rule.impact,
            attack_vector=rule.attack_vector,
            cwe_ids=rule.cwe_ids,
            cwss_score=rule.cvss_base,
            recommendation=rule.recommendation,
            code_snippet=match['match_text'],
            function_signature=match['function_signature'],
            line_number=match['line_number'],
            exploitability=rule.exploitability,
            remediation_complexity=rule.remediation_complexity,
            references=rule.references
        )
    
    def get_report(self) -> Dict[str, Any]:
        """Generate detection report"""
        return {
            'total_vulnerabilities': len(self.detected_vulnerabilities),
            'by_category': dict(self.statistics),
            'by_severity': self._count_by_severity(),
            'vulnerabilities': [v.to_dict() for v in self.detected_vulnerabilities]
        }
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = defaultdict(int)
        for v in self.detected_vulnerabilities:
            counts[v.severity.name] += 1
        return dict(counts)


def check_auth_vulnerabilities(source_code: str, contract_name: str = "Unknown") -> Dict[str, Any]:
    """
    Main entry point for authentication vulnerability detection.
    
    Args:
        source_code: Solidity source code to analyze
        contract_name: Name of the smart contract
    
    Returns:
        Dictionary containing detected vulnerabilities and statistics
    """
    engine = AuthRuleEngine()
    vulnerabilities = engine.analyze(source_code, contract_name)
    return {
        'contract': contract_name,
        'total_issues': len(vulnerabilities),
        'vulnerabilities': vulnerabilities,
        'statistics': engine.get_report()
    }


def check_access_control(source_code: str) -> Dict[str, Any]:
    """
    Check for missing access control patterns.
    
    Args:
        source_code: Solidity source code
    
    Returns:
        Access control vulnerabilities
    """
    context = AuthDetectionContext(source_code)
    vulnerabilities = []
    
    for func_name, func in context.functions.items():
        has_auth = any(mod in ['onlyOwner', 'onlyRole', 'onlyAdmin', 'onlyMinter', 
                            'onlyPauser', 'onlyGovernance', 'auth'] 
                     for mod in func.get('modifiers', ''))
        
        critical_funcs = ['withdraw', 'mint', 'burn', 'pause', 'upgrade', 
                        'execute', 'setFee', 'transferOwnership']
        
        if any(cf in func_name.lower() for cf in critical_funcs) and not has_auth:
            vulnerabilities.append({
                'function': func_name,
                'type': 'missing_access_control',
                'severity': 'CRITICAL',
                'recommendation': f'Add access control modifier to {func_name}'
            })
    
    return {'access_control': vulnerabilities}


def check_role_based_access(source_code: str) -> Dict[str, Any]:
    """
    Check role-based access control vulnerabilities.
    
    Args:
        source_code: Solidity source code
    
    Returns:
        RBAC vulnerabilities
    """
    vulnerabilities = []
    context = AuthDetectionContext(source_code)
    
    if 'mint' in context.functions and 'onlyMinter' not in context.functions['mint'].get('modifiers', ''):
        vulnerabilities.append({
            'function': 'mint',
            'type': 'unrestricted_mint',
            'severity': 'CRITICAL'
        })
    
    if 'burn' in context.functions and 'onlyBurner' not in context.functions['burn'].get('modifiers', ''):
        vulnerabilities.append({
            'function': 'burn',
            'type': 'unrestricted_burn',
            'severity': 'HIGH'
        })
    
    return {'role_based': vulnerabilities}


def check_governance_auth(source_code: str) -> Dict[str, Any]:
    """
    Check governance authorization vulnerabilities.
    
    Args:
        source_code: Solidity source code
    
    Returns:
        Governance vulnerabilities
    """
    vulnerabilities = []
    
    if 'execute' in source_code and 'timelock' not in source_code:
        vulnerabilities.append({
            'type': 'missing_timelock',
            'severity': 'CRITICAL',
            'recommendation': 'Add timelock to execute function'
        })
    
    if 'castVote' in source_code and 'quorum' not in source_code:
        vulnerabilities.append({
            'type': 'missing_quorum',
            'severity': 'HIGH',
            'recommendation': 'Verify quorum before execution'
        })
    
    return {'governance': vulnerabilities}


def generate_auth_test_cases(vulnerability: Dict[str, Any]) -> List[str]:
    """
    Generate Foundry test cases for authentication vulnerabilities.
    
    Args:
        vulnerability: Detected vulnerability details
    
    Returns:
        List of test case code snippets
    """
    test_cases = []
    vuln_type = vulnerability.get('pattern_type', 'unknown')
    
    if 'MISSING_MODIFIER' in vuln_type:
        test_cases.append(f'''function testAccessControl{len(test_cases)+1}() public {{
    address attacker = makeAddr("attacker");
    vm.prank(attacker);
    vm.expectRevert(abi.encodeWithSignature("Ownable: caller is not the owner"));
    // Call vulnerable function
    this.vulnerableFunction();
}}'''
        )
    
    return test_cases


if __name__ == "__main__":
    sample_code = '''
    pragma solidity ^0.8.0;
    
    contract VulnerableToken is ERC20 {
        address public owner;
        
        function mint(address to, uint256 amount) public {
            _mint(to, amount);
        }
        
        function withdraw() public {
            payable(msg.sender).transfer(address(this).balance);
        }
        
        function pause() public {
            _pause();
        }
        
        function setFee(uint256 newFee) public {
            fee = newFee;
        }
    }
    '''
    
    results = check_auth_vulnerabilities(sample_code, "VulnerableToken")
    print(json.dumps(results, indent=2))