"""
Bypass Security Rules for Blockchain Smart Contracts

This module provides comprehensive security bypass detection rules specifically
designed for Solidity smart contracts and EVM-based blockchain protocols.
Covers common bypass techniques attackers use to circumvent security controls
in DeFi protocols, NFT marketplaces, DAOs, and other Web3 applications.

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


class BypassCategory(Enum):
    """Categories of bypass vulnerabilities in blockchain"""
    CALL_REPLAY = "call_replay"
    SIGNATURE_REPLAY = "signature_replay"
    CHAIN_REPLAY = "chain_replay"
    ACCESS_CONTROL_BYPASS = "access_control_bypass"
    GAS_LIMIT_BYPASS = "gas_limit_bypass"
    TIMING_BYPASS = "timing_bypass"
    PRICE_ORACLE_BYPASS = "price_oracle_bypass"
    LIQUIDATION_BYPASS = "liquidation_bypass"
    GOVERNANCE_BYPASS = "governance_bypass"
    WRAPPER_BYPASS = "wrapper_bypass"
    PROXY_UPGRADE_BYPASS = "proxy_upgrade_bypass"
    TOKEN_BYPASS = "token_bypass"
    FLASH_LOAN_BYPASS = "flash_loan_bypass"
    ROUNDING_BYPASS = "rounding_bypass"
    DIVISION_BYPASS = "division_bypass"
    FRONT_RUNNING = "front_running"
    DELEGATION_CALL = "delegation_call"
    INITIALIZE_PROTECTION = "initialize_protection"


class BypassType(Enum):
    """Types of bypass vulnerabilities"""
    SIGNATURE_REPLAY_ATTACK = "signature_replay_attack"
    CALL_REPLAY_ATTACK = "call_replay_attack"
    CHAIN_REPLAY_ATTACK = "chain_replay_attack"
    FRONT_RUNNING = "front_running"
    SANDWICH_ATTACK = "sandwich_attack"
    ORACLE_MANIPULATION = "oracle_manipulation"
    TIMING_ORACLE = "timing_oracle"
    GAS_TOKEN_VICTIM = "gas_token_victim"
    DELEGATION_CALL = "delegation_call"
    INITIALIZE_PROTECTION = "initialize_protection"
    ACCESS_CONTROL = "access_control"
    ROLE_ESCALATION = "role_escalation"
    OWNERSHIP_TAKEOVER = "ownership_takeover"
    TIMING_BYPASS = "timing_bypass"
    TOKEN_BYPASS = "token_bypass"
    FLASH_LOAN_BYPASS = "flash_loan_bypass"
    ROUNDING_BYPASS = "rounding_bypass"


class SeverityLevel(Enum):
    """Severity levels for vulnerabilities"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


class ExploitabilityLevel(Enum):
    """How exploitable the vulnerability is"""
    TRIVIAL = 5
    EASY = 4
    MODERATE = 3
    DIFFICULT = 2
    EXPERT = 1


@dataclass
class BypassVulnerability:
    """Represents a discovered bypass vulnerability"""
    vulnerability_id: str
    title: str
    category: BypassCategory
    bypass_type: BypassType
    severity: SeverityLevel
    exploitability: ExploitabilityLevel
    description: str
    impact: str
    attack_vector: str
    cwe_id: str
    cwe_url: str
    recommendation: str
    code_snippet: str
    function_name: str
    line_number: int
    gas_impact: Optional[int] = None
    references: List[str] = field(default_factory=list)
    test_cases: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerability_id': self.vulnerability_id,
            'title': self.title,
            'category': self.category.value,
            'bypass_type': self.bypass_type.value,
            'severity': self.severity.name,
            'exploitability': self.exploitability.name,
            'description': self.description,
            'impact': self.impact,
            'attack_vector': self.attack_vector,
            'cwe_id': self.cwe_id,
            'cwe_url': self.cwe_url,
            'recommendation': self.recommendation,
            'code_snippet': self.code_snippet,
            'function_name': self.function_name,
            'line_number': self.line_number,
            'gas_impact': self.gas_impact,
            'references': self.references,
            'test_cases': self.test_cases
        }


@dataclass
class BypassRule:
    """Represents a bypass detection rule"""
    rule_id: str
    name: str
    category: BypassCategory
    bypass_type: BypassType
    severity: SeverityLevel
    exploitability: ExploitabilityLevel
    pattern: str
    description: str
    impact: str
    attack_vector: str
    cwe_id: str
    cvss_base: float
    recommendation: str
    detection_technique: str
    false_positive_filters: List[str] = field(default_factory=list)
    required_context: List[str] = field(default_factory=list)
    severity_modifiers: Dict[str, float] = field(default_factory=dict)
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
            'bypass_type': self.bypass_type.value,
            'severity': self.severity.name,
            'exploitability': self.exploitability.name,
            'pattern': self.pattern,
            'description': self.description,
            'impact': self.impact,
            'attack_vector': self.attack_vector,
            'cwe_id': self.cwe_id,
            'cvss_base': self.cvss_base,
            'recommendation': self.recommendation,
            'detection_technique': self.detection_technique,
            'false_positive_filters': self.false_positive_filters,
            'references': self.references
        }


class BypassRuleRegistry:
    """Registry of all bypass detection rules"""
    
    def __init__(self):
        self.rules: Dict[str, BypassRule] = {}
        self._register_all_rules()
    
    def _register_all_rules(self) -> None:
        """Register all Web3 bypass rules"""
        self._register_signature_replay_rules()
        self._register_call_replay_rules()
        self._register_chain_replay_rules()
        self._register_front_running_rules()
        self._register_oracle_manipulation_rules()
        self._register_gas_related_rules()
        self._register_delegation_rules()
        self._register_initialization_rules()
        self._register_access_control_rules()
        self._register_governance_bypass_rules()
        self._register_liquidation_rules()
        self._register_wrapper_rules()
        self._register_proxy_upgrade_rules()
        self._register_token_bypass_rules()
    
    def _register_signature_replay_rules(self) -> None:
        """Register signature replay bypass rules"""
        self.rules['BYP-SIG-001'] = BypassRule(
            rule_id='BYP-SIG-001',
            name='Missing Signature Replay Protection',
            category=BypassCategory.SIGNATURE_REPLAY,
            bypass_type=BypassType.SIGNATURE_REPLAY_ATTACK,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.TRIVIAL,
            pattern=r'function\s+permit\([^)]*\)\s*(?:external|public).*\{(?!nonce|nonces)',
            description='permit() function does not use nonce, allowing signature replay',
            impact='Attacker can replay valid signatures to approve unlimited token transfers',
            attack_vector='Call permit() multiple times with same signature',
            cwe_id='CWE-514',
            cvss_base=9.1,
            recommendation='Add and increment nonce after each signature use',
            detection_technique='Check for nonce increment in permit function',
            false_positive_filters=['EIP2612 implementation'],
            required_context=['ERC20Permit'],
            references=['https://eips.ethereum.org/EIP/2612']
        )
        
        self.rules['BYP-SIG-002'] = BypassRule(
            rule_id='BYP-SIG-002',
            name='Missing Domain Separator',
            category=BypassCategory.SIGNATURE_REPLAY,
            bypass_type=BypassType.SIGNATURE_REPLAY_ATTACK,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.EASY,
            pattern=r'function\s+\w+Signed\([^)]*\)\s*(?:external|public).*\{(?!DOMAIN_SEPARATOR|_domainSeparator)',
            description='Signed function lacks domain separator for EIP-712 domain separation',
            impact='Signatures can be replayed across different contracts',
            attack_vector='Replay signature on different contract with same domain',
            cwe_id='CWE-514',
            cvss_base=8.8,
            recommendation='Implement _domainSeparator() following EIP-712',
            detection_technique='Verify domain separator in ecrecover logic',
            false_positive_filters=['Multi-sig implementation'],
            references=['https://eips.ethereum.org/EIP/712']
        )
        
        self.rules['BYP-SIG-003'] = BypassRule(
            rule_id='BYP-SIG-003',
            name='Unsigned Deadline Replay',
            category=BypassCategory.SIGNATURE_REPLAY,
            bypass_type=BypassType.SIGNATURE_REPLAY_ATTACK,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.EASY,
            pattern=r'permit\([^)]*\)\s*\{(?!block\.timestamp|deadline|expiry)',
            description='permit() lacks deadline check allowing late execution',
            impact='Signature valid indefinitely',
            attack_vector='Execute permit() at any later time',
            cwe_id='CWE-514',
            cvss_base=7.5,
            recommendation='Add deadline check: require(block.timestamp <= deadline)',
            detection_technique='Check deadline validation in permit',
            false_positive_filters=['Expiry validation'],
            references=['EIP-2612 deadline']
        )
        
        self.rules['BYP-SIG-004'] = BypassRule(
            rule_id='BYP-SIG-004',
            name='Signature V Bit Not Validated',
            category=BypassCategory.SIGNATURE_REPLAY,
            bypass_type=BypassType.SIGNATURE_REPLAY_ATTACK,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.MODERATE,
            pattern=r'ecrecover\([^)]*\)(?!.*v\s*==|.*v\s*=|require.*\(.*v\s*=)',
            description='ecrecover does not validate signature V value',
            impact=' malleable signatures can be created',
            attack_vector='Modify signature V value for replay',
            cwe_id='CWE-302',
            cvss_base=7.2,
            recommendation='Verify v is 27 or 28 (EIP-155)',
            detection_technique='Check V value validation in ecrecover',
            false_positive_filters=['EIP-155 implementation'],
            references=['https://eips.ethereum.org/EIP/155']
        )
    
    def _register_call_replay_rules(self) -> None:
        """Register call replay bypass rules"""
        self.rules['BYP-CALL-001'] = BypassRule(
            rule_id='BYP-CALL-001',
            name='Unprotected Zero-value Transfer',
            category=BypassCategory.CALL_REPLAY,
            bypass_type=BypassType.CALL_REPLAY_ATTACK,
            severity=SeverityLevel.MEDIUM,
            exploitability=ExploitabilityLevel.EASY,
            pattern=r'function\s+\w+For\([^)]*\)\s*(?:external|public).*\{(?!msg\.value\s*>\s*0|require\(msg\.value)',
            description='Function callable with zero value enabling replay',
            impact='Can replay zero-value calls to trigger state changes',
            attack_vector='Call repeatedly with zero value',
            cwe_id='CWE-820',
            cvss_base=5.5,
            recommendation='Add require(msg.value > 0)',
            detection_technique='Check value validation',
            false_positive_filters=['Free minting'],
            references=['Reentrancy via zero value']
        )
        
        self.rules['BYP-CALL-002'] = BypassRule(
            rule_id='BYP-CALL-002',
            name='Unchecked Callback',
            category=BypassCategory.CALL_REPLAY,
            bypass_type=BypassType.CALL_REPLAY_ATTACK,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.MODERATE,
            pattern=r'call\([^)]*\)(?!require|assert|if\(.*success)',
            description='Low-level call result not checked for success',
            impact='Can cause silent failures',
            attack_vector='Call that appears to succeed but fails',
            cwe_id='CWE-703',
            cvss_base=6.8,
            recommendation='Use require(success, "Call failed")',
            detection_technique='Check call return value',
            false_positive_filters=['Unchecked low-level calls'],
            references=['Unchecked call returns']
        )
    
    def _register_chain_replay_rules(self) -> None:
        """Register chain replay bypass rules"""
        self.rules['BYP-CHAIN-001'] = BypassRule(
            rule_id='BYP-CHAIN-001',
            name='Missing Chain ID Validation',
            category=BypassCategory.CHAIN_REPLAY,
            bypass_type=BypassType.CHAIN_REPLAY_ATTACK,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.EASY,
            pattern=r'DOMAIN_SEPARATOR\([^)]*\)(?!block\.chainid|chainId|_CHAIN_ID)',
            description='Domain separator does not include chain ID',
            impact='Signatures replayable across different chains',
            attack_vector='Sign transaction on testnet, execute on mainnet',
            cwe_id='CWE-514',
            cvss_base=9.0,
            recommendation='Include block.chainid in domain separator',
            detection_technique='Verify chainid in domain hash',
            false_positive_filters=['Multi-chain wrapper'],
            references=['chain-specific signatures']
        )
    
    def _register_front_running_rules(self) -> None:
        """Register front-running bypass rules"""
        self.rules['BYP-FRONT-001'] = BypassRule(
            rule_id='BYP-FRONT-001',
            name='Unprotected Swap Output',
            category=BypassCategory.FRONT_RUNNING,
            bypass_type=BypassType.SANDWICH_ATTACK,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.TRIVIAL,
            pattern=r'function\s+swap\([^)]*\)\s*external\s*(?!withdraw|callback).*\{(?!callback|\.cast\(\))',
            description='Swap function returns tokens before external call protection',
            impact='Sandwich attack possible to steal swap output',
            attack_vector='Front-run swap, back-run to capture profit',
            cwe_id='CWE-841',
            cvss_base=8.9,
            recommendation='Use callback pattern or implement flash swaps properly',
            detection_technique='Check token transfer timing',
            false_positive_filters=['Uniswap V3'],
            references=['Sandwich attack']
        )
        
        self.rules['BYP-FRONT-002'] = BypassRule(
            rule_id='BYP-FRONT-002',
            name='Pending Transaction View',
            category=BypassCategory.FRONT_RUNNING,
            bypass_type=BypassType.FRONT_RUNNING,
            severity=SeverityLevel.MEDIUM,
            exploitability=ExploitabilityLevel.EASY,
            pattern=r'function\s+getAmountOut\([^)]*\)\s*view\s*(?:external|public)',
            description='Public view function reveals pending swap prices',
            impact='Attackers can read mempool and front-run',
            attack_vector='Monitor mempool, front-run large swaps',
            cwe_id='CWE-770',
            cvss_base=5.8,
            recommendation='Use commit-reveal scheme or private pools',
            detection_technique='Check price impact functions',
            false_positive_filters=['TWAP oracle'],
            references=['Mempool front-running']
        )
        
        self.rules['BYP-FRONT-003'] = BypassRule(
            rule_id='BYP-FRONT-003',
            name='Unprotected Flash Loan Callback',
            category=BypassCategory.FRONT_RUNNING,
            bypass_type=BypassType.FLASH_LOAN_BYPASS,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.MODERATE,
            pattern=r'function\s+flashLoan\([^)]*\)\s*(?:external|public).*\{(?!require\(.*balance|require\(.*amount)',
            description='Flash loan callback lacks token balance validation',
            impact='Can receive flash loan without proper repayment',
            attack_vector='Flash loan attack vector check',
            cwe_id='CWE-841',
            cvss_base=7.5,
            recommendation='Verify token balance before and after callback',
            detection_technique='Check balance validation',
            false_positive_filters=['Aave flash loan'],
            references=['Flash loan attacks']
        )
    
    def _register_oracle_manipulation_rules(self) -> None:
        """Register oracle manipulation bypass rules"""
        self.rules['BYP-ORACLE-001'] = BypassRule(
            rule_id='BYP-ORACLE-001',
            name='Single Price Source Oracle',
            category=BypassCategory.PRICE_ORACLE_BYPASS,
            bypass_type=BypassType.ORACLE_MANIPULATION,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.TRIVIAL,
            pattern=r'function\s+getPrice\([^)]*\)\s*(?:external|public).*return\s+\w+\[0\]',
            description='Oracle uses single price source (spot price)',
            impact='Price easily manipulable with small capital',
            attack_vector='Flash loan price manipulation',
            cwe_id='CWE-1105',
            cvss_base=9.3,
            recommendation='Use TWAP or multiple oracle sources',
            detection_technique='Check price aggregation',
            false_positive_filters=['Chainlink'],
            references=['Oracle manipulation']
        )
        
        self.rules['BYP-ORACLE-002'] = BypassRule(
            rule_id='BYP-ORACLE-002',
            name='Unprotected TWAP Oracle',
            category=BypassCategory.PRICE_ORACLE_BYPASS,
            bypass_type=BypassType.TIMING_ORACLE,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.EASY,
            pattern=r'function\s+consult\([^)]*\)\s*view.*return\s+\w+',
            description='TWAP oracle with insufficient observation period',
            impact='Short TWAP windows manipulable',
            attack_vector='Manipulate price within TWAP window',
            cwe_id='CWE-1105',
            cvss_base=7.8,
            recommendation='Use longer TWAP periods (30 min+)',
            detection_technique='Check observation time',
            false_positive_filters=['Long TWAP'],
            references=['TWAP manipulation']
        )
        
        self.rules['BYP-ORACLE-003'] = BypassRule(
            rule_id='BYP-ORACLE-003',
            name='Unverified Oracle Data',
            category=BypassCategory.PRICE_ORACLE_BYPASS,
            bypass_type=BypassType.ORACLE_MANIPULATION,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.MODERATE,
            pattern=r'function\s+latestAnswer\([^)]*\)\s*external\s*(?!require|staleCheck)',
            description='Oracle answer used without staleness check',
            impact='Stale oracle data can cause wrong liquidations',
            attack_vector='Use outdated price after market move',
            cwe_id='CWE-1104',
            cvss_base=7.2,
            recommendation='Check staleness with latestTimestamp',
            detection_technique='Verify staleness check',
            false_positive_filters=['Pyth oracle'],
            references=['Stale oracle data']
        )
    
    def _register_gas_related_rules(self) -> None:
        """Register gas-related bypass rules"""
        self.rules['BYP-GAS-001'] = BypassRule(
            rule_id='BYP-GAS-001',
            name='Unlimited Gas Griefing',
            category=BypassCategory.GAS_LIMIT_BYPASS,
            bypass_type=BypassType.GAS_TOKEN_VICTIM,
            severity=SeverityLevel.MEDIUM,
            exploitability=ExploitabilityLevel.MODERATE,
            pattern=r'call\(\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*(?!2300|gas)',
            description='No gas limit specified in call',
            impact='Attacker can cause out-of-gas griefing',
            attack_vector='Send with insufficient gas',
            cwe_id='CWE-410',
            cvss_base=5.5,
            recommendation='Specify gas limit: call(..., 2300)',
            detection_technique='Check gas parameter',
            false_positive_filters=[' gasleft() usage'],
            references=['Gas griefing']
        )
        
        self.rules['BYP-GAS-002'] = BypassRule(
            rule_id='BYP-GAS-002',
            name='Variable Stack Overflow',
            category=BypassCategory.GAS_LIMIT_BYPASS,
            bypass_type=BypassType.GAS_TOKEN_VICTIM,
            severity=SeverityLevel.MEDIUM,
            exploitability=ExploitabilityLevel.DIFFICULT,
            pattern=r'function\s+batchMint\([^)]*\)\s*for\s*\(\s*\w+\s*<\s*\d+',
            description='Loop without gas check allows OOG',
            impact='Can fail unexpectedly for large batches',
            attack_vector='Transaction with many items',
            cwe_id='CWE-400',
            cvss_base=4.5,
            recommendation='Add gas checks in loops',
            detection_technique='Check loop gas estimation',
            required_context=['batch operations'],
            references=['Out of gas']
        )
    
    def _register_delegation_rules(self) -> None:
        """Register delegation call bypass rules"""
        self.rules['BYP-DELEGATE-001'] = BypassRule(
            rule_id='BYP-DELEGATE-001',
            name='Unsafe Delegatecall',
            category=BypassCategory.DELEGATION_CALL,
            bypass_type=BypassType.DELEGATION_CALL,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.MODERATE,
            pattern=r'delegatecall\([^)]*\)',
            description='delegatecall to untrusted contract',
            impact='Attacker can execute arbitrary code in contract context',
            attack_vector='delegatecall to malicious contract',
            cwe_id='CWE-252',
            cvss_base=9.5,
            recommendation='Whitelist allowed delegatecall targets',
            detection_technique='Analyze delegatecall targets',
            false_positive_filters=['proxy pattern'],
            references=['delegatecall vulnerabilities']
        )
        
        self.rules['BYP-DELEGATE-002'] = BypassRule(
            rule_id='BYP-DELEGATE-002',
            name='Unprotected Assembly Delegatecall',
            category=BypassCategory.DELEGATION_CALL,
            bypass_type=BypassType.DELEGATION_CALL,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.MODERATE,
            pattern=r'assembly\s*\{.*delegatecall',
            description='delegatecall in assembly without validation',
            impact='Storage can be corrupted via delegatecall',
            attack_vector='delegatecall in assembly',
            cwe_id='CWE-252',
            cvss_base=9.4,
            recommendation='Validate target address and gas',
            detection_technique='Find assembly delegatecall',
            required_context=['inline assembly'],
            references=['Assembly delegatecall']
        )
    
    def _register_initialization_rules(self) -> None:
        """Register initialization bypass rules"""
        self.rules['BYP-INIT-001'] = BypassRule(
            rule_id='BYP-INIT-001',
            name='Missing Initializer Check',
            category=BypassCategory.INITIALIZE_PROTECTION,
            bypass_type=BypassType.INITIALIZE_PROTECTION,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.TRIVIAL,
            pattern=r'function\s+initialize\([^)]*\)\s*(?:external|public)',
            description='initialize can be called multiple times',
            impact='Contract can be re-initialized by anyone',
            attack_vector='Call initialize again',
            cwe_id='CWE-665',
            cvss_base=9.2,
            recommendation='Add initializer modifier with _disableInitializers()',
            detection_technique='Check initializer modifier usage',
            false_positive_filters=['OpenZeppelin Initializable'],
            references=['UUPS proxy initialize']
        )
        
        self.rules['BYP-INIT-002'] = BypassRule(
            rule_id='BYP-INIT-002',
            name='Missing Proxy Initializer',
            category=BypassCategory.PROXY_UPGRADE_BYPASS,
            bypass_type=BypassType.INITIALIZE_PROTECTION,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.TRIVIAL,
            pattern=r'contract\s+\w+\s+is\s+\w+Proxy.*initialize\([^)]*\)\s*public',
            description='Proxy contract missing initialization protection',
            impact='Can initialize proxy with malicious logic',
            attack_vector='Call initialize on proxy',
            cwe_id='CWE-665',
            cvss_base=9.0,
            recommendation='Use disableInitializers() at deployment',
            detection_technique='Check proxy initialization',
            required_context=['proxy pattern'],
            references=['Transparent proxy pattern']
        )
        
        self.rules['BYP-INIT-003'] = BypassRule(
            rule_id='BYP-INIT-003',
            name='Constructor Initialization',
            category=BypassCategory.INITIALIZE_PROTECTION,
            bypass_type=BypassType.INITIALIZE_PROTECTION,
            severity=SeverityLevel.MEDIUM,
            exploitability=ExploitabilityLevel.EASY,
            pattern=r'constructor\s*\{[^}]*initialize',
            description='initialize called in constructor instead of constructor directly',
            impact='Initial values set once but proxy upgrade may bypass',
            attack_vector='Proxy implementation confusion',
            cwe_id='CWE-665',
            cvss_base=6.5,
            recommendation='Use initializer pattern',
            detection_technique='Check initialization pattern',
            false_positive_filters=['Constructable pattern'],
            references=['Constructor vs initialize']
        )
    
    def _register_access_control_rules(self) -> None:
        """Register access control bypass rules"""
        self.rules['BYP-ACCESS-001'] = BypassRule(
            rule_id='BYP-ACCESS-001',
            name='Typosquatting Role Check',
            category=BypassCategory.ACCESS_CONTROL_BYPASS,
            bypass_type=BypassType.ROLE_ESCALATION,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.EASY,
            pattern=r'require\s*\(\s*hasRole\s*\(\s*[^)]*\s*,\s*[^)]*\s*\)|_msgSender\(\)|msg\.sender',
            description='Role check using msg.sender vs _msgSender() mismatch',
            impact='Can bypass access control',
            attack_vector='Use different sender in proxy calls',
            cwe_id='CWE-639',
            cvss_base=7.0,
            recommendation='Consistently use _msgSender() or msg.sender',
            detection_technique='Analyze role checks',
            false_positive_filters=['Multi-sig'],
            references=['msg.sender vs _msgSender']
        )
        
        self.rules['BYP-ACCESS-002'] = BypassRule(
            rule_id='BYP-ACCESS-002',
            name='Zero Address Role Assignment',
            category=BypassCategory.ACCESS_CONTROL_BYPASS,
            bypass_type=BypassType.ACCESS_CONTROL,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.TRIVIAL,
            pattern=r'grantRole\s*\(\s*[^)]*,\s*address\s*\(0\)',
            description='Role can be granted to zero address',
            impact='Role assigned to burn address, irreversible',
            attack_vector='Grant role to zero address',
            cwe_id='CWE-20',
            cvss_base=6.8,
            recommendation='Check role recipient is not zero',
            detection_technique='Check role assignment',
            false_positive_filters=['Burnable roles'],
            references=['Zero address role']
        )
        
        self.rules['BYP-ACCESS-003'] = BypassRule(
            rule_id='BYP-ACCESS-003',
            name='Owner Self-Destruct',
            category=BypassCategory.ACCESS_CONTROL_BYPASS,
            bypass_type=BypassType.OWNERSHIP_TAKEOVER,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.TRIVIAL,
            pattern=r'selfdestruct\s*\(\s*owner\(\)',
            description='Contract can self-destruct to owner address',
            impact='Contract destruction callable by anyone via execute()',
            attack_vector='Call execute to selfdestruct',
            cwe_id='CWE-862',
            cvss_base=9.0,
            recommendation='Add onlyOwner to selfdestruct',
            detection_technique='Check selfdestruct access',
            false_positive_filters=['Destructible pattern'],
            references=['Self-destruct access']
        )
    
    def _register_governance_bypass_rules(self) -> None:
        """Register governance bypass rules"""
        self.rules['BYP-GOV-001'] = BypassRule(
            rule_id='BYP-GOV-001',
            name='Quorum Bypass',
            category=BypassCategory.GOVERNANCE_BYPASS,
            bypass_type=BypassType.ROLE_ESCALATION,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.MODERATE,
            pattern=r'function\s+execute\([^)]*\)\s*(?:external|public).*quorum\s*<',
            description='Low quorum enables execution with few votes',
            impact='Proposals pass with minimal participation',
            attack_vector='Execute with flash governance token',
            cwe_id='CWE-1105',
            cvss_base=7.0,
            recommendation='Set high quorum percentage',
            detection_technique='Check quorum value',
            false_positive_filters=['High quorum'],
            references=['Governance quorum']
        )
        
        self.rules['BYP-GOV-002'] = BypassRule(
            rule_id='BYP-GOV-002',
            name='Timelock Bypass',
            category=BypassCategory.GOVERNANCE_BYPASS,
            bypass_type=BypassType.TIMING_BYPASS,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.EASY,
            pattern=r'function\s+execute\([^)]*\)\s*public\s*(?!timelock|delay)',
            description='Execution without mandatory timelock',
            impact='Execute proposal immediately',
            attack_vector='Direct execute call',
            cwe_id='CWE-382',
            cvss_base=7.5,
            recommendation='Implement timelock for all execution',
            detection_technique='Check timelock',
            false_positive_filters=['Fixed timelock'],
            references=['Timelock bypass']
        )
        
        self.rules['BYP-GOV-003'] = BypassRule(
            rule_id='BYP-GOV-003',
            name='Vote Power Snapshot Bypass',
            category=BypassCategory.GOVERNANCE_BYPASS,
            bypass_type=BypassType.FRONT_RUNNING,
            severity=SeverityLevel.MEDIUM,
            exploitability=ExploitabilityLevel.EASY,
            pattern=r'function\s+castVote\([^)]*\)\s*view\s*return\s+uint256.*balanceOf',
            description='Vote counted based on current balance not snapshot',
            impact='Can buy governance tokens, vote, then dump',
            attack_vector='Buy tokens -> vote -> sell',
            cwe_id='CWE-1259',
            cvss_base=6.0,
            recommendation='Snapshot voting power at proposal creation',
            detection_technique='Check snapshot logic',
            false_positive_filters=['Snapshot voting'],
            references=['Snapshot bypass']
        )
    
    def _register_liquidation_rules(self) -> None:
        """Register liquidation bypass rules"""
        self.rules['BYP-LIQ-001'] = BypassRule(
            rule_id='BYP-LIQ-001',
            name='Liquidation Protection Bypass',
            category=BypassCategory.LIQUIDATION_BYPASS,
            bypass_type=BypassType.FRONT_RUNNING,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.TRIVIAL,
            pattern=r'function\s+liquidate\([^)]*\)\s*(?:external|public).*\{(?!require.*health|require.*liquidation)',
            description='Liquidation lacks health factor check',
            impact='Liquidate positions regardless of health',
            attack_vector='Liquidation on healthy positions',
            cwe_id='CWE-1105',
            cvss_base=8.8,
            recommendation='Verify health factor before liquidation',
            detection_technique='Check liquidation logic',
            false_positive_filters=[' health check'],
            references=['Liquidation protection']
        )
        
        self.rules['BYP-LIQ-002'] = BypassRule(
            rule_id='BYP-LIQ-002',
            name='Liquidation Bonus Manipulation',
            category=BypassCategory.LIQUIDATION_BYPASS,
            bypass_type=BypassType.ORACLE_MANIPULATION,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.MODERATE,
            pattern=r'function\s+_liquidate\([^)]*bonus[^)]*\)',
            description='Liquidator can set liquidation bonus',
            impact='Liquidator can steal excess collateral',
            attack_vector='Set high bonus to steal',
            cwe_id='CWE-1105',
            cvss_base=7.5,
            recommendation='Use fixed bonus percentage',
            detection_technique='Check bonus parameter',
            false_positive_filters=['Fixed bonus'],
            references=['Liquidation bonus']
        )
    
    def _register_wrapper_rules(self) -> None:
        """Register wrapper/token bypass rules"""
        self.rules['BYP-WRAP-001'] = BypassRule(
            rule_id='BYP-WRAP-001',
            name='Unlimited Approval Wrapper',
            category=BypassCategory.WRAPPER_BYPASS,
            bypass_type=BypassType.TOKEN_BYPASS,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.TRIVIAL,
            pattern=r'function\s+wrap\([^)]*\)\s*public\s*\{[^}]*approve\(type\(\w+\)\.max',
            description='Wrapper gives unlimited approval',
            impact='Spender can steal all wrapped tokens',
            attack_vector='Use approval to drain',
            cwe_id='CWE-649',
            cvss_base=7.8,
            recommendation='Use exact amounts in approval',
            detection_technique='Check approval limits',
            false_positive_filters=['Unlimited wrapper'],
            references=['Unlimited approval']
        )
        
        self.rules['BYP-WRAP-002'] = BypassRule(
            rule_id='BYP-WRAP-002',
            name='Wrapper Balance Manipulation',
            category=BypassCategory.WRAPPER_BYPASS,
            bypass_type=BypassType.TOKEN_BYPASS,
            severity=SeverityLevel.MEDIUM,
            exploitability=ExploitabilityLevel.EASY,
            pattern=r'function\s+deposit\([^)]*\)\s*public.*balanceOf\[.*\]\s*=',
            description='Deposit calculates balance on-chain incorrectly',
            impact='Potential balance discrepancy',
            attack_vector='Manipulate deposit calculations',
            cwe_id='CWE-1105',
            cvss_base=5.5,
            recommendation='Use balance tracking properly',
            detection_technique='Check balance logic',
            false_positive_filters=['Correct deposit'],
            references=['Wrapper balance']
        )
    
    def _register_proxy_upgrade_rules(self) -> None:
        """Register proxy upgrade bypass rules"""
        self.rules['BYP-PROXY-001'] = BypassRule(
            rule_id='BYP-PROXY-001',
            name='Upgrade Without Delay',
            category=BypassCategory.PROXY_UPGRADE_BYPASS,
            bypass_type=BypassType.ACCESS_CONTROL,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.TRIVIAL,
            pattern=r'function\s+upgradeTo\([^)]*\)\s*public\s*(?!timelock|upgradeDelay)',
            description='Proxy upgrade without timelock',
            impact='Owner can upgrade to malicious implementation',
            attack_vector='Immediate upgrade call',
            cwe_id='CWE-862',
            cvss_base=9.2,
            recommendation='Implement upgrade delay',
            detection_technique='Check upgrade timing',
            false_positive_filters=['Timelock upgrade'],
            references=['Proxy upgrade']
        )
        
        self.rules['BYP-PROXY-002'] = BypassRule(
            rule_id='BYP-PROXY-002',
            name='Implementation Not Verified',
            category=BypassCategory.PROXY_UPGRADE_BYPASS,
            bypass_type=BypassType.ACCESS_CONTROL,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.MODERATE,
            pattern=r'function\s+upgradeToAndCall\([^)]*\)\s*\{(?!require.*implementation|require.*code)',
            description='Upgrade does not verify new implementation',
            impact='Can upgrade to non-contract address',
            attack_vector='Upgrade to EOA or empty address',
            cwe_id='CWE-20',
            cvss_base=7.5,
            recommendation='Verify code at implementation address',
            detection_technique='Check verification',
            required_context=['proxy pattern'],
            references=['Implementation check']
        )
    
    def _register_token_bypass_rules(self) -> None:
        """Register token-specific bypass rules"""
        self.rules['BYP-TOKEN-001'] = BypassRule(
            rule_id='BYP-TOKEN-001',
            name='Fee-on-Transfer Manipulation',
            category=BypassCategory.TOKEN_BYPASS,
            bypass_type=BypassType.TOKEN_BYPASS,
            severity=SeverityLevel.CRITICAL,
            exploitability=ExploitabilityLevel.TRIVIAL,
            pattern=r'transfer\(\s*\w+\s*,\s*\w+\s*\)\s*public\s*\{(?!balanceOf|balance)',
            description='Transfer does not check balance changes',
            impact='Fee-on-transfer tokens can be stolen',
            attack_vector='Transfer via fee-on-transfer token',
            cwe_id='CWE-1105',
            cvss_base=8.9,
            recommendation='Verify balance change after transfer',
            detection_technique='Check balance logic',
            false_positive_filters=['Fee tokens disabled'],
            references=['Fee on transfer']
        )
        
        self.rules['BYP-TOKEN-002'] = BypassRule(
            rule_id='BYP-TOKEN-002',
            name='Inflation Attack',
            category=BypassCategory.TOKEN_BYPASS,
            bypass_type=BypassType.TOKEN_BYPASS,
            severity=SeverityLevel.HIGH,
            exploitability=ExploitabilityLevel.EASY,
            pattern=r'function\s+donate\([^)]*\)\s*public\s*\{(?!shares|totalSupply)',
            description='Donation without share calculation',
            impact='Can inflate shares to steal others deposits',
            attack_vector='Donate before large deposit',
            cwe_id='CWE-1105',
            cvss_base=7.8,
            recommendation='Calculate shares based on ratio',
            detection_technique='Check share calculation',
            required_context=['ERC4626'],
            references=['Inflation attack']
        )
        
        self.rules['BYP-TOKEN-003'] = BypassRule(
            rule_id='BYP-TOKEN-003',
            name='Return Value Mismatch',
            category=BypassCategory.TOKEN_BYPASS,
            bypass_type=BypassType.TOKEN_BYPASS,
            severity=SeverityLevel.MEDIUM,
            exploitability=ExploitabilityLevel.MODERATE,
            pattern=r'function\s+transferFrom\([^)]*\)\s*returns\s*\(\s*bool\s*\)\s*\{(?!return\s+true|return)',
            description='transferFrom returns true without actual transfer',
            impact='Silent failure can be exploited',
            attack_vector='Call appears to succeed',
            cwe_id='CWE-1105',
            cvss_base=5.8,
            recommendation='Return true only on success',
            detection_technique='Check return value',
            false_positive_filters=['Correct implementation'],
            references=['Return value']
        )
        
        self.rules['BYP-TOKEN-004'] = BypassRule(
            rule_id='BYP-TOKEN-004',
            name='Rounding Error Exploitation',
            category=BypassCategory.ROUNDING_BYPASS,
            bypass_type=BypassType.ROUNDING_BYPASS,
            severity=SeverityLevel.MEDIUM,
            exploitability=ExploitabilityLevel.DIFFICULT,
            pattern=r'depositFor\(\s*\w+\s*\)[\s\n]*for\s*\(\s*\w+\s*<\s*\(\s*\w+\s*\s*/',
            description='Division rounding down causes dust accumulation',
            impact='Attacker can accumulate fractional dust',
            attack_vector='Many small deposits',
            cwe_id='CWE-190',
            cvss_base=4.5,
            recommendation='Use mulDiv for precision',
            detection_technique='Check math precision',
            required_context=['Precision math'],
            references=['Rounding error']
        )


class BypassDetectionContext:
    """Context for bypass detection analysis"""
    
    def __init__(self, source_code: str, contract_name: str = "Unknown"):
        self.source_code = source_code
        self.contract_name = contract_name
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.imports: Set[str] = set()
        self.interface_usages: Set[str] = set()
        self._analyze_contract()
    
    def _analyze_contract(self) -> None:
        """Extract contract components"""
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*([^{]*)\{([^}]*\{[^}]*\}[^}]*)*\}'
        for match in re.finditer(func_pattern, self.source_code, re.MULTILINE | re.DOTALL):
            func_name = match.group(1)
            self.functions[func_name] = {
                'params': match.group(2),
                'modifiers': match.group(3),
                'body': match.group(4)
            }
        
        import_pattern = r'import\s+\{[^}]+\}\s+from\s+[\'"]([^\'"]+)[\'"]'
        for match in re.finditer(import_pattern, self.source_code):
            self.imports.add(match.group(1))
        
        interface_pattern = r'(IERC20|IERC721|IOracle|IAccessControl)'
        for match in re.finditer(interface_pattern, self.source_code):
            self.interface_usages.add(match.group(1))
    
    def has_interface(self, interface: str) -> bool:
        """Check if contract uses specific interface"""
        return interface in self.interface_usages
    
    def get_function(self, func_name: str) -> Optional[Dict[str, Any]]:
        """Get function details"""
        return self.functions.get(func_name)


class BypassDetectionEngine:
    """Main engine for detecting bypass vulnerabilities"""
    
    def __init__(self):
        self.registry = BypassRuleRegistry()
        self.detected_vulnerabilities: List[BypassVulnerability] = []
        self.statistics = defaultdict(int)
    
    def analyze(self, source_code: str, contract_name: str = "Unknown") -> List[Dict[str, Any]]:
        """Analyze source code for bypass vulnerabilities"""
        self.detected_vulnerabilities.clear()
        context = BypassDetectionContext(source_code, contract_name)
        
        results = []
        for rule in self.registry.rules.values():
            matches = self._scan_rule(rule, source_code, context)
            for match in matches:
                vulnerability = self._create_vulnerability(match, rule, context)
                self.detected_vulnerabilities.append(vulnerability)
                results.append(vulnerability.to_dict())
                self.statistics[rule.category.value] += 1
        
        return results
    
    def _scan_rule(self, rule: BypassRule, source_code: str, 
                   context: BypassDetectionContext) -> List[Dict[str, Any]]:
        """Scan for a specific rule"""
        matches = []
        pattern = rule.pattern
        
        try:
            for match in re.finditer(pattern, source_code, re.MULTILINE | re.DOTALL):
                line_num = source_code[:match.start()].count('\n') + 1
                matches.append({
                    'match_text': match.group(0)[:200],
                    'line_number': line_num,
                    'function_name': self._extract_function_name(match.group(0))
                })
        except re.error as e:
            logger.warning(f"Invalid regex pattern {rule.rule_id}: {e}")
        
        return matches
    
    def _extract_function_name(self, code_snippet: str) -> str:
        """Extract function name from code snippet"""
        match = re.search(r'function\s+(\w+)', code_snippet)
        return match.group(1) if match else "Unknown"
    
    def _create_vulnerability(self, match: Dict[str, Any], rule: BypassRule,
                              context: BypassDetectionContext) -> BypassVulnerability:
        """Create vulnerability object from match"""
        return BypassVulnerability(
            vulnerability_id=f"{rule.rule_id}-{len(self.detected_vulnerabilities) + 1}",
            title=rule.name,
            category=rule.category,
            bypass_type=rule.bypass_type,
            severity=rule.severity,
            exploitability=rule.exploitability,
            description=rule.description,
            impact=rule.impact,
            attack_vector=rule.attack_vector,
            cwe_id=rule.cwe_id,
            cwe_url=f"https://cwe.mitre.org/data/definitions/{rule.cwe_id.split('-')[1]}.html",
            recommendation=rule.recommendation,
            code_snippet=match['match_text'],
            function_name=match['function_name'],
            line_number=match['line_number'],
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


def check_bypass_vulnerabilities(source_code: str, contract_name: str = "Unknown") -> Dict[str, Any]:
    """
    Main entry point for bypass vulnerability detection.
    
    Args:
        source_code: Solidity source code to analyze
        contract_name: Name of the smart contract
    
    Returns:
        Dictionary containing detected vulnerabilities and statistics
    """
    engine = BypassDetectionEngine()
    vulnerabilities = engine.analyze(source_code, contract_name)
    return {
        'contract': contract_name,
        'total_issues': len(vulnerabilities),
        'vulnerabilities': vulnerabilities,
        'statistics': engine.get_report()
    }


def check_signature_replay(source_code: str) -> Dict[str, Any]:
    """
    Check for signature replay vulnerabilities.
    
    Args:
        source_code: Solidity source code
    
    Returns:
        Signature replay vulnerabilities
    """
    context = BypassDetectionContext(source_code)
    vulnerabilities = []
    
    for func_name in context.functions:
        func = context.get_function(func_name)
        if 'permit' in func_name.lower() or 'Signed' in func_name:
            if 'nonce' not in func['body'].lower() if func else True:
                vulnerabilities.append({
                    'type': 'signature_replay',
                    'function': func_name,
                    'severity': 'CRITICAL',
                    'description': 'Missing nonce check allows replay'
                })
    
    return {'signature_replay': vulnerabilities}


def check_oracle_manipulation(source_code: str) -> Dict[str, Any]:
    """
    Check for oracle manipulation vulnerabilities.
    
    Args:
        source_code: Solidity source code
    
    Returns:
        Oracle manipulation vulnerabilities
    """
    vulnerabilities = []
    
    single_price_pattern = r'return\s+\w+\[0\]'
    if re.search(single_price_pattern, source_code):
        vulnerabilities.append({
            'type': 'single_price_source',
            'severity': 'CRITICAL',
            'description': 'Oracle uses single spot price'
        })
    
    no_staleness = r'latestAnswer\([^)]*\)'
    if 'latestAnswer' in source_code and 'require' not in source_code:
        vulnerabilities.append({
            'type': 'stale_price',
            'severity': 'HIGH',
            'description': 'No staleness check'
        })
    
    return {'oracle_manipulation': vulnerabilities}


def check_delegatecall_usage(source_code: str) -> Dict[str, Any]:
    """
    Check for unsafe delegatecall usage.
    
    Args:
        source_code: Solidity source code
    
    Returns:
        Delegatecall vulnerabilities
    """
    vulnerabilities = []
    
    delegate_pattern = r'delegatecall\('
    if re.search(delegate_pattern, source_code):
        vulnerabilities.append({
            'type': 'delegatecall',
            'severity': 'HIGH',
            'description': 'delegatecall usage detected',
            'recommendation': 'Validate target contract'
        })
    
    return {'delegatecall_issues': vulnerabilities}


def generate_bypass_test_cases(vulnerability: Dict[str, Any]) -> List[str]:
    """
    Generate Foundry test cases for bypass vulnerabilities.
    
    Args:
        vulnerability: Detected vulnerability details
    
    Returns:
        List of test case code snippets
    """
    test_cases = []
    vuln_type = vulnerability.get('bypass_type', 'unknown')
    severity = vulnerability.get('severity', 'MEDIUM')
    
    if 'signature' in vuln_type:
        test_cases.append(f'''function test{severity}SignatureReplay() public {{
    // Test signature replay protection
    vm.prank(attacker);
    // Attempt replay attack
    vm.expectRevert();
    // Execute vulnerable function
}}''')
    
    if 'oracle' in vuln_type:
        test_cases.append(f'''function test{severity}OracleManipulation() public {{
    // Test oracle manipulation
    vm.prank(attacker);
    // Manipulate oracle price
    // Execute liquidation/swaps
    vm.expectRevert();
    // This should revert with proper oracle
}}''')
    
    return test_cases


if __name__ == "__main__":
    sample_code = '''
    contract VulnerableToken is ERC20 {
        function permit(
            address owner,
            address spender,
            uint256 value,
            uint256 deadline,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) public {
            require(deadline >= block.timestamp);
            // Missing nonce check!
            _permit(owner, spender, value, deadline, v, r, s);
            _approve(owner, spender, value);
        }
        
        function getPrice() external view returns (uint256) {
            return priceFeed.latestAnswer();
        }
    }
    '''
    
    results = check_bypass_vulnerabilities(sample_code, "VulnerableToken")
    print(json.dumps(results, indent=2))