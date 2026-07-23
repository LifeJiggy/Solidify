"""
IDOR Security Rules for Blockchain Smart Contracts

This module provides comprehensive Insecure Direct Object Reference (IDOR)
security rules specifically designed for Solidity smart contracts and
EVM-based blockchain protocols. IDOR in Web3 context refers to vulnerabilities
where unauthorized users can interact with or manipulate on-chain objects
(ERC20 tokens, NFTs, vault positions, governance votes) belonging to other users.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IDORCategory(Enum):
    """Categories of IDOR vulnerabilities in blockchain systems"""
    TOKEN_TRANSFER = "token_transfer"
    NFT_TRANSFER = "nft_transfer"
    OWNERSHIP_TRANSFER = "ownership_transfer"
    PERMISSION_MANIPULATION = "permission_manipulation"
    VAULT_ACCESS = "vault_access"
    GOVERNANCE_MANIPULATION = "governance_manipulation"
    CROSS_CHAIN_ACCESS = "cross_chain_access"
    DELEGATION_MANIPULATION = "delegation_manipulation"
    STAKING_MANIPULATION = "staking_manipulation"
    ORDER_MANIPULATION = "order_manipulation"


class IDORSeverity(Enum):
    """Severity levels for IDOR vulnerabilities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IDORPatternType(Enum):
    """Types of vulnerability patterns"""
    MISSING_ACCESS_CONTROL = "missing_access_control"
    WEAK_ACCESS_CONTROL = "weak_access_control"
    FRONT_RUNNABLE = "front_runnable"
    ROLE_CONFUSION = "role_confusion"
    APPROVAL_MISUSE = "approval_misuse"
    CALLER_CONFUSION = "caller_confusion"
    ORACLE_MANIPULATION = "oracle_manipulation"
    TIMING_ATTACK = "timing_attack"


@dataclass
class IDORVulnerability:
    """Represents a discovered IDOR vulnerability"""
    vulnerability_id: str
    category: IDORCategory
    severity: IDORSeverity
    title: str
    description: str
    pattern_type: IDORPatternType
    cwe_id: str
    cwss_score: float
    impact: str
    likelihood: str
    recommendation: str
    code_snippet: str
    function_signature: str
    line_number: int
    remediation_complexity: str
    references: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerability_id': self.vulnerability_id,
            'category': self.category.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'pattern_type': self.pattern_type.value,
            'cwe_id': self.cwe_id,
            'cwss_score': self.cwss_score,
            'impact': self.impact,
            'likelihood': self.likelihood,
            'recommendation': self.recommendation,
            'code_snippet': self.code_snippet,
            'function_signature': self.function_signature,
            'line_number': self.line_number,
            'remediation_complexity': self.remediation_complexity,
            'references': self.references
        }


@dataclass 
class IDORRule:
    """Represents an IDOR detection rule"""
    rule_id: str
    name: str
    category: IDORCategory
    severity: IDORSeverity
    pattern: str
    description: str
    pattern_type: IDORPatternType
    cwe_id: str
    cwss_base: float
    recommendation: str
    detection_logic: str
    false_positive_filters: List[str] = field(default_factory=list)
    severity_modifiers: Dict[str, float] = field(default_factory=dict)
    
    def calculate_cwss(self, context: Dict[str, Any]) -> float:
        """Calculate contextual CWSS score"""
        base_score = self.cwss_base
        for modifier, value in context.items():
            if modifier in self.severity_modifiers:
                base_score += self.severity_modifiers[modifier] * value
        return min(10.0, max(0.0, base_score))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'category': self.category.value,
            'severity': self.severity.value,
            'pattern': self.pattern,
            'description': self.description,
            'pattern_type': self.pattern_type.value,
            'cwe_id': self.cwe_id,
            'cwss_base': self.cwss_base,
            'recommendation': self.recommendation,
            'detection_logic': self.detection_logic,
            'false_positive_filters': self.false_positive_filters,
            'severity_modifiers': self.severity_modifiers
        }


class IDORRuleRegistry:
    """Registry of all IDOR detection rules"""
    
    def __init__(self):
        self.rules: Dict[str, IDORRule] = {}
        self._register_all_rules()
    
    def _register_all_rules(self) -> None:
        """Register all Web3 IDOR rules"""
        self._register_token_transfer_rules()
        self._register_nft_transfer_rules()
        self._register_ownership_rules()
        self._register_permission_rules()
        self._register_vault_rules()
        self._register_governance_rules()
        self._register_staking_rules()
        self._register_delegation_rules()
        self._register_cross_chain_rules()
    
    def _register_token_transfer_rules(self) -> None:
        """Register ERC20 token transfer IDOR rules"""
        self.rules['IDOR-TOKEN-001'] = IDORRule(
            rule_id='IDOR-TOKEN-001',
            name='Unrestricted Token Transfer',
            category=IDORCategory.TOKEN_TRANSFER,
            severity=IDORSeverity.CRITICAL,
            pattern=r'function\s+transfer\([^)]*\)\s*public\s*(?:nonReentrant|reentrancyGuard)?.*\{[^}]*(?!require\s*\(\s*msg\.sender\s*===|require\s*\(_msgSender\(\)|require\s*\(_ownerOf|onlyOwner|onlyRole)',
            description='Token transfer function lacks msg.sender verification, allowing anyone to transfer tokens from any address',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-639',
            cwss_base=9.1,
            recommendation='Add require(msg.sender == from, "Not authorized") or use OpenZeppelin Ownable',
            detection_logic='Analyzes transfer functions for missing caller verification',
            false_positive_filters=['OpenZeppelin ERC20 implementation', 'Gas optimized paths'],
            severity_modifiers={'has_value': 0.5, 'high_value_token': 0.3}
        )
        
        self.rules['IDOR-TOKEN-002'] = IDORRule(
            rule_id='IDOR-TOKEN-002',
            name='Unchecked approve() Race Condition',
            category=IDORCategory.TOKEN_TRANSFER,
            severity=IDORSeverity.HIGH,
            pattern=r'function\s+approve\([^)]*\)\s*public\s*(?:nonReentrant)?.*\{[^}]*(?!require\s*\(\s*msg\.sender',
            description='approve() function vulnerable to race condition allowing attackers to steal tokens via front-running',
            pattern_type=IDORPatternType.FRONT_RUNNABLE,
            cwe_id='CWE-302',
            cwss_base=7.5,
            recommendation='Use increaseAllowance/decreaseAllowance instead of approve()',
            detection_logic='Checks for approve() without msg.sender validation',
            false_positive_filters=['ERC20Pausable'],
            severity_modifiers={'in_production': 0.2, 'has_flashloan': 0.4}
        )
        
        self.rules['IDOR-TOKEN-003'] = IDORRule(
            rule_id='IDOR-TOKEN-003',
            name='TransferFrom Without Allowance Check',
            category=IDORCategory.TOKEN_TRANSFER,
            severity=IDORSeverity.CRITICAL,
            pattern=r'function\s+transferFrom\([^)]*\)\s*public.*\{[^}]*_spender\s*==\s*msg\.sender',
            description='transferFrom checks allowance but not if spender == msg.sender allowing unauthorized transfers',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-639',
            cwss_base=8.8,
            recommendation='Ensure allowance is properly checked and use safeTransferFrom',
            detection_logic='Verifies transferFrom has proper allowance validation',
            false_positive_filters=['Wrapper contracts'],
            severity_modifiers={'unlimited_allowance': 0.3}
        )
        
        self.rules['IDOR-TOKEN-004'] = IDORRule(
            rule_id='IDOR-TOKEN-004',
            name='Mint Function Without Access Control',
            category=IDORCategory.TOKEN_TRANSFER,
            severity=IDORSeverity.CRITICAL,
            pattern=r'function\s+mint\([^)]*\)\s*public\s*(?!onlyOwner|onlyMinter|hasRole|MINTER_ROLE)',
            description='Token minting function lacks access control, anyone can mint unlimited tokens',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-862',
            cwss_base=9.5,
            recommendation='Add onlyMinter role check or onlyOwner modifier',
            detection_logic='Scans for mint functions without role-based access',
            false_positive_filters=['MinterPauser role'],
            severity_modifiers={'no_supply_cap': 0.4}
        )
        
        self.rules['IDOR-TOKEN-005'] = IDORRule(
            rule_id='IDOR-TOKEN-005',
            name='Burn Function Without Ownership验证',
            category=IDORCategory.TOKEN_TRANSFER,
            severity=IDORSeverity.HIGH,
            pattern=r'function\s+burn\([^)]*\)\s*public\s*(?:nonReentrant)?.*\{[^}]*(?!require\s*\(\s*msg\.sender\s*===|require\s*\(\s*_ownerOf',
            description='Burn function allows anyone to burn tokens they dont own',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-639',
            cwss_base=7.8,
            recommendation='Verify msg.sender owns the tokens before burning',
            detection_logic='Checks burn functions for owner verification',
            false_positive_filters=['Burnable ERC20'],
            severity_modifiers={'irreversible': 0.2}
        )
        
        self.rules['IDOR-TOKEN-006'] = IDORRule(
            rule_id='IDOR-TOKEN-006',
            name='SetReserveRates Without Authorization',
            category=IDORCategory.TOKEN_TRANSFER,
            severity=IDORSeverity.HIGH,
            pattern=r'function\s+setReserveRate\([^)]*\)\s*external\s*(?!onlyOwner|onlyAdmin|hasRole)',
            description='Reserve rate setting lacks access control affecting token economics',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-862',
            cwss_base=7.2,
            recommendation='Add role-based access control for rate setting',
            detection_logic='Analyzes reserve functions for access control',
            false_positive_filters=['Rate limiter contracts'],
            severity_modifiers={'governance_controlled': 0.1}
        )

    def _register_nft_transfer_rules(self) -> None:
        """Register NFT (ERC721/ERC1155) IDOR rules"""
        self.rules['IDOR-NFT-001'] = IDORRule(
            rule_id='IDOR-NFT-001',
            name='NFT SafeTransferFrom Without Owner Check',
            category=IDORCategory.NFT_TRANSFER,
            severity=IDORSeverity.CRITICAL,
            pattern=r'function\s+safeTransferFrom\([^)]*\)\s*public\s*(?:nonReentrant)?.*\{[^}]*(?!require\s*\(\s*_ownerOf\[|ownerOf\(',
            description='NFT safeTransferFrom does not verify msg.sender owns the token',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-639',
            cwss_base=8.9,
            recommendation='Use openzeppelin safeTransferFrom which includes owner verification',
            detection_logic='Checks safeTransferFrom implementation',
            false_positive_filters=['openzeppelin SafeNFT'],
            severity_modifiers={'high_value_nft': 0.5}
        )
        
        self.rules['IDOR-NFT-002'] = IDORRule(
            rule_id='IDOR-NFT-002',
            name='Batch Transfer Without Authorization',
            category=IDORCategory.NFT_TRANSFER,
            severity=IDORSeverity.HIGH,
            pattern=r'function\s+batchTransfer\([^)]*\)\s*public\s*(?!onlyOwner|hasRole)',
            description='Batch NFT transfer lacks authorization allowing mass theft',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-862',
            cwss_base=8.5,
            recommendation='Implement batch transfer with proper access control',
            detection_logic='Analyzes batch operations for authorization',
            false_positive_filters=['Batchable extension'],
            severity_modifiers={'large_batch': 0.3}
        )
        
        self.rules['IDOR-NFT-003'] = IDORRule(
            rule_id='IDOR-NFT-003',
            name='SetURI Without Access Control',
            category=IDORCategory.NFT_TRANSFER,
            severity=IDORSeverity.MEDIUM,
            pattern=r'function\s+setURI\([^)]*\)\s*public\s*(?:virtual)?\s*(?!onlyOwner|onlyAdmin|hasRole)',
            description='ERC1155 setURI allows anyone to change metadata URI',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-862',
            cwss_base=6.5,
            recommendation='Add onlyOwner or admin role for setURI',
            detection_logic='Checks URI setting functions',
            false_positive_filters=['Immutable URI'],
            severity_modifiers={'mutable_metadata': 0.2}
        )
        
        self.rules['IDOR-NFT-004'] = IDORRule(
            rule_id='IDOR-NFT-004',
            name='Mint Without Token ID Validation',
            category=IDORCategory.NFT_TRANSFER,
            severity=IDORSeverity.MEDIUM,
            pattern=r'function\s+mint\([^)]*uint256\s+tokenId[^)]*\)[^}]*(?!_exists\(|!_exists\(',
            description='Mint function does not verify tokenId is unique, allowing ID collision',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-20',
            cwss_base=5.5,
            recommendation='Check token does not exist before minting',
            detection_logic='Validates tokenId uniqueness checks',
            false_positive_filters=['Auto-increment IDs'],
            severity_modifiers={'sequential_ids': 0.2}
        )
        
        self.rules['IDOR-NFT-005'] = IDORRule(
            rule_id='IDOR-NFT-005',
            name='Approve For All Without Confirmation',
            category=IDORCategory.NFT_TRANSFER,
            severity=IDORSeverity.HIGH,
            pattern=r'setApprovalForAll[^}]*(?!require\s*\(\s*msg\.sender',
            description='setApprovalForAll can be front-run to steal all NFTs',
            pattern_type=IDORPatternType.FRONT_RUNNABLE,
            cwe_id='CWE-302',
            cwss_base=7.0,
            recommendation='Use SafeSetApprovalForAll with operator confirmation',
            detection_logic='Checks approval for all race conditions',
            false_positive_filters=['Zero address approval'],
            severity_modifiers={'flashloan_exploitable': 0.4}
        )

    def _register_ownership_rules(self) -> None:
        """Register ownership transfer IDOR rules"""
        self.rules['IDOR-OWN-001'] = IDORRule(
            rule_id='IDOR-OWN-001',
            name='Ownership Transfer Without New Owner Verification',
            category=IDORCategory.OWNERSHIP_TRANSFER,
            severity=IDORSeverity.CRITICAL,
            pattern=r'function\s+transferOwnership\([^)]*\)\s*public\s*(?:onlyOwner)?.*\{[^}]*(?!require\s*\(\s*newOwner\s*!=|require\s*\(\s*newOwner\s*!)',
            description='Ownership transfer accepts any address including zero address',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-20',
            cwss_base=7.5,
            recommendation='Verify newOwner is not zero address',
            detection_logic='Checks ownership transfer validation',
            false_positive_filters=['AdvancedOwnable'],
            severity_modifiers={'no_timelock': 0.3}
        )
        
        self.rules['IDOR-OWN-002'] = IDORRule(
            rule_id='IDOR-OWN-002',
            name='Pending Owner Without Timelock',
            category=IDORCategory.OWNERSHIP_TRANSFER,
            severity=IDORSeverity.MEDIUM,
            pattern=r'function\s+claimOwnership\([^)]*\)\s*public\s*(?!onlyPendingOwner|withinTime)',
            description='Immediate ownership claim without timelock window',
            pattern_type=IDORPatternType.TIMING_ATTACK,
            cwe_id='CWE-382',
            cwss_base=5.5,
            recommendation='Implement delay between transferOwnership and claimOwnership',
            detection_logic='Checks for pending ownership pattern',
            false_positive_filters=['TimelockController'],
            severity_modifiers={'no_timelock': 0.3}
        )
        
        self.rules['IDOR-OWN-003'] = IDORRule(
            rule_id='IDOR-OWN-003',
            name='Renounce Ownership Without Validation',
            category=IDORCategory.OWNERSHIP_TRANSFER,
            severity=IDORSeverity.HIGH,
            pattern=r'function\s+renounceOwnership\([^)]*\)\s*public\s*(?!onlyOwner|confirm)',
            description='Renounce ownership callable by anyone after ownership transfer',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-862',
            cwss_base=6.8,
            recommendation='Add additional confirmation for renounce',
            detection_logic='Analyzes renounce function access',
            false_positive_filters=['Multi-sig renounce'],
            severity_modifiers={'loss_irreversible': 0.4}
        )

    def _register_permission_rules(self) -> None:
        """Register permission management IDOR rules"""
        self.rules['IDOR-PERM-001'] = IDORRule(
            rule_id='IDOR-PERM-001',
            name='Grant Role Without Validator',
            category=IDORCategory.PERMISSION_MANIPULATION,
            severity=IDORSeverity.CRITICAL,
            pattern=r'function\s+grantRole\([^)]*\)\s*public\s*(?:onlyRole|onlyAdmin)?.*\{[^}]*(?!require\s*\(\s*hasRole\(',
            description='Role granting not validated against grantor permissions',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-862',
            cwss_base=8.7,
            recommendation='Verify grantor has proper role',
            detection_logic='Checks role grant authorization',
            false_positive_filters=['AccessControlEnumerable'],
            severity_modifiers={'privileged_role': 0.5}
        )
        
        self.rules['IDOR-PERM-002'] = IDORRule(
            rule_id='IDOR-PERM-002',
            name='Revoke Role Without Access Control',
            category=IDORCategory.PERMISSION_MANIPULATION,
            severity=IDORSeverity.HIGH,
            pattern=r'function\s+revokeRole\([^)]*\)\s*public\s*(?!onlyRole\(|hasRole\()',
            description='Anyone can revoke any role including admin roles',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-862',
            cwss_base=7.8,
            recommendation='Verify revoker has appropriate role',
            detection_logic='Checks revoke role authorization',
            false_positive_filters=['Multi-sig revoke'],
            severity_modifiers={'last_admin': 0.5}
        )
        
        self.rules['IDOR-PERM-003'] = IDORRule(
            rule_id='IDOR-PERM-003',
            name='Pause Without Admin Check',
            category=IDORCategory.PERMISSION_MANIPULATION,
            severity=IDORSeverity.HIGH,
            pattern=r'function\s+pause\([^)]*\)\s*external\s*(?!onlyPauser|hasRole|Pauser_ROLE)',
            description='Pause function callable by non-pauser',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-862',
            cwss_base=6.5,
            recommendation='Add pauser role requirement',
            detection_logic='Checks pause access control',
            false_positive_filters=['Governance pause'],
            severity_modifiers={'unlimited_pause': 0.2}
        )

    def _register_vault_rules(self) -> None:
        """Register vault/treasury IDOR rules"""
        self.rules['IDOR-VAULT-001'] = IDORRule(
            rule_id='IDOR-VAULT-001',
            name='Vault Withdrawal Without Multi-Sig',
            category=IDORCategory.VAULT_ACCESS,
            severity=IDORSeverity.CRITICAL,
            pattern=r'function\s+withdraw\([^)]*\)\s*public\s*(?:nonReentrant)?.*\{[^}]*(?!require\s*\(\s*_msgSender\(\)|multisig)',
            description='Vault withdrawal lacks multi-signature requirement',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-862',
            cwss_base=9.0,
            recommendation='Implement multi-sig or timelock for withdrawals',
            detection_logic='Scans withdrawal functions',
            false_positive_filters=['TimelockWithdraw'],
            severity_modifiers={'high_value': 0.4}
        )
        
        self.rules['IDOR-VAULT-002'] = IDORRule(
            rule_id='IDOR-VAULT-002',
            name='Vault Asset Allocation Without Governance',
            category=IDORCategory.VAULT_ACCESS,
            severity=IDORSeverity.HIGH,
            pattern=r'function\s+allocate\([^)]*\)\s*external\s*(?:onlyOwner|only Governan)?.*\{[^}]*(?! governance\(|proposal)',
            description='Asset allocation does not require governance approval',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-862',
            cwss_base=7.2,
            recommendation='Route allocation through governance',
            detection_logic='Checks governance integration',
            false_positive_filters=[' governance Vault'],
            severity_modifiers={'no_timelock': 0.3}
        )

    def _register_governance_rules(self) -> None:
        """Register governance IDOR rules"""
        self.rules['IDOR-GOV-001'] = IDORRule(
            rule_id='IDOR-GOV-001',
            name='Vote Manipulation Without Weight Verification',
            category=IDORCategory.GOVERNANCE_MANIPULATION,
            severity=IDORSeverity.CRITICAL,
            pattern=r'function\s+castVote\([^)]*\)\s*external\s*(?:nonReentrant)?.*\{[^}]*(?!require\s*\(\s*getVotes\(',
            description='Vote casting does not verify voting weight',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-1259',
            cwss_base=8.2,
            recommendation='Use getVotes() to verify weight before counting',
            detection_logic='Checks vote weight validation',
            false_positive_filters=['IVotes implementation'],
            severity_modifiers={'提案_power': 0.4}
        )
        
        self.rules['IDOR-GOV-002'] = IDORRule(
            rule_id='IDOR-GOV-002',
            name='Delegate Vote Without Balance Check',
            category=IDORCategory.GOVERNANCE_MANIPULATION,
            severity=IDORSeverity.MEDIUM,
            pattern=r'function\s+delegate\([^)]*\)\s*public\s*(?:nonReentrant)?.*\{[^}]*(?!require\s*\(\s*getVotes|balanceOf)',
            description='Delegation does not verify token balance',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-20',
            cwss_base=5.8,
            recommendation='Verify delegator has voting power',
            detection_logic='Checks delegation validation',
            false_positive_filters=['Dynamic delegation'],
            severity_modifiers={'zero_balance': 0.2}
        )
        
        self.rules['IDOR-GOV-003'] = IDORRule(
            rule_id='IDOR-GOV-003',
            name='Execute Without Timelock',
            category=IDORCategory.GOVERNANCE_MANIPULATION,
            severity=IDORSeverity.HIGH,
            pattern=r'function\s+execute\([^)]*\)\s*public\s*(?:onlyProposal|onlyGovernance)?.*\{[^}]*(?!delay|timelock)',
            description='Proposal execution without timelock delay',
            pattern_type=IDORPatternType.TIMING_ATTACK,
            cwe_id='CWE-382',
            cwss_base=6.5,
            recommendation='Implement timelock for execution',
            detection_logic='Checks timelock implementation',
            false_positive_filters=['TimelockController'],
            severity_modifiers={'no_undo': 0.3}
        )

    def _register_staking_rules(self) -> None:
        """Register staking IDOR rules"""
        self.rules['IDOR-STAK-001'] = IDORRule(
            rule_id='IDOR-STAK-001',
            name='Stake Withdrawal Without Lock Period',
            category=IDORCategory.STAKING_MANIPULATION,
            severity=IDORSeverity.HIGH,
            pattern=r'function\s+withdraw\([^)]*\)\s*public\s*(?:nonReentrant)?.*\{[^}]*(?!block\.timestamp|stakeTime|unlockTime)',
            description='Withdrawal immediately allowed without lock period',
            pattern_type=IDORPatternType.TIMING_ATTACK,
            cwe_id='CWE-382',
            cwss_base=6.0,
            recommendation='Implement forced lock period',
            detection_logic='Checks lock period logic',
            false_positive_filters=['Early withdrawal penalty'],
            severity_modifiers={'no_penalty': 0.3}
        )
        
        self.rules['IDOR-STAK-002'] = IDORRule(
            rule_id='IDOR-STAK-002',
            name='Claim Rewards Without Period Verification',
            category=IDORCategory.STAKING_MANIPULATION,
            severity=IDORSeverity.MEDIUM,
            pattern=r'function\s+claimReward\([^)]*\)\s*public\s*\{[^}]*(?!lastClaimTime|periodEnd)',
            description='Reward claim without check for completed period',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-20',
            cwss_base=5.2,
            recommendation='Verify period completion before claiming',
            detection_logic='Checks reward period logic',
            false_positive_filters=['Streaming rewards'],
            severity_modifiers={'infinite_claim': 0.2}
        )

    def _register_delegation_rules(self) -> None:
        """Register delegation IDOR rules"""
        self.rules['IDOR-DEL-001'] = IDORRule(
            rule_id='IDOR-DEL-001',
            name='Unrestricted Delegate Assignment',
            category=IDORCategory.DELEGATION_MANIPULATION,
            severity=IDORSeverity.HIGH,
            pattern=r'function\s+delegateFor\([^)]*\)\s*public\s*(?!onlyOwner|hasRole)',
            description='Can delegate voting power to any address',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-862',
            cwss_base=6.8,
            recommendation='Restrict delegation to whitelisted accounts',
            detection_logic='Checks delegation permissions',
            false_positive_filters=['Gov contract'],
            severity_modifiers={'no_limit': 0.2}
        )

    def _register_cross_chain_rules(self) -> None:
        """Register cross-chain IDOR rules"""
        self.rules['IDOR-XCH-001'] = IDORRule(
            rule_id='IDOR-XCH-001',
            name='Cross-Chain Message Without Source Verification',
            category=IDORCategory.CROSS_CHAIN_ACCESS,
            severity=IDORSeverity.CRITICAL,
            pattern=r'function\s+receiveMessage\([^)]*\)\s*external\s*\{[^}]*(?!require\s*\(\s*lib\.verifyBridge|require\s*\(\s*_verifyMessage)',
            description='Cross-chain message handler lacks origin verification',
            pattern_type=IDORPatternType.MISSING_ACCESS_CONTROL,
            cwe_id='CWE-862',
            cwss_base=9.2,
            recommendation='Implement bridge message verification',
            detection_logic='Checks bridge message validation',
            false_positive_filters=['VerifiedBridge'],
            severity_modifiers={'no_trusted_relay': 0.5}
        )
        
        self.rules['IDOR-XCH-002'] = IDORRule(
            rule_id='IDOR-XCH-002',
            name='Remote Chain Callback Without Auth',
            category=IDORCategory.CROSS_CHAIN_ACCESS,
            severity=IDORSeverity.CRITICAL,
            pattern=r'function\s+onMessageReceived\([^)]*\)\s*external\s*(?!onlyTrustedChain|fromTrusted)',
            description='Cross-chain callback callable by any chain',
            pattern_type=IDORPatternType.CALLER_CONFUSION,
            cwe_id='CWE-862',
            cwss_base=8.5,
            recommendation='Verify source chain in callback',
            detection_logic='Checks source chain validation',
            false_positive_filters=['Multi-chain verify'],
            severity_modifiers={'single_bridge': 0.3}
        )


class IDORDetectionContext:
    """Context for IDOR detection analysis"""
    
    def __init__(self, source_code: str, contract_name: str = "Unknown"):
        self.source_code = source_code
        self.contract_name = contract_name
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.modifiers: Dict[str, Any] = {}
        self.state_variables: Dict[str, Any] = {}
        self.imports: Set[str] = set()
        self._analyze_contract()
    
    def _analyze_contract(self) -> None:
        """Extract contract components"""
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*([^{]*)\{([^}]*)\}'
        for match in re.finditer(func_pattern, self.source_code, re.MULTILINE | re.DOTALL):
            func_name = match.group(1)
            params = match.group(2)
            modifiers = match.group(3)
            body = match.group(4)
            self.functions[func_name] = {
                'params': params,
                'modifiers': modifiers,
                'body': body,
                'has_authorization': 'require' in body and ('msg.sender' in body or 'onlyOwner' in modifiers)
            }
        
        mod_pattern = r'modifier\s+(\w+)\s*\(([^)]*)\)\s*\{([^}]+)\}'
        for match in re.finditer(mod_pattern, self.source_code, re.MULTILINE | re.DOTALL):
            mod_name = match.group(1)
            self.modifiers[mod_name] = match.group(3)
        
        var_pattern = r'(uint256|address|bool|string|bytes)(\d+)?\s+(\w+)\s*(?:public|private|internal)?'
        for match in re.finditer(var_pattern, self.source_code):
            var_name = match.group(3)
            self.state_variables[var_name] = match.group(1)
        
        import_pattern = r'import\s+[\'"]([^\'"]+)[\'"]'
        for match in re.finditer(import_pattern, self.source_code):
            self.imports.add(match.group(1))
    
    def has_modifier(self, modifier_name: str) -> bool:
        """Check if any function has a modifier"""
        return any(modifier_name in self.functions[f].get('modifiers', '') 
                  for f in self.functions)
    
    def get_unprotected_functions(self) -> List[str]:
        """Get functions without access control"""
        return [f for f in self.functions 
                if not self.functions[f].get('has_authorization', False)]


class IDORRuleEngine:
    """Main engine for detecting IDOR vulnerabilities"""
    
    def __init__(self):
        self.registry = IDORRuleRegistry()
        self.detected_vulnerabilities: List[IDORVulnerability] = []
        self.statistics = defaultdict(int)
    
    def analyze(self, source_code: str, contract_name: str = "Unknown") -> List[Dict[str, Any]]:
        """Analyze source code for IDOR vulnerabilities"""
        self.detected_vulnerabilities.clear()
        context = IDORDetectionContext(source_code, contract_name)
        
        results = []
        for rule in self.registry.rules.values():
            matches = self._scan_rule(rule, source_code, context)
            for match in matches:
                vulnerability = self._create_vulnerability(match, rule, context)
                self.detected_vulnerabilities.append(vulnerability)
                results.append(vulnerability.to_dict())
                self.statistics[rule.category.value] += 1
        
        return results
    
    def _scan_rule(self, rule: IDORRule, source_code: str, context: IDORDetectionContext) -> List[Dict[str, Any]]:
        """Scan for a specific rule"""
        matches = []
        pattern = rule.pattern
        
        try:
            for match in re.finditer(pattern, source_code, re.MULTILINE | re.DOTALL):
                line_num = source_code[:match.start()].count('\n') + 1
                matches.append({
                    'match_text': match.group(0),
                    'line_number': line_num,
                    'function_signature': self._extract_function_signature(match.group(0))
                })
        except re.error as e:
            logger.warning(f"Invalid regex pattern {rule.rule_id}: {e}")
        
        return matches
    
    def _extract_function_signature(self, code_snippet: str) -> str:
        """Extract function signature from code"""
        match = re.search(r'function\s+(\w+)\s*\([^)]*\)', code_snippet)
        return match.group(0) if match else code_snippet[:50]
    
    def _create_vulnerability(self, match: Dict[str, Any], rule: IDORRule, 
                               context: IDORDetectionContext) -> IDORVulnerability:
        """Create vulnerability object from match"""
        return IDORVulnerability(
            vulnerability_id=f"{rule.rule_id}-{len(self.detected_vulnerabilities) + 1}",
            category=rule.category,
            severity=rule.severity,
            title=rule.name,
            description=rule.description,
            pattern_type=rule.pattern_type,
            cwe_id=rule.cwe_id,
            cwss_score=rule.cwss_base,
            impact=f"Allows unauthorized access to {rule.category.value}",
            likelihood="Medium - exploitation requires simple transaction",
            recommendation=rule.recommendation,
            code_snippet=match['match_text'][:200],
            function_signature=match['function_signature'],
            line_number=match['line_number'],
            remediation_complexity="Medium - add access control checks",
            references=[
                f"https://cwe.mitre.org/data/definitions/{rule.cwe_id.split('-')[1]}.html",
                "https://docs.openzeppelin.com/contracts/4.x/access-control"
            ]
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
            counts[v.severity.value] += 1
        return dict(counts)


def check_idor_vulnerabilities(source_code: str, contract_name: str = "Unknown") -> Dict[str, Any]:
    """
    Main entry point for IDOR vulnerability detection.
    
    Args:
        source_code: Solidity source code to analyze
        contract_name: Name of the smart contract
    
    Returns:
        Dictionary containing detected vulnerabilities and statistics
    """
    engine = IDORRuleEngine()
    vulnerabilities = engine.analyze(source_code, contract_name)
    return {
        'contract': contract_name,
        'total_issues': len(vulnerabilities),
        'vulnerabilities': vulnerabilities,
        'statistics': engine.get_report()
    }


def verify_access_control(source_code: str) -> Dict[str, Any]:
    """
    Specialized check for missing access control patterns.
    
    Args:
        source_code: Solidity source code
    
    Returns:
        List of functions with missing access control
    """
    context = IDORDetectionContext(source_code)
    unprotected = context.get_unprotected_functions()
    
    return {
        'unprotected_functions': unprotected,
        'count': len(unprotected),
        'recommendation': 'Add onlyOwner modifier or custom access control'
    }


def detect_approval_vulnerabilities(source_code: str) -> Dict[str, Any]:
    """
    Check for ERC20 approval race conditions.
    
    Args:
        source_code: Solidity source code
    
    Returns:
        Approval-related vulnerabilities
    """
    vulnerabilities = []
    
    approve_pattern = r'function\s+approve\([^)]+\)\s*public'
    transfer_from_pattern = r'function\s+transferFrom\([^)]+\)\s*public'
    
    if re.search(approve_pattern, source_code):
        vulnerabilities.append({
            'type': 'approve_race_condition',
            'severity': 'HIGH',
            'description': 'Use increaseAllowance/decreaseAllowance to prevent front-running',
            'cwe_id': 'CWE-302'
        })
    
    if re.search(transfer_from_pattern, source_code):
        vulnerabilities.append({
            'type': 'unlimited_allowance',
            'severity': 'MEDIUM',
            'description': 'Consider using safeTransferFrom with allowance check',
            'cwe_id': 'CWE-20'
        })
    
    return {
        'approval_vulnerabilities': vulnerabilities,
        'count': len(vulnerabilities)
    }


def detect_governance_manipulation(source_code: str) -> Dict[str, Any]:
    """
    Check for governance manipulation vulnerabilities.
    
    Args:
        source_code: Solidity source code
    
    Returns:
        Governance-related vulnerabilities
    """
    context = IDORDetectionContext(source_code)
    vulnerabilities = []
    
    if 'castVote' in context.functions and not context.functions['castVote'].get('has_authorization'):
        vulnerabilities.append({
            'type': 'vote_manipulation',
            'severity': 'CRITICAL',
            'line': 'Unknown',
            'description': 'Vote weight not verified before counting'
        })
    
    if 'execute' in context.functions and not context.functions['execute'].get('has_authorization'):
        vulnerabilities.append({
            'type': 'execution_no_timelock',
            'severity': 'HIGH',
            'line': 'Unknown', 
            'description': 'Proposal execution without timelock delay'
        })
    
    return {
        'governance_issues': vulnerabilities,
        'count': len(vulnerabilities)
    }


def generate_idor_test_cases(vulnerability: Dict[str, Any]) -> List[str]:
    """
    Generate Foundry test cases for IDOR vulnerabilities.
    
    Args:
        vulnerability: Detected vulnerability details
    
    Returns:
        List of test case code snippets
    """
    test_cases = []
    vuln_type = vulnerability.get('type', 'unknown')
    severity = vulnerability.get('severity', 'MEDIUM')
    
    test_template = f'''function testIDOR{severity}_{{vuln_type.replace(' ', '_')}}() public {{
    vm.prank(attacker);
    vm.expectRevert();
    // Execute vulnerable function
}}'''
    
    test_cases.append(test_template)
    return test_cases


if __name__ == "__main__":
    sample_code = '''
    contract InsecureToken is ERC20 {
        function transfer(address to, uint256 amount) public {
            _transfer(msg.sender, to, amount);
        }
        
        function approve(address spender, uint256 amount) public {
            _approve(msg.sender, spender, amount);
        }
        
        function mint(address to, uint256 amount) public {
            _mint(to, amount);
        }
    }
    '''
    
    results = check_idor_vulnerabilities(sample_code, "InsecureToken")
    print(json.dumps(results, indent=2))