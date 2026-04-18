"""
Gas Optimization Rules for Blockchain Smart Contracts

This module provides comprehensive gas optimization detection rules specifically
designed for Solidity smart contracts and EVM-based blockchain protocols.
Covers storage optimization, function optimization, state management, loops,
external calls, event emissions, and various gas-saving patterns for
DeFi protocols, NFT marketplaces, DAOs, and Web3 applications.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import logging
import json
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class GasImprovementLevel(Enum):
    """Gas improvement severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class GasPatternCategory(Enum):
    """Categories of gas patterns"""
    STORAGE_READ = "storage_read"
    STORAGE_WRITE = "storage_write"
    STORAGE_PACKING = "storage_packing"
    EXTERNAL_CALL = "external_call"
    INTERNAL_CALL = "internal_call"
    LOOP = "loop"
    EVENT = "event"
    STRING = "string"
    FUNCTION_VISIBILITY = "function_visibility"
    DATA_LOCATION = "data_location"
    MATH_OPERATION = "math_operation"
    CONSTANT = "constant"
    IMMUTABLE = "immutable"
    STRUCT = "struct"
    MAPPING = "mapping"
    ARRAY = "array"
    LIBRARY = "library"
    CUSTOM_ERROR = "custom_error"
    UNCHECKED = "unchecked"
    BATCH_OPERATION = "batch_operation"
    CACHE = "cache"
    SHORT_CIRCUIT = "short_circuit"


class GasVulnerabilityType(Enum):
    """Types of gas inefficiency"""
    EXCESSIVE_STORAGE_READS = "excessive_storage_reads"
    UNCHECKED_EXTERNAL_CALL = "unchecked_external_call"
    INEFFICIENT_LOOP = "inefficient_loop"
    MISSING_CONSTANT = "missing_constant"
    MISSING_IMMUTABLE = "missing_immutable"
    UNOPTIMIZED_FUNCTION = "unoptimized_function"
    REDUNDANT_STATE_UPDATE = "redundant_state_update"
    EXPENSIVE_STRING = "expensive_string"
    UNOPTIMIZED_EVENT = "unoptimized_event"
    CACHE_MISS = "cache_miss"


@dataclass
class GasRule:
    """Represents a gas optimization rule"""
    rule_id: str
    name: str
    category: GasPatternCategory
    severity: GasImprovementLevel
    pattern: str
    description: str
    impact: str
    gas_saved: int
    gas_wasted: int
    recommendation: str
    detection_logic: str
    false_positive_filters: List[str] = field(default_factory=list)
    severity_modifiers: Dict[str, float] = field(default_factory=dict)
    examples: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    def calculate_impact(self, context: Dict[str, Any]) -> int:
        """Calculate gas impact based on context"""
        base = self.gas_saved - self.gas_wasted
        multiplier = context.get('frequency', 1)
        return base * multiplier
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'category': self.category.value,
            'severity': self.severity.value,
            'description': self.description,
            'impact': self.impact,
            'gas_saved': self.gas_saved,
            'gas_wasted': self.gas_wasted,
            'recommendation': self.recommendation,
            'detection_logic': self.detection_logic,
            'examples': self.examples
        }


@dataclass
class GasIssue:
    """Represents a detected gas issue"""
    issue_id: str
    rule_id: str
    title: str
    category: GasPatternCategory
    severity: GasImprovementLevel
    description: str
    code_snippet: str
    function_name: str
    line_number: int
    estimated_gas_saved: int
    estimated_gas_wasted: int
    recommendation: str
    is_false_positive: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'issue_id': self.issue_id,
            'rule_id': self.rule_id,
            'title': self.title,
            'category': self.category.value,
            'severity': self.severity.value,
            'description': self.description,
            'code_snippet': self.code_snippet,
            'function_name': self.function_name,
            'line_number': self.line_number,
            'estimated_gas_saved': self.estimated_gas_saved,
            'estimated_gas_wasted': self.estimated_gas_wasted,
            'recommendation': self.recommendation
        }


class GasRuleRegistry:
    """Registry of all gas optimization rules"""
    
    def __init__(self):
        self.rules: Dict[str, GasRule] = {}
        self._register_all_rules()
    
    def _register_all_rules(self) -> None:
        """Register all gas optimization rules"""
        self._register_storage_rules()
        self._register_function_rules()
        self._register_loop_rules()
        self._register_event_rules()
        self._register_string_rules()
        self._register_math_rules()
        self._register_constant_rules()
        self._register_data_location_rules()
        self._register_call_rules()
        self._register_batch_rules()
        self._register_struct_rules()
        self._register_mapping_rules()
        self._register_error_rules()
    
    def _register_storage_rules(self) -> None:
        """Register storage optimization rules"""
        self.rules['GAS-STORE-001'] = GasRule(
            rule_id='GAS-STORE-001',
            name='Multiple Storage Reads',
            category=GasPatternCategory.STORAGE_READ,
            severity=GasImprovementLevel.HIGH,
            pattern=r'(\w+)\s*=\s*(\w+)\[.*?\].*?\{.*?\1\s*=\s*\w+\[',
            description='Storage variable read multiple times in function',
            impact='Each storage read costs 2100 gas, cached memory read costs 3 gas',
            gas_saved=5000,
            gas_wasted=0,
            recommendation='Cache storage value in memory variable',
            detection_logic='Check for repeated storage access',
            examples=['value = balances[user]; doSomething(value); doOther(value);'],
            references=['https://ethereum.github.io/yellowpaper/paper.pdf']
        )
        
        self.rules['GAS-STORE-002'] = GasRule(
            rule_id='GAS-STORE-002',
            name='Storage Write After Read',
            category=GasPatternCategory.STORAGE_WRITE,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'\w+\s*=\s*\w+\[.*?\].*?\{.*?\w+\s*=\s*\w+\[',
            description='Storage read followed by write without optimization',
            impact='Unoptimized storage access wastes gas',
            gas_saved=2000,
            gas_wasted=0,
            recommendation='Use scratch space or cache value',
            detection_logic='Check read-then-write patterns',
            references=['Storage optimization']
        )
        
        self.rules['GAS-STORE-003'] = GasRule(
            rule_id='GAS-STORE-003',
            name='SLOAD in Loop Condition',
            category=GasPatternCategory.STORAGE_READ,
            severity=GasImprovementLevel.HIGH,
            pattern=r'for\s*\([^)]*\w+\[.*?\][^)]*\)\s*\{',
            description='Storage load in loop condition causes repeated reads',
            impact='Storage loaded every iteration',
            gas_saved=10000,
            gas_wasted=0,
            recommendation='Cache array length outside loop',
            detection_logic='Find SLOAD in for loop',
            examples=['for (uint i = 0; i < array.length; i++)'],
            references=['Loop optimization']
        )
        
        self.rules['GAS-STORE-004'] = GasRule(
            rule_id='GAS-STORE-004',
            name='Struct Assignment Without Packing',
            category=GasPatternCategory.STRUCT,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'struct\s+\w+\s*\{[^}]{150,}',
            description='Struct members not ordered for optimal packing',
            impact='Poor struct packing increases storage costs',
            gas_saved=5000,
            gas_wasted=0,
            recommendation='Order struct members by size (largest first)',
            detection_logic='Check struct member ordering',
            references=['Struct packing']
        )
        
        self.rules['GAS-STORE-005'] = GasRule(
            rule_id='GAS-STORE-005',
            name='Mapping Iteration Without Index',
            category=GasPatternCategory.MAPPING,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'for\s*\([^)]*\.length[^)]*\)[^{]*mapping',
            description='Iterating mapping without index array',
            impact='Cannot efficiently iterate mappings',
            gas_saved=5000,
            gas_wasted=0,
            recommendation='Use mapping with index array pattern',
            detection_logic='Check mapping iteration',
            references=['Mapping iteration']
        )
    
    def _register_function_rules(self) -> None:
        """Register function optimization rules"""
        self.rules['GAS-FUNC-001'] = GasRule(
            rule_id='GAS-FUNC-001',
            name='Public Instead of External',
            category=GasPatternCategory.FUNCTION_VISIBILITY,
            severity=GasImprovementLevel.LOW,
            pattern=r'function\s+\w+\s*\([^)]*\)\s*public(?!\s+returns)',
            description='Function using public visibility instead of external',
            impact='Public costs more than external for external-only functions',
            gas_saved=200,
            gas_wasted=0,
            recommendation='Use external for functions called externally only',
            detection_logic='Check function visibility',
            references=['Visibility optimization']
        )
        
        self.rules['GAS-FUNC-002'] = GasRule(
            rule_id='GAS-FUNC-002',
            name='Missing View Modifier',
            category=GasPatternCategory.FUNCTION_VISIBILITY,
            severity=GasImprovementLevel.LOW,
            pattern=r'function\s+\w+\s*\([^)]*\)\s*public\s+returns(?!\s+view)',
            description='Function not modifying state but missing view modifier',
            impact='Missing view costs gas in call',
            gas_saved=1,
            gas_wasted=0,
            recommendation='Add view modifier to non-state-modifying functions',
            detection_logic='Check for state reads without view',
            references=['View functions']
        )
        
        self.rules['GAS-FUNC-003'] = GasRule(
            rule_id='GAS-FUNC-003',
            name='Missing Pure Modifier',
            category=GasPatternCategory.FUNCTION_VISIBILITY,
            severity=GasImprovementLevel.LOW,
            pattern=r'function\s+\w+\s*\([^)]*\)\s*public\s+returns\s*\([^)]*\)\s*\{(?!\s*\w+\[|\w+\.)',
            description='Function does not read or modify state but missing pure',
            impact='Missing pure does not affect gas much but indicates intent',
            gas_saved=1,
            gas_wasted=0,
            recommendation='Add pure modifier to pure functions',
            detection_logic='Check function body for state access',
            references=['Pure functions']
        )
        
        self.rules['GAS-FUNC-004'] = GasRule(
            rule_id='GAS-FUNC-004',
            name='Unnecessary Public Variable',
            category=GasPatternCategory.FUNCTION_VISIBILITY,
            severity=GasImprovementLevel.LOW,
            pattern=r'uint256\s+public\s+(\w+)',
            description='Public state variable creates getter function',
            impact='Public variable has auto-generated getter costing gas',
            gas_saved=100,
            gas_wasted=0,
            recommendation='Use private + manual getter if needed',
            detection_logic='Check public state variables',
            references=['Variable visibility']
        )
        
        self.rules['GAS-FUNC-005'] = GasRule(
            rule_id='GAS-FUNC-005',
            name='Empty Fallback Function',
            category=GasPatternCategory.FUNCTION_VISIBILITY,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'function\s+\(\s*\)\s*external\s+\{[^}]*\}',
            description='Empty fallback function exists',
            impact='Empty fallback uses gas unnecessarily',
            gas_saved=2000,
            gas_wasted=0,
            recommendation='Use receive() for ETH reception',
            detection_logic='Check for empty fallback',
            references=['Fallback function']
        )
        
        self.rules['GAS-FUNC-006'] = GasRule(
            rule_id='GAS-FUNC-006',
            name='Missing Receive Function',
            category=GasPatternCategory.FUNCTION_VISIBILITY,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'contract\s+\w+\s*\{(?!.*receive\s*\()',
            description='Contract can receive ETH but no receive() function',
            impact='Fallback used unnecessarily',
            gas_saved=2000,
            gas_wasted=0,
            recommendation='Add receive() function',
            detection_logic='Check for receive function',
            references=['Receive function']
        )
    
    def _register_loop_rules(self) -> None:
        """Register loop optimization rules"""
        self.rules['GAS-LOOP-001'] = GasRule(
            rule_id='GAS-LOOP-001',
            name='Array Length Not Cached',
            category=GasPatternCategory.LOOP,
            severity=GasImprovementLevel.HIGH,
            pattern=r'for\s*\([^)]*\.length[^)]*\)[^{]*',
            description='Array .length accessed in loop condition each iteration',
            impact='Array length loaded from storage each iteration',
            gas_saved=10000,
            gas_wasted=0,
            recommendation='Cache array length: uint len = array.length',
            detection_logic='Check for .length in for loop',
            examples=['for (uint i = 0; i < array.length; i++)'],
            references=['Loop length caching']
        )
        
        self.rules['GAS-LOOP-002'] = GasRule(
            rule_id='GAS-LOOP-002',
            name='Unchecked Loop Index Overflow',
            category=GasPatternCategory.LOOP,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'for\s*\(\s*int\d*\s+\w+',
            description='Loop index using signed int could overflow',
            impact='Using uint256 recommended for indices',
            gas_saved=50,
            gas_wasted=0,
            recommendation='Use uint256 for loop counters',
            detection_logic='Check for signed int in loop',
            references=['Loop index type']
        )
        
        self.rules['GAS-LOOP-003'] = GasRule(
            rule_id='GAS-LOOP-003',
            name='Expensive Operation in Loop',
            category=GasPatternCategory.LOOP,
            severity=GasImprovementLevel.HIGH,
            pattern=r'for\s*\{[^}]*emit\s+\w+\(',
            description='Event emitted inside loop',
            impact='Events cost gas, emit after loop if possible',
            gas_saved=10000,
            gas_wasted=0,
            recommendation='Emit event after loop with batched data',
            detection_logic='Search for emit in for loop',
            references=['Loop events']
        )
        
        self.rules['GAS-LOOP-004'] = GasRule(
            rule_id='GAS-LOOP-004',
            name='Storage Write Inside Loop',
            category=GasPatternCategory.LOOP,
            severity=GasImprovementLevel.CRITICAL,
            pattern=r'for\s*\{[^}]*\w+\s*\[\s*\w+\s*\]\s*=',
            description='Storage write inside loop without optimization',
            impact='Each storage write costs 5000+ gas minimum',
            gas_saved=20000,
            gas_wasted=0,
            recommendation='Use memory accumulation then single storage write',
            detection_logic='Check for storage writes in loops',
            examples=['balances[user] += amount;'],
            references=['Storage in loops']
        )
        
        self.rules['GAS-LOOP-005'] = GasRule(
            rule_id='GAS-LOOP-005',
            name='Inefficient Loop Type',
            category=GasPatternCategory.LOOP,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'while\s*\([^)]*\.length[^)]*\)',
            description='Using while loop instead of for',
            impact='for loops generally more optimal',
            gas_saved=100,
            gas_wasted=0,
            recommendation='Use for loop when possible',
            detection_logic='Check while loops',
            references=['Loop types']
        )
    
    def _register_event_rules(self) -> None:
        """Register event optimization rules"""
        self.rules['GAS-EVENT-001'] = GasRule(
            rule_id='GAS-EVENT-001',
            name='Unindexed Event Parameters',
            category=GasPatternCategory.EVENT,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'event\s+\w+\s*\(\s*(?!\w+\s+indexed)',
            description='Event parameters not indexed',
            impact='Indexed parameters cost less to filter',
            gas_saved=500,
            gas_wasted=0,
            recommendation='Add indexed to event parameters that need filtering',
            detection_logic='Check event definitions',
            references=['Event indexing']
        )
        
        self.rules['GAS-EVENT-002'] = GasRule(
            rule_id='GAS-EVENT-002',
            name='Event Emitted Before State Change',
            category=GasPatternCategory.EVENT,
            severity=GasImprovementLevel.LOW,
            pattern=r'emit\s+\w+\([^)]*\)[^{]*\{[^}]*(?!transfer|mint|burn)',
            description='Event emitted before state change',
            impact='State update should emit after for correct indexing',
            gas_saved=100,
            gas_wasted=0,
            recommendation='Emit events after state changes',
            detection_logic='Check emit position',
            references=['Event order']
        )
        
        self.rules['GAS-EVENT-003'] = GasRule(
            rule_id='GAS-EVENT-003',
            name='Too Many Indexed Parameters',
            category=GasPatternCategory.EVENT,
            severity=GasImprovementLevel.LOW,
            pattern=r'event\s+\w+\s*\(((?:\w+\s+indexed\s*,?\s*){4,})',
            description='More than 3 indexed parameters',
            impact='More than 3 indexed costs extra gas',
            gas_saved=100,
            gas_wasted=0,
            recommendation='Limit indexed parameters to 3',
            detection_logic='Count indexed in event',
            references=['Indexed limit']
        )
    
    def _register_string_rules(self) -> None:
        """Register string optimization rules"""
        self.rules['GAS-STRING-001'] = GasRule(
            rule_id='GAS-STRING-001',
            name='Long Error Strings',
            category=GasPatternCategory.STRING,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'require\s*\(\s*[^,]+,\s*"[^"]{32,}"',
            description='Error string longer than 32 bytes',
            impact='Long strings cost more gas',
            gas_saved=3000,
            gas_wasted=0,
            recommendation='Use custom errors instead',
            detection_logic='Check require string length',
            references=['Error strings']
        )
        
        self.rules['GAS-STRING-002'] = GasRule(
            rule_id='GAS-STRING-002',
            name='String Comparison',
            category=GasPatternCategory.STRING,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'keccak256\(\s*abi\.encodePacked\(\s*\w+\s*==\s*\w+',
            description='String equality using keccak256',
            impact='Can use custom errors for known strings',
            gas_saved=1000,
            gas_wasted=0,
            recommendation='Consider custom error for string checks',
            detection_logic='Check string comparison',
            references=['String comparison']
        )
        
        self.rules['GAS-STRING-003'] = GasRule(
            rule_id='GAS-STRING-003',
            name='Empty String Check',
            category=GasPatternCategory.STRING,
            severity=GasImprovementLevel.LOW,
            pattern=r'require\s*\(\s*bytes\(\s*\w+\s*\)\.length\s*>\s*0',
            description='Checking string length with bytes().length',
            impact='Can simplify to check empty string',
            gas_saved=100,
            gas_wasted=0,
            recommendation='Consider bytes(str).length > 0 check',
            detection_logic='Check string empty',
            references=['Empty string']
        )
    
    def _register_math_rules(self) -> None:
        """Register math optimization rules"""
        self.rules['GAS-MATH-001'] = GasRule(
            rule_id='GAS-MATH-001',
            name='Multiplication by Power of 2',
            category=GasPatternCategory.MATH_OPERATION,
            severity=GasImprovementLevel.LOW,
            pattern=r'\*\s*2\b|\*\s*4\b|\*\s*8\b|\*\s*16\b|\*\s*32\b|\*\s*64\b|\*\s*128\b|\*\s*256\b',
            description='Multiplication by power of 2',
            impact='Bit shifting cheaper than multiplication',
            gas_saved=100,
            gas_wasted=0,
            recommendation='Use bit shifting for powers of 2',
            detection_logic='Check multiplication constants',
            examples=['value * 2 => value << 1'],
            references=['Bit shifting']
        )
        
        self.rules['GAS-MATH-002'] = GasRule(
            rule_id='GAS-MATH-002',
            name='Division by Power of 2',
            category=GasPatternCategory.MATH_OPERATION,
            severity=GasImprovementLevel.LOW,
            pattern=r'/\s*2\b|/\s*4\b|/\s*8\b|/\s*16\b|/\s*32\b',
            description='Division by power of 2',
            impact='Bit shifting cheaper than division',
            gas_saved=100,
            gas_wasted=0,
            recommendation='Use bit shifting for divisions',
            detection_logic='Check division constants',
            references=['Bit shifting division']
        )
        
        self.rules['GAS-MATH-003'] = GasRule(
            rule_id='GAS-MATH-003',
            name='Unchecked Math',
            category=GasPatternCategory.MATH_OPERATION,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'\+\s*\w+\s*\+\s*[^;]{50,}\+\s*\w+',
            description='Checked addition that could be unchecked',
            impact='Unchecked saves 20-30 gas per operation',
            gas_saved=200,
            gas_wasted=0,
            recommendation='Use unchecked for proven safe operations',
            detection_logic='Check for overflow-safe additions',
            references=['Unchecked math']
        )
        
        self.rules['GAS-MATH-004'] = GasRule(
            rule_id='GAS-MATH-004',
            name='SafeMath Instead of Built-in',
            category=GasPatternCategory.MATH_OPERATION,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'using\s+SafeMath\s+for\s+',
            description='Using SafeMath when not needed in Solidity 0.8+',
            impact='Built-in overflow checks more efficient',
            gas_saved=500,
            gas_wasted=0,
            recommendation='Remove SafeMath in Solidity 0.8+',
            detection_logic='Check SafeMath usage',
            references=['SafeMath usage']
        )
        
        self.rules['GAS-MATH-005'] = GasRule(
            rule_id='GAS-MATH-005',
            name='Expensive Decimal Math',
            category=GasPatternCategory.MATH_OPERATION,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'\w+\s*/\s*\w+\s*\*\s*\w+',
            description='Division before multiplication loses precision',
            impact='Should multiply before divide',
            gas_saved=100,
            gas_wasted=0,
            recommendation='Use (a * b) / c for better precision',
            detection_logic='Check division order',
            references=['Math order']
        )
    
    def _register_constant_rules(self) -> None:
        """Register constant optimization rules"""
        self.rules['GAS-CONST-001'] = GasRule(
            rule_id='GAS-CONST-001',
            name='Non-constant Literal',
            category=GasPatternCategory.CONSTANT,
            severity=GasImprovementLevel.HIGH,
            pattern=r'(?:uint256|int256|address)\s+(\w+)\s*=\s*\d+[^;]{0,30}(?!.*constant)',
            description='Numeric literal not marked constant',
            impact='Non-constant costs gas on every access',
            gas_saved=20000,
            gas_wasted=0,
            recommendation='Mark as constant',
            detection_logic='Check numeric assignments',
            examples=['uint256 public constant RATE = 1000;'],
            references=['Constant variables']
        )
        
        self.rules['GAS-CONST-002'] = GasRule(
            rule_id='GAS-CONST-002',
            name='Non-immutable After Constructor',
            category=GasPatternCategory.IMMUTABLE,
            severity=GasImprovementLevel.HIGH,
            pattern=r'(?:uint256|address)\s+(\w+)\s*[;](?:(?!immutable)(?!=))*constructor\s*\([^)]*\)\s*\{[^}]*\1\s*=',
            description='State variable set in constructor but not immutable',
            impact='Storage costs more than immutable',
            gas_saved=15000,
            gas_wasted=0,
            recommendation='Mark as immutable',
            detection_logic='Check constructor assignments',
            references=['Immutable variables']
        )
        
        self.rules['GAS-CONST-003'] = GasRule(
            rule_id='GAS-CONST-003',
            name='Hardcoded Address',
            category=GasPatternCategory.CONSTANT,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'address\s+(\w+)\s*=\s*0x[0-9a-fA-F]{40}',
            description='Hardcoded contract address',
            impact='Should be configurable or immutable',
            gas_saved=1000,
            gas_wasted=0,
            recommendation='Use immutable or constructor parameter',
            detection_logic='Check address assignments',
            references=['Address constants']
        )
        
        self.rules['GAS-CONST-004'] = GasRule(
            rule_id='GAS-CONST-004',
            name='Magic Numbers',
            category=GasPatternCategory.CONSTANT,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'require\s*\([^)]*\s*\d{4,}[^)]*\)',
            description='Magic number in require statement',
            impact='Should use named constant',
            gas_saved=500,
            gas_wasted=0,
            recommendation='Define constant for magic numbers',
            detection_logic='Check require conditions',
            references=['Magic numbers']
        )
    
    def _register_data_location_rules(self) -> None:
        """Register data location optimization rules"""
        self.rules['GAS-DATA-001'] = GasRule(
            rule_id='GAS-DATA-001',
            name='Memory Instead of Calldata',
            category=GasPatternCategory.DATA_LOCATION,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'function\s+\w+\s*\([^)]*memory[^)]*\)\s*(?:public|external)(?!\s+returns)',
            description='Using memory instead of calldata for external functions',
            impact='Memory copies calldata, calldata directly accesses',
            gas_saved=1000,
            gas_wasted=0,
            recommendation='Use calldata for external function parameters',
            detection_logic='Check function parameter data locations',
            references=['Calldata usage']
        )
        
        self.rules['GAS-DATA-002'] = GasRule(
            rule_id='GAS-DATA-002',
            name='Unnecessary Memory Copy',
            category=GasPatternCategory.DATA_LOCATION,
            severity=GasImprovementLevel.LOW,
            pattern=r'bytes\s+(\w+)\s*=\s*abi\.encodePacked\(\s*\..*\)',
            description='ABI encoding to memory',
            impact='Can use directly without intermediate',
            gas_saved=500,
            gas_wasted=0,
            recommendation='Consider encoding in-place',
            detection_logic='Check encoding patterns',
            references=['ABI encoding']
        )
    
    def _register_call_rules(self) -> None:
        """Register external call optimization rules"""
        self.rules['GAS-CALL-001'] = GasRule(
            rule_id='GAS-CALL-001',
            name='Unchecked Low-level Call',
            category=GasPatternCategory.EXTERNAL_CALL,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'\w+\.call\s*\(\s*(?!\s*\"',
            description='Low-level call without return value check',
            impact='Return value should be checked',
            gas_saved=100,
            gas_wasted=0,
            recommendation='Check return value or use require',
            detection_logic='Check call return handling',
            references=['Low-level calls']
        )
        
        self.rules['GAS-CALL-002'] = GasRule(
            rule_id='GAS-CALL-002',
            name='.call(abi.encode())',
            category=GasPatternCategory.EXTERNAL_CALL,
            severity=GasImprovementLevel.LOW,
            pattern=r'\.call\(abi\.encode',
            description='Using call with abi.encode',
            impact='abi.encodePacked is cheaper',
            gas_saved=1000,
            gas_wasted=0,
            recommendation='Use abi.encodePacked when possible',
            detection_logic='Check encoding in calls',
            references=['Encode optimization']
        )
        
        self.rules['GAS-CALL-003'] = GasRule(
            rule_id='GAS-CALL-003',
            name='Multiple External Calls in Loop',
            category=GasPatternCategory.EXTERNAL_CALL,
            severity=GasImprovementLevel.CRITICAL,
            pattern=r'for\s*\{[^}]*\w+\.call\(',
            description='External call inside loop',
            impact='External calls are expensive',
            gas_saved=50000,
            gas_wasted=0,
            recommendation='Batch calls or accumulate then call',
            detection_logic='Find calls in loops',
            references=['Call batching']
        )
        
        self.rules['GAS-CALL-004'] = GasRule(
            rule_id='GAS-CALL-004',
            name='Send Without Gas', 
            category=GasPatternCategory.EXTERNAL_CALL,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'\.send\(\s*\d+\s*\)',
            description='send() with fixed gas',
            impact='Should use transfer or call with more gas',
            gas_saved=100,
            gas_wasted=0,
            recommendation='Use call for reentrancy protection',
            detection_logic='Check send usage',
            references=['Send vs transfer']
        )
    
    def _register_batch_rules(self) -> None:
        """Register batch operation rules"""
        self.rules['GAS-BATCH-001'] = GasRule(
            rule_id='GAS-BATCH-001',
            name='Multiple Transfers',
            category=GasPatternCategory.BATCH_OPERATION,
            severity=GasImprovementLevel.HIGH,
            pattern=r'for\s*\([^)]*\.length[^)]*\)[^{]*\.transfer',
            description='Multiple individual transfers',
            impact='Batch transfers save significant gas',
            gas_saved=10000,
            gas_wasted=0,
            recommendation='Batch transfers in single transaction',
            detection_logic='Find transfer loops',
            references=['Batch transfers']
        )
        
        self.rules['GAS-BATCH-002'] = GasRule(
            rule_id='GAS-BATCH-002',
            name='Multiple Mints',
            category=GasPatternCategory.BATCH_OPERATION,
            severity=GasImprovementLevel.HIGH,
            pattern=r'for\s*\{[^}]*_mint\(',
            description='Mint in loop',
            impact='Batch minting more efficient',
            gas_saved=10000,
            gas_wasted=0,
            recommendation='Use batch minting function',
            detection_logic='Find mint loops',
            references=['Batch minting']
        )
        
        self.rules['GAS-BATCH-003'] = GasRule(
            rule_id='GAS-BATCH-003',
            name='Multiple Events',
            category=GasPatternCategory.BATCH_OPERATION,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'for\s*\{[^}]*emit\s+\w+\(',
            description='Events emitted in loop',
            impact='Batch events save gas',
            gas_saved=5000,
            gas_wasted=0,
            recommendation='Emit single batched event',
            detection_logic='Find emit in loops',
            references=['Event batching']
        )
    
    def _register_struct_rules(self) -> None:
        """Register struct optimization rules"""
        self.rules['GAS-STRUCT-001'] = GasRule(
            rule_id='GAS-STRUCT-001',
            name='Struct Without Packing',
            category=GasPatternCategory.STRUCT,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'struct\s+\w+\s*\{[^}]{100,}(?!uint128)',
            description='Struct members could be packed better',
            impact='Packed structs use less storage',
            gas_saved=5000,
            gas_wasted=0,
            recommendation='Order by size: uint256, uint128, address, bytes32',
            detection_logic='Check struct ordering',
            references=['Struct packing']
        )
        
        self.rules['GAS-STRUCT-002'] = GasRule(
            rule_id='GAS-STRUCT-002',
            name='Struct Assignment',
            category=GasPatternCategory.STRUCT,
            severity=GasImprovementLevel.LOW,
            pattern=r'(\w+)\s*=\s*(\w+)\s*\(\)',
            description='Struct copied without storage',
            impact='Memory to memory copy is cheap',
            gas_saved=100,
            gas_wasted=0,
            recommendation='Use memory copy when possible',
            detection_logic='Check struct assignments',
            references=['Struct copying']
        )
    
    def _register_mapping_rules(self) -> None:
        """Register mapping optimization rules"""
        self.rules['GAS-MAP-001'] = GasRule(
            rule_id='GAS-MAP-001',
            name='Double Mapping Lookups',
            category=GasPatternCategory.MAPPING,
            severity=GasImprovementLevel.LOW,
            pattern=r'\w+\[\w+][\w+]\[\w+]',
            description='Nested mapping lookups',
            impact='Can simplify to single mapping',
            gas_saved=500,
            gas_wasted=0,
            recommendation='Consider mapping restructure',
            detection_logic='Check nested mappings',
            references=['Mapping optimization']
        )
        
        self.rules['GAS-MAP-002'] = GasRule(
            rule_id='GAS-MAP-002',
            name='Unnecessary Mapping Check',
            category=GasPatternCategory.MAPPING,
            severity=GasImprovementLevel.LOW,
            pattern=r'require\s*\(\s*\w+\[\w+]\s*==\s*0\s*\)',
            description='Checking mapping for zero before write',
            impact='Maps return zero for non-existent keys',
            gas_saved=500,
            gas_wasted=0,
            recommendation='Remove unnecessary zero check',
            detection_logic='Check mapping zero checks',
            references=['Mapping checks']
        )
    
    def _register_error_rules(self) -> None:
        """Register error handling optimization rules"""
        self.rules['GAS-ERR-001'] = GasRule(
            rule_id='GAS-ERR-001',
            name='Require With String',
            category=GasPatternCategory.CUSTOM_ERROR,
            severity=GasImprovementLevel.MEDIUM,
            pattern=r'require\s*\(\s*[^,]+,\s*"',
            description='Using require with string error',
            impact='Custom errors save deployment gas',
            gas_saved=3000,
            gas_wasted=0,
            recommendation='Define custom errors',
            detection_logic='Check require strings',
            examples=['revert CustomError();'],
            references=['Custom errors']
        )
        
        self.rules['GAS-ERR-002'] = GasRule(
            rule_id='GAS-ERR-002',
            name='Long Require String',
            category=GasPatternCategory.CUSTOM_ERROR,
            severity=GasImprovementLevel.LOW,
            pattern=r'require\s*\([^,]+,\s*"[^"]{32,}"',
            description='Require message longer than 32 bytes',
            impact='Each 32 bytes costs extra gas',
            gas_saved=2000,
            gas_wasted=0,
            recommendation='Shorten error message or use custom error',
            detection_logic='Check require string length',
            references=['Error length']
        )
        
        self.rules['GAS-ERR-003'] = GasRule(
            rule_id='GAS-ERR-003',
            name='Assert Instead of Require',
            category=GasPatternCategory.CUSTOM_ERROR,
            severity=GasImprovementLevel.LOW,
            pattern=r'assert\s*\(\s*\w+\s*==',
            description='Using assert for validation',
            impact='Use require for validation errors',
            gas_saved=100,
            gas_wasted=0,
            recommendation='Use require for validation',
            detection_logic='Check assert usage',
            references=['Assert vs require']
        )


class GasDetectionContext:
    """Context for gas detection analysis"""
    
    def __init__(self, source_code: str, contract_name: str = "Unknown"):
        self.source_code = source_code
        self.contract_name = contract_name
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.state_variables: Dict[str, str] = {}
        self.events: Dict[str, Any] = {}
        self.structs: Dict[str, Any] = {}
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
        
        var_pattern = r'(uint256|address|bool|string|bytes)(\d+)?\s+(\w+)'
        for match in re.finditer(var_pattern, self.source_code):
            var_name = match.group(3)
            var_type = match.group(1)
            self.state_variables[var_name] = var_type
        
        event_pattern = r'event\s+(\w+)\s*\('
        for match in re.finditer(event_pattern, self.source_code):
            self.events[match.group(1)] = match.group(0)
        
        struct_pattern = r'struct\s+(\w+)\s*\{'
        for match in re.finditer(struct_pattern, self.source_code):
            self.structs[match.group(1)] = match.group(0)


class GasRuleEngine:
    """Main engine for detecting gas optimization opportunities"""
    
    def __init__(self):
        self.registry = GasRuleRegistry()
        self.detected_issues: List[GasIssue] = []
        self.statistics = defaultdict(int)
    
    def analyze(self, source_code: str, contract_name: str = "Unknown") -> List[Dict[str, Any]]:
        """Analyze source code for gas optimization opportunities"""
        self.detected_issues.clear()
        context = GasDetectionContext(source_code, contract_name)
        
        results = []
        for rule in self.registry.rules.values():
            matches = self._scan_rule(rule, source_code, context)
            for match in matches:
                if self._is_false_positive(match, rule):
                    continue
                issue = self._create_issue(match, rule, context)
                self.detected_issues.append(issue)
                results.append(issue.to_dict())
                self.statistics[rule.category.value] += 1
        
        return results
    
    def _scan_rule(self, rule: GasRule, source_code: str, 
                context: GasDetectionContext) -> List[Dict[str, Any]]:
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
        """Extract function name from code"""
        match = re.search(r'function\s+(\w+)', code_snippet)
        return match.group(1) if match else code_snippet[:50]
    
    def _is_false_positive(self, match: Dict[str, Any], rule: GasRule) -> bool:
        """Check if match is false positive"""
        for filter_pattern in rule.false_positive_filters:
            if re.search(filter_pattern, match['match_text'], re.IGNORECASE):
                return True
        return False
    
    def _create_issue(self, match: Dict[str, Any], rule: GasRule,
                     context: GasDetectionContext) -> GasIssue:
        """Create issue from match"""
        return GasIssue(
            issue_id=f"{rule.rule_id}-{len(self.detected_issues) + 1}",
            rule_id=rule.rule_id,
            title=rule.name,
            category=rule.category,
            severity=rule.severity,
            description=rule.description,
            code_snippet=match['match_text'],
            function_name=match['function_name'],
            line_number=match['line_number'],
            estimated_gas_saved=rule.gas_saved,
            estimated_gas_wasted=rule.gas_wasted,
            recommendation=rule.recommendation
        )
    
    def get_report(self) -> Dict[str, Any]:
        """Generate detection report"""
        total_saved = sum(i.estimated_gas_saved for i in self.detected_issues)
        total_wasted = sum(i.estimated_gas_wasted for i in self.detected_issues)
        
        return {
            'total_issues': len(self.detected_issues),
            'total_gas_saved': total_saved,
            'total_gas_wasted': total_wasted,
            'by_category': dict(self.statistics),
            'by_severity': self._count_by_severity(),
            'issues': [i.to_dict() for i in self.detected_issues]
        }
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count issues by severity"""
        counts = defaultdict(int)
        for issue in self.detected_issues:
            counts[issue.severity.value] += 1
        return dict(counts)


def check_gas_optimization(source_code: str, contract_name: str = "Unknown") -> Dict[str, Any]:
    """
    Main entry point for gas optimization detection.
    
    Args:
        source_code: Solidity source code to analyze
        contract_name: Name of the smart contract
    
    Returns:
        Dictionary containing detected optimization opportunities
    """
    engine = GasRuleEngine()
    issues = engine.analyze(source_code, contract_name)
    return {
        'contract': contract_name,
        'total_issues': len(issues),
        'issues': issues,
        'statistics': engine.get_report()
    }


def identify_critical_gas_issues(source_code: str) -> List[Dict[str, Any]]:
    """Find critical gas issues requiring immediate attention"""
    engine = GasRuleEngine()
    issues = engine.analyze(source_code)
    
    critical = [i for i in issues if i['severity'] == 'critical']
    return critical[:10]


def estimate_gas_savings(source_code: str) -> int:
    """Estimate total potential gas savings"""
    engine = GasRuleEngine()
    engine.analyze(source_code)
    report = engine.get_report()
    return report['total_gas_saved']


def suggest_optimizations(source_code: str) -> List[str]:
    """Generate optimization suggestions"""
    issues = check_gas_optimization(source_code)
    suggestions = []
    
    for issue in issues['issues']:
        suggestions.append(issue['recommendation'])
    
    return list(set(suggestions))


if __name__ == "__main__":
    sample_code = '''
    pragma solidity ^0.8.0;
    
    contract GasExample {
        uint256 public constant RATE = 1000;
        uint256 public fee = 100;
        
        mapping(address => uint256) public balances;
        address[] public users;
        
        event Transfer(address indexed from, address indexed to, uint256 value);
        
        function batchTransfer(address[] memory recipients, uint256 amount) public {
            for (uint i = 0; i < recipients.length; i++) {
                balances[recipients[i]] += amount;
                emit Transfer(msg.sender, recipients[i], amount);
            }
        }
        
        function calculate(uint256 value) public view returns (uint256) {
            return value * 2;
        }
    }
    '''
    
    results = check_gas_optimization(sample_code, "GasExample")
    print(json.dumps(results, indent=2))