"""
Solidify Vulnerability Taxonomy
Comprehensive vulnerability definitions and metadata

Author: Peace Stephen (Tech Lead)
Description: Smart contract vulnerability database
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class VulnerabilityCategory(Enum):
    """Categories of smart contract vulnerabilities"""
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ARITHMETIC = "arithmetic"
    UNCHECKED_CALLS = "unchecked_calls"
    FRONT_RUNNING = "front_running"
    TIMESTAMP = "timestamp"
    DOS = "dos"
    INITIALIZATION = "initialization"
    SELF_DESTRUCT = "self_destruct"
    ORACLE = "oracle"
    GOVERNANCE = "governance"
    NFT = "nft"
    TOKEN = "token"
    PROXY = "proxy"
    PRIVACY = "privacy"


class SeverityLevel(Enum):
    """Severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class VulnerabilityDef:
    """Vulnerability definition"""
    id: str
    name: str
    category: str
    severity: str
    cwe_id: str
    description: str
    impact: str
    remediation: str
    detection_methods: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    common_patterns: List[str] = field(default_factory=list)


# ============================================================================
# Vulnerability Taxonomy
# ============================================================================

class VulnTaxonomy:
    """
    Smart contract vulnerability taxonomy
    
    Features:
    - Comprehensive vulnerability definitions
    - Category-based organization
    - Search and lookup
    - Severity information
    """
    
    # Comprehensive vulnerability definitions
    VULNERABILITIES = {
        # Critical Vulnerabilities
        "reentrancy": VulnerabilityDef(
            id="reentrancy",
            name="Reentrancy",
            category=VulnerabilityCategory.REENTRANCY.value,
            severity="CRITICAL",
            cwe_id="CWE-307",
            description="The contract makes external calls to untrusted contracts before updating state, allowing attackers to re-enter the contract through the fallback function.",
            impact="Attacker can drain all funds from the contract by repeatedly withdrawing in a single transaction.",
            remediation="Use ReentrancyGuard from OpenZeppelin, follow Checks-Effects-Interactions pattern, or use pull-payment mechanism.",
            detection_methods=["Static analysis", "Gas usage patterns", "External call tracking"],
            references=["Ethereum Security Best Practices", "SWC-107"],
            common_patterns=["msg.sender.call.value()", "address.call()", "tx.origin"]
        ),
        
        "unprotected-selfdestruct": VulnerabilityDef(
            id="unprotected-selfdestruct",
            name="Unprotected Self-Destruct",
            category=VulnerabilityCategory.SELF_DESTRUCT.value,
            severity="CRITICAL",
            cwe_id="CWE-306",
            description="The selfdestruct function can be called by anyone, allowing anyone to destroy the contract and steal funds.",
            impact="Complete loss of all contract funds and functionality. Contract becomes permanently unusable.",
            remediation="Add access control to selfdestruct, use Ownable contract, or remove selfdestruct if not needed.",
            detection_methods=["Access control analysis", "Function visibility check"],
            references=["SWC-106"],
            common_patterns=["selfdestruct()", "suicide()"]
        ),
        
        "uninitialized-storage-pointer": VulnerabilityDef(
            id="uninitialized-storage-pointer",
            name="Uninitialized Storage Pointer",
            category=VulnerabilityCategory.INITIALIZATION.value,
            severity="CRITICAL",
            cwe_id="CWE-824",
            description="Local variable pointing to storage slot that wasn't initialized, causing storage corruption.",
            impact="Can overwrite existing storage values, potentially stealing funds or breaking contract logic.",
            remediation="Always initialize struct variables with Storage() or explicitly set all fields.",
            detection_methods=["Storage layout analysis", "Compiler warnings"],
            references=["Ethereum Smart Contract Security Best Practices"],
            common_patterns=["structVar.x = value without Storage()"]
        ),
        
        # High Vulnerabilities
        "integer-overflow": VulnerabilityDef(
            id="integer-overflow",
            name="Integer Overflow/Underflow",
            category=VulnerabilityCategory.ARITHMETIC.value,
            severity="HIGH",
            cwe_id="CWE-190",
            description="Arithmetic operations that exceed the maximum or minimum value of the data type, causing unexpected behavior.",
            impact="Attackers can bypass checks, mint unlimited tokens, or drain funds.",
            remediation="Use SafeMath library for Solidity < 0.8.0, or use Solidity 0.8+ with checked arithmetic.",
            detection_methods=["AST analysis", "Arithmetic pattern matching"],
            references=["SWC-101", "CVE-2018-10299"],
            common_patterns=["+ - * / without SafeMath", "unchecked {}"]
        ),
        
        "access-control": VulnerabilityDef(
            id="access-control",
            name="Access Control Violation",
            category=VulnerabilityCategory.ACCESS_CONTROL.value,
            severity="HIGH",
            cwe_id="Cwe-284",
            description="Missing or insufficient access control on critical functions, allowing unauthorized users to execute privileged operations.",
            impact="Unauthorized users can mint tokens, change ownership, withdraw funds, or modify critical state.",
            remediation="Use OpenZeppelin's Ownable, AccessControl, or Pausable. Implement role-based access.",
            detection_methods=["Function visibility analysis", "Access control pattern matching"],
            references=["SWC-100", "SWC-103"],
            common_patterns=["missing onlyOwner", "public mint function", "tx.origin"]
        ),
        
        "unchecked-return-value": VulnerabilityDef(
            id="unchecked-return-value",
            name="Unchecked Return Value",
            category=VulnerabilityCategory.UNCHECKED_CALLS.value,
            severity="HIGH",
            cwe_id="CWE-252",
            description="Return value from external call is not checked, allowing failures to go unnoticed.",
            impact="Silent failures can cause logic errors, funds stuck, or unexpected contract state.",
            remediation="Always check return values, use require() statements, or use SafeERC20.",
            detection_methods=["Call return value analysis"],
            references=["SWC-104"],
            common_patterns=[".call() without checking return", ".transfer() without return check"]
        ),
        
        "delegatecall-vulnerability": VulnerabilityDef(
            id="delegatecall-vulnerability",
            name="Dangerous Delegatecall",
            category=VulnerabilityCategory.PROXY.value,
            severity="CRITICAL",
            cwe_id="CWE-829",
            description="Using delegatecall with untrusted code or uninitialized storage can lead to contract takeover.",
            impact="Attacker can execute arbitrary code in the context of the calling contract, stealing all state and funds.",
            remediation="Only use delegatecall with trusted contracts, initialize storage before delegatecall, use proxy patterns carefully.",
            detection_methods=["Delegatecall usage analysis", "Storage layout verification"],
            references=["Ethereum Yellow Paper", "Proxy Security"],
            common_patterns=["delegatecall() to user-provided address"]
        ),
        
        "flash-loan-attack": VulnerabilityDef(
            id="flash-loan-attack",
            name="Flash Loan Attack Surface",
            category=VulnerabilityCategory.ORACLE.value,
            severity="HIGH",
            cwe_id="CWE-1273",
            description="Contract relies on single-source or manipulable price oracle, allowing flash loan price manipulation.",
            impact="Attacker can manipulate prices in a single transaction using flash loans to drain protocol funds.",
            remediation="Use TWAP oracles, Chainlink, or multiple oracle sources. Implement price deviation checks.",
            detection_methods=["Oracle usage analysis", "Price feed verification"],
            references=["Trail of Bits DeFi Security"],
            common_patterns=["single price oracle", "spot price usage", "no price bounds"]
        ),
        
        # Medium Vulnerabilities
        "front-running": VulnerabilityDef(
            id="front-running",
            name="Front-Running",
            category=VulnerabilityCategory.FRONT_RUNNING.value,
            severity="MEDIUM",
            cwe_id="CWE-1270",
            description="Transaction order can be observed in mempool and attackers can front-run with higher gas price.",
            impact="Users lose money to arbitrageurs, MEV extractors can profit, unfair trade execution.",
            remediation="Use commit-reveal scheme, batch auctions, or signed transactions.",
            detection_methods=["Transaction ordering analysis", "Mempool simulation"],
            references=["Ethereum Smart Contract Security Best Practices"],
            common_patterns=["direct trading without commit-reveal", "first-come-first-served"]
        ),
        
        "timestamp-dependence": VulnerabilityDef(
            id="timestamp-dependence",
            name="Timestamp Dependence",
            category=VulnerabilityCategory.TIMESTAMP.value,
            severity="MEDIUM",
            cwe_id="CWE-829",
            description="Using block.timestamp for critical logic can be manipulated by miners within limits.",
            impact="Miners can manipulate timing for personal gain, affecting random number generation or payment timing.",
            remediation="Don't use block.timestamp for critical logic, use block numbers for time-sensitive operations.",
            detection_methods=["Block property usage analysis"],
            references=["SWC-116"],
            common_patterns=["block.timestamp for randomization", "block.timestamp for critical delays"]
        ),
        
        "tx-origin-authentication": VulnerabilityDef(
            id="tx-origin-authentication",
            name="Tx.origin Authentication",
            category=VulnerabilityCategory.ACCESS_CONTROL.value,
            severity="MEDIUM",
            cwe_id="CWE-477",
            description="Using tx.origin for authorization allows phishing contracts to trick users into authorizing attacks.",
            impact="Attacker can trick users into signing transactions that call vulnerable contracts through phishing.",
            remediation="Use msg.sender instead of tx.origin for authorization.",
            detection_methods=["Authorization pattern analysis"],
            references=["SWC-115"],
            common_patterns=["tx.origin == msg.sender", "require(tx.origin == msg.sender)"]
        ),
        
        "denial-of-service": VulnerabilityDef(
            id="denial-of-service",
            name="Denial of Service",
            category=VulnerabilityCategory.DOS.value,
            severity="MEDIUM",
            cwe_id="CWE-400",
            description="Contract can be made unusable through gas exhaustion, unhandled exceptions, or accessibility issues.",
            impact="Contract becomes unusable, funds locked, users cannot access their assets.",
            remediation="Avoid unbounded loops, use pull payments instead of push, handle failures gracefully.",
            detection_methods=["Gas analysis", "Loop detection"],
            references=["SWC-113"],
            common_patterns=["for loop without bounds", "address.call() without gas", "iteration over dynamic array"]
        ),
        
        # Low Vulnerabilities
        "circular-dependency": VulnerabilityDef(
            id="circular-dependency",
            name="Circular Dependency",
            category=VulnerabilityCategory.INITIALIZATION.value,
            severity="LOW",
            cwe_id="CWE-827",
            description="Contract A imports B which imports A, causing deployment issues or unexpected behavior.",
            impact="Deployment failures, unexpected behavior, potential security vulnerabilities.",
            remediation="Refactor code to remove circular dependencies, use interfaces.",
            detection_methods=["Import graph analysis"],
            references=["Solidity Documentation"],
            common_patterns=["circular import statements"]
        ),
        
        "shadowing-state-variables": VulnerabilityDef(
            id="shadowing-state-variables",
            name="Shadowing State Variables",
            category=VulnerabilityCategory.INITIALIZATION.value,
            severity="LOW",
            cwe_id="CWE-1160",
            description="Local variable with same name as state variable shadows it, causing confusion and bugs.",
            impact="Logic errors, incorrect state updates, unexpected contract behavior.",
            remediation="Use different variable names, enable compiler warnings, follow naming conventions.",
            detection_methods=["Variable name analysis"],
            references=["SWC-119"],
            common_patterns=["same name in function as state variable"]
        ),
        
        # NFT Specific
        "unrestricted-mint": VulnerabilityDef(
            id="unrestricted-mint",
            name="Unrestricted Minting",
            category=VulnerabilityCategory.NFT.value,
            severity="HIGH",
            cwe_id="CWE-284",
            description="Anyone can mint new tokens without proper access control.",
            impact="Unlimited token supply inflation, attacker can drain value from legitimate holders.",
            remediation="Add access control to mint functions, use Ownable or AccessControl.",
            detection_methods=["Minting function analysis"],
            references=["OpenZeppelin NFT Security"],
            common_patterns=["public mint function", "missing AccessControl on mint"]
        ),
        
        "metadata-uri-injection": VulnerabilityDef(
            id="metadata-uri-injection",
            name="Metadata URI Injection",
            category=VulnerabilityCategory.NFT.value,
            severity="MEDIUM",
            cwe_id="CWE-20",
            description="Token URI can be set to malicious URLs pointing to attacker-controlled servers.",
            impact="Users may be directed to phishing sites or malicious content when viewing NFT metadata.",
            remediation="Validate URI endpoints, use IPFS, or add content hash verification.",
            detection_methods=["URI setter analysis"],
            references=["NFT Security Best Practices"],
            common_patterns=["setTokenURI with user input", "non-verified URI storage"]
        ),
        
        # DeFi Specific
        "approval-for-all": VulnerabilityDef(
            id="approval-for-all",
            name="setApprovalForAll Risk",
            category=VulnerabilityCategory.TOKEN.value,
            severity="HIGH",
            cwe_id="CWE-377",
            description="Users approving contracts with setApprovalForAll give complete control of their tokens.",
            impact="If approved contract is compromised, all user's tokens can be stolen.",
            remediation="Limit approvals, review approved contracts carefully, use per-token approvals when possible.",
            detection_methods=["Approval analysis"],
            references=["OpenZeppelin Security"],
            common_patterns=["setApprovalForAll() without limits"]
        ),
    }
    
    def __init__(self):
        """Initialize taxonomy"""
        self._index_by_category = self._build_category_index()
        self._index_by_cwe = self._build_cwe_index()
        logger.info(f"✅ Vulnerability taxonomy initialized with {len(self.VULNERABILITIES)} definitions")
    
    def _build_category_index(self) -> Dict[str, List[str]]:
        """Build index by category"""
        index = {}
        for vuln_id, vuln in self.VULNERABILITIES.items():
            if vuln.category not in index:
                index[vuln.category] = []
            index[vuln.category].append(vuln_id)
        return index
    
    def _build_cwe_index(self) -> Dict[str, str]:
        """Build index by CWE ID"""
        return {
            vuln.cwe_id: vuln_id
            for vuln_id, vuln in self.VULNERABILITIES.items()
        }
    
    def get_vulnerability(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """
        Get vulnerability definition by ID
        
        Args:
            vuln_id: Vulnerability ID or name
        
        Returns:
            Vulnerability dictionary or None
        """
        # Direct lookup
        if vuln_id.lower() in self.VULNERABILITIES:
            vuln = self.VULNERABILITIES[vuln_id.lower()]
            return self._vuln_to_dict(vuln)
        
        # Search by name
        for v in self.VULNERABILITIES.values():
            if vuln_id.lower() in v.name.lower():
                return self._vuln_to_dict(v)
        
        return None
    
    def _vuln_to_dict(self, vuln: VulnerabilityDef) -> Dict[str, Any]:
        """Convert vulnerability to dictionary"""
        return {
            "id": vuln.id,
            "name": vuln.name,
            "category": vuln.category,
            "severity": vuln.severity,
            "cwe_id": vuln.cwe_id,
            "description": vuln.description,
            "impact": vuln.impact,
            "remediation": vuln.remediation,
            "detection_methods": vuln.detection_methods,
            "references": vuln.references,
            "common_patterns": vuln.common_patterns
        }
    
    def get_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get all vulnerability definitions"""
        return [
            self._vuln_to_dict(v)
            for v in self.VULNERABILITIES.values()
        ]
    
    def get_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities by category"""
        vuln_ids = self._index_by_category.get(category, [])
        return [
            self._vuln_to_dict(self.VULNERABILITIES[vuln_id])
            for vuln_id in vuln_ids
        ]
    
    def get_by_cwe(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """Get vulnerability by CWE ID"""
        vuln_id = self._index_by_cwe.get(cwe_id.upper())
        if vuln_id:
            return self._vuln_to_dict(self.VULNERABILITIES[vuln_id])
        return None
    
    def get_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities by severity"""
        return [
            self._vuln_to_dict(v)
            for v in self.VULNERABILITIES.values()
            if v.severity.upper() == severity.upper()
        ]
    
    def search(self, query: str) -> List[Dict[str, Any]]:
        """Search vulnerabilities by query"""
        query = query.lower()
        results = []
        
        for vuln in self.VULNERABILITIES.values():
            if (query in vuln.name.lower() or
                query in vuln.description.lower() or
                query in vuln.category or
                query in vuln.cwe_id.lower()):
                results.append(self._vuln_to_dict(vuln))
        
        return results
    
    def get_categories(self) -> List[str]:
        """Get all categories"""
        return list(self._index_by_category.keys())
    
    def get_severities(self) -> List[str]:
        """Get all severity levels"""
        return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ============================================================================
# Factory Functions
# ============================================================================

def create_vuln_taxonomy() -> VulnTaxonomy:
    """Create vulnerability taxonomy instance"""
    return VulnTaxonomy()


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    taxonomy = VulnTaxonomy()
    
    # Test get vulnerability
    reentrancy = taxonomy.get_vulnerability("reentrancy")
    print(f"Reentrancy: {reentrancy['name']} - {reentrancy['severity']}")
    
    # Test by category
    critical_vulns = taxonomy.get_by_severity("CRITICAL")
    print(f"\nCritical vulnerabilities: {len(critical_vulns)}")
    
    # Test search
    results = taxonomy.search("overflow")
    print(f"\nSearch results for 'overflow': {len(results)}")
    
    # Test categories
    categories = taxonomy.get_categories()
    print(f"\nCategories: {categories}")