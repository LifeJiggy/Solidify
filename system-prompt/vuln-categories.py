"""
Solidify Vulnerability Categories
Vulnerability taxonomy and classification

Author: Peace Stephen (Tech Lead)
Description: Vulnerability categories with CWE references
"""

from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackSurface(Enum):
    EXTERNAL_CALL = "external_call"
    ARITHMETIC = "arithmetic"
    ACCESS_CONTROL = "access_control"
    ORACLE = "oracle"
    MEMPOOL = "mempool"
    OWNERSHIP = "ownership"
    TOKEN = "token"
    PRNG = "prng"
    STORAGE = "storage"
    ETHER_MANAGEMENT = "ether_management"
    DELEGATION = "delegation"
    UPGRADEABILITY = "upgradeability"
    CROSS_CHAIN = "cross_chain"


@dataclass
class MitigationStrategy:
    pattern: str
    implementation: str
    libraries: List[str] = field(default_factory=list)
    best_practices: List[str] = field(default_factory=list)


@dataclass
class DetectionPattern:
    regex: str
    ast_pattern: Optional[str] = None
    severity_indicators: List[str] = field(default_factory=list)
    false_positive_indicators: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityCategory:
    name: str
    cwe_id: str
    severity: Severity
    description: str
    attack_surface: AttackSurface = AttackSurface.EXTERNAL_CALL
    impact: str = ""
    likelihood: str = ""
    mitigations: List[MitigationStrategy] = field(default_factory=list)
    detection_patterns: List[DetectionPattern] = field(default_factory=list)
    related_cwes: List[str] = field(default_factory=list)
    cvss_vector: str = ""
    examples: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


VULNERABILITY_CATEGORIES = {
    "reentrancy": VulnerabilityCategory(
        name="Reentrancy",
        cwe_id="CWE-362",
        severity=Severity.CRITICAL,
        description="External calls before state changes allow recursive calls that drain funds",
        attack_surface=AttackSurface.EXTERNAL_CALL,
        impact="Complete loss of funds through recursive withdraws",
        likelihood="High - common pattern in DeFi protocols",
        related_cwes=["CWE-841", "CWE-663"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        examples=[
            "DAO Hack (The DAO)",
            "Cream Finance",
            "Squid Game Token"
        ],
        references=[
            "https://swcre-neg.googlecode.com/files/SWC-107.pdf",
            "https://solidity.readthedocs.io/en/develop/security-considerations.html"
        ]
    ),
    "access_control": VulnerabilityCategory(
        name="Access Control",
        cwe_id="CWE-862",
        severity=Severity.HIGH,
        description="Missing or insufficient access control on critical functions",
        attack_surface=AttackSurface.ACCESS_CONTROL,
        impact="Unauthorized access to privileged functions",
        likelihood="Medium - often overlooked in development",
        related_cwes=["CWE-284", "CWE-863"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        references=[
            "https://swcre-neg.googlecode.com/files/SWC-103.pdf"
        ]
    ),
    "arithmetic": VulnerabilityCategory(
        name="Arithmetic",
        cwe_id="CWE-190",
        severity=Severity.HIGH,
        description="Integer overflow or underflow in arithmetic operations",
        attack_surface=AttackSurface.ARITHMETIC,
        impact="Incorrect token balances, unlocked funds",
        likelihood="High - common before Solidity 0.8.0",
        related_cwes=["CWE-191", "CWE-192", "CWE-680"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        examples=["BatchOverflow", "ProxyOverflow"],
        references=[
            "https://swcre-neg.googlecode.com/files/SWC-101.pdf"
        ]
    ),
    "oracle_manipulation": VulnerabilityCategory(
        name="Oracle Manipulation",
        cwe_id="CWE-707",
        severity=Severity.HIGH,
        description="Price oracle can be manipulated through flash loans",
        attack_surface=AttackSurface.ORACLE,
        impact="Catastrophic loss through artificial price manipulation",
        likelihood="High - easy with flash loans",
        related_cwes=["CWE-754", "CWE-755"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        examples=[
            "Trading Technologies Exploit",
            "Inverse Finance",
            "Beanstalk"
        ],
        references=[
            "https://chain.link/blog/flash-loans-and-the-importance-of-oracle-diversity"
        ]
    ),
    "front_running": VulnerabilityCategory(
        name="Front-Running",
        cwe_id="CWE-200",
        severity=Severity.MEDIUM,
        description="Transaction can be front-run in public mempool",
        attack_surface=AttackSurface.MEMPOOL,
        impact="Financial loss through transaction ordering",
        likelihood="High - all Ethereum transactions visible",
        related_cwes=["CWE-377"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L",
        examples=[
            "Sandwich Attacks",
            "NFT Mint Front-Running"
        ]
    ),
    "centralization": VulnerabilityCategory(
        name="Centralization",
        cwe_id="CWE-862",
        severity=Severity.HIGH,
        description="Single point of failure in contract ownership",
        attack_surface=AttackSurface.OWNERSHIP,
        impact="Rug pull, frozen funds, admin abuse",
        likelihood="Medium - common in early projects",
        related_cwes=["CWE-665"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        examples=[
            "Tornado Cash Sanctions",
            "Various Admin Key Compromise"
        ]
    ),
    "denial_of_service": VulnerabilityCategory(
        name="Denial of Service",
        cwe_id="CWE-400",
        severity=Severity.HIGH,
        description="Contract can be rendered unusable through various attacks",
        attack_surface=AttackSurface.ETHER_MANAGEMENT,
        impact="Protocol becomes non-functional",
        likelihood="Medium - varies by attack vector",
        related_cwes=["CWE-770", "CWE-403"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        examples=[
            "Parity Multisig Hack",
            "Various Gas Griefing"
        ]
    ),
    "validation": VulnerabilityCategory(
        name="Validation",
        cwe_id="CWE-754",
        severity=Severity.MEDIUM,
        description="Missing or improper input validation",
        attack_surface=AttackSurface.STORAGE,
        impact="Unexpected behavior, potential exploits",
        likelihood="High - often overlooked",
        related_cwes=["CWE-20", "CWE-1284"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N"
    ),
    "privacy": VulnerabilityCategory(
        name="Privacy",
        cwe_id="CWE-200",
        severity=Severity.LOW,
        description="Sensitive information exposed",
        attack_surface=AttackSurface.STORAGE,
        impact="Information leakage",
        likelihood="Low",
        related_cwes=["CWE-316", "CWE-522"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
    ),
    "immutability": VulnerabilityCategory(
        name="Immutability",
        cwe_id="CWE-501",
        severity=Severity.MEDIUM,
        description="Contract claims to be immutable but isn't",
        attack_surface=AttackSurface.UPGRADEABILITY,
        impact="Broken trust assumptions",
        likelihood="Low - documentation issue",
        related_cwes=["CWE-830"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"
    ),
    "compatibility": VulnerabilityCategory(
        name="Compatibility",
        cwe_id="CWE-1104",
        severity=Severity.LOW,
        description="Using deprecated or incompatible components",
        attack_surface=AttackSurface.DELEGATION,
        impact="Unexpected behavior in edge cases",
        likelihood="Medium - common in migrations",
        related_cwes=["CWE-234"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"
    ),
    "unverified_external_call": VulnerabilityCategory(
        name="Unverified External Call",
        cwe_id="CWE-1041",
        severity=Severity.HIGH,
        description="External call result not checked",
        attack_surface=AttackSurface.EXTERNAL_CALL,
        impact="Silent failures, lost funds",
        likelihood="High",
        related_cwes=["CWE-754", "CWE-655"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"
    ),
    "tx_origin_authorization": VulnerabilityCategory(
        name="TX Origin Authorization",
        cwe_id="CWE-867",
        severity=Severity.MEDIUM,
        description="Using tx.origin for authorization",
        attack_surface=AttackSurface.ACCESS_CONTROL,
        impact="Phishing via malicious contracts",
        likelihood="Medium",
        related_cwes=["CWE-346"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L"
    ),
    "weak_randomness": VulnerabilityCategory(
        name="Weak Randomness",
        cwe_id="CWE-338",
        severity=Severity.HIGH,
        description="Predictable random number generation",
        attack_surface=AttackSurface.PRNG,
        impact="Predictable lottery outcomes, cheatable games",
        likelihood="High",
        related_cwes=["CWE-341"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        examples=["Predictable Random NFT"]
    ),
    "storage_collision": VulnerabilityCategory(
        name="Storage Collision",
        cwe_id="CWE-1881",
        severity=Severity.HIGH,
        description="Storage layout collision in proxy patterns",
        attack_surface=AttackSurface.STORAGE,
        impact="Data corruption, fund loss",
        likelihood="Medium - proxy pattern issues",
        related_cwes=["CWE-119"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    ),
    "access_control_bypass": VulnerabilityCategory(
        name="Access Control Bypass",
        cwe_id="CWE-639",
        severity=Severity.CRITICAL,
        description="Authorization bypass through IDOR",
        attack_surface=AttackSurface.ACCESS_CONTROL,
        impact="Unauthorized access to any user assets",
        likelihood="Medium",
        related_cwes=["CWE-640"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    ),
    "erc20_approvals": VulnerabilityCategory(
        name="ERC20 Approval",
        cwe_id="CWE-C71",
        severity=Severity.MEDIUM,
        description="Unlimited ERC20 approvals",
        attack_surface=AttackSurface.TOKEN,
        impact="Unlimited fund access if compromised",
        likelihood="High",
        related_cwes=["CWE-771"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    ),
    "assembly_injection": VulnerabilityCategory(
        name="Assembly Injection",
        cwe_id="CWE-95",
        severity=Severity.CRITICAL,
        description="Inline assembly with security issues",
        attack_surface=AttackSurface.STORAGE,
        impact="Complete contract compromise",
        likelihood="Low",
        related_cwes=["CWE-94"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    ),
    "delegatecall_untrusted": VulnerabilityCategory(
        name="Untrusted Delegatecall",
        cwe_id="CWE-827",
        severity=Severity.CRITICAL,
        description="Delegatecall to untrusted contract",
        attack_surface=AttackSurface.DELEGATION,
        impact="Storage corruption, complete compromise",
        likelihood="High - common in proxy patterns",
        related_cwes=["CWE-828"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        examples=["Parity Multisig Bug"]
    ),
    "variable_shadowing": VulnerabilityCategory(
        name="Variable Shadowing",
        cwe_id="CWE-1009",
        severity=Severity.MEDIUM,
        description="State variable shadowing",
        attack_surface=AttackSurface.STORAGE,
        impact="Incorrect value access",
        likelihood="Low",
        related_cwes=["CWE-1121"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
    ),
    "events_missing": VulnerabilityCategory(
        name="Missing Events",
        cwe_id="CWE-778",
        severity=Severity.LOW,
        description="Critical operations lack events",
        attack_surface=AttackSurface.STORAGE,
        impact="Off-chain monitoring difficult",
        likelihood="High",
        related_cwes=["CWE-832"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"
    ),
    "events_emit_after": VulnerabilityCategory(
        name="Event Emission After State Change",
        cwe_id="CWE-679",
        severity=Severity.LOW,
        description="Event emitted after state change enables front-running",
        attack_surface=AttackSurface.MEMPOOL,
        impact="MEV extraction",
        likelihood="Medium",
        related_cwes=["CWE-364"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"
    ),
    "unprotected_eth": VulnerabilityCategory(
        name="Unprotected Ether",
        cwe_id="CWE-300",
        severity=Severity.HIGH,
        description="Contract can receive Ether without withdrawal",
        attack_surface=AttackSurface.ETHER_MANAGEMENT,
        impact="Funds stuck forever",
        likelihood="Medium",
        related_cwes=["CWE-475"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H"
    ),
    "incorrect_erc721": VulnerabilityCategory(
        name="Incorrect ERC721 Implementation",
        cwe_id="CWE-1088",
        severity=Severity.MEDIUM,
        description="Non-standard ERC721 behavior",
        attack_surface=AttackSurface.TOKEN,
        impact="Token stuck in contract, incompatibility",
        likelihood="Medium",
        related_cwes=["CWE-573"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"
    ),
    "burn_mechanism": VulnerabilityCategory(
        name="Missing Burn Mechanism",
        cwe_id="CWE-1066",
        severity=Severity.LOW,
        description="No token burn function",
        attack_surface=AttackSurface.TOKEN,
        impact="Cannot reduce supply",
        likelihood="Low",
        related_cwes=["CWE-401"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"
    ),
    "recover_ownership": VulnerabilityCategory(
        name="Ownership Recovery",
        cwe_id="CWE-C72",
        severity=Severity.HIGH,
        description="No ownership recovery mechanism",
        attack_surface=AttackSurface.OWNERSHIP,
        impact="Lost admin access permanently",
        likelihood="Medium",
        related_cwes=["CWE-640"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    ),
}


def get_category(name: str) -> Optional[VulnerabilityCategory]:
    return VULNERABILITY_CATEGORIES.get(name.lower())


def get_all_categories() -> Dict[str, VulnerabilityCategory]:
    return VULNERABILITY_CATEGORIES


def get_by_severity(severity: Severity) -> List[VulnerabilityCategory]:
    return [v for v in VULNERABILITY_CATEGORIES.values() if v.severity == severity]


def get_by_attack_surface(surface: AttackSurface) -> List[VulnerabilityCategory]:
    return [v for v in VULNERABILITY_CATEGORIES.values() if v.attack_surface == surface]


def get_related_cwes(cwe_id: str) -> List[str]:
    category = next((v for v in VULNERABILITY_CATEGORIES.values() if v.cwe_id == cwe_id), None)
    if category:
        return category.related_cwes
    return []


def get_critical_vulnerabilities() -> List[VulnerabilityCategory]:
    return get_by_severity(Severity.CRITICAL)


def search_categories(query: str) -> List[VulnerabilityCategory]:
    query_lower = query.lower()
    results = []
    for category in VULNERABILITY_CATEGORIES.values():
        if query_lower in category.name.lower() or query_lower in category.description.lower():
            results.append(category)
    return results


def get_category_names() -> List[str]:
    return list(VULNERABILITY_CATEGORIES.keys())


def category_exists(name: str) -> bool:
    return name.lower() in VULNERABILITY_CATEGORIES


def get_cvss_score(severity: Severity) -> float:
    scores = {
        Severity.CRITICAL: 9.0,
        Severity.HIGH: 7.0,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 3.0,
        Severity.INFO: 0.0
    }
    return scores.get(severity, 0.0)


def severity_to_number(severity: Severity) -> int:
    levels = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1
    }
    return levels.get(severity, 0)


def compare_severity(a: Severity, b: Severity) -> int:
    return severity_to_number(a) - severity_to_number(b)


def prioritize_categories(categories: List[str]) -> List[str]:
    priority_map = {
        "reentrancy": 1,
        "delegatecall_untrusted": 2,
        "access_control": 3,
        "arithmetic": 4,
        "oracle_manipulation": 5,
        "weak_randomness": 6,
        "centralization": 7,
        "denial_of_service": 8,
        "front_running": 9,
        "validation": 10
    }
    sorted_cats = sorted(
        categories,
        key=lambda x: priority_map.get(x, 999)
    )
    return sorted_cats