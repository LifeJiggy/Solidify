"""
Transaction Analyzer

Analyzes on-chain transactions for security patterns, risk assessment,
and exploit detection. Provides transaction history analysis for smart contracts.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import logging
import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

from . import (
    ChainType,
    TransactionInfo,
    validate_address,
    normalize_address,
    format_wei_to_eth,
)
from .etherscan_client import EtherscanClient
from .rpc_client import RPCClient

logger = logging.getLogger(__name__)


class TransactionPattern(Enum):
    FLASH_LOAN = "flash_loan"
    WRAP_UNWRAP = "wrap_unwrap"
    TOKEN_SWAP = "token_swap"
    LARGE_TRANSFER = "large_transfer"
    SUSPICIOUS_CALL = "suspicious_call"
    VULNERABLE_CALL = "vulnerable_call"
    FRONT_RUN = "front_run"
    SANITARY_ATTACK = "sandwich_attack"
    TIMELOCK = "timelock"
    GOVERNANCE = "governance"


@dataclass
class TransactionRisk:
    pattern: TransactionPattern
    severity: str
    description: str
    evidence: Dict[str, Any]
    recommendation: str


@dataclass
class TransactionAnalysis:
    address: str
    total_transactions: int
    unique_senders: Set[str]
    unique_receivers: Set[str]
    total_volume_eth: float
    first_seen_block: int
    last_seen_block: int
    patterns: List[TransactionRisk]
    risks: List[TransactionRisk]
    risk_score: float
    is Contract: bool
    has_malicious_history: bool


class TransactionAnalyzer:
    PATTERN_SIGNATURES = {
        TransactionPattern.FLASH_LOAN: {
            "uniswap_v2": [
                r"swapExactETHForTokens",
                r"swapExactTokensForETH",
                r"flashSwap",
            ],
            "uniswap_v3": [
                r"exactInputSingle",
                r"exactInput",
                r"flash",
            ],
            "aave": [
                r"executeOperation",
                r"flashLoan",
                r"flashLoanSimple",
            ],
            "lending": [
                r"borrow",
                r"liquidateBorrow",
            ],
        },
        TransactionPattern.WRAP_UNWRAP: {
            "wrap": [
                r"deposit",
                r"wrap\(\)",
                r"approveAndCall",
            ],
            "unwrap": [
                r"withdraw",
                r"withdraw\(uint256\)|unwrap\(\)",
            ],
        },
        TransactionPattern.TOKEN_SWAP: [
            r"swap\(",
            r"swapExact.*for.*",
            r"swap.*forExact.*",
            r"trade\(",
            r"exchange\(",
            r"token.*swap",
        ],
        TransactionPattern.LARGE_TRANSFER: {
            "threshold_eth": 100,
            "threshold_token": 100000,
        },
        TransactionPattern.SUSPICIOUS_CALL: [
            r"delegatecall",
            r"callcode",
            r"selfdestruct",
            r"suicide",
            r"exec\(",
            r"create2\(",
            r"create\(",
        ],
    }

    KNOWN_ATTACKER_ADDRESSES = {
        "0xeb2a31e1c2f8b4e5d4e6f8a1b3c5d7e9f2a4c6b8",
        "0xfac7c9a1b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0",
        "0xbadc0deab2c4d6e8f0a2b4c6d8e0f2a4b6c8d0",
    }

    SUSPICIOUS_PROXY_CONTRACTS = {
        "0x5a52e96bacdabb86fda5a2a3c1a3e96bacd",
        "0x3c4c16aaab2c3d4e5f6a7b8c9d0e1f2a3b4c",
    }

    def __init__(self, chain: ChainType = ChainType.ETHEREUM_MAINNET):
        self.chain = chain
        self.etherscan = EtherscanClient(chain=chain)
        self.rpc = RPCClient(chain=chain)

    def analyze(
        self,
        address: str,
        max_transactions: int = 1000,
    ) -> TransactionAnalysis:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        address = normalize_address(address)

        transactions = self._fetch_transactions(address, max_transactions)

        if not transactions:
            return TransactionAnalysis(
                address=address,
                total_transactions=0,
                unique_senders=set(),
                unique_receivers=set(),
                total_volume_eth=0.0,
                first_seen_block=0,
                last_seen_block=0,
                patterns=[],
                risks=[],
                risk_score=0.0,
                is_contract=self._is_contract(address),
                has_malicious_history=False,
            )

        unique_senders = set()
        unique_receivers = set()
        total_volume = 0.0
        first_block = float('inf')
        last_block = 0
        patterns = []
        risks = []

        for tx in transactions:
            unique_senders.add(tx.from_address)
            if tx.to_address:
                unique_receivers.add(tx.to_address)

            try:
                total_volume += float(tx.value)
            except (ValueError, TypeError):
                pass

            first_block = min(first_block, tx.block_number)
            last_block = max(last_block, tx.block_number)

            tx_patterns = self._detect_transaction_patterns(tx)
            patterns.extend(tx_patterns)

        unique_senders.discard(address)
        unique_receivers.discard(address)

        patterns = self._aggregate_patterns(patterns)

        risk_score = self._calculate_risk_score(
            address, transactions, patterns
        )
        risks = self._identify_risks(address, patterns, transactions)

        return TransactionAnalysis(
            address=address,
            total_transactions=len(transactions),
            unique_senders=unique_senders,
            unique_receivers=unique_receivers,
            total_volume_eth=format_wei_to_eth(str(int(total_volume)), 18),
            first_seen_block=int(first_block),
            last_seen_block=int(last_block),
            patterns=patterns,
            risks=risks,
            risk_score=risk_score,
            is_contract=self._is_contract(address),
            has_malicious_history=self._check_malicious_history(address),
        )

    def analyze_multiple(
        self,
        addresses: List[str],
        max_transactions: int = 500,
    ) -> Dict[str, TransactionAnalysis]:
        results = {}
        for address in addresses:
            try:
                results[address] = self.analyze(address, max_transactions)
            except Exception as e:
                logger.error(f"Failed to analyze {address}: {e}")
        return results

    def search_exploits(
        self,
        address: str,
        exploit_type: Optional[TransactionPattern] = None,
    ) -> List[Dict[str, Any]]:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        address = normalize_address(address)
        transactions = self._fetch_transactions(address, 1000)

        exploits = []

        for tx in transactions:
            if self._is_exploit_transaction(tx, exploit_type):
                exploits.append({
                    "tx_hash": tx.hash,
                    "from": tx.from_address,
                    "to": tx.to_address,
                    "value": tx.value,
                    "block": tx.block_number,
                    "timestamp": tx.timestamp,
                    "input": tx.input_data[:100],
                })

        return exploits

    def _fetch_transactions(
        self,
        address: str,
        max_count: int,
    ) -> List[TransactionInfo]:
        try:
            raw_transactions = self.etherscan.get_contract_transactions(
                address,
                page=1,
                offset=max_count,
            )

            transactions = []
            for tx_data in raw_transactions:
                transactions.append(
                    TransactionInfo(
                        hash=tx_data.get("hash", ""),
                        from_address=normalize_address(tx_data.get("from", "")),
                        to_address=normalize_address(tx_data.get("to", "")),
                        value=tx_data.get("value", "0"),
                        gas_price=tx_data.get("gasPrice", "0"),
                        gas_used=tx_data.get("gasUsed", "0"),
                        block_number=int(tx_data.get("blockNumber", 0)),
                        timestamp=int(tx_data.get("timeStamp", 0)),
                        input_data=tx_data.get("input", "0x"),
                        status=tx_data.get("isError", "0"),
                    )
                )

            return transactions

        except Exception as e:
            logger.error(f"Failed to fetch transactions: {e}")
            return []

    def _detect_transaction_patterns(
        self,
        tx: TransactionInfo,
    ) -> List[TransactionPattern]:
        patterns = []

        input_data = tx.input_data.lower()

        if len(input_data) > 10:
            if any(sig in input_data for sig in ["swap", "exchange", "trade"]):
                patterns.append(TransactionPattern.TOKEN_SWAP)

            if any(sig in input_data for sig in ["flash", "borrow", "liquidate"]):
                patterns.append(TransactionPattern.FLASH_LOAN)

            if any(sig in input_data for sig in ["delegatecall", "callcode", "exec"]):
                patterns.append(TransactionPattern.SUSPICIOUS_CALL)

        try:
            value_eth = float(tx.value) / 1e18
            if value_eth > 100:
                patterns.append(TransactionPattern.LARGE_TRANSFER)
        except (ValueError, TypeError):
            pass

        return patterns

    def _aggregate_patterns(
        self,
        patterns: List[TransactionPattern],
    ) -> List[TransactionRisk]:
        pattern_counts = defaultdict(int)
        for pattern in patterns:
            pattern_counts[pattern] += 1

        aggregated = []
        for pattern, count in pattern_counts.items():
            if count >= 3:
                severity = "HIGH" if count >= 10 else "MEDIUM"
                risk = TransactionRisk(
                    pattern=pattern,
                    severity=severity,
                    description=f"Detected {count} transactions matching {pattern.value} pattern",
                    evidence={"count": count},
                    recommendation=self._get_pattern_recommendation(pattern),
                )
                aggregated.append(risk)

        return aggregated

    def _calculate_risk_score(
        self,
        address: str,
        transactions: List[TransactionInfo],
        patterns: List[TransactionRisk],
    ) -> float:
        score = 0.0

        if self._is_contract(address):
            score += 2.0

        if self._check_malicious_history(address):
            score += 5.0

        for risk in patterns:
            if risk.severity == "HIGH":
                score += 2.0
            elif risk.severity == "MEDIUM":
                score += 1.0

        try:
            for tx in transactions:
                value_eth = float(tx.value) / 1e18
                if value_eth > 1000:
                    score += 1.0
        except (ValueError, TypeError):
            pass

        return min(10.0, score)

    def _identify_risks(
        self,
        address: str,
        patterns: List[TransactionRisk],
        transactions: List[TransactionInfo],
    ) -> List[TransactionRisk]:
        risks = []

        for risk in patterns:
            if risk.severity == "HIGH":
                risks.append(risk)

        if self._check_interaction_with_malicious(transactions):
            risks.append(
                TransactionRisk(
                    pattern=TransactionPattern.SUSPICIOUS_CALL,
                    severity="HIGH",
                    description="Contract has interacted with known malicious addresses",
                    evidence={"suspicious_count": len(transactions)},
                    recommendation="Avoid interacting with this contract",
                )
            )

        return risks

    def _get_pattern_recommendation(
        self,
        pattern: TransactionPattern,
    ) -> str:
        recommendations = {
            TransactionPattern.FLASH_LOAN: "Review flash loan interactions",
            TransactionPattern.LARGE_TRANSFER: "Verify large transfers are intended",
            TransactionPattern.SUSPICIOUS_CALL: "Investigate delegatecall usage",
            TransactionPattern.TOKEN_SWAP: "Monitor DEX interactions",
        }
        return recommendations.get(pattern, "Review transaction pattern")

    def _is_contract(self, address: str) -> bool:
        try:
            code = self.rpc.get_code(address)
            return code and code != "0x"
        except Exception:
            return False

    def _check_malicious_history(
        self,
        address: str,
    ) -> bool:
        return address.lower() in [
            addr.lower() for addr in self.KNOWN_ATTACKER_ADDRESSES
        ]

    def _check_interaction_with_malicious(
        self,
        transactions: List[TransactionInfo],
    ) -> bool:
        for tx in transactions:
            if tx.to_address and tx.to_address.lower() in [
                addr.lower() for addr in self.KNOWN_ATTACKER_ADDRESSES
            ]:
                return True
        return False

    def _is_exploit_transaction(
        self,
        tx: TransactionInfo,
        exploit_type: Optional[TransactionPattern],
    ) -> bool:
        if exploit_type == TransactionPattern.FLASH_LOAN:
            return "flash" in tx.input_data.lower()
        elif exploit_type == TransactionPattern.SANITARY_ATTACK:
            return "swap" in tx.input_data.lower()
        else:
            return len(tx.input_data) > 10


def create_analyzer(
    chain: ChainType = ChainType.ETHEREUM_MAINNET,
) -> TransactionAnalyzer:
    return TransactionAnalyzer(chain=chain)


__all__ = [
    "TransactionAnalyzer",
    "TransactionPattern",
    "TransactionRisk",
    "TransactionAnalysis",
    "create_analyzer",
]