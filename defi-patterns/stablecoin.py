"""
Stablecoin Protocol Security Analysis Module

This module provides comprehensive security analysis for stablecoin smart contracts
including algorithmic, collateral-backed, and seigniorage stablecoins.

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
from collections import defaultdict, Counter, deque
from abc import ABC, abstractmethod
import logging
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StablecoinType(Enum):
    FIAT_BACKED = "fiat_backed"
    CRYPTO_BACKED = "crypto_backed"
    ALGORITHMIC = "algorithmic"
    FRACTIONAL = "fractional"
    SEIGNIORAGE = "seigniorage"
    REBASING = "rebasing"
    UNKNOWN = "unknown"


class CollateralType(Enum):
    USD = "usd"
    CRYPTO = "crypto"
    SYNTHETIC = "synthetic"
    NFT = "nft"
    MULTI_COLLATERAL = "multi_collateral"


class StabilityMechanism(Enum):
    CENTRALIZED_ORACLE = "centralized_oracle"
    DECENTRALIZED_ORACLE = "decentralized_oracle"
    ALGORITHMIC = "algorithmic"
    AMM_BASED = "amm_based"
    TWAP_ORACLE = "twap_oracle"


class VulnerabilityType(Enum):
    UNDERCOLLATERALIZATION = "under_collateralization"
    ORACLE_MANIPULATION = "oracle_manipulation"
    CENTRALIZATION = "centralization"
    BANK_RUN = "bank_run"
    REBASE_EXPLOIT = "rebase_exploit"
    ORACLE_DEPEG = "oracle_depeg"
    LIQUIDATION_FAIL = "liquidation_failure"


@dataclass
class StablecoinConfig:
    name: str
    symbol: str
    decimals: int
    stablecoin_type: StablecoinType
    collateral_type: CollateralType
    stability_mechanism: StabilityMechanism
    target_price: float = 1.0
    collateral_ratio: float = 1.0
    liquidation_ratio: float = 0.8
    stability_fee: float = 0.0
    minting_fee: float = 0.0
    redemption_fee: float = 0.0


@dataclass
class MarketState:
    price: float
    target_price: float
    deviation: float
    timestamp: int
    volume_24h: float
    liquidity: float
    
    def __post_init__(self):
        self.deviation = ((self.price - self.target_price) / self.target_price) * 100


@dataclass
class Vault:
    vault_id: str
    owner: str
    collateral_token: str
    collateral_amount: float
    debt_amount: float
    collateral_ratio: float
    created_at: int
    last_update: int
    
    def calculate_health_ratio(self, collateral_price: float, token_price: float) -> float:
        collateral_value = self.collateral_amount * collateral_price
        debt_value = self.debt_amount * token_price
        
        if debt_value == 0:
            return float('inf')
        
        return collateral_value / debt_value
    
    def is_healthy(self, collateral_price: float, token_price: float, 
                  liquidation_ratio: float = 0.8) -> bool:
        return self.calculate_health_ratio(collateral_price, token_price) >= liquidation_ratio
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vault_id': self.vault_id,
            'owner': self.owner,
            'collateral_token': self.collateral_token,
            'collateral_amount': self.collateral_amount,
            'debt_amount': self.debt_amount,
            'collateral_ratio': self.collateral_ratio,
            'created_at': self.created_at,
            'last_update': self.last_update
        }


class StablecoinSecurityAnalyzer:
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.risk_score: float = 0.0
    
    def detect_stablecoin_type(self, source_code: str) -> StablecoinType:
        source_lower = source_code.lower()
        
        if 'rebase' in source_lower or 'epoch' in source_lower or 'supply' in source_lower:
            if 'expand' in source_lower or 'contract' in source_lower:
                return StablecoinType.REBASING
        
        if 'seigniorage' in source_lower or 'share' in source_lower:
            return StablecoinType.SEIGNIORAGE
        
        if 'fractional' in source_lower or 'partial' in source_lower:
            return StablecoinType.FRACTIONAL
        
        if 'algorithm' in source_lower or 'bank' in source_lower:
            return StablecoinType.ALGORITHMIC
        
        if 'collateral' in source_lower or 'vault' in source_lower:
            if 'crypto' in source_lower or 'eth' in source_lower:
                return StablecoinType.CRYPTO_BACKED
            return StablecoinType.FIAT_BACKED
        
        return StablecoinType.UNKNOWN
    
    def analyze_oracle_system(self, source_code: str) -> Dict[str, Any]:
        has_chainlink = bool(re.search(r'chainlink|AggregatorV3|latestAnswer', source_code))
        has_uniswap = bool(re.search(r'uniswap|getReserves|token0|token1', source_code))
        has_twap = bool(re.search(r'twap|TWAP|timeWeighted|priceAverage', source_code))
        has_oracle = bool(re.search(r'oracle|priceFeed|priceAgg', source_code))
        
        return {
            'has_chainlink': has_chainlink,
            'has_uniswap': has_uniswap,
            'has_twap': has_twap,
            'has_oracle': has_oracle,
            'oracle_type': 'chainlink' if has_chainlink else ('twap' if has_twap else 'unknown')
        }
    
    def analyze_collateral_system(self, source_code: str) -> Dict[str, Any]:
        has_vault = bool(re.search(r'vault|Vault|collateral', source_code))
        has_ratio = bool(re.search(r'ratio|collateralization|CF|LT', source_code, re.IGNORECASE))
        has_liquidation = bool(re.search(r'liquidate|seize|liquidation', source_code))
        has_oracle_price = bool(re.search(r'getPrice|latestAnswer|priceFeed', source_code))
        
        return {
            'has_vault': has_vault,
            'has_ratio': has_ratio,
            'has_liquidation': has_liquidation,
            'has_oracle_price': has_oracle_price
        }
    
    def check_undercollateralization_risk(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if not re.search(r'collateral|ratio|CF|ltv', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.UNDERCOLLATERALIZATION.value,
                'severity': 'critical',
                'description': 'No collateral ratio enforcement detected'
            })
        
        if re.search(r'ratio\s*[<>=]+\s*0|ratio\s*=\s*0', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.UNDERCOLLATERALIZATION.value,
                'severity': 'high',
                'description': 'Zero collateral ratio possible'
            })
        
        if not re.search(r'getPrice|latestAnswer|chainlink', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.ORACLE_MANIPULATION.value,
                'severity': 'high',
                'description': 'No oracle price feed detected'
            })
        
        if re.search(r'block\.timestamp.*block\.timestamp', source_code):
            vulnerabilities.append({
                'type': VulnerabilityType.ORACLE_MANIPULATION.value,
                'severity': 'medium',
                'description': 'Block timestamp used in price calculation'
            })
        
        return vulnerabilities
    
    def check_centralization_risk(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if re.search(r'owner\s*=|onlyOwner', source_code):
            vulnerabilities.append({
                'type': VulnerabilityType.CENTRALIZATION.value,
                'severity': 'medium',
                'description': 'Single owner has control over critical functions'
            })
        
        if re.search(r'mint.*owner|owner.*mint', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.CENTRALIZATION.value,
                'severity': 'high',
                'description': 'Owner can mint unlimited tokens'
            })
        
        if re.search(r'pause.*owner|owner.*pause', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.CENTRALIZATION.value,
                'severity': 'medium',
                'description': 'Owner can pause contract'
            })
        
        return vulnerabilities
    
    def check_algorithmic_stability(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        stablecoin_type = self.detect_stablecoin_type(source_code)
        
        if stablecoin_type in [StablecoinType.ALGORITHMIC, StablecoinType.SEIGNIORAGE]:
            if not re.search(r'price.*feed|oracle|rate', source_code, re.IGNORECASE):
                vulnerabilities.append({
                    'type': VulnerabilityType.ORACLE_DEPEG.value,
                    'severity': 'critical',
                    'description': 'Algorithmic stablecoin without oracle - high depeg risk'
                })
            
            if not re.search(r'seed|expansion|contraction|supply', source_code, re.IGNORECASE):
                vulnerabilities.append({
                    'type': VulnerabilityType.BANK_RUN.value,
                    'severity': 'high',
                    'description': 'No supply expansion/contraction mechanism'
                })
        
        if re.search(r'rebase|adjust|supply.*change', source_code, re.IGNORECASE):
            if not re.search(r'checkpoint|balance.*snapshot', source_code, re.IGNORECASE):
                vulnerabilities.append({
                    'type': VulnerabilityType.REBASE_EXPLOIT.value,
                    'severity': 'high',
                    'description': 'Rebasing token without checkpoint - vulnerable to flash loan'
                })
        
        return vulnerabilities
    
    def analyze_liquidation_mechanism(self, source_code: str) -> Dict[str, Any]:
        has_liquidate = bool(re.search(r'liquidate|seize|auction', source_code, re.IGNORECASE))
        has_bonus = bool(re.search(r'bonus|incentive|discount', source_code, re.IGNORECASE))
        has_keeper = bool(re.search(r'keeper|bot|keeperReward', source_code, re.IGNORECASE))
        has_stability = bool(re.search(r'stable|spread|penalty', source_code, re.IGNORECASE))
        
        return {
            'has_liquidate': has_liquidate,
            'has_bonus': has_bonus,
            'has_keeper': has_keeper,
            'has_stability': has_stability
        }
    
    def calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        weights = {
            'critical': 10.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 1.0
        }
        
        total_risk = sum(weights.get(v.get('severity', 'low'), 1.0) for v in vulnerabilities)
        self.risk_score = min(total_risk / 10, 10.0)
        
        return self.risk_score
    
    def generate_security_report(self, source_code: str) -> Dict[str, Any]:
        undercollateral_vulns = self.check_undercollateralization_risk(source_code)
        centralization_vulns = self.check_centralization_risk(source_code)
        algorithmic_vulns = self.check_algorithmic_stability(source_code)
        
        all_vulnerabilities = undercollateral_vulns + centralization_vulns + algorithmic_vulns
        self.calculate_risk_score(all_vulnerabilities)
        
        return {
            'stablecoin_type': self.detect_stablecoin_type(source_code).value,
            'oracle_system': self.analyze_oracle_system(source_code),
            'collateral_system': self.analyze_collateral_system(source_code),
            'liquidation_mechanism': self.analyze_liquidation_mechanism(source_code),
            'vulnerabilities': all_vulnerabilities,
            'risk_score': self.risk_score,
            'recommendations': self._generate_recommendations(all_vulnerabilities)
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        recommendations = []
        
        vuln_types = {v.get('type') for v in vulnerabilities}
        
        if VulnerabilityType.UNDERCOLLATERALIZATION.value in vuln_types:
            recommendations.append('Implement proper collateral ratio enforcement')
            recommendations.append('Use decentralized oracle like Chainlink')
        
        if VulnerabilityType.CENTRALIZATION.value in vuln_types:
            recommendations.append('Add multi-sig governance')
            recommendations.append('Implement timelock for admin actions')
        
        if VulnerabilityType.ORACLE_DEPEG.value in vuln_types:
            recommendations.append('Add oracle price feed with deviation checks')
            recommendations.append('Implement emergency shutdown mechanism')
        
        if VulnerabilityType.REBASE_EXPLOIT.value in vuln_types:
            recommendations.append('Implement balance checkpoints before transfers')
            recommendations.append('Add flash loan protection')
        
        return recommendations


class PegStabilityMonitor:
    def __init__(self):
        self.price_history: List[MarketState] = []
        self.deviation_threshold: float = 5.0
    
    def add_price_point(self, price: float, volume: float = 0, liquidity: float = 0):
        if not self.price_history:
            target = 1.0
        else:
            target = self.price_history[-1].target_price
        
        state = MarketState(
            price=price,
            target_price=target,
            deviation=0,
            timestamp=int(time.time()),
            volume_24h=volume,
            liquidity=liquidity
        )
        
        self.price_history.append(state)
    
    def get_current_deviation(self) -> float:
        if not self.price_history:
            return 0.0
        
        return self.price_history[-1].deviation
    
    def is_peg_broken(self) -> bool:
        return abs(self.get_current_deviation()) > self.deviation_threshold
    
    def calculate_recovery_time(self, avg_volatility: float) -> float:
        if avg_volatility == 0:
            return float('inf')
        
        current_deviation = abs(self.get_current_deviation())
        return current_deviation / avg_volatility
    
    def get_stability_score(self) -> float:
        if not self.price_history:
            return 0.0
        
        deviations = [abs(p.deviation) for p in self.price_history]
        avg_deviation = sum(deviations) / len(deviations)
        
        return max(0, 100 - avg_deviation * 10)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'current_deviation': self.get_current_deviation(),
            'is_peg_broken': self.is_peg_broken(),
            'stability_score': self.get_stability_score(),
            'history_length': len(self.price_history)
        }


class VaultManager:
    def __init__(self):
        self.vaults: Dict[str, Vault] = {}
        self.user_vaults: Dict[str, List[str]] = defaultdict(list)
    
    def create_vault(self, owner: str, collateral_token: str, 
                    collateral_amount: float, debt_amount: float) -> str:
        vault_id = f"vault_{len(self.vaults)}_{int(time.time())}"
        
        vault = Vault(
            vault_id=vault_id,
            owner=owner,
            collateral_token=collateral_token,
            collateral_amount=collateral_amount,
            debt_amount=debt_amount,
            collateral_ratio=collateral_amount / debt_amount if debt_amount > 0 else float('inf'),
            created_at=int(time.time()),
            last_update=int(time.time())
        )
        
        self.vaults[vault_id] = vault
        self.user_vaults[owner].append(vault_id)
        
        return vault_id
    
    def get_vault(self, vault_id: str) -> Optional[Vault]:
        return self.vaults.get(vault_id)
    
    def get_user_vaults(self, user: str) -> List[Vault]:
        vault_ids = self.user_vaults.get(user, [])
        return [self.vaults[vid] for vid in vault_ids if vid in self.vaults]
    
    def liquidate_unhealthy_vaults(self, collateral_price: float, token_price: float,
                                  liquidation_ratio: float = 0.8) -> List[str]:
        liquidatable = []
        
        for vault_id, vault in self.vaults.items():
            if not vault.is_healthy(collateral_price, token_price, liquidation_ratio):
                liquidatable.append(vault_id)
        
        return liquidatable
    
    def get_total_debt(self) -> float:
        return sum(v.debt_amount for v in self.vaults.values())
    
    def get_total_collateral(self) -> float:
        return sum(v.collateral_amount for v in self.vaults.values())
    
    def calculate_collateralization_ratio(self) -> float:
        total_debt = self.get_total_debt()
        if total_debt == 0:
            return float('inf')
        
        total_collateral = self.get_total_collateral()
        return total_collateral / total_debt
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_vaults': len(self.vaults),
            'total_debt': self.get_total_debt(),
            'total_collateral': self.get_total_collateral(),
            'collateralization_ratio': self.calculate_collateralization_ratio(),
            'vaults': [v.to_dict() for v in self.vaults.values()]
        }


def analyze_stablecoin(source_code: str) -> Dict[str, Any]:
    analyzer = StablecoinSecurityAnalyzer()
    return analyzer.generate_security_report(source_code)


if __name__ == '__main__':
    sample = """
    pragma solidity ^0.8.0;
    
    contract Stablecoin {
        address public owner;
        mapping(address => uint256) public collateral;
        mapping(address => uint256) public debt;
        uint256 public collateralRatio = 150;
        address public oracle;
        
        function mint(uint256 amount) external {
            require(collateral[msg.sender] * collateralRatio / 100 >= debt[msg.sender] + amount);
            debt[msg.sender] += amount;
            _mint(msg.sender, amount);
        }
        
        function liquidate(address user) external {
            require(collateral[user] * collateralRatio / 100 < debt[user]);
            uint256 seized = debt[user] * 110 / 100;
            collateral[msg.sender] += seized;
            collateral[user] -= seized;
            debt[user] = 0;
        }
    }
    """
    
    result = analyze_stablecoin(sample)
    print(json.dumps(result, indent=2))