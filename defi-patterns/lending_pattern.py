"""
DeFi Lending Protocol Security Analysis Module

This module provides comprehensive security analysis for lending protocol smart contracts
including Aave, Compound, Yearn, and other lending/borrowing DeFi protocols.

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


class LendingProtocol(Enum):
    AAVE = "aave"
    COMPOUND = "compound"
    YEARN = "yearn"
    CREAM = "cream"
    ALCHEMIX = "alchemix"
    LIDO = "lido"
    RARI = "rari"
    UNKNOWN = "unknown"


class CollateralType(Enum):
    ERC20 = "erc20"
    ERC721 = "erc721"
    ERC1155 = "erc1155"
    NFT = "nft"
    SYNTHETIC = "synthetic"


class VulnerabilityType(Enum):
    LIQUIDATION_MANIPULATION = "liquidation_manipulation"
    INTEREST_RATE_MANIPULATION = "interest_rate_manipulation"
    COLLATERAL_MANIPULATION = "collateral_manipulation"
    ORACLE_MANIPULATION = "oracle_manipulation"
    FLASH_LOAN_ATTACK = "flash_loan_attack"
    UNDERCOLLATERALIZATION = "undercollateralization"
    SORRY_PROTECTION = "sporadic_protection"
    PRICE_ORACLE_ATTACK = "price_oracle_attack"


class Asset:
    def __init__(self, symbol: str, address: str, decimals: int):
        self.symbol = symbol
        self.address = address
        self.decimals = decimals
        self.price_usd: float = 0.0
        self.reserve_factor: float = 0.0
        self.collateral_factor: float = 0.0
        self.liquidation_threshold: float = 0.0
        self.liquidation_bonus: float = 0.0
    
    def set_price(self, price: float):
        self.price_usd = price
    
    def calculate_collateral_value(self, amount: float) -> float:
        return amount * self.price_usd * self.collateral_factor
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'symbol': self.symbol,
            'address': self.address,
            'decimals': self.decimals,
            'price_usd': self.price_usd,
            'reserve_factor': self.reserve_factor,
            'collateral_factor': self.collateral_factor,
            'liquidation_threshold': self.liquidation_threshold,
            'liquidation_bonus': self.liquidation_bonus
        }


class UserPosition:
    def __init__(self, user_address: str):
        self.user_address = user_address
        self.collateral_assets: Dict[str, float] = {}
        self.borrowed_assets: Dict[str, float] = {}
        self.accrued_interest: Dict[str, float] = {}
    
    def add_collateral(self, asset_address: str, amount: float):
        current = self.collateral_assets.get(asset_address, 0.0)
        self.collateral_assets[asset_address] = current + amount
    
    def add_borrow(self, asset_address: str, amount: float):
        current = self.borrowed_assets.get(asset_address, 0.0)
        self.borrowed_assets[asset_address] = current + amount
    
    def calculate_health_factor(self, assets: Dict[str, Asset]) -> float:
        total_collateral = 0.0
        total_borrowed = 0.0
        
        for asset_addr, amount in self.collateral_assets.items():
            asset = assets.get(asset_addr)
            if asset:
                total_collateral += asset.calculate_collateral_value(amount)
        
        for asset_addr, amount in self.borrowed_assets.items():
            asset = assets.get(asset_addr)
            if asset:
                total_borrowed += amount * asset.price_usd
        
        if total_borrowed == 0:
            return float('inf')
        
        return total_collateral / total_borrowed
    
    def is_healthy(self, assets: Dict[str, Asset], threshold: float = 1.0) -> bool:
        health_factor = self.calculate_health_factor(assets)
        return health_factor >= threshold
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'user_address': self.user_address,
            'collateral_assets': self.collateral_assets,
            'borrowed_assets': self.borrowed_assets,
            'accrued_interest': self.accrued_interest
        }


class Liquidation:
    def __init__(self, liquidator: str, borrower: str, collateral_asset: str, debt_asset: str):
        self.liquidator = liquidator
        self.borrower = borrower
        self.collateral_asset = collateral_asset
        self.debt_asset = debt_asset
        self.collateral_amount: float = 0.0
        self.debt_amount: float = 0.0
        self.profit: float = 0.0
        self.timestamp = time.time()
        self.block_number: int = 0
    
    def execute(self, assets: Dict[str, Asset]) -> float:
        collateral_asset = assets.get(self.collateral_asset)
        debt_asset = assets.get(self.debt_asset)
        
        if not collateral_asset or not debt_asset:
            return 0.0
        
        debt_value = self.debt_amount * debt_asset.price_usd
        self.collateral_amount = debt_value / collateral_asset.price_usd
        
        bonus = collateral_asset.liquidation_bonus
        self.profit = self.collateral_amount * (1 + bonus) * collateral_asset.price_usd - debt_value
        
        return self.profit
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'liquidator': self.liquidator,
            'borrower': self.borrower,
            'collateral_asset': self.collateral_asset,
            'debt_asset': self.debt_asset,
            'collateral_amount': self.collateral_amount,
            'debt_amount': self.debt_amount,
            'profit': self.profit,
            'timestamp': self.timestamp
        }


class LendingPool:
    def __init__(self, pool_address: str, asset: Asset):
        self.pool_address = pool_address
        self.asset = asset
        self.total_supply: float = 0.0
        self.total_borrowed: float = 0.0
        self.supply_rate: float = 0.0
        self.borrow_rate: float = 0.0
        self.utilization_rate: float = 0.0
        self.interest_index: float = 1.0
        self.last_update_timestamp: int = 0
    
    def calculate_supply_rate(self, utilization: float) -> float:
        optimal_utilization = 0.8
        slope_low = 0.1
        slope_high = 1.0
        
        if utilization <= optimal_utilization:
            return utilization * slope_low
        else:
            excess = utilization - optimal_utilization
            return slope_low * optimal_utilization + excess * slope_high
    
    def calculate_borrow_rate(self, utilization: float) -> float:
        base_rate = 0.02
        optimal_utilization = 0.8
        slope_low = 0.1
        slope_high = 1.5
        
        if utilization <= optimal_utilization:
            return base_rate + utilization * slope_low
        else:
            excess = utilization - optimal_utilization
            return base_rate + optimal_utilization * slope_low + excess * slope_high
    
    def update_utilization(self):
        if self.total_supply == 0:
            self.utilization_rate = 0.0
        else:
            self.utilization_rate = self.total_borrowed / self.total_supply
        
        self.supply_rate = self.calculate_supply_rate(self.utilization_rate)
        self.borrow_rate = self.calculate_borrow_rate(self.utilization_rate)
    
    def accrue_interest(self, time_delta: int):
        if time_delta == 0:
            return
        
        rate_per_second = self.borrow_rate / 31536000
        interest_multiplier = 1 + rate_per_second * time_delta
        
        self.interest_index *= interest_multiplier
        self.total_borrowed *= interest_multiplier
        self.last_update_timestamp = int(time.time())
    
    def deposit(self, amount: float):
        self.total_supply += amount
        self.update_utilization()
    
    def borrow(self, amount: float):
        if amount > self.total_supply * 0.8:
            raise ValueError("Insufficient liquidity")
        
        self.total_borrowed += amount
        self.update_utilization()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pool_address': self.pool_address,
            'asset': self.asset.symbol,
            'total_supply': self.total_supply,
            'total_borrowed': self.total_borrowed,
            'supply_rate': self.supply_rate,
            'borrow_rate': self.borrow_rate,
            'utilization_rate': self.utilization_rate
        }


class LendingSecurityAnalyzer:
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.risk_score: float = 0.0
    
    def detect_protocol_type(self, source_code: str) -> LendingProtocol:
        source_lower = source_code.lower()
        
        if 'aave' in source_lower or 'lendingpool' in source_lower:
            return LendingProtocol.AAVE
        elif 'compound' in source_lower or 'comptroller' in source_lower:
            return LendingProtocol.COMPOUND
        elif 'yearn' in source_lower or 'yvault' in source_lower:
            return LendingProtocol.YEARN
        elif 'cream' in source_lower or 'credit' in source_lower:
            return LendingProtocol.CREAM
        elif 'alchemix' in source_lower or 'alchemist' in source_lower:
            return LendingProtocol.ALCHEMIX
        elif 'lido' in source_lower or 'steth' in source_lower:
            return LendingProtocol.LIDO
        
        return LendingProtocol.UNKNOWN
    
    def analyze_collateral_system(self, source_code: str) -> Dict[str, Any]:
        has_oracle = bool(re.search(r'oracle|priceFeed|Aggregator', source_code, re.IGNORECASE))
        has_ltv = bool(re.search(r'ltv|loanToValue|collateralFactor', source_code, re.IGNORECASE))
        has_liquidation = bool(re.search(r'liquidate|seize|collateral', source_code, re.IGNORECASE))
        has_health_factor = bool(re.search(r'healthFactor|checkHealth|isHealthy', source_code, re.IGNORECASE))
        
        return {
            'has_oracle': has_oracle,
            'has_ltv': has_ltv,
            'has_liquidation': has_liquidation,
            'has_health_factor': has_health_factor
        }
    
    def analyze_interest_mechanism(self, source_code: str) -> Dict[str, Any]:
        has_interest_rate = bool(re.search(r'interestRate|rateModel|model', source_code, re.IGNORECASE))
        has_borrow_rate = bool(re.search(r'borrowRate|borrowIndex', source_code, re.IGNORECASE))
        has_supply_rate = bool(re.search(r'supplyRate|supplyIndex', source_code, re.IGNORECASE))
        has_accrual = bool(re.search(r'accrueInterest|accrue|accrued', source_code, re.IGNORECASE))
        
        return {
            'has_interest_rate': has_interest_rate,
            'has_borrow_rate': has_borrow_rate,
            'has_supply_rate': has_supply_rate,
            'has_accrual': has_accrual
        }
    
    def check_liquidation_bypass(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if not re.search(r'liquidate.*health|liquidate.*threshold', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': 'liquidation_bypass',
                'severity': 'high',
                'description': 'Missing health check in liquidation'
            })
        
        if not re.search(r'price.*twap|price.*average|price.*feed', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': 'oracle_manipulation',
                'severity': 'high',
                'description': 'Spot price oracle vulnerable to manipulation'
            })
        
        if re.search(r'delegatecall', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': 'delegatecall_risk',
                'severity': 'critical',
                'description': 'Delegatecall detected - potential storage manipulation'
            })
        
        if not re.search(r'liquidationBonus|liquidationIncentive|seizeBonus', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': 'low_liquidation_bonus',
                'severity': 'medium',
                'description': 'Low or missing liquidation bonus'
            })
        
        return vulnerabilities
    
    def analyze_access_control(self, source_code: str) -> Dict[str, Any]:
        has_pausable = bool(re.search(r'Pausable|paused|pause', source_code, re.IGNORECASE))
        has_governance = bool(re.search(r'governance|Governor|gov', source_code, re.IGNORECASE))
        has_timelock = bool(re.search(r'Timelock|Delay|timelock', source_code, re.IGNORECASE))
        has_flashloan_protection = bool(re.search(r'flash.*loan|flash.*repay|block.*flash', source_code, re.IGNORECASE))
        
        return {
            'has_pausable': has_pausable,
            'has_governance': has_governance,
            'has_timelock': has_timelock,
            'has_flashloan_protection': has_flashloan_protection
        }
    
    def check_flash_loan_attack(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if re.search(r'flashLoan|flashBorrow', source_code, re.IGNORECASE):
            if not re.search(r'balance.*before|balance.*after|check.*balance', source_code, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'flash_loan_sandbox',
                    'severity': 'high',
                    'description': 'Flash loan protection may be insufficient'
                })
            
            if not re.search(r'callback|onFlashLoan|repay', source_code, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'flash_loan_repayment',
                    'severity': 'critical',
                    'description': 'Missing flash loan repayment check'
                })
        
        return vulnerabilities
    
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
        liquidation_vulns = self.check_liquidation_bypass(source_code)
        flash_loan_vulns = self.check_flash_loan_attack(source_code)
        
        all_vulnerabilities = liquidation_vulns + flash_loan_vulns
        self.calculate_risk_score(all_vulnerabilities)
        
        return {
            'protocol_type': self.detect_protocol_type(source_code).value,
            'collateral_system': self.analyze_collateral_system(source_code),
            'interest_mechanism': self.analyze_interest_mechanism(source_code),
            'access_control': self.analyze_access_control(source_code),
            'vulnerabilities': all_vulnerabilities,
            'risk_score': self.risk_score,
            'recommendations': self._generate_recommendations(all_vulnerabilities)
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        recommendations = []
        
        vuln_types = {v.get('type') for v in vulnerabilities}
        
        if 'oracle_manipulation' in vuln_types:
            recommendations.append('Implement TWAP oracle for price feeds')
        
        if 'flash_loan_repayment' in vuln_types:
            recommendations.append('Add flash loan repayment validation')
        
        if 'liquidation_bypass' in vuln_types:
            recommendations.append('Add health factor check before liquidation')
        
        if 'delegatecall_risk' in vuln_types:
            recommendations.append('Remove or properly validate delegatecall usage')
        
        return recommendations


class LendingPoolAnalyzer:
    def __init__(self):
        self.pools: Dict[str, LendingPool] = {}
    
    def add_pool(self, pool: LendingPool):
        self.pools[pool.pool_address] = pool
    
    def get_pool(self, address: str) -> Optional[LendingPool]:
        return self.pools.get(address)
    
    def calculate_total_value_locked(self) -> float:
        return sum(pool.total_supply for pool in self.pools.values())
    
    def analyze_utilization_distribution(self) -> Dict[str, Any]:
        pools_by_utilization = {
            'low': [],
            'optimal': [],
            'high': [],
            'critical': []
        }
        
        for pool_addr, pool in self.pools.items():
            util = pool.utilization_rate
            if util < 0.5:
                pools_by_utilization['low'].append(pool_addr)
            elif util < 0.8:
                pools_by_utilization['optimal'].append(pool_addr)
            elif util < 0.95:
                pools_by_utilization['high'].append(pool_addr)
            else:
                pools_by_utilization['critical'].append(pool_addr)
        
        return pools_by_utilization
    
    def find_liquidation_opportunities(self, positions: Dict[str, UserPosition], 
                                     assets: Dict[str, Asset]) -> List[Dict[str, Any]]:
        opportunities = []
        
        for user_addr, position in positions.items():
            if not position.is_healthy(assets):
                health = position.calculate_health_factor(assets)
                opportunities.append({
                    'user': user_addr,
                    'health_factor': health,
                    'collateral': position.collateral_assets,
                    'debt': position.borrowed_assets,
                    'liquidation_bonus': 0.05
                })
        
        return opportunities
    
    def generate_lending_report(self) -> Dict[str, Any]:
        return {
            'total_pools': len(self.pools),
            'total_value_locked': self.calculate_total_value_locked(),
            'utilization_distribution': self.analyze_utilization_distribution(),
            'pools': [pool.to_dict() for pool in self.pools.values()]
        }


def analyze_lending_protocol(source_code: str) -> Dict[str, Any]:
    analyzer = LendingSecurityAnalyzer()
    return analyzer.generate_security_report(source_code)


if __name__ == '__main__':
    sample = """
    pragma solidity ^0.8.0;
    
    contract LendingPool {
        address public collateralToken;
        address public debtToken;
        address public oracle;
        uint256 public collateralFactor = 80;
        uint256 public liquidationThreshold = 75;
        
        function liquidate(address borrower, uint256 amount) external {
            require(msg.sender == liquidator || msg.sender == governance);
            require(healthFactor[borrower] < 100);
            
            _liquidate(borrower, msg.sender, amount);
        }
        
        function borrow(uint256 amount) external {
            require(availableLiquidity >= amount);
            require(isCollateral[msg.sender][collateralToken] >= amount * collateralFactor);
            
            borrowedBalance[msg.sender] += amount;
            debtToken.transfer(msg.sender, amount);
        }
    }
    """
    
    result = analyze_lending_protocol(sample)
    print(json.dumps(result, indent=2))