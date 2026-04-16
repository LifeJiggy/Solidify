"""
Automated Market Maker (AMM) Pattern Detection and Security Analysis Module

This module provides comprehensive security analysis for AMM (Automated Market Maker)
smart contracts including Uniswap, Sushiswap, Balancer, and other DEX protocols.

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


class AMMType(Enum):
    UNISWAP_V2 = "uniswap_v2"
    UNISWAP_V3 = "uniswap_v3"
    SUSHISWAP = "sushiswap"
    BALANCER = "balancer"
    CURVE = "curve"
    KYBER = "kyber"
    BANKSY = "banksy"
    UNKNOWN = "unknown"


class PoolType(Enum):
    CONSTANT_PRODUCT = "constant_product"
    CONSTANT_SUM = "constant_sum"
    WEIGHTED = "weighted"
    STABLE_SWAP = "stable_swap"
    CONCENTRATED = "concentrated"


class VulnerabilityType(Enum):
    FRONT_RUNNING = "front_running"
    PRICE_MANIPULATION = "price_manipulation"
    SLIPPAGE = "slippage"
    INSUFFICIENT_LIQUIDITY = "insufficient_liquidity"
    FLASH_SWAP_ATTACK = "flash_swap_attack"
    ORACLE_MANIPULATION = "oracle_manipulation"
    ROUTING_ATTACK = "routing_attack"
    POOL_DRAIN = "pool_drain"
    ROYALTY_BYPASS = "royalty_bypass"


class LiquidityPosition:
    def __init__(self, token_a: str, token_b: str, amount_a: float, amount_b: float):
        self.token_a = token_a
        self.token_b = token_b
        self.amount_a = amount_a
        self.amount_b = amount_b
        self.share_percentage = 0.0
        self.value_usd = 0.0
    
    def calculate_share(self, total_a: float, total_b: float) -> float:
        if total_a == 0 or total_b == 0:
            return 0.0
        share_a = self.amount_a / total_a
        share_b = self.amount_b / total_b
        self.share_percentage = min(share_a, share_b) * 100
        return self.share_percentage
    
    def calculate_value(self, price_a: float, price_b: float) -> float:
        self.value_usd = (self.amount_a * price_a) + (self.amount_b * price_b)
        return self.value_usd
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'token_a': self.token_a,
            'token_b': self.token_b,
            'amount_a': self.amount_a,
            'amount_b': self.amount_b,
            'share_percentage': self.share_percentage,
            'value_usd': self.value_usd
        }


class SwapPath:
    def __init__(self, path: List[str]):
        self.path = path
        self.pools: List[str] = []
        self.estimated_output: float = 0.0
        self.minimum_output: float = 0.0
        self.price_impact: float = 0.0
        self.gas_estimate: int = 0
    
    def add_pool(self, pool_address: str):
        self.pools.append(pool_address)
    
    def calculate_price_impact(self, input_amount: float, output_amount: float, 
                             reserves_before: Tuple[float, float], 
                             reserves_after: Tuple[float, float]) -> float:
        if reserves_before[0] == 0 or reserves_before[1] == 0:
            return 0.0
        
        price_before = reserves_before[0] / reserves_before[1]
        price_after = reserves_after[0] / reserves_after[1]
        
        if price_before == 0:
            return 0.0
        
        self.price_impact = ((price_after - price_before) / price_before) * 100
        return self.price_impact
    
    def estimate_gas(self) -> int:
        base_gas = 50000
        pool_gas = 30000 * len(self.pools)
        self.gas_estimate = base_gas + pool_gas
        return self.gas_estimate
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'path': self.path,
            'pools': self.pools,
            'estimated_output': self.estimated_output,
            'minimum_output': self.minimum_output,
            'price_impact': self.price_impact,
            'gas_estimate': self.gas_estimate
        }


class PoolReserves:
    def __init__(self, pool_address: str, token_a: str, token_b: str):
        self.pool_address = pool_address
        self.token_a = token_a
        self.token_b = token_b
        self.reserve_a: float = 0.0
        self.reserve_b: float = 0.0
        self.block_timestamp_last: int = 0
        self.price_cumulative_last: Tuple[float, float] = (0.0, 0.0)
    
    def update_reserves(self, reserve_a: float, reserve_b: float, timestamp: int):
        self.reserve_a = reserve_a
        self.reserve_b = reserve_b
        self.block_timestamp_last = timestamp
    
    def get_spot_price(self) -> float:
        if self.reserve_b == 0:
            return 0.0
        return self.reserve_a / self.reserve_b
    
    def calculate_output_amount(self, input_amount: float, fee: float = 0.003) -> float:
        input_with_fee = input_amount * (1 - fee)
        numerator = input_with_fee * self.reserve_b
        denominator = self.reserve_a + input_with_fee
        return numerator / denominator
    
    def calculate_input_amount(self, output_amount: float, fee: float = 0.003) -> float:
        numerator = self.reserve_a * output_amount
        denominator = (self.reserve_b - output_amount) * (1 - fee)
        if denominator == 0:
            return float('inf')
        return numerator / denominator
    
    def get_twap_price(self, time_interval: int = 300) -> float:
        if self.price_cumulative_last[0] == 0:
            return self.get_spot_price()
        
        price_cumulative_now = (self.reserve_a, self.reserve_b)
        time_elapsed = time_interval
        
        if time_elapsed == 0:
            return self.get_spot_price()
        
        price_diff = (
            price_cumulative_now[0] - self.price_cumulative_last[0],
            price_cumulative_now[1] - self.price_cumulative_last[1]
        )
        
        if price_diff[1] == 0:
            return self.get_spot_price()
        
        return price_diff[0] / price_diff[1]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pool_address': self.pool_address,
            'token_a': self.token_a,
            'token_b': self.token_b,
            'reserve_a': self.reserve_a,
            'reserve_b': self.reserve_b,
            'spot_price': self.get_spot_price(),
            'twap_price': self.get_twap_price()
        }


class AMMDetector:
    def __init__(self):
        self.detected_pools: Dict[str, PoolReserves] = {}
        self.liquidity_positions: List[LiquidityPosition] = []
        self.swap_paths: List[SwapPath] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
    
    def detect_amm_type(self, source_code: str) -> AMMType:
        source_lower = source_code.lower()
        
        if 'uniswapv3' in source_lower or 'iuniswapv3' in source_lower:
            return AMMType.UNISWAP_V3
        elif 'sushiswap' in source_lower or 'masterchef' in source_lower:
            return AMMType.SUSHISWAP
        elif 'balancer' in source_lower or 'bpool' in source_lower:
            return AMMType.BALANCER
        elif 'curve' in source_lower or 'stableSwap' in source_lower:
            return AMMType.CURVE
        elif 'kyber' in source_lower or 'ikyber' in source_lower:
            return AMMType.KYBER
        elif 'banksy' in source_lower:
            return AMMType.BANKSY
        elif 'factory' in source_lower and 'pair' in source_lower:
            return AMMType.UNISWAP_V2
        
        return AMMType.UNKNOWN
    
    def detect_pool_addresses(self, source_code: str) -> List[str]:
        pattern = r'0x[a-fA-F0-9]{40}'
        addresses = re.findall(pattern, source_code)
        return list(set(addresses))
    
    def analyze_swap_function(self, source_code: str) -> Dict[str, Any]:
        result = {
            'has_swap': False,
            'has_swap_exact_tokens': False,
            'has_swap_tokens_exact': False,
            'has_flash_swap': False,
            'has_multihop': False,
            'slippage_protection': False,
            'fee_on_transfer': False,
            'external_calls': []
        }
        
        if re.search(r'function\s+swap\s*\(', source_code, re.IGNORECASE):
            result['has_swap'] = True
        
        if re.search(r'swapExactTokensForTokens|swapTokensForExactTokens', source_code):
            result['has_swap_exact_tokens'] = True
            result['has_multihop'] = True
        
        if re.search(r'flashSwap|flashSwapInternal', source_code):
            result['has_flash_swap'] = True
        
        if re.search(r'amountOutMin|amountOutMin', source_code):
            result['slippage_protection'] = True
        
        if re.search(r'transfer.*address\(0\)|_transfer.*address\(0\)', source_code):
            result['fee_on_transfer'] = True
        
        external_calls = re.findall(r'(call|delegatecall|staticcall)\s*\{', source_code)
        result['external_calls'] = external_calls
        
        return result
    
    def detect_vulnerabilities(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if re.search(r'block\.timestamp.*block\.timestamp', source_code):
            vulnerabilities.append({
                'type': VulnerabilityType.PRICE_MANIPULATION.value,
                'severity': 'high',
                'description': 'Timestamp used in price calculation',
                'line': self._find_line(source_code, 'block.timestamp')
            })
        
        if re.search(r'getReserves\s*\(\s*\)', source_code):
            if not re.search(r'twap|TWAP|timeWeighted', source_code):
                vulnerabilities.append({
                    'type': VulnerabilityType.ORACLE_MANIPULATION.value,
                    'severity': 'high',
                    'description': 'Spot price used without TWAP protection',
                    'line': self._find_line(source_code, 'getReserves')
                })
        
        if re.search(r'swap.*send|swap.*transfer.*value', source_code, re.DOTALL):
            vulnerabilities.append({
                'type': VulnerabilityType.FRONT_RUNNING.value,
                'severity': 'medium',
                'description': 'Swap may be front-runnable',
                'line': self._find_line(source_code, 'swap')
            })
        
        if not re.search(r'amountOutMin|minimum.*output', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.SLIPPAGE.value,
                'severity': 'high',
                'description': 'No minimum output protection',
                'line': 0
            })
        
        if re.search(r'delegatecall', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.POOL_DRAIN.value,
                'severity': 'critical',
                'description': 'Delegatecall usage detected',
                'line': self._find_line(source_code, 'delegatecall')
            })
        
        return vulnerabilities
    
    def _find_line(self, source_code: str, pattern: str) -> int:
        match = re.search(pattern, source_code, re.IGNORECASE)
        if match:
            return source_code[:match.start()].count('\n') + 1
        return 0
    
    def analyze_liquidity_providers(self, source_code: str) -> Dict[str, Any]:
        return {
            'has_mint': 'function mint' in source_code.lower(),
            'has_burn': 'function burn' in source_code.lower(),
            'has_sync': 'function sync' in source_code.lower(),
            'has_skim': 'function skim' in source_code.lower(),
            'has_token0': 'token0' in source_code.lower(),
            'has_token1': 'token1' in source_code.lower(),
        }
    
    def calculate_liquidity_depth(self, reserves: Dict[str, PoolReserves], 
                                 min_liquidity: float = 10000) -> Dict[str, Any]:
        total_value = 0.0
        low_liquidity_pools = []
        
        for pool_addr, pool in reserves.items():
            value = pool.reserve_a + pool.reserve_b
            total_value += value
            
            if value < min_liquidity:
                low_liquidity_pools.append(pool_addr)
        
        return {
            'total_value': total_value,
            'pool_count': len(reserves),
            'low_liquidity_pools': low_liquidity_pools,
            'avg_liquidity': total_value / len(reserves) if reserves else 0
        }
    
    def analyze_routing(self, source_code: str) -> Dict[str, Any]:
        routes = []
        
        path_pattern = r'path\s*\[|address\[\]\s+path'
        if re.search(path_pattern, source_code):
            routes.append({
                'type': 'path_based',
                'supports_multihop': True
            })
        
        factory_pattern = r'factory\s*\.|\.factory'
        if re.search(factory_pattern, source_code):
            routes.append({
                'type': 'factory_based',
                'dynamic_pairs': True
            })
        
        return {
            'routes': routes,
            'max_hops': len(routes) * 2,
            'supports_arbitrage': len(routes) > 1
        }
    
    def generate_report(self, source_code: str) -> Dict[str, Any]:
        return {
            'amm_type': self.detect_amm_type(source_code).value,
            'pool_addresses': self.detect_pool_addresses(source_code),
            'swap_analysis': self.analyze_swap_function(source_code),
            'vulnerabilities': self.detect_vulnerabilities(source_code),
            'liquidity_analysis': self.analyze_liquidity_providers(source_code),
            'routing': self.analyze_routing(source_code)
        }


class AMMSecurityAnalyzer:
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.risk_score: float = 0.0
    
    def analyze_price_oracle(self, source_code: str) -> Dict[str, Any]:
        has_twap = bool(re.search(r'TWAP|twap|timeWeighted|priceAverage', source_code))
        has_spot = bool(re.search(r'getReserves|spotPrice|getSpotPrice', source_code))
        has_chainlink = bool(re.search(r'chainlink|AggregatorV3|latestAnswer', source_code))
        
        oracle_type = 'unknown'
        security_level = 'low'
        
        if has_chainlink:
            oracle_type = 'chainlink'
            security_level = 'high'
        elif has_twap:
            oracle_type = 'twap'
            security_level = 'medium'
        elif has_spot:
            oracle_type = 'spot'
            security_level = 'low'
        
        return {
            'oracle_type': oracle_type,
            'has_twap': has_twap,
            'has_spot': has_spot,
            'has_chainlink': has_chainlink,
            'security_level': security_level,
            'manipulation_risk': 'high' if security_level == 'low' else 'medium'
        }
    
    def analyze_fee_structure(self, source_code: str) -> Dict[str, Any]:
        fee_patterns = [
            (r'fee\s*=\s*(\d+)', 'custom_fee'),
            (r'FEE_DENOMINATOR\s*=\s*(\d+)', 'fee_denominator'),
            (r'0\.003|3e-3', '0.3%'),
            (r'0\.001|1e-3', '0.1%'),
            (r'0\.0005|5e-4', '0.05%'),
        ]
        
        detected_fees = []
        for pattern, fee_type in fee_patterns:
            if re.search(pattern, source_code):
                detected_fees.append(fee_type)
        
        return {
            'detected_fees': detected_fees,
            'has_dynamic_fee': bool(re.search(r'dynamicFee|adjustFee', source_code)),
            'protocol_fee': bool(re.search(r'protocolFee|communityFee', source_code))
        }
    
    def analyze_permissions(self, source_code: str) -> Dict[str, Any]:
        return {
            'has_owner': bool(re.search(r'owner|Ownable', source_code, re.IGNORECASE)),
            'has_admin': bool(re.search(r'admin|Admin', source_code, re.IGNORECASE)),
            'has_governance': bool(re.search(r'governance|Governor', source_code, re.IGNORECASE)),
            'has_timelock': bool(re.search(r'Timelock|Delay', source_code, re.IGNORECASE)),
            'has_pausable': bool(re.search(r'Pausable|paused', source_code, re.IGNORECASE)),
            'has_upgradeable': bool(re.search(r'Upgradeable|Proxy|Delegate', source_code, re.IGNORECASE))
        }
    
    def calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        weights = {
            'critical': 10.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 1.0
        }
        
        total_risk = 0.0
        for finding in findings:
            severity = finding.get('severity', 'low')
            total_risk += weights.get(severity, 1.0)
        
        self.risk_score = min(total_risk / 10, 10.0)
        return self.risk_score
    
    def generate_security_report(self, source_code: str) -> Dict[str, Any]:
        findings = self.analyze_price_oracle(source_code)
        findings['fee_structure'] = self.analyze_fee_structure(source_code)
        findings['permissions'] = self.analyze_permissions(source_code)
        
        self.calculate_risk_score(findings.get('vulnerabilities', []))
        
        return {
            'risk_score': self.risk_score,
            'findings': findings,
            'recommendations': self._generate_recommendations(findings)
        }
    
    def _generate_recommendations(self, findings: Dict[str, Any]) -> List[str]:
        recommendations = []
        
        if findings.get('oracle_type') == 'spot':
            recommendations.append('Implement TWAP oracle for price feeds')
        
        if not findings.get('permissions', {}).get('has_timelock'):
            recommendations.append('Add timelock for critical functions')
        
        if not findings.get('fee_structure', {}).get('protocol_fee'):
            recommendations.append('Consider protocol fee mechanism')
        
        return recommendations


class AMMRouterAnalyzer:
    def __init__(self):
        self.paths: List[SwapPath] = []
        self.best_path: Optional[SwapPath] = None
    
    def find_best_path(self, token_in: str, token_out: str, 
                      amount_in: float, pools: Dict[str, PoolReserves]) -> SwapPath:
        path = SwapPath([token_in, token_out])
        
        best_output = 0.0
        best_path = path
        
        for pool_addr, pool in pools.items():
            if pool.token_a == token_in and pool.token_b == token_out:
                output = pool.calculate_output_amount(amount_in)
                if output > best_output:
                    best_output = output
                    best_path = SwapPath([token_in, token_out])
                    best_path.add_pool(pool_addr)
                    best_path.estimated_output = output
        
        self.best_path = best_path
        return best_path
    
    def analyze_arbitrage_opportunity(self, pools: Dict[str, PoolReserves]) -> Dict[str, Any]:
        opportunities = []
        
        pool_list = list(pools.values())
        for i, pool_a in enumerate(pool_list):
            for pool_b in pool_list[i+1:]:
                price_a = pool_a.get_spot_price()
                price_b = pool_b.get_spot_price()
                
                if price_a == 0 or price_b == 0:
                    continue
                
                price_diff = abs(price_a - price_b) / price_a
                
                if price_diff > 0.01:
                    opportunities.append({
                        'pool_a': pool_a.pool_address,
                        'pool_b': pool_b.pool_address,
                        'price_a': price_a,
                        'price_b': price_b,
                        'price_diff_percent': price_diff * 100,
                        'profit_potential': price_diff * 1000
                    })
        
        return {
            'opportunities': opportunities,
            'total_opportunities': len(opportunities),
            'max_profit_percent': max((o['profit_potential'] for o in opportunities), default=0)
        }


def analyze_amm_contract(source_code: str) -> Dict[str, Any]:
    detector = AMMDetector()
    analyzer = AMMSecurityAnalyzer()
    
    return {
        'detection': detector.generate_report(source_code),
        'security': analyzer.generate_security_report(source_code)
    }


if __name__ == '__main__':
    sample = """
    pragma solidity ^0.8.0;
    
    contract AMMPool {
        address public token0;
        address public token1;
        uint112 private reserve0;
        uint112 private reserve1;
        
        function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external {
            require(amount0Out > 0 || amount1Out > 0);
            uint balance0 = IERC20(token0).balanceOf(address(this));
            uint balance1 = IERC20(token1).balanceOf(address(this));
            require(balance0 >= reserve0 + amount0Out && balance1 >= reserve1 + amount1Out);
            
            if (amount0Out > 0) IERC20(token0).transfer(to, amount0Out);
            if (amount1Out > 0) IERC20(token1).transfer(to, amount1Out);
            
            uint balance0Adjusted = balance0 * 1000 - amount0Out * 3;
            uint balance1Adjusted = balance1 * 1000 - amount1Out * 3;
            require(balance0Adjusted * balance1Adjusted >= uint112(reserve0) * uint112(reserve1) * 1000000);
        }
    }
    """
    
    result = analyze_amm_contract(sample)
    print(json.dumps(result, indent=2))
