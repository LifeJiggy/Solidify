"""
SoliGuard Chain Prompt
Multi-chain and cross-chain security prompts

Author: Peace Stephen (Tech Lead)
Description: Chain-specific security prompts for EVM chains
"""

import json
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


CHAIN_CONFIGS = {
    "ethereum": {
        "name": "Ethereum",
        "chain_id": 1,
        "symbol": "ETH",
        "explorer": "etherscan.io",
        "rpc": "eth.llamarpc.com",
        "gas_limit": 3000000,
        "supports": ["eip155", "erc20", "erc721", "erc4626"]
    },
    "bsc": {
        "name": "BNB Smart Chain",
        "chain_id": 56,
        "symbol": "BNB",
        "explorer": "bscscan.com",
        "rpc": "https://bsc-dataseed.binance.org",
        "gas_limit": 8000000,
        "supports": ["bep20", "erc721"]
    },
    "polygon": {
        "name": "Polygon",
        "chain_id": 137,
        "symbol": "MATIC",
        "explorer": "polygonscan.com",
        "rpc": "https://polygon-rpc.com",
        "gas_limit": 20000000,
        "supports": ["erc20", "erc721", "erc1155"]
    },
    "arbitrum": {
        "name": "Arbitrum One",
        "chain_id": 42161,
        "symbol": "ETH",
        "explorer": "arbiscan.io",
        "rpc": "https://arb1.arbitrum.io/rpc",
        "gas_limit": 10000000,
        "supports": ["erc20", "erc721", "arbretryabletx"]
    },
    "optimism": {
        "name": "Optimism",
        "chain_id": 10,
        "symbol": "ETH",
        "explorer": "optimistic.etherscan.io",
        "rpc": "https://mainnet.optimism.io",
        "gas_limit": 30000000,
        "supports": ["erc20", "erc721", "opl2"]
    },
    "base": {
        "name": "Base",
        "chain_id": 8453,
        "symbol": "ETH",
        "explorer": "basescan.org",
        "rpc": "https://mainnet.base.org",
        "gas_limit": 5000000,
        "supports": ["erc20", "erc721", "erc1155"]
    },
    "avalanche": {
        "name": "Avalanche",
        "chain_id": 43114,
        "symbol": "AVAX",
        "explorer": "snowtrace.io",
        "rpc": "https://api.avax.network/ext/bc/C/r",
        "gas_limit": 8000000,
        "supports": ["erc20", "erc721"]
    },
    "fantom": {
        "name": "Fantom",
        "chain_id": 250,
        "symbol": "FTM",
        "explorer": "ftmscan.com",
        "rpc": "https://rpc.ftm.network",
        "gas_limit": 10000000,
        "supports": ["erc20", "erc721"]
    }
}


CHAIN_SPECIFIC_VULNS = {
    "ethereum": {
        "state_variable_initialization": "Check for uninitialized storage pointers",
        "network_specific": "No specific vulnerabilities"
    },
    "bsc": {
        "unsafe_js_parse": "BNB Chain uses JavaScript-like uint behavior (wrapped)",
        "multiple_payable": "Different msg.value handling in BSC"
    },
    "polygon": {
        "checkpoint_manipulation": "Potential checkpoint manipulation",
        "state_sync": "Check for state sync vulnerabilities"
    },
    "arbitrum": {
        "retryable_ticket": "Check retryable ticket parameters",
        "sequencer_failure": "Sequencer downtime considerations"
    },
    "optimism": {
        "l1_l2_differences": "OVM vs EVM differences",
        "storage_root": "L2 state root validity"
    },
    "base": {
        "bridge_operations": "Check Base bridge operations",
        "gas_pool": "Check gas pool assumptions"
    }
}


@dataclass
class ChainContext:
    chain: str
    chain_id: Optional[int] = None
    rpc_url: Optional[str] = None
    explorer_url: Optional[str] = None
    native_symbol: str = "ETH"
    token_standard: str = "erc20"


class ChainPromptBuilder:
    """Build chain-specific prompts"""
    
    def __init__(self):
        self.default_chain = "ethereum"
    
    def get_chain_info(self, chain: str) -> Dict[str, Any]:
        return CHAIN_CONFIGS.get(chain, CHAIN_CONFIGS["ethereum"])
    
    def build_chain_context(self, chain: str) -> ChainContext:
        info = self.get_chain_info(chain)
        return ChainContext(
            chain=chain,
            chain_id=info.get("chain_id"),
            rpc_url=info.get("rpc"),
            explorer_url=info.get("explorer"),
            native_symbol=info.get("symbol", "ETH")
        )
    
    def build_multi_chain_prompt(
        self,
        contract_code: str,
        chains: Optional[List[str]] = None
    ) -> str:
        if not chains:
            chains = ["ethereum", "bsc", "polygon"]
        
        chains_info = [self.get_chain_info(c) for c in chains]
        
        prompt = f"""Analyze this smart contract for security vulnerabilities across multiple chains: {contract_code}

Chains to analyze:
{json.dumps(chains_info, indent=2)}

Chain-specific considerations:
{self._format_chain_considerations(chains)}

Output format:
{{
    "ethereum_vulnerabilities": [...],
    "bsc_vulnerabilities": [...],
    "polygon_vulnerabilities": [...],
    "cross_chain_risks": [...],
    "recommendations": [...]
}}"""
        return prompt
    
    def _format_chain_considerations(self, chains: List[str]) -> str:
        lines = []
        for chain in chains:
            vulns = CHAIN_SPECIFIC_VULNS.get(chain, {})
            lines.append(f"\n{chain.upper()}:")
            for key, value in vulns.items():
                lines.append(f"  - {key}: {value}")
        return "\n".join(lines)
    
    def build_bridge_prompt(self, contract_code: str) -> str:
        return f"""Analyze this contract as a cross-chain bridge:

{contract_code}

Bridge-specific checks:
1. Message verification - Ensure messages are validated with signatures
2. Access control - Only authorized relayers can call
3. Fee accounting - Cross-chain gas estimation
4. Replay protection - Nonce management
5. Destination validation - Target chain verification

Output format:
{{
    "vulnerabilities": [...],
    "risk_score": 0.0-10.0,
    "cross_chain_risks": {...}
}}"""
    
    def build_gas_optimization_prompt(self, contract_code: str, chain: str = "ethereum") -> str:
        chain_info = self.get_chain_info(chain)
        gas_limit = chain_info.get("gas_limit", 3000000)
        
        return f"""Analyze for gas optimizations:

{contract_code}

Chain: {chain}
Gas limit: {gas_limit}

Check for:
1. Storage packing opportunities
2. Unnecessary SLOADs
3. Loop optimizations
4. Library usage
5. Event emission

Output:
{{
    "optimizations": [
        {{"type": "...", "estimated_savings": "..."}}
    ]
}}"""


class CrossChainAnalyzer:
    """Analyze cross-chain vulnerabilities"""
    
    def __init__(self):
        self.chain_configs = CHAIN_CONFIGS
    
    def analyze_bridge_risks(self, contract_code: str) -> Dict[str, Any]:
        risks = {
            "message_verification": self._check_message_verification(contract_code),
            "access_control": self._check_bridge_access_control(contract_code),
            "relayer_centralization": self._check_relayer_risks(contract_code),
            "fee_manipulation": self._check_fee_manipulation(contract_code)
        }
        return risks
    
    def _check_message_verification(self, code: str) -> Dict[str, Any]:
        has_check = "verify" in code.lower() or "signature" in code.lower()
        return {
            "risk": "medium" if not has_check else "none",
            "description": "Check for message signature verification"
        }
    
    def _check_bridge_access_control(self, code: str) -> Dict[str, Any]:
        has_owner = "onlyowner" in code.lower() or "onlyrole" in code.lower()
        return {
            "risk": "high" if not has_owner else "low",
            "description": "Check bridge access control"
        }
    
    def _check_relayer_risks(self, code: str) -> Dict[str, Any]:
        relayers = len([l for l in code.split("\n") if "relayer" in l.lower()])
        return {
            "risk": "medium" if relayers < 2 else "low",
            "relayer_count": relayers
        }
    
    def _check_fee_manipulation(self, code: str) -> Dict[str, Any]:
        return {"risk": "low"}


class ChainSecurityChecker:
    """Chain-specific security checks"""
    
    def __init__(self):
        self.chain_vulns = CHAIN_SPECIFIC_VULNS
    
    def check_chain(self, chain: str, contract_code: str) -> List[Dict[str, Any]]:
        vulns = []
        chain_checks = self.chain_vulns.get(chain, {})
        
        for vuln_type, description in chain_checks.items():
            if self._detect_pattern(contract_code, vuln_type):
                vulns.append({
                    "type": vuln_type,
                    "description": description,
                    "chain": chain
                })
        
        return vulns
    
    def _detect_pattern(self, code: str, pattern: str) -> bool:
        patterns = {
            "unsafe_js_parse": ["parseInt", "Number("],
            "checkpoint_manipulation": ["checkpoint", "block.header"],
            "retryable_ticket": ["retryable", "ticket"],
            "l1_l2_differences": ["ovm", "l2state"],
            "bridge_operations": ["bridge", "l1token"]
        }
        search = patterns.get(pattern, [])
        return any(p.lower() in code.lower() for p in search)


class ChainPrompt:
    """Main chain prompt manager"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.builder = ChainPromptBuilder()
        self.cross_chain = CrossChainAnalyzer()
        self.checker = ChainSecurityChecker()
        logger.info("✅ Chain Prompt initialized")
    
    def get_supported_chains(self) -> List[str]:
        return list(CHAIN_CONFIGS.keys())
    
    def get_chain_info(self, chain: str) -> Dict[str, Any]:
        return self.builder.get_chain_info(chain)
    
    def build_audit_prompt(
        self,
        contract_code: str,
        chain: str = "ethereum",
        multi_chain: bool = False
    ) -> str:
        if multi_chain:
            return self.builder.build_multi_chain_prompt(contract_code)
        return self.builder.build_gas_optimization_prompt(contract_code, chain)
    
    def build_bridge_prompt(self, contract_code: str) -> str:
        return self.builder.build_bridge_prompt(contract_code)
    
    def analyze_cross_chain(self, contract_code: str) -> Dict[str, Any]:
        return self.cross_chain.analyze_bridge_risks(contract_code)
    
    def check_chain_security(self, chain: str, contract_code: str) -> List[Dict[str, Any]]:
        return self.checker.check_chain(chain, contract_code)