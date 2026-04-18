"""
Solidify Recon Prompt
Reconnaissance and information gathering prompts

Author: Peace Stephen (Tech Lead)
Description: Prompts for smart contract reconnaissance
"""

import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


RECON_TARGETS = {
    "contract_source": "Get contract source code from Etherscan",
    "abi": "Extract contract ABI",
    "transactions": "Fetch recent transactions",
    "internal_transfers": "Find internal transfers",
    "token_holders": "List token holders",
    "contract_creator": "Find contract creator",
    "deployment_tx": "Get deployment transaction",
    "events": "Extract emitted events"
}


RECON_PROMPTS = {
    "source": """Find and analyze the contract source code:

1. Check Etherscan for verified source
2. Look for proxy implementation
3. Check for upgradeable patterns
4. Identify libraries used""",
    
    "abis": """Extract contract ABI:

1. Get ABI from block explorer
2. Identify external functions
3. Map function signatures
4. Find upgradeable proxies""",
    
    "transactions": """Analyze recent transactions:

1. Fetch last 100 transactions
2. Identify large transfers
3. Map caller patterns
4. Find flash loan transactions""",
    
    "token_holders": """Analyze token holders:

1. Get top holders
2. Analyze distribution
3. Check for centralized wallets
4. Find burn addresses""",
    
    "deployer": """Find contract deployer:

1. Trace back deployment transaction
2. Identify deployer address
3. Check for CREATE2 factory
4. Map deployment patterns"""
}


@dataclass
class ReconTarget:
    target_type: str
    address: str
    chain: str
    gather_source: bool = False


class ReconBuilder:
    """Build reconnaissance prompts"""
    
    def __init__(self):
        self.targets = RECON_TARGETS
    
    def build_contract_lookup(self, address: str, chain: str = "ethereum") -> str:
        return f"""Look up this contract:

Address: {address}
Chain: {chain}

Steps:
1. Get contract source code from {chain}scan
2. Verify contract on explorer
3. Check for proxy implementation
4. Identify compiler version
5. Extract deployment info"""
    
    def build_analysis_prompt(
        self,
        address: str,
        analysis_type: str = "full"
    ) -> str:
        prompts = {
            "full": f"""Perform full reconnaissance on: {address}

1. Get source code and verify
2. Extract ABI
3. Analyze transactions
4. Find proxy patterns
5. Map dependencies""",
            "security": f"""Security-focused recon on: {address}

1. Check for proxy/upgradeable
2. Find ownership functions
3. Analyze access control
4. Check pausable functions
5. Map admin keys""",
            "financial": f"""Financial analysis on: {address}

1. Get token holders
2. Analyze transfers
3. Map large transactions
4. Calculate TVL
5. Find price impact"""
        }
        return prompts.get(analysis_type, prompts["full"])
    
    def build_dependency_map(self, contract_code: str) -> str:
        return f"""Map contract dependencies:

{contract_code}

Identify:
1. Imported libraries
2. Interface contracts
3. Parent contracts
4. External calls
5. Token standards used"""


class ReconPrompt:
    """Main recon prompt manager"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.builder = ReconBuilder()
        
        logger.info("✅ Recon Prompt initialized")
    
    def build_lookup(self, address: str, chain: str = "ethereum") -> str:
        return self.builder.build_contract_lookup(address, chain)
    
    def build_analysis(self, address: str, analysis: str = "full") -> str:
        return self.builder.build_analysis_prompt(address, analysis)
    
    def build_dependency(self, code: str) -> str:
        return self.builder.build_dependency_map(code)