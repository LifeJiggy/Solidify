"""
Solidify Hunting Prompt
Bug bounty hunting prompts

Author: Peace Stephen (Tech Lead)
Description: Prompts for vulnerability hunting
"""

import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


HUNTING_CATEGORIES = {
    "defi": ["flash_loan", "oracle_manipulation", "yield_stripping", "collateral_squeeze"],
    "nft": ["mint_manipulation", "floor_price", "royalty_bypass", "metadata"],
    "bridge": ["message_relay", "asset_mint", "signature_replay", "validator_ collusion"],
    "governance": ["proposal_manipulation", "vote_buying", "timelock_bypass"],
    "oracle": ["data_manipulation", "feed_migration", " staleness"],
    "access": ["privilege_escalation", "role_confusion", "function_collision"]
}


HUNTING_PROMPTS = {
    "flash_loan": """Hunt for flash loan attack vectors:

1. Check for insufficient validation
2. Look for price manipulation
3. Find oracle usage
4. Map external calls
5. Identify economic assumptions""",
    
    "oracle": """Hunt for oracle manipulation:

1. Check oracle data sources
2. Look for TWAP usage
3. Find price threshold checks
4. Map AMM usage
5. Identify manipulation vectors""",
    
    "reentrancy": """Hunt for reentrancy:

1. Look for external calls before state changes
2. Check for missing reentrancy guards
3. Map callback patterns
4. Find callback functions
5. Identify affected functions""",
    
    "access_control": """Hunt for access control issues:

1. Check owner functions
2. Look for missing modifiers
3. Find public functions
4. Map role definitions
5. Identify permission escalation"""
}


@dataclass
class HuntTarget:
    protocol: str
    category: str
    contracts: List[str] = field(default_factory=list)


class HuntBuilder:
    """Build hunting prompts"""
    
    def __init__(self):
        self.categories = HUNTING_CATEGORIES
    
    def build_defi_hunt(self, protocol: str, code: str) -> str:
        return f"""Hunt for DeFi vulnerabilities in {protocol}:

{code}

Focus on:
1. Flash loan vectors
2. Oracle manipulation
3. Yield manipulation
4. Liquidation raids
5. Price oracle edges"""
    
    def build_nft_hunt(self, code: str) -> str:
        return f"""Hunt for NFT vulnerabilities:

{code}

Focus on:
1. Minting logic
2. Metadata manipulation
3. Royalty bypass
4. Transfer restrictions
5. Approval issues"""
    
    def build_bridge_hunt(self, code: str) -> str:
        return f"""Hunt for bridge vulnerabilities:

{code}

Focus on:
1. Message validation
2. Relayer permissions
3. Fee modeling
4. Destination safety
5. Signature replay"""


class HuntPrompt:
    """Main hunt prompt manager"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.builder = HuntBuilder()
        
        logger.info("✅ Hunt Prompt initialized")
    
    def build_defi_hunt(self, code: str) -> str:
        return self.builder.build_defi_hunt("protocol", code)
    
    def build_nft_hunt(self, code: str) -> str:
        return self.builder.build_nft_hunt(code)
    
    def build_bridge_hunt(self, code: str) -> str:
        return self.builder.build_bridge_hunt(code)