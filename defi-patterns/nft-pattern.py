"""
NFT (Non-Fungible Token) Security Analysis Module

This module provides comprehensive security analysis for NFT smart contracts
including ERC-721, ERC-1155, and custom NFT implementations.

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


class NFTStandard(Enum):
    ERC721 = "erc721"
    ERC721A = "erc721a"
    ERC721URI_STORAGE = "erc721_uri_storage"
    ERC1155 = "erc1155"
    ERC1155_URI_STORAGE = "erc1155_uri_storage"
    CUSTOM = "custom"


class TokenType(Enum):
    COLLECTIBLE = "collectible"
    GAME_ITEM = "game_item"
    REAL_ESTATE = "real_estate"
    IDENTITY = "identity"
    MEMBERSHIP = "membership"
    TICKET = "ticket"


class VulnerabilityType(Enum):
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    APPROVAL_BYPASS = "approval_bypass"
    FRONT_RUNNING = "front_running"
    METADATA_MANIPULATION = "metadata_manipulation"
    ROYALTY_BYPASS = "royalty_bypass"
    MINT_MANIPULATION = "mint_manipulation"
    BURN_BYPASS = "burn_bypass"


@dataclass
class NFTMetadata:
    token_id: int
    name: str
    description: str
    image_url: str
    attributes: Dict[str, Any]
    external_url: Optional[str] = None
    animation_url: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'token_id': self.token_id,
            'name': self.name,
            'description': self.description,
            'image_url': self.image_url,
            'attributes': self.attributes,
            'external_url': self.external_url,
            'animation_url': self.animation_url
        }


@dataclass
class NFTOwner:
    address: str
    token_ids: List[int]
    balance: int
    approved_tokens: Dict[int, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': self.address,
            'token_count': len(self.token_ids),
            'balance': self.balance,
            'approved_tokens': self.approved_tokens
        }


@dataclass
class NFTCollection:
    name: str
    symbol: str
    standard: NFTStandard
    total_supply: int
    max_supply: Optional[int] = None
    base_uri: Optional[str] = None
    royalty_fee: int = 0
    royalty_recipient: Optional[str] = None
    
    def get_minted_percentage(self) -> float:
        if not self.max_supply or self.max_supply == 0:
            return 0.0
        return (self.total_supply / self.max_supply) * 100
    
    def is_minted_out(self) -> bool:
        if not self.max_supply:
            return False
        return self.total_supply >= self.max_supply
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'symbol': self.symbol,
            'standard': self.standard.value,
            'total_supply': self.total_supply,
            'max_supply': self.max_supply,
            'base_uri': self.base_uri,
            'royalty_fee': self.royalty_fee,
            'royalty_recipient': self.royalty_recipient
        }


class NFTSecurityAnalyzer:
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.risk_score: float = 0.0
    
    def detect_nft_standard(self, source_code: str) -> NFTStandard:
        source_lower = source_code.lower()
        
        if 'erc721a' in source_lower:
            return NFTStandard.ERC721A
        
        if 'uri storage' in source_lower or 'seturi' in source_lower:
            if '1155' in source_lower:
                return NFTStandard.ERC1155_URI_STORAGE
            return NFTStandard.ERC721URI_STORAGE
        
        if '1155' in source_lower:
            return NFTStandard.ERC1155
        
        if '721' in source_lower:
            return NFTStandard.ERC721
        
        if 'nft' in source_lower or 'tokenid' in source_lower:
            return NFTStandard.CUSTOM
        
        return NFTStandard.CUSTOM
    
    def analyze_mint_mechanism(self, source_code: str) -> Dict[str, Any]:
        has_mint = bool(re.search(r'mint|_mint', source_code, re.IGNORECASE))
        has_batch_mint = bool(re.search(r'mintBatch|batch.*mint', source_code, re.IGNORECASE))
        has_max_supply = bool(re.search(r'maxSupply|max_supply|_maxSupply', source_code, re.IGNORECASE))
        has_counter = bool(re.search(r'counter|_tokenId|_nextTokenId', source_code, re.IGNORECASE))
        has_owner_mint = bool(re.search(r'onlyowner.*mint|owner.*mint', source_code, re.IGNORECASE))
        
        return {
            'has_mint': has_mint,
            'has_batch_mint': has_batch_mint,
            'has_max_supply': has_max_supply,
            'has_counter': has_counter,
            'has_owner_mint': has_owner_mint
        }
    
    def analyze_transfer_mechanism(self, source_code: str) -> Dict[str, Any]:
        has_safe_transfer = bool(re.search(r'safeTransfer|safeMint', source_code, re.IGNORECASE))
        has_transfer = bool(re.search(r'transferFrom|transfer\(', source_code, re.IGNORECASE))
        has_batch_transfer = bool(re.search(r'safeBatchTransfer|frombatch', source_code, re.IGNORECASE))
        has_approval = bool(re.search(r'setApprovalForAll|approve', source_code, re.IGNORECASE))
        
        return {
            'has_safe_transfer': has_safe_transfer,
            'has_transfer': has_transfer,
            'has_batch_transfer': has_batch_transfer,
            'has_approval': has_approval
        }
    
    def check_mint_vulnerabilities(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if not re.search(r'maxSupply|max_supply|_maxSupply', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.MINT_MANIPULATION.value,
                'severity': 'high',
                'description': 'No maximum supply limit - unlimited minting possible'
            })
        
        if not re.search(r'onlyowner|owner.*mint', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.ACCESS_CONTROL.value,
                'severity': 'high',
                'description': 'Mint function lacks access control'
            })
        
        if re.search(r'mint.*balance|balance.*mint', source_code, re.IGNORECASE):
            if not re.search(r'require|if.*>|\.call', source_code):
                vulnerabilities.append({
                    'type': VulnerabilityType.MINT_MANIPULATION.value,
                    'severity': 'medium',
                    'description': 'Mint may be manipulated based on balance'
                })
        
        if re.search(r'block\.timestamp.*mint|mint.*block\.timestamp', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.FRONT_RUNNING.value,
                'severity': 'medium',
                'description': 'Mint vulnerable to front-running'
            })
        
        return vulnerabilities
    
    def check_approval_vulnerabilities(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if not re.search(r'setApprovalForAll|approve', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.APPROVAL_BYPASS.value,
                'severity': 'medium',
                'description': 'Missing approval mechanisms'
            })
        
        if re.search(r'approve.*owner|owner.*approve', source_code, re.IGNORECASE):
            if not re.search(r'require|msg\.sender\s*==', source_code):
                vulnerabilities.append({
                    'type': VulnerabilityType.APPROVAL_BYPASS.value,
                    'severity': 'high',
                    'description': 'Approval can be set by anyone'
                })
        
        return vulnerabilities
    
    def check_metadata_vulnerabilities(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if re.search(r'setTokenURI|setBaseURI', source_code, re.IGNORECASE):
            if not re.search(r'onlyowner|owner|auth', source_code, re.IGNORECASE):
                vulnerabilities.append({
                    'type': VulnerabilityType.METADATA_MANIPULATION.value,
                    'severity': 'high',
                    'description': 'Token URI can be changed by anyone'
                })
        
        if re.search(r'hiddenMetadata|reveal', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.METADATA_MANIPULATION.value,
                'severity': 'medium',
                'description': 'Hidden metadata reveal pattern detected'
            })
        
        return vulnerabilities
    
    def check_royalty_vulnerabilities(self, source_code: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if re.search(r'royalty|setRoyalty', source_code, re.IGNORECASE):
            if not re.search(r'onlyowner|owner', source_code, re.IGNORECASE):
                vulnerabilities.append({
                    'type': VulnerabilityType.ROYALTY_BYPASS.value,
                    'severity': 'medium',
                    'description': 'Royalty can be changed by anyone'
                })
        
        if re.search(r'royalty.*=.*0|setRoyalty.*0', source_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': VulnerabilityType.ROYALTY_BYPASS.value,
                'severity': 'high',
                'description': 'Royalty can be set to zero'
            })
        
        return vulnerabilities
    
    def analyze_access_control(self, source_code: str) -> Dict[str, Any]:
        has_ownable = bool(re.search(r'Ownable|ownable|own', source_code, re.IGNORECASE))
        has_access_control = bool(re.search(r'AccessControl|roles|Roles', source_code, re.IGNORECASE))
        has_pausable = bool(re.search(r'Pausable|paused', source_code, re.IGNORECASE))
        has_timelock = bool(re.search(r'Timelock|timelock|Delay', source_code, re.IGNORECASE))
        
        return {
            'has_ownable': has_ownable,
            'has_access_control': has_access_control,
            'has_pausable': has_pausable,
            'has_timelock': has_timelock
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
        mint_vulns = self.check_mint_vulnerabilities(source_code)
        approval_vulns = self.check_approval_vulnerabilities(source_code)
        metadata_vulns = self.check_metadata_vulnerabilities(source_code)
        royalty_vulns = self.check_royalty_vulnerabilities(source_code)
        
        all_vulnerabilities = mint_vulns + approval_vulns + metadata_vulns + royalty_vulns
        self.calculate_risk_score(all_vulnerabilities)
        
        return {
            'nft_standard': self.detect_nft_standard(source_code).value,
            'mint_mechanism': self.analyze_mint_mechanism(source_code),
            'transfer_mechanism': self.analyze_transfer_mechanism(source_code),
            'access_control': self.analyze_access_control(source_code),
            'vulnerabilities': all_vulnerabilities,
            'risk_score': self.risk_score,
            'recommendations': self._generate_recommendations(all_vulnerabilities)
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        recommendations = []
        
        vuln_types = {v.get('type') for v in vulnerabilities}
        
        if VulnerabilityType.MINT_MANIPULATION.value in vuln_types:
            recommendations.append('Implement maximum supply limit')
            recommendations.append('Add access control to mint function')
        
        if VulnerabilityType.APPROVAL_BYPASS.value in vuln_types:
            recommendations.append('Review and secure approval mechanisms')
        
        if VulnerabilityType.METADATA_MANIPULATION.value in vuln_types:
            recommendations.append('Secure URI management with access control')
        
        if VulnerabilityType.ROYALTY_BYPASS.value in vuln_types:
            recommendations.append('Lock royalty at deployment or use timelock')
        
        return recommendations


class NFTMarketAnalyzer:
    def __init__(self):
        self.sales_history: List[Dict[str, Any]] = []
        self.floor_price: float = 0.0
    
    def add_sale(self, token_id: int, price: float, buyer: str, seller: str):
        self.sales_history.append({
            'token_id': token_id,
            'price': price,
            'buyer': buyer,
            'seller': seller,
            'timestamp': time.time()
        })
    
    def calculate_floor_price(self) -> float:
        if not self.sales_history:
            return 0.0
        
        prices = sorted([s['price'] for s in self.sales_history])
        self.floor_price = prices[0]
        return self.floor_price
    
    def calculate_average_price(self) -> float:
        if not self.sales_history:
            return 0.0
        
        total = sum(s['price'] for s in self.sales_history)
        return total / len(self.sales_history)
    
    def get_volume_24h(self) -> float:
        cutoff = time.time() - 86400
        recent_sales = [s for s in self.sales_history if s['timestamp'] > cutoff]
        
        return sum(s['price'] for s in recent_sales)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'floor_price': self.calculate_floor_price(),
            'average_price': self.calculate_average_price(),
            'volume_24h': self.get_volume_24h(),
            'total_sales': len(self.sales_history)
        }


class NFTGatingAnalyzer:
    def __init__(self):
        self.gating_contracts: Dict[str, List[str]] = {}
    
    def check_gating_pattern(self, source_code: str) -> Dict[str, Any]:
        has_token_gating = bool(re.search(r'token.*balance|balanceOf.*>=', source_code, re.IGNORECASE))
        has_nft_gating = bool(re.search(r'balanceOf.*>.*0|nft.*holder', source_code, re.IGNORECASE))
        has_whitelist = bool(re.search(r'whitelist|whitelist', source_code, re.IGNORECASE))
        has_merkle = bool(re.search(r'merkle|merkleProof', source_code, re.IGNORECASE))
        
        return {
            'has_token_gating': has_token_gating,
            'has_nft_gating': has_nft_gating,
            'has_whitelist': has_whitelist,
            'has_merkle': has_merkle
        }


def analyze_nft_contract(source_code: str) -> Dict[str, Any]:
    analyzer = NFTSecurityAnalyzer()
    return analyzer.generate_security_report(source_code)


if __name__ == '__main__':
    sample = """
    pragma solidity ^0.8.0;
    
    contract NFTContract is ERC721 {
        uint256 public maxSupply = 10000;
        uint256 public totalSupply;
        string public baseURI;
        mapping(uint256 => string) public tokenURIs;
        
        function mint(uint256 amount) external {
            require(totalSupply + amount <= maxSupply);
            require(msg.value >= amount * mintPrice);
            
            for (uint i = 0; i < amount; i++) {
                _mint(msg.sender, totalSupply++);
            }
        }
        
        function setTokenURI(uint256 tokenId, string memory _tokenURI) external {
            tokenURIs[tokenId] = _tokenURI;
        }
        
        function safeTransferFrom(address from, address to, uint256 tokenId) external {
            _transfer(from, to, tokenId);
        }
    }
    """
    
    result = analyze_nft_contract(sample)
    print(json.dumps(result, indent=2))