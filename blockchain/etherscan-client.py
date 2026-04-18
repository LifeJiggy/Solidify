"""
Etherscan API Client

Production-grade Etherscan API client for fetching verified contract source code,
ABI, bytecode, and transaction data from multiple EVM chains.

Supports:
- Ethereum Mainnet & Testnets
- BSC (BNB Smart Chain)
- Polygon
- Arbitrum
- Optimism
- Avalanche
- Base

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import os
import time
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

import requests
from dotenv import load_dotenv

from . import (
    ChainType,
    ChainConfig,
    get_chain_config,
    ContractSource,
    ContractMetadata,
    validate_address,
)

load_dotenv()

logger = logging.getLogger(__name__)


class EtherscanAPIError(Exception):
    pass


class RateLimitError(Exception):
    pass


class ContractNotVerifiedError(Exception):
    pass


class APIAction(Enum):
    GET_SOURCE_CODE = "getsourcecode"
    GET_ABI = "getabi"
    GET_BYTECODE = "getcontractcreation"
    GET_TX_LIST = "txlist"
    GET_TX_LIST_INTERNAL = "txlistinternal"
    GET_TOKEN_INFO = "tokeninfo"
    GET_BALANCE = "balance"
    GET_BLOCK_NUMBER = "eth_block_number"
    GET_BLOCK_BY_NUMBER = "eth_getBlockByNumber"


@dataclass
class EtherscanAPIResponse:
    status: str
    message: str
    result: Any


class EtherscanClient:
    MAX_RETRIES = 3
    RETRY_DELAY = 5
    RATE_LIMIT_DELAY = 1

    CHAIN_API_URLS = {
        ChainType.ETHEREUM_MAINNET: "https://api.etherscan.io/api",
        ChainType.ETHEREUM_GOERLI: "https://api-goerli.etherscan.io/api",
        ChainType.ETHEREUM_SEPOLIA: "https://api-sepolia.etherscan.io/api",
        ChainType.BSC_MAINNET: "https://api.bscscan.com/api",
        ChainType.BSC_TESTNET: "https://api-testnet.bscscan.com/api",
        ChainType.POLYGON_MAINNET: "https://api.polygonscan.com/api",
        ChainType.POLYGON_MUMBAI: "https://api-mumbai.polygonscan.com/api",
        ChainType.ARBITRUM_MAINNET: "https://api.arbiscan.io/api",
        ChainType.ARBITRUM_GOERLI: "https://api-goerli.arbiscan.io/api",
        ChainType.OPTIMISM_MAINNET: "https://api-optimistic.etherscan.io/api",
        ChainType.OPTIMISM_GOERLI: "https://api-goerli-optimistic.etherscan.io/api",
        ChainType.AVALANCHE_MAINNET: "https://api.snowtrace.io/api",
        ChainType.AVALANCHE_TESTNET: "https://api-testnet.snowtrace.io/api",
        ChainType.BASE_MAINNET: "https://api.basescan.org/api",
        ChainType.BASE_GOERLI: "https://api-goerli.basescan.org/api",
    }

    def __init__(
        self,
        chain: ChainType = ChainType.ETHEREUM_MAINNET,
        api_key: Optional[str] = None,
    ):
        self.chain = chain
        self.config = get_chain_config(chain)
        self.api_key = api_key or os.getenv("ETHERSCAN_API_KEY", "")
        self.base_url = self.CHAIN_API_URLS.get(chain)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Solidify/1.0"})

    def fetch_contract_source(
        self, address: str
    ) -> ContractSource:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        response = self._make_request(
            action=APIAction.GET_SOURCE_CODE.value,
            address=address,
        )

        if response.status != "1":
            if "Contract source code not verified" in str(response.result):
                raise ContractNotVerifiedError(
                    f"Contract at {address} is not verified on {self.config.name}"
                )
            raise EtherscanAPIError(f"API error: {response.result}")

        result = response.result[0]
        return self._parse_contract_source(result, address)

    def fetch_contract_abi(self, address: str) -> List[Dict[str, Any]]:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        response = self._make_request(
            action=APIAction.GET_ABI.value,
            address=address,
        )

        if response.status != "1":
            raise EtherscanAPIError(f"API error: {response.result}")

        try:
            abi = eval(response.result)
            return abi
        except Exception as e:
            logger.error(f"Failed to parse ABI: {e}")
            return []

    def fetch_contract_metadata(self, address: str) -> ContractMetadata:
        if not validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        source = self.fetch_contract_source(address)
        balance = self.get_contract_balance(address)
        tx_count = self.get_transaction_count(address)

        return ContractMetadata(
            address=address,
            chain=self.chain,
            abi=source.abi,
            bytecode=source.source_code,
            source_code=source.source_code,
            compiler_version=source.compiler_version,
            contract_name=source.contract_name,
            tx_count=tx_count,
            balance=balance,
        )

    def get_contract_balance(self, address: str) -> str:
        response = self._make_request(
            action=APIAction.GET_BALANCE.value,
            address=address,
            tag="latest",
        )

        if response.status == "1":
            return response.result

        return "0"

    def get_transaction_count(self, address: str) -> int:
        response = self._make_request(
            action=APIAction.GET_TX_LIST.value,
            address=address,
            startblock=0,
            endblock=99999999,
            page=1,
            offset=1,
            sort="desc",
        )

        if response.status == "1" and int(response.result) > 0:
            response = self._make_request(
                action=APIAction.GET_TX_LIST.value,
                address=address,
                startblock=0,
                endblock=99999999,
                page=1,
                offset=10000,
                sort="desc",
            )
            return len(response.result) if isinstance(response.result, list) else 0

        return 0

    def get_contract_creation_tx(
        self, address: str
    ) -> Optional[Dict[str, Any]]:
        response = self._make_request(
            action=APIAction.GET_BYTECODE.value,
            contractaddresses=address,
        )

        if response.status == "1" and response.result:
            return response.result[0]

        return None

    def get_contract_transactions(
        self,
        address: str,
        start_block: int = 0,
        end_block: int = 99999999,
        page: int = 1,
        offset: int = 100,
    ) -> List[Dict[str, Any]]:
        response = self._make_request(
            action=APIAction.GET_TX_LIST.value,
            address=address,
            startblock=start_block,
            endblock=end_block,
            page=page,
            offset=offset,
            sort="desc",
        )

        if response.status == "1":
            return response.result

        return []

    def get_internal_transactions(
        self,
        address: str,
        start_block: int = 0,
        end_block: int = 99999999,
    ) -> List[Dict[str, Any]]:
        response = self._make_request(
            action=APIAction.GET_TX_LIST_INTERNAL.value,
            address=address,
            startblock=start_block,
            endblock=end_block,
            sort="desc",
        )

        if response.status == "1":
            return response.result

        return []

    def _make_request(
        self,
        action: str,
        **kwargs
    ) -> EtherscanAPIResponse:
        params = {
            "module": "account" if "list" in action or "balance" in action else "contract",
            "action": action,
            "apikey": self.api_key,
            **kwargs,
        }

        for attempt in range(self.MAX_RETRIES):
            try:
                response = self.session.get(
                    self.base_url,
                    params=params,
                    timeout=30,
                )

                if response.status_code != 200:
                    raise EtherscanAPIError(
                        f"HTTP {response.status_code}: {response.text}"
                    )

                data = response.json()

                if data.get("status") == "0" and "rate limit" in data.get("message", "").lower():
                    wait_time = self.RATE_LIMIT_DELAY * (attempt + 1)
                    logger.warning(f"Rate limited, waiting {wait_time}s")
                    time.sleep(wait_time)
                    continue

                return EtherscanAPIResponse(
                    status=data.get("status", "0"),
                    message=data.get("message", ""),
                    result=data.get("result"),
                )

            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout, attempt {attempt + 1}/{self.MAX_RETRIES}")
                time.sleep(self.RETRY_DELAY)

            except requests.exceptions.RequestException as e:
                logger.error(f"Request error: {e}")
                raise EtherscanAPIError(str(e))

        raise EtherscanAPIError("Max retries exceeded")

    def _parse_contract_source(
        self, result: Dict[str, Any], address: str
    ) -> ContractSource:
        source_code = result.get("SourceCode", "")
        if not source_code:
            raise ContractNotVerifiedError(f"No source code available for {address}")

        if source_code.startswith("{{"):
            source_code = source_code.replace("{{", "{").replace("}}", "}")
            try:
                source_code = json.dumps(json.loads(source_code))
            except json.JSONDecodeError:
                pass

        abi = result.get("ABI", "[]")
        if isinstance(abi, str):
            try:
                abi = json.loads(abi)
            except json.JSONDecodeError:
                abi = []

        optimization_used = result.get("OptimizationUsed", "0") == "1"
        runs = result.get("Runs", "200")

        return ContractSource(
            contract_name=result.get("ContractName", "Unknown"),
            source_code=source_code,
            abi=json.dumps(abi) if isinstance(abi, list) else abi,
            compiler_version=result.get("CompilerVersion", ""),
            optimization_settings={
                "optimization_used": optimization_used,
                "runs": runs,
                "evm_version": result.get("EVMVersion", ""),
            },
            chain=self.chain,
            contract_address=address,
            verification_status=result.get("VerificationStatus", ""),
        )


def create_etherscan_client(
    chain: ChainType = ChainType.ETHEREUM_MAINNET,
    api_key: Optional[str] = None,
) -> EtherscanClient:
    return EtherscanClient(chain=chain, api_key=api_key)


__all__ = [
    "EtherscanClient",
    "EtherscanAPIError",
    "RateLimitError",
    "ContractNotVerifiedError",
    "APIAction",
    "EtherscanAPIResponse",
    "create_etherscan_client",
]
