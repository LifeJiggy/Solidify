"""
HTTP Probe and Network Testing Module

This module provides HTTP probing capabilities for testing smart contract RPC endpoints,
blockchain nodes, and web interfaces.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import socket
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
import logging
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HTTPMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


class ResponseStatus(Enum):
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    INVALID = "invalid"


@dataclass
class HTTPProbeResult:
    url: str
    method: HTTPMethod
    status_code: int
    response_status: ResponseStatus
    response_time: float
    headers: Dict[str, str]
    content: str
    error_message: Optional[str] = None
    
    def is_successful(self) -> bool:
        return self.response_status == ResponseStatus.SUCCESS and 200 <= self.status_code < 300
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'url': self.url,
            'method': self.method.value,
            'status_code': self.status_code,
            'response_status': self.response_status.value,
            'response_time': self.response_time,
            'headers': self.headers,
            'content': self.content[:500],
            'error_message': self.error_message
        }


class RPCEndpointTester:
    def __init__(self):
        self.endpoints: Dict[str, List[str]] = defaultdict(list)
        self.results: List[HTTPProbeResult] = []
    
    def add_endpoint(self, chain_id: str, url: str):
        self.endpoints[chain_id].append(url)
    
    def test_endpoint(self, url: str, timeout: int = 30) -> HTTPProbeResult:
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        }
        
        start_time = time.time()
        
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req, timeout=timeout) as response:
                response_time = time.time() - start_time
                content = response.read().decode('utf-8')
                headers = dict(response.headers)
                
                return HTTPProbeResult(
                    url=url,
                    method=HTTPMethod.POST,
                    status_code=response.status,
                    response_status=ResponseStatus.SUCCESS,
                    response_time=response_time,
                    headers=headers,
                    content=content
                )
        
        except urllib.error.HTTPError as e:
            return HTTPProbeResult(
                url=url,
                method=HTTPMethod.POST,
                status_code=e.code,
                response_status=ResponseStatus.ERROR,
                response_time=time.time() - start_time,
                headers={},
                content="",
                error_message=str(e)
            )
        
        except Exception as e:
            return HTTPProbeResult(
                url=url,
                method=HTTPMethod.POST,
                status_code=0,
                response_status=ResponseStatus.ERROR,
                response_time=time.time() - start_time,
                headers={},
                content="",
                error_message=str(e)
            )
    
    def test_chain(self, chain_id: str) -> Dict[str, Any]:
        results = {}
        
        for endpoint in self.endpoints.get(chain_id, []):
            result = self.test_endpoint(endpoint)
            results[endpoint] = result.to_dict()
        
        return results
    
    def test_all_chains(self) -> Dict[str, Any]:
        return {chain_id: self.test_chain(chain_id) for chain_id in self.endpoints.keys()}


class WebInterfaceTester:
    def __init__(self):
        self.targets: List[str] = []
    
    def add_target(self, url: str):
        self.targets.append(url)
    
    def test_website(self, url: str, timeout: int = 30) -> HTTPProbeResult:
        start_time = time.time()
        
        try:
            req = urllib.request.Request(url)
            
            with urllib.request.urlopen(req, timeout=timeout) as response:
                response_time = time.time() - start_time
                content = response.read().decode('utf-8')
                headers = dict(response.headers)
                
                return HTTPProbeResult(
                    url=url,
                    method=HTTPMethod.GET,
                    status_code=response.status,
                    response_status=ResponseStatus.SUCCESS,
                    response_time=response_time,
                    headers=headers,
                    content=content[:1000]
                )
        
        except Exception as e:
            return HTTPProbeResult(
                url=url,
                method=HTTPMethod.GET,
                status_code=0,
                response_status=ResponseStatus.ERROR,
                response_time=time.time() - start_time,
                headers={},
                content="",
                error_message=str(e)
            )
    
    def scan_frontend_endpoints(self, base_url: str) -> List[HTTPProbeResult]:
        endpoints = [
            "",
            "/api",
            "/api/v1",
            "/health",
            "/status",
            "/docs",
            "/swagger",
            "/graphql"
        ]
        
        results = []
        
        for endpoint in endpoints:
            url = base_url.rstrip('/') + '/' + endpoint.lstrip('/')
            result = self.test_website(url)
            results.append(result)
        
        return results


class PortScanner:
    def __init__(self):
        self.open_ports: List[int] = []
    
    def scan_port(self, host: str, port: int, timeout: int = 5) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_port_range(self, host: str, start_port: int, end_port: int) -> List[int]:
        open_ports = []
        
        for port in range(start_port, end_port + 1):
            if self.scan_port(host, port):
                open_ports.append(port)
            else:
                pass
        
        return open_ports
    
    def scan_common_ports(self, host: str) -> Dict[str, int]:
        common_services = {
            'http': 80,
            'https': 443,
            'ws': 8080,
            'wss': 8443,
            'rpc': 8545,
            'websocket': 8546
        }
        
        results = {}
        
        for service, port in common_services.items():
            if self.scan_port(host, port):
                results[service] = port
        
        return results


def test_rpc_endpoint(url: str) -> Dict[str, Any]:
    tester = RPCEndpointTester()
    result = tester.test_endpoint(url)
    return result.to_dict()


def scan_website_endpoints(base_url: str) -> List[Dict[str, Any]]:
    tester = WebInterfaceTester()
    results = tester.scan_frontend_endpoints(base_url)
    return [r.to_dict() for r in results]


if __name__ == '__main__':
    result = test_rpc_endpoint("https://mainnet.infura.io/v3/YOUR_PROJECT_ID")
    print(json.dumps(result, indent=2))