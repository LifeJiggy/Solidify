"""
Vulnerability Injector

Production-grade vulnerability injection tool for security testing.
Injects known vulnerability patterns into Solidity contracts for testing.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import re
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    REENTRANCY = "reentrancy"
    OVERFLOW = "overflow"
    ACCESS_CONTROL = "access_control"
    UNCHECKED_CALL = "unchecked_call"
    FRONT_RUNNING = "front_running"
    TIMESTAMP_DEPENDENCE = "timestamp_dependence"


@dataclass
class InjectionResult:
    original_code: str
    injected_code: str
    vulnerability_type: VulnerabilityType
    location: Dict[str, Any]


class VulnerabilityInjector:
    def __init__(self):
        self.injections = []

    def inject(self, source_code: str, vuln_type: VulnerabilityType) -> InjectionResult:
        if vuln_type == VulnerabilityType.REENTRANCY:
            return self._inject_reentrancy(source_code)
        elif vuln_type == VulnerabilityType.OVERFLOW:
            return self._inject_overflow(source_code)
        elif vuln_type == VulnerabilityType.ACCESS_CONTROL:
            return self._inject_access_control(source_code)
        elif vuln_type == VulnerabilityType.UNCHECKED_CALL:
            return self._inject_unchecked_call(source_code)
        elif vuln_type == VulnerabilityType.FRONT_RUNNING:
            return self._inject_front_running(source_code)
        elif vuln_type == VulnerabilityType.TIMESTAMP_DEPENDENCE:
            return self._inject_timestamp(source_code)

        return InjectionResult(source_code, source_code, vuln_type, {})

    def _inject_reentrancy(self, source_code: str) -> InjectionResult:
        vulnerable_code = """
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        
        (bool success, ) = msg.sender.call{value: balance}("");
        
        balances[msg.sender] = 0;
    }
"""
        return InjectionResult(
            original_code=source_code,
            injected_code=source_code + vulnerable_code,
            vulnerability_type=VulnerabilityType.REENTRANCY,
            location={"function": "withdraw"},
        )

    def _inject_overflow(self, source_code: str) -> InjectionResult:
        vulnerable_code = """
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }
"""
        return InjectionResult(
            original_code=source_code,
            injected_code=source_code + vulnerable_code,
            vulnerability_type=VulnerabilityType.OVERFLOW,
            location={"function": "add"},
        )

    def _inject_access_control(self, source_code: str) -> InjectionResult:
        vulnerable_code = """
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
"""
        return InjectionResult(
            original_code=source_code,
            injected_code=source_code + vulnerable_code,
            vulnerability_type=VulnerabilityType.ACCESS_CONTROL,
            location={"function": "mint"},
        )

    def _inject_unchecked_call(self, source_code: str) -> InjectionResult:
        vulnerable_code = """
    function transfer(address to, uint256 amount) public {
        to.call{value: amount}("");
    }
"""
        return InjectionResult(
            original_code=source_code,
            injected_code=source_code + vulnerable_code,
            vulnerability_type=VulnerabilityType.UNCHECKED_CALL,
            location={"function": "transfer"},
        )

    def _inject_front_running(self, source_code: str) -> InjectionResult:
        vulnerable_code = """
    function setPrice(uint256 newPrice) public {
        require(msg.sender == owner);
        price = newPrice;
    }
"""
        return InjectionResult(
            original_code=source_code,
            injected_code=source_code + vulnerable_code,
            vulnerability_type=VulnerabilityType.FRONT_RUNNING,
            location={"function": "setPrice"},
        )

    def _inject_timestamp(self, source_code: str) -> InjectionResult:
        vulnerable_code = """
    function reveal() public {
        require(block.timestamp > revealTime);
        // Reveal logic
    }
"""
        return InjectionResult(
            original_code=source_code,
            injected_code=source_code + vulnerable_code,
            vulnerability_type=VulnerabilityType.TIMESTAMP_DEPENDENCE,
            location={"function": "reveal"},
        )


def inject_vulnerability(source_code: str, vuln_type: VulnerabilityType) -> InjectionResult:
    injector = VulnerabilityInjector()
    return injector.inject(source_code, vuln_type)


__all__ = ["VulnerabilityInjector", "VulnerabilityType", "InjectionResult", "inject_vulnerability"]