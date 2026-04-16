"""
Taint Analysis

Production-grade taint tracking for Solidity smart contracts.
Identifies untrusted input sources and sinks with potential security risks.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TaintSource(Enum):
    MSG_SENDER = "msg.sender"
    MSG_VALUE = "msg.value"
    MSG_DATA = "msg.data"
    MSG_SIG = "msg.sig"
    TX_ORIGIN = "tx.origin"
    BLOCK_TIMESTAMP = "block.timestamp"
    BLOCK_NUMBER = "block.number"
    BLOCK_DIFFICULTY = "block.difficulty"
    BLOCK_COINBASE = "block.coinbase"
    CALLDATA = "calldata"
    EXTERNAL_CALL = "external_call"
    ORACLE = "oracle"
    RANDOM = "random"


class TaintSink(Enum):
    CALL = "call"
    DELEGATECALL = "delegatecall"
    STATICCALL = "staticcall"
    EXTERNAL_WRITE = "external_write"
    STORAGE_WRITE = "storage_write"
    TRANSFER = "transfer"
    SELFDESTRUCT = "selfdestruct"
    LOG = "log"
    AUTHORIZATION = "authorization"
    ARITHMETIC = "arithmetic"


@dataclass
class TaintedVariable:
    name: str
    source: TaintSource
    introduced_at: int
    sinks: List[str] = field(default_factory=list)
    is_sanitized: bool = False


@dataclass
class TaintAnalysis:
    tainted_vars: Dict[str, TaintedVariable] = field(default_factory=dict)
    sources: Dict[int, List[TaintSource]] = field(default_factory=dict)
    sinks: Dict[int, List[TaintSink]] = field(default_factory=dict)
    flows: List[Dict[str, Any]] = field(default_factory=list)


class TaintAnalyzer:
    UNTRUSTED_INPUTS = {
        "msg.sender",
        "msg.value",
        "msg.data",
        "msg.sig",
        "tx.origin",
        "block.timestamp",
        "block.number",
        "block.difficulty",
    }

    SINK_PATTERNS = {
        TaintSink.CALL: [
            r"\.(call|send|transfer|delegateCall|callStatic)\s*\(",
        ],
        TaintSink.STORAGE_WRITE: [
            r"(\w+)\s*=\s*[^;]+;(?:\s*(?:\w+)\s*(?!=))",
        ],
        TaintSink.SELFDESTRUCT: [
            r"selfdestruct\s*\(",
            r"suicide\s*\(",
        ],
        TaintSink.LOG: [
            r"emit\s+\w+\s*\(",
        ],
        TaintSink.AUTHORIZATION: [
            r"require\s*\(\s*msg\.sender\s*[!=]=",
            r"if\s*\(\s*msg\.sender\s*[!=]=",
        ],
    }

    SANITIZERS = {
        "require",
        "assert",
        "revert",
        "check",
        "validate",
        "verify",
    }

    def __init__(self, source_code: str = ""):
        self.source_code = source_code
        self.analysis: Optional[TaintAnalysis] = None

    def analyze(self) -> TaintAnalysis:
        analysis = TaintAnalysis()

        self._identify_sources(analysis)
        self._identify_sinks(analysis)
        self._track_taint(analysis)
        self._find_vulnerable_flows(analysis)

        self.analysis = analysis
        return analysis

    def _identify_sources(self, analysis: TaintAnalysis):
        source_patterns = {
            TaintSource.MSG_SENDER: r"\bmsg\.sender\b",
            TaintSource.MSG_VALUE: r"\bmsg\.value\b",
            TaintSource.MSG_DATA: r"\bmsg\.data\b",
            TaintSource.MSG_SIG: r"\bmsg\.sig\b",
            TaintSource.TX_ORIGIN: r"\btx\.origin\b",
            TaintSource.BLOCK_TIMESTAMP: r"\bblock\.timestamp\b",
            TaintSource.BLOCK_NUMBER: r"\bblock\.number\b",
            TaintSource.BLOCK_DIFFICULTY: r"\bblock\.difficulty\b",
        }

        for source_type, pattern in source_patterns.items():
            for match in re.finditer(pattern, self.source_code):
                line = self.source_code[:match.start()].count("\n") + 1

                if line not in analysis.sources:
                    analysis.sources[line] = []

                if source_type not in analysis.sources[line]:
                    analysis.sources[line].append(source_type)

    def _identify_sinks(self, analysis: TaintAnalysis):
        for sink_type, patterns in self.SINK_PATTERNS.items():
            for pattern in patterns:
                for match in re.finditer(pattern, self.source_code):
                    line = self.source_code[:match.start()].count("\n") + 1

                    if line not in analysis.sinks:
                        analysis.sinks[line] = []

                    if sink_type not in analysis.sinks[line]:
                        analysis.sinks[line].append(sink_type)

    def _track_taint(self, analysis: TaintAnalysis):
        for line, sources in analysis.sources.items():
            for source in sources:
                var_name = self._get_source_variable(source)
                if var_name:
                    analysis.tainted_vars[var_name] = TaintedVariable(
                        name=var_name,
                        source=source,
                        introduced_at=line,
                    )

        for line, sinks in analysis.sinks.items():
            for sink in sinks:
                for var_name, tainted_var in analysis.tainted_vars.items():
                    if line > tainted_var.introduced_at:
                        if var_name not in tainted_var.sinks:
                            tainted_var.sinks.append(sink.value)

    def _find_vulnerable_flows(self, analysis: TaintAnalysis):
        for var_name, tainted_var in analysis.tainted_vars.items():
            if tainted_var.sinks and not tainted_var.is_sanitized:
                flow = {
                    "source": tainted_var.source.value,
                    "sink": tainted_var.sinks,
                    "introduced_at": tainted_var.introduced_at,
                    "severity": self._determine_severity(tainted_var.sinks),
                }
                analysis.flows.append(flow)

    def _get_source_variable(self, source: TaintSource) -> str:
        source_map = {
            TaintSource.MSG_SENDER: "msg.sender",
            TaintSource.MSG_VALUE: "msg.value",
            TaintSource.MSG_DATA: "msg.data",
            TaintSource.TX_ORIGIN: "tx.origin",
            TaintSource.BLOCK_TIMESTAMP: "block.timestamp",
            TaintSource.BLOCK_NUMBER: "block.number",
        }
        return source_map.get(source, "")

    def _determine_severity(self, sinks: List[str]) -> str:
        high_risk = {TaintSink.CALL.value, TaintSink.SELFDESTRUCT.value}
        medium_risk = {TaintSink.STORAGE_WRITE.value, TaintSink.AUTHORIZATION.value}

        if any(sink in high_risk for sink in sinks):
            return "HIGH"
        if any(sink in medium_risk for sink in sinks):
            return "MEDIUM"

        return "LOW"

    def find_taint_sources(self) -> Dict[str, TaintedVariable]:
        if not self.analysis:
            return {}
        return self.analysis.tainted_vars

    def find_flows(self) -> List[Dict[str, Any]]:
        if not self.analysis:
            return []
        return self.analysis.flows

    def identify_sanitizers(self) -> List[Dict[str, Any]]:
        sanitizers = []

        for match in re.finditer(r"require\s*\(\s*([^,]+),\s*([^)]+)\)", self.source_code):
            line = self.source_code[:match.start()].count("\n") + 1
            condition = match.group(1)
            error = match.group(2)

            sanitizers.append({
                "type": "require",
                "line": line,
                "condition": condition.strip(),
                "error": error.strip(),
            })

        return sanitizers

    def check_authorization_bypass(self) -> List[Dict[str, Any]]:
        issues = []

        auth_patterns = [
            (r"require\s*\(\s*msg\.sender\s*==\s*(\w+)\)", "missing owner check"),
            (r"if\s*\(\s*msg\.sender\s*!=\s*owner", "incomplete owner check"),
        ]

        for pattern, issue_type in auth_patterns:
            for match in re.finditer(pattern, self.source_code):
                line = self.source_code[:match.start()].count("\n") + 1
                issues.append({
                    "type": "authorization",
                    "issue": issue_type,
                    "line": line,
                })

        return issues

    def get_security_report(self) -> Dict[str, Any]:
        if not self.analysis:
            return {}

        flows = self.analysis.flows
        high_severity = [f for f in flows if f.get("severity") == "HIGH"]
        medium_severity = [f for f in flows if f.get("severity") == "MEDIUM"]

        return {
            "total_tainted_flows": len(flows),
            "high_severity": len(high_severity),
            "medium_severity": len(medium_severity),
            "flows": flows,
        }


def analyze_taint(source_code: str) -> TaintAnalysis:
    analyzer = TaintAnalyzer(source_code)
    return analyzer.analyze()


__all__ = [
    "TaintAnalyzer",
    "TaintSource",
    "TaintSink",
    "TaintedVariable",
    "TaintAnalysis",
    "analyze_taint",
]