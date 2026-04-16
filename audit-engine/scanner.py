"""
Smart Contract Scanner

Production-grade scanner for smart contract vulnerability detection and analysis.
Coordinates multiple detectors and aggregages findings.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib

logger = logging.getLogger(__name__)


class ScanPhase(Enum):
    PARSING = "parsing"
    DETECTION = "detection"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    COMPLETE = "complete"


class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanConfig:
    max_workers: int = 4
    timeout_seconds: int = 300
    enable_parallel: bool = True
    include_dependencies: bool = False
    strict_mode: bool = False
    confidence_threshold: float = 0.7


@dataclass
class ScanProgress:
    phase: ScanPhase
    progress_percent: float
    current_task: str
    findings_count: int = 0


@dataclass
class ScanResult:
    contract_name: str
    source_hash: str
    findings: List[Dict[str, Any]]
    scan_time_ms: int
    detectors_run: List[str]
    errors: List[str]
    metadata: Dict[str, Any]


class Scanner:
    DETECTOR_REGISTRY = {
        "reentrancy": "vuln_detection.reentrancy_detector.ReentrancyDetector",
        "overflow": "vuln_detection.overflow_detector.OverflowDetector",
        "access_control": "vuln_detection.access_control_detector.AccessControlDetector",
        "unchecked_call": "vuln_detection.unchecked_call_detector.UncheckedCallDetector",
        "self_destruct": "vuln_detection.selfdestruct_detector.SelfDestructDetector",
        "dos": "vuln_detection.dos_detector.DoSDetector",
        "front_running": "vuln_detection.front_run_detector.FrontRunDetector",
        "timestamp": "vuln_detection.timestamp_detector.TimestampDetector",
    }

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.detectors = {}
        self._initialize_detectors()

    def _initialize_detectors(self):
        for name, module_path in self.DETECTOR_REGISTRY.items():
            try:
                parts = module_path.split(".")
                module = __import__(".".join(parts[:-1]), fromlist=[parts[-1]])
                detector_class = getattr(module, parts[-1].replace("_", "").title() + "Detector")
                self.detectors[name] = detector_class()
            except (ImportError, AttributeError) as e:
                logger.debug(f"Detector {name} not available: {e}")

    def scan(
        self,
        source_code: str,
        contract_name: str = "Unknown",
    ) -> ScanResult:
        import time
        start_time = time.time()

        findings = []
        errors = []
        detectors_run = []

        try:
            parsed = self._parse_source(source_code)
            if not parsed:
                errors.append("Failed to parse source code")

            if self.config.enable_parallel:
                findings = self._scan_parallel(source_code, contract_name)
            else:
                findings = self._scan_sequential(source_code, contract_name)

            detectors_run = list(self.detectors.keys())

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            errors.append(str(e))

        scan_time_ms = int((time.time() - start_time) * 1000)

        return ScanResult(
            contract_name=contract_name,
            source_hash=hashlib.sha256(source_code.encode()).hexdigest(),
            findings=findings,
            scan_time_ms=scan_time_ms,
            detectors_run=detectors_run,
            errors=errors,
        )

    def _parse_source(self, source_code: str) -> Dict[str, Any]:
        contracts = re.findall(
            r"contract\s+(\w+)\s*(?:is\s+([^{]+))?",
            source_code
        )

        functions = re.findall(
            r"function\s+(\w+)\s*\(",
            source_code
        )

        return {
            "contracts": [c[0] for c in contracts],
            "functions": functions,
            "line_count": len(source_code.split("\n")),
        }

    def _scan_sequential(
        self,
        source_code: str,
        contract_name: str,
    ) -> List[Dict[str, Any]]:
        findings = []

        for name, detector in self.detectors.items():
            try:
                results = detector.detect(source_code, contract_name)
                for result in results:
                    if hasattr(result, "to_dict"):
                        findings.append(result.to_dict())
                    else:
                        findings.append(result)
            except Exception as e:
                logger.warning(f"Detector {name} failed: {e}")

        return findings

    def _scan_parallel(
        self,
        source_code: str,
        contract_name: str,
    ) -> List[Dict[str, Any]]:
        findings = []

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {}
            for name, detector in self.detectors.items():
                future = executor.submit(
                    detector.detect,
                    source_code,
                    contract_name
                )
                futures[future] = name

            for future in as_completed(futures):
                detector_name = futures[future]
                try:
                    results = future.result(timeout=60)
                    for result in results:
                        if hasattr(result, "to_dict"):
                            findings.append(result.to_dict())
                        else:
                            findings.append(result)
                except Exception as e:
                    logger.warning(f"Detector {detector_name} failed: {e}")

        return findings

    def scan_with_callback(
        self,
        source_code: str,
        contract_name: str,
        progress_callback: Optional[Callable] = None,
    ) -> ScanResult:
        if progress_callback:
            progress_callback(ScanProgress(
                phase=ScanPhase.PARSING,
                progress_percent=0.0,
                current_task="Parsing source code",
            ))

        result = self.scan(source_code, contract_name)

        if progress_callback:
            progress_callback(ScanProgress(
                phase=ScanPhase.COMPLETE,
                progress_percent=100.0,
                current_task="Scan complete",
                findings_count=len(result.findings),
            ))

        return result

    def apply_filters(
        self,
        findings: List[Dict[str, Any]],
        filter_config: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        if not filter_config:
            return findings

        filtered = findings

        if "severity" in filter_config:
            severity = filter_config["severity"]
            filtered = [f for f in filtered if f.get("severity") == severity]

        if "confidence_min" in filter_config:
            confidence = filter_config["confidence_min"]
            filtered = [f for f in filtered 
                if f.get("confidence", 0) >= confidence]

        if "category" in filter_config:
            category = filter_config["category"]
            filtered = [f for f in filtered if f.get("category") == category]

        return filtered

    def prioritize_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        priority_map = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }

        sorted_findings = sorted(
            findings,
            key=lambda f: (
                priority_map.get(f.get("severity", "INFO"), 4),
                -f.get("cvss_score", 0),
            )
        )

        return sorted_findings


def create_scanner(
    max_workers: int = 4,
    strict_mode: bool = False,
) -> Scanner:
    config = ScanConfig(
        max_workers=max_workers,
        strict_mode=strict_mode,
    )
    return Scanner(config=config)


__all__ = [
    "Scanner",
    "ScanPhase",
    "ScanStatus",
    "ScanConfig",
    "ScanProgress",
    "ScanResult",
    "create_scanner",
]