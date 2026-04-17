"""
Solidify Vulnerability Detection Engine
Unified Orchestration Layer | Production Grade
Version: 2.1.0 | Build 2026.04.17
Copyright 2026 Solidify Security Inc.
"""

import asyncio
import logging
import hashlib
import time
import re
from enum import Enum
from typing import List, Dict, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
import threading
from queue import Queue
import warnings

from .reentrancy_detector import ReentrancyDetector
from .overflow_detector import OverflowDetector
from .access_control_detector import AccessControlDetector
from .unchecked_call_detector import UncheckedCallDetector
from .selfdestruct_detector import SelfDestructDetector
from .dos_detector import DoSDetector
from .front_run_detector import FrontRunDetector
from .timestamp_detector import TimestampDetector

logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(Enum):
    CRITICAL = 10
    HIGH = 7
    MEDIUM = 5
    LOW = 2
    INFO = 1


@dataclass
class ScanContext:
    contract_code: str
    contract_address: Optional[str] = None
    chain_id: int = 1
    compiler_version: Optional[str] = None
    evm_version: str = "london"
    metadata: Dict[str, Any] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    scan_id: str = field(init=False)

    def __post_init__(self):
        hash_input = (
            f"{self.contract_code}{self.contract_address}{self.start_time}".encode()
        )
        self.scan_id = hashlib.sha256(hash_input).hexdigest()[:16]


@dataclass
class Finding:
    vulnerability_id: str
    detector_type: str
    severity: SeverityLevel
    confidence: float
    line_number: Optional[int] = None
    column: Optional[int] = None
    function_name: Optional[str] = None
    description: str = ""
    recommendation: str = ""
    exploit_code: Optional[str] = None
    cve_references: List[str] = field(default_factory=list)
    contract_address: Optional[str] = None
    false_positive_probability: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            k: v.name if isinstance(v, Enum) else v for k, v in self.__dict__.items()
        }


@dataclass
class ScanResult:
    scan_id: str
    status: ScanStatus
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    execution_time_ms: int = 0
    detectors_executed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "status": self.status.name,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "execution_time_ms": self.execution_time_ms,
            "detectors_count": len(self.detectors_executed),
            "critical_findings": len(
                [f for f in self.findings if f.severity == SeverityLevel.CRITICAL]
            ),
            "high_findings": len(
                [f for f in self.findings if f.severity == SeverityLevel.HIGH]
            ),
        }


class BaseDetector(ABC):
    detector_type: str
    vulnerability_id: str
    severity: SeverityLevel
    description: str

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.timeout = self.config.get("timeout", 25)
        self.max_findings = self.config.get("max_findings", 80)
        self.patterns: List[re.Pattern] = []
        self._execution_count = 0
        self._error_count = 0

    @abstractmethod
    def detect(
        self, contract_code: str, context: Optional[ScanContext] = None
    ) -> List[Finding]:
        pass

    async def detect_async(
        self, contract_code: str, context: Optional[ScanContext] = None
    ) -> List[Finding]:
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as executor:
            return await loop.run_in_executor(
                executor, self.detect, contract_code, context
            )

    def get_info(self) -> Dict[str, Any]:
        return {
            "detector_type": self.detector_type,
            "severity": self.severity.name,
            "enabled": self.enabled,
            "execution_count": self._execution_count,
            "error_count": self._error_count,
        }


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = "closed"

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "open"

    def record_success(self):
        self.failure_count = 0
        self.state = "closed"

    def allow_execution(self) -> bool:
        if self.state == "closed":
            return True
        if time.time() - self.last_failure_time > self.recovery_timeout:
            self.state = "half_open"
            return True
        return False


class VulnerabilityDetector:
    DEFAULT_MAX_WORKERS = 4

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.max_workers = self.config.get("max_workers", self.DEFAULT_MAX_WORKERS)
        self.cache_scans = self.config.get("cache_scans", True)
        self._shutdown = False
        self.detectors: Dict[str, BaseDetector] = {}
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._init_detectors()
        self._result_cache: Dict[str, ScanResult] = {}
        self._active_scans: Set[str] = set()
        self._lock = threading.RLock()
        logger.info(
            f"Initialized with {len(self.detectors)} detectors | workers={self.max_workers}"
        )

    def _init_detectors(self):
        detector_classes = [
            ReentrancyDetector,
            OverflowDetector,
            AccessControlDetector,
            UncheckedCallDetector,
            SelfDestructDetector,
            DoSDetector,
            FrontRunDetector,
            TimestampDetector,
        ]
        for cls in detector_classes:
            cfg = self.config.get(cls.detector_type, {})
            detector = cls(cfg)
            self.detectors[detector.detector_type] = detector
            self.circuit_breakers[detector.detector_type] = CircuitBreaker()

    def scan(
        self,
        contract_code: str,
        detector_types: Optional[List[str]] = None,
        context: Optional[ScanContext] = None,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> ScanResult:
        if not contract_code or not isinstance(contract_code, str):
            raise ValueError("Contract code must be non-empty string")
        if context is None:
            context = ScanContext(contract_code=contract_code)
        scan_id = context.scan_id
        with self._lock:
            if self.cache_scans and scan_id in self._result_cache:
                return self._result_cache[scan_id]
            if scan_id in self._active_scans:
                raise RuntimeError(f"Scan {scan_id} already running")
            self._active_scans.add(scan_id)
        try:
            result = ScanResult(scan_id=scan_id, status=ScanStatus.RUNNING)
            detectors_to_run = (
                detector_types if detector_types else list(self.detectors.keys())
            )
            valid_detectors = [d for d in detectors_to_run if d in self.detectors]
            findings: List[Finding] = []
            completed = 0
            total = len(valid_detectors)
            if progress_callback:
                progress_callback(0.0, "Initializing")
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_map = {}
                for dt in valid_detectors:
                    if self._shutdown:
                        break
                    cb = self.circuit_breakers[dt]
                    if not cb.allow_execution():
                        result.warnings.append(
                            f"Detector {dt} skipped: circuit breaker open"
                        )
                        continue
                    future = executor.submit(
                        self._run_detector, self.detectors[dt], contract_code, context
                    )
                    future_map[future] = dt
                for future in future_map.keys():
                    dt = future_map[future]
                    try:
                        f = future.result(timeout=self.detectors[dt].timeout)
                        findings.extend(f)
                        result.detectors_executed.append(dt)
                        self.circuit_breakers[dt].record_success()
                    except Exception as e:
                        err = f"Detector {dt} failed: {str(e)}"
                        logger.error(err, exc_info=True)
                        result.errors.append(err)
                        self.circuit_breakers[dt].record_failure()
                    completed += 1
                    if progress_callback:
                        progress_callback(completed / total, f"Completed {dt}")
            result.findings = findings
            result.status = ScanStatus.COMPLETED
            result.execution_time_ms = int((time.time() - context.start_time) * 1000)
            if self.cache_scans:
                self._result_cache[scan_id] = result
            logger.info(
                f"Scan {scan_id} done | {len(findings)} findings | {result.execution_time_ms}ms"
            )
            return result
        finally:
            with self._lock:
                self._active_scans.discard(scan_id)

    def _run_detector(
        self, detector: BaseDetector, code: str, ctx: ScanContext
    ) -> List[Finding]:
        detector._execution_count += 1
        try:
            res = detector.detect(code, ctx)
            for f in res:
                f.contract_address = ctx.contract_address
            return res[: detector.max_findings]
        except Exception:
            detector._error_count += 1
            raise

    async def scan_async(self, *args, **kwargs) -> ScanResult:
        return await asyncio.to_thread(self.scan, *args, **kwargs)

    def get_detector_info(self) -> Dict[str, Dict[str, Any]]:
        return {n: d.get_info() for n, d in self.detectors.items()}

    def clear_cache(self):
        with self._lock:
            self._result_cache.clear()

    def shutdown(self):
        self._shutdown = True
        logger.info("Detector shutdown complete")

    def get_supported_types(self) -> List[str]:
        return list(self.detectors.keys())


__all__ = [
    "VulnerabilityDetector",
    "BaseDetector",
    "ScanContext",
    "ScanResult",
    "Finding",
    "SeverityLevel",
    "ScanStatus",
    "CircuitBreaker",
]
















































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































