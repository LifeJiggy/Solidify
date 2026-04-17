"""Vulnerability Detection - Unified detector interface"""

from typing import List, Dict, Any, Optional
from vuln_detection.reentrancy_detector import ReentrancyDetector
from vuln_detection.overflow_detector import OverflowDetector
from vuln_detection.access_control_detector import AccessControlDetector
from vuln_detection.unchecked_call_detector import UncheckedCallDetector
from vuln_detection.selfdestruct_detector import SelfDestructDetector
from vuln_detection.dos_detector import DoSDetector
from vuln_detection.front_run_detector import FrontRunDetector
from vuln_detection.timestamp_detector import TimestampDetector


class VulnerabilityDetector:
    """Unified vulnerability detector"""

    def __init__(self):
        self.detectors = {
            "reentrancy": ReentrancyDetector(),
            "overflow": OverflowDetector(),
            "access_control": AccessControlDetector(),
            "unchecked_call": UncheckedCallDetector(),
            "self_destruct": SelfDestructDetector(),
            "dos": DoSDetector(),
            "front_running": FrontRunDetector(),
            "timestamp": TimestampDetector(),
        }

    def scan(
        self, contract_code: str, detector_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Scan contract code for vulnerabilities"""
        findings = []

        detectors_to_run = (
            detector_types if detector_types else list(self.detectors.keys())
        )

        for detector_type in detectors_to_run:
            if detector_type in self.detectors:
                try:
                    detector = self.detectors[detector_type]
                    result = detector.detect(contract_code)
                    if result:
                        if isinstance(result, list):
                            findings.extend(result)
                        else:
                            findings.append(result)
                except Exception as e:
                    pass

        return findings

    def get_supported_types(self) -> List[str]:
        """Get list of supported vulnerability types"""
        return list(self.detectors.keys())


__all__ = ["VulnerabilityDetector"]
