"""
Reconnaissance Package

Production-grade recon for Web3 smart contract security auditing.
Exports: ReconEngine, ReconResult, TechType

Author: Solidify Security Team
Version: 1.0.0
"""

import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Re-export from recon modules
try:
    from .tech_detection import TechDetector, TechType
    from .endpoint_discovery import EndpointDiscovery
    from .subdomain_enum import SubdomainEnumeration
    from .js_analysis import JSAnalyzer
    from .header_analysis import HeaderAnalyzer
    from .param_fuzzing import ParameterFuzzer
    from .target_profiling import TargetProfiler
    from .service_enum import ServiceEnumeration

    __all__ = [
        "TechDetector",
        "TechType",
        "EndpointDiscovery",
        "SubdomainEnumeration",
        "JSAnalyzer",
        "HeaderAnalyzer",
        "ParameterFuzzer",
        "TargetProfiler",
        "ServiceEnumeration",
    ]

except ImportError as e:
    logger.warning(f"Recon modules not fully available: {e}")
    __all__ = []

logger.info(f"✅ Recon package loaded: {len(__all__)} exports")
