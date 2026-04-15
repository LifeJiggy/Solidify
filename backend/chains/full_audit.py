import json
import asyncio
from vuln_detection.reentrancy_detector import ReentrancyDetector
from vuln_detection.overflow_detector import OverflowDetector
from vuln_detection.access_control_detector import AccessControlDetector

class FullAuditChain:
    """Master chain that orchestrates all Priority 1 Vulnerability Detectors."""
    
    @staticmethod
    def run_all(contract_code: str) -> str:
        # We run the AI scans sequentially here, but you can upgrade this 
        # to asyncio.gather() later for parallel lightning-fast execution.
        
        try:
            # 1. Run Reentrancy
            reentrancy_raw = ReentrancyDetector.scan(contract_code)
            reentrancy_data = json.loads(reentrancy_raw) if not reentrancy_raw.startswith('{"error"') else {"error": reentrancy_raw}

            # 2. Run Overflow
            overflow_raw = OverflowDetector.scan(contract_code)
            overflow_data = json.loads(overflow_raw) if not overflow_raw.startswith('{"error"') else {"error": overflow_raw}

            # 3. Run Access Control
            access_raw = AccessControlDetector.scan(contract_code)
            access_data = json.loads(access_raw) if not access_raw.startswith('{"error"') else {"error": access_raw}

            # 4. Aggregate Master Report
            master_report = {
                "audit_status": "COMPLETED",
                "modules_run": 3,
                "findings": {
                    "reentrancy_module": reentrancy_data,
                    "overflow_module": overflow_data,
                    "access_control_module": access_data
                }
            }
            return json.dumps(master_report, indent=4)
            
        except Exception as e:
            return json.dumps({"audit_status": "FAILED", "error": str(e)})

# Quick test block
if __name__ == "__main__":
    test_contract = "function withdraw() public { msg.sender.call{value: address(this).balance}(''); }"
    print(FullAuditChain.run_all(test_contract))