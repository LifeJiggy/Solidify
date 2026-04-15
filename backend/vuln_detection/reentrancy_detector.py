import google.generativeai as genai
import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")

class ReentrancyDetector:
    """Specialized AI scanner for CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Reentrancy)."""
    
    @staticmethod
    def scan(contract_code: str) -> str:
        prompt = f"""
        You are an elite Smart Contract Security Auditor. 
        Analyze the following Solidity code STRICTLY for Reentrancy vulnerabilities (CWE-362).
        Look for instances where external calls (e.g., .call.value(), .transfer(), .send()) are made BEFORE state variables (like balances) are updated.

        Return ONLY a JSON object matching this exact schema:
        {{
            "vulnerability": "Reentrancy",
            "detected": true/false,
            "severity": "Critical, High, Medium, Low, or None",
            "lines": [line_numbers_where_it_occurs],
            "description": "Explanation of the attack vector",
            "fix": "Code snippet showing the Checks-Effects-Interactions pattern or reentrancy guard"
        }}

        Contract Code:
        {contract_code}
        """
        
        try:
            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    response_mime_type="application/json",
                )
            )
            return response.text
        except Exception as e:
            return f'{{"error": "{str(e)}"}}'

# Quick test if run directly
if __name__ == "__main__":
    test_code = """
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);
        (bool sent, ) = msg.sender.call{value: _amount}("");
        require(sent, "Failed to send Ether");
        balances[msg.sender] -= _amount;
    }
    """
    print(ReentrancyDetector.scan(test_code))