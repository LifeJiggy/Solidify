import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")

class AccessControlDetector:
    """Specialized AI scanner for CWE-284: Improper Access Control."""
    
    @staticmethod
    def scan(contract_code: str) -> str:
        prompt = f"""
        You are an elite Smart Contract Security Auditor. 
        Analyze the following Solidity code for Access Control vulnerabilities (CWE-284).
        Look for sensitive functions (like minting, burning, withdrawing, or transferring ownership) that are missing 'onlyOwner' or equivalent role-based modifiers.

        Return ONLY a JSON object:
        {{
            "vulnerability": "Improper Access Control",
            "detected": true/false,
            "severity": "Critical/High/None",
            "lines": [line_numbers],
            "description": "Explanation of who can maliciously call this",
            "fix": "Code snippet showing the required modifier"
        }}

        Contract Code:
        {contract_code}
        """
        try:
            return model.generate_content(prompt).text
        except Exception as e:
            return f'{{"error": "{str(e)}"}}'