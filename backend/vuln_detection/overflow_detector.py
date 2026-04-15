import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")

class OverflowDetector:
    """Specialized AI scanner for CWE-190: Integer Overflow or Wraparound."""
    
    @staticmethod
    def scan(contract_code: str) -> str:
        prompt = f"""
        You are an elite Smart Contract Security Auditor. 
        Analyze the following Solidity code for Integer Overflow/Underflow vulnerabilities (CWE-190).
        CRITICAL: Check the pragma version. If it is ^0.8.0 or higher, math is safe by default unless 'unchecked' blocks are used. If it is <0.8.0, look for missing SafeMath.

        Return ONLY a JSON object:
        {{
            "vulnerability": "Integer Overflow/Underflow",
            "detected": true/false,
            "severity": "High/Medium/Low/None",
            "lines": [line_numbers],
            "description": "Explanation of the risk",
            "fix": "Code snippet showing SafeMath or pragma update"
        }}

        Contract Code:
        {contract_code}
        """
        try:
            return model.generate_content(prompt).text
        except Exception as e:
            return f'{{"error": "{str(e)}"}}'