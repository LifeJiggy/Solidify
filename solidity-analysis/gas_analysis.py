import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")

class GasAnalyzer:
    """Analyzes EVM bytecode and Solidity logic for gas optimization opportunities."""
    
    @staticmethod
    def analyze(contract_code: str) -> str:
        prompt = f"""
        You are an EVM Gas Optimization Expert. Analyze this Solidity contract for gas inefficiencies.
        Focus on:
        1. Storage vs Memory (e.g., caching state variables).
        2. Calldata vs Memory for external functions.
        3. Custom Errors instead of require strings.

        Return ONLY a JSON object:
        {{
            "optimization_score": "A/B/C/D/F",
            "optimizations": [
                {{
                    "title": "Optimization Name",
                    "description": "Why this saves gas",
                    "optimized_code_snippet": "The fixed Solidity code"
                }}
            ]
        }}

        Contract Code:
        {contract_code}
        """
        try:
            return model.generate_content(prompt).text
        except Exception as e:
            return f'{{"error": "{str(e)}"}}'