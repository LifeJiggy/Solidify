import os
import requests
from dotenv import load_dotenv

load_dotenv()

class EtherscanClient:
    """Fetches verified Smart Contract source code directly from Mainnet using Etherscan V2."""
    
    def __init__(self):
        self.api_key = os.getenv("ETHERSCAN_API_KEY")
        self.base_url = "https://api.etherscan.io/v2/api"

    def fetch_contract(self, chain_id: int, address: str) -> str:
        params = {
            "chainid": chain_id,
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self.api_key
        }
        
        try:
            response = requests.get(self.base_url, params=params)
            data = response.json()
            
            if data["status"] == "1" and data["message"] == "OK":
                return data["result"][0]["SourceCode"]
            else:
                return f"Error: {data.get('result', 'Unknown Etherscan error')}"
        except Exception as e:
            return f"Error fetching from Etherscan: {str(e)}"