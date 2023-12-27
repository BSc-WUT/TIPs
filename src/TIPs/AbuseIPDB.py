import requests
import os
from dotenv import load_dotenv

def get_reputation(ip: str) -> dict:
    load_dotenv()
    api_key: str = os.getenv('IPDB_API_KEY')
    if api_key:
        url: str = f"https://api.abuseipdb.com/api/v2/check"
        headers: dict = {
            "Accept": "application/json",
            "Key": api_key
        }
        params: dict = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        response: requests.Response = requests.get(url, headers=headers, params=params, verify=False)
        return response.json()
    else:
        return {"results": "API key for AbuseIPDB was not found"}