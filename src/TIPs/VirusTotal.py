import requests
import os
from dotenv import load_dotenv

def get_reputation(ip: str) -> dict:
    load_dotenv()
    api_key: str = os.getenv('VT_API_KEY')
    if api_key:
        url: str = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        params: dict = {
            'apikey': api_key,
            "ip": ip
        }
        response: requests.Response = requests.get(url, params=params, verify=False)
        return response.json()
    else:
        return {"results": "API key for VirusTotal was not found"}