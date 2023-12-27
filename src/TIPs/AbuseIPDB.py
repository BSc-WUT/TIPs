import requests
import os
from dotenv import load_dotenv

def calculate_reputation(results: dict) -> str:
    load_dotenv()
    threshold: float = os.getenv("IPDB_THRESHOLD") if os.getenv("IPDB_THRESHOLD") else 0.1
    confidence_score: int = results.get('data', {}).get('abuseConfidenceScore')
    print(confidence_score)
    if confidence_score is not None:
        count: float = 1 - confidence_score / 100
        if results.get('data', {}).get("isWhitelisted") == True or count < threshold:
            return "Benign"
        elif count < 2 * threshold:
            return "Suspicious"
        else:
            return "Malicious"
    else:
        return "Unknown"


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
        results: dict = {
            'results': response.json(),
            'value': calculate_reputation(response.json())
        }
        return results
    else:
        return {"results": "API key for AbuseIPDB was not found"}