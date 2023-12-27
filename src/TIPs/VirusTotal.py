import requests
import os
from dotenv import load_dotenv


def calculate_reputation(results: dict) -> str:
    load_dotenv()
    threshold: float = os.getenv("VT_THRESHOLD") if os.getenv("VT_THRESHOLD") else 0.1
    total_votes: dict = results.get('data', {}).get('attributes', {}).get('total_votes', {})
    if total_votes.get('harmless') and total_votes.get('malicious'):
        total_malicious_ratio: float = int(total_votes.get('malicious')) / (int(total_votes.get('harmless')) + int(total_votes.get('malicious')))
        if total_malicious_ratio <= threshold:
            return "Benign"
        elif total_malicious_ratio < threshold * 2:
            return "Suspicious"
        else:
            return "Malicious"
    else:
        return "Unknown"
    

def get_reputation(ip: str) -> dict:
    load_dotenv()
    api_key: str = os.getenv('VT_API_KEY')
    if api_key:
        url: str = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers: dict = {
            'X-Apikey': api_key
        }
        response: requests.Response = requests.get(url, headers=headers, verify=False)
        results: dict = {
            'results': response.json(),
            'value': calculate_reputation(response.json())
        }
        return results
    else:
        return {"results": "API key for VirusTotal was not found", "value": "Unknown"}