import requests
import os
from dotenv import load_dotenv

def calculate_reputation(results: dict) -> str:
    load_dotenv()
    threshold: int = os.getenv("AV_THRESHOLD") if os.getenv("AV_THRESHOLD") else 1
    false_positive: dict = results.get('false_positive', [])
    pulse_info_dict: dict = results.get('pulse_info', {})
    try:
        assert false_positive[0].get("assessment") == "accepted"
        return "Benign"
    except:
        if pulse_info_dict:
            count = int(pulse_info_dict.get('count', '0'))
            if count <= threshold:
                return "Benign"
            elif 0 < count < threshold:
                return "Suspicious"
            else:
                return "Malicious"
        else:
            return "Unknown"


def get_reputation(ip: str) -> dict:
    url: str = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers: dict = {}
    response: requests.Response = requests.get(url, headers=headers, verify=False)
    results: dict = {
        'results': response.json(),
        "value": calculate_reputation(response.json())
    }
    return results