import requests

def get_reputation(ip: str) -> dict:
    url: str = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers: dict = {}
    response: requests.Response = requests.get(url, headers=headers, verify=False)
    return response.json()