from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

from .TIPs.AlienValut import get_reputation as av_reputation
from .TIPs.VirusTotal import get_reputation as vt_reputation
from .TIPs.AbuseIPDB import get_reputation as ipdb_reputation
from .models import IPReputation, IP
from .file_metadata import set_is_active_flag, get_is_active_flag



def get_env_vars() -> dict:
    load_dotenv()
    return {
        "DB_API_URL": f'http://{os.getenv("DB_API")}:{os.getenv("DB_API_PORT")}',
        "ML_API_URL": f'http://{os.getenv("ML_API")}:{os.getenv("ML_API_PORT")}',
        "API_PORT": os.getenv('API_PORT'),
    }


app = FastAPI()
ENV_VARS = get_env_vars()
INTEGRATIONS_PATH = 'src/TIPs'


origins = [
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def set_integration_flag(integration_name: str, flag_value: bool) -> dict:
    integration_path: str = os.path.join(INTEGRATIONS_PATH, f"{integration_name}.py")
    set_is_active_flag(integration_path, flag_value)
    return {
        'result': f'Sucessfully set is_active flag to {flag_value} for integration: {integration_name}'
    }


''' Threat Intelligence Platforms '''

@app.get('/tips/AlienVault/{ip}')
def get_av_reputation(ip: str) -> IPReputation:
    tip_result: dict = av_reputation(ip)
    reputation: IPReputation = {
        'service': "AlienVault",
        **tip_result
    }
    return reputation


@app.get('/tips/VirusTotal/{ip}')
def get_vt_reputation(ip: str) -> IPReputation:
    tip_result: dict = vt_reputation(ip)
    reputation: IPReputation = {
        'service': "VirusTotal",
        **tip_result
    }
    return reputation


@app.get('/tips/AbuseIPDB/{ip}')
def get_ipdb_reputation(ip: str) -> IPReputation:
    tip_result: dict = ipdb_reputation(ip)
    reputation: IPReputation = {
        'service': "AbuseIPDB",
        **tip_result
    }
    return reputation


@app.post('/tips/activate/{TIP_name}')
def activate(TIP_name: str) -> JSONResponse:
    result: dict = set_integration_flag(TIP_name, True)
    return result


@app.post('/tips/deactivate/{TIP_name}')
def deactivate(TIP_name: str) -> JSONResponse:
    result: dict = set_integration_flag(TIP_name, False)
    return result


@app.get('/tips/all/{ip}')
def get_reputation(ip: str) -> IP:
    integrations: list = [path for path in os.listdir(INTEGRATIONS_PATH) if path.endswith('.py')]
    active_integrations: list = [path.split('.')[0] for path in integrations if get_is_active_flag(os.path.join(INTEGRATIONS_PATH, path))]
    integrations_commands: dict = {
        'AbuseIPDB': get_ipdb_reputation,
        "AlienVault": get_av_reputation,
        "VirusTotal": get_vt_reputation
    }
    results: dict = {
        'ip': ip,
        'reputation': []
    }
    for active_integration in active_integrations:
        if active_integration in integrations_commands:
            reputation: IPReputation = integrations_commands[active_integration](ip)
            results['reputation'].append(reputation)
    return results
    