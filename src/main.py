from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

from .TIPs.AlienValut import get_reputation as av_reputation
from .TIPs.VirusTotal import get_reputation as vt_reputation
from .TIPs.AbuseIPDB import get_reputation as ipdb_reputation
from .models import IPReputation



def get_env_vars() -> dict:
    load_dotenv()
    return {
        "DB_API_URL": f'http://{os.getenv("DB_API")}:{os.getenv("DB_API_PORT")}',
        "ML_API_URL": f'http://{os.getenv("ML_API")}:{os.getenv("ML_API_PORT")}',
        "API_PORT": os.getenv('API_PORT'),
    }


app = FastAPI()
ENV_VARS = get_env_vars()


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


''' Threat Intelligence Platforms '''

@app.get('/tips/AlienVault/{ip}')
def get_reputation(ip: str) -> IPReputation:
    tip_result: dict = av_reputation(ip)
    reputation: IPReputation = {
        'service': "AlienVault",
        **tip_result
    }
    return reputation


@app.get('/tips/VirusTotal/{ip}')
def get_reputation(ip: str) -> JSONResponse:
    reputation: dict = vt_reputation(ip)
    return reputation


@app.get('/tips/AbuseIPDB/{ip}')
def get_reputation(ip: str) -> JSONResponse:
    reputation: dict = ipdb_reputation(ip)
    return reputation