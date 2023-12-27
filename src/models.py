from pydantic import BaseModel
from pydantic.typing import Literal
from typing import List


class IPReputation(BaseModel):
    service: str
    results: dict
    value: Literal['Unknown', "Benign", "Suspicious", "Malicious"] 


class IP(BaseModel):
    reputation: List[IPReputation]
    ip: str


class TIP(BaseModel):
    name: str
    is_active: bool

class TIPs(BaseModel):
    tips: List[TIP]

