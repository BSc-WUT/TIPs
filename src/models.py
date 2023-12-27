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

