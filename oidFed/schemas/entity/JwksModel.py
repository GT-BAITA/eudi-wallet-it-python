from typing import List

from pydantic import BaseModel, Extra, StrictStr


class KeyModel(BaseModel):
    kty: StrictStr
    n: StrictStr
    e: StrictStr
    kid: StrictStr

    class Config:
        extra = Extra.ignore


class JwksModel(BaseModel):
    keys: List[KeyModel]

    class Config:
        extra = Extra.ignore
