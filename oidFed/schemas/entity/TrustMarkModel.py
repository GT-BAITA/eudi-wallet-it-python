from pydantic import BaseModel, Extra, StrictStr

from oidFed.schemas.entity.JwksModel import JwksModel


class TrustMarkModel(BaseModel):
    trust_mark_type: StrictStr
    trust_mark: StrictStr

    class Config:
        extra = Extra.ignore


class TrustMarkOwnerModel(BaseModel):
    sub: StrictStr
    jwks: JwksModel

    class Config:
        extra = Extra.ignore
