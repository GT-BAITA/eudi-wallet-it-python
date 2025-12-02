from typing import Dict, List, Optional

from pydantic import BaseModel, Extra, StrictInt, StrictStr

from oidFed.schemas.entity.JwksModel import JwksModel
from oidFed.schemas.entity.MetadataModel import MetadataModel
from oidFed.schemas.entity.TrustMarkModel import TrustMarkModel, TrustMarkOwnerModel


class EntityStatementsModel(BaseModel):
    """
    Model for representing an OpenID Entity Statements

    Reference:
        OpenID Connect Federation 1.0 - Section 3 Entity Statements
        https://openid.net/specs/openid-federation-1_0.html#name-entity-statement
    """

    iss: StrictStr
    sub: StrictStr
    iat: StrictInt
    exp: StrictInt
    jwks: JwksModel
    metadata: Optional[MetadataModel] = None
    crit: Optional[List[StrictStr]] = None
    metadata_policy_crit: Optional[List[StrictStr]] = None
    trust_anchor: Optional[StrictStr] = None
    trust_marks: Optional[TrustMarkModel | List] = []
    trust_mark_owners: Optional[TrustMarkOwnerModel] = None
    source_endpoint: Optional[StrictStr] = None

    class Config:
        extra = Extra.ignore
