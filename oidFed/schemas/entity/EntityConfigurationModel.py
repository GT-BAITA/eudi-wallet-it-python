from typing import Dict, List, Optional

from pydantic import Extra, StrictStr

from oidFed.schemas.entity.EntityStatementsModel import EntityStatementsModel


class EntityConfigurationModel(EntityStatementsModel):
    """
    Model for representing an OpenID Entity Configuration

    Reference:
        OpenID Connect Federation 1.0 - Section 9.2 Entity Configuration
        https://openid.net/specs/openid-federation-1_0.html#name-federation-entity-configurat
    """

    authority_hints: List[Optional[StrictStr]] = []
    trust_mark_issuers: Optional[Dict[StrictStr, List[StrictStr]]] = None

    class Config:
        extra = Extra.ignore
