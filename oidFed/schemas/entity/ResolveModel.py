from typing import List

from pydantic import Field, StrictStr

from .oidFed.schemas.entity.EntityStatementsModel import EntityStatementsModel


class ResolveModel(EntityStatementsModel):
    """
    Model for representing an OpenID Entity Statements Resolution

    Reference:
        OpenID Connect Federation 1.0 - Section 8.3.2. Resolve Response
        https://openid.net/specs/openid-federation-1_0.html#name-resolve-response
    """

    trust_chain: List[StrictStr]
    jwks: None = Field(default=None, exclude=True)
