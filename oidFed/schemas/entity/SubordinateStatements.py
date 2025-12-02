from typing import Any, Dict, Literal

from pydantic import Field, root_validator

from oidFed.schemas.entity.EntityStatementsModel import EntityStatementsModel
from oidFed.schemas.entity.MetadataPolicyModel import MetadataPolicyModel


class SubordinateStatementsModel(EntityStatementsModel):
    type: Literal[
        "openid_relying_party", "openid_provider", "federation_entity", "oauth_resource"
    ] = Field("openid_relying_party", exclude=True)
    metadata_policy: Dict[str, Any] = Field(default_factory=dict)

    @root_validator(pre=True)
    def set_metadata_policy(cls, values):
        policy_model = MetadataPolicyModel()
        t = values.get("type", "openid_relying_party")
        values["metadata_policy"] = getattr(policy_model, t)
        return values
