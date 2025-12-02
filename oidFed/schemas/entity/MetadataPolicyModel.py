from pydantic import BaseModel, Extra


class MetadataPolicyModel(BaseModel):
    openid_relying_party: dict = {"openid_relying_party": {}}
    openid_provider: dict = {"openid_provider": {}}
    federation_entity: dict = {"federation_entity": {}}
    oauth_resource: dict = {"oauth_resource": {}}

    class Config:
        extra = Extra.ignore
