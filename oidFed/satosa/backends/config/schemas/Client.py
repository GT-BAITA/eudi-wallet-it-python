from typing import Optional

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, StrictStr


class AuthReqParams(BaseModel):
    scope: list[StrictStr] = ["openid"]
    response_type: StrictStr


class ProviderMetadata(BaseModel):
    issuer: AnyHttpUrl


class ClientConfigSchema(BaseModel):
    provider_metadata: ProviderMetadata
    auth_req_params: AuthReqParams
    token_endpoint_auth_method: StrictStr
    application_name: StrictStr
    client_secret: Optional[StrictStr] = ""
