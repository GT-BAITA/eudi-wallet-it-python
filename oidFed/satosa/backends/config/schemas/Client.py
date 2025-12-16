"""
Representação das configurações do cliente satosa, para validação
de configurações do plugin
"""

from typing import Optional

from pydantic import AnyHttpUrl, BaseModel, StrictStr


class AuthReqParams(BaseModel):
    """
    Paramentros de requisição de autenticação
    """

    scope: list[StrictStr] = ["openid"]
    response_type: StrictStr


class ProviderMetadata(BaseModel):
    """
    Informações necessárias do provedor de identidade
    """

    issuer: AnyHttpUrl


class ClientConfigSchema(BaseModel):
    """
    Schema de informações a cerca do client relying party
    """

    provider_metadata: ProviderMetadata
    auth_req_params: AuthReqParams
    token_endpoint_auth_method: StrictStr
    application_name: StrictStr
    client_secret: Optional[StrictStr] = ""
