from typing import Any, Optional

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, StrictInt, StrictStr


class Jwks(BaseModel):
    kty: StrictStr
    d: Optional[StrictStr] = ""
    e: StrictStr
    use: StrictStr
    kid: StrictStr
    n: StrictStr
    p: Optional[StrictStr] = ""
    q: Optional[StrictStr] = ""


class Metadata(BaseModel):
    application_type: StrictStr
    client_id: Optional[AnyHttpUrl]
    contacts: list[StrictStr]
    jwks: list[Jwks]
    authorization_encrypted_response_alg: list[StrictStr]
    authorization_encrypted_response_enc: list[StrictStr]
    authorization_signed_response_alg: list[StrictStr]

    id_token_encrypted_response_alg: list[StrictStr]
    id_token_encrypted_response_enc: list[StrictStr]
    id_token_signed_response_alg: list[StrictStr]

    redirect_uris: list[AnyHttpUrl]
    request_uris: list[AnyHttpUrl]


class FederationConfigSchema(BaseModel):
    subject_type: StrictStr
    metadata_type: StrictStr
    authority_hints: list[AnyHttpUrl]
    trust_anchors: list[AnyHttpUrl]
    default_sig_alg: StrictStr
    organization_name: StrictStr
    homepage_uri: StrictStr
    policy_uri: StrictStr
    tos_uri: StrictStr
    logo_uri: StrictStr
    cache_ttl: StrictInt
    entity_configuration_exp: StrictInt
    metadata: Metadata
    trust_marks: Optional[list[Any]] = []
