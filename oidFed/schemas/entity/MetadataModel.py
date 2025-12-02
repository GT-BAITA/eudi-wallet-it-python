from typing import List, Optional

from pydantic import BaseModel, Extra, StrictStr


class InformationalMetadaModel(BaseModel):
    """
    Model for representing Informational Metadata and optional claims.

    Reference:
        OpenID Connect Federation 1.0 - Section 5.2.2 Informational Metadata Extensions
        https://openid.net/specs/openid-federation-1_0.html#name-informational-metadata-exte
    """

    organization_name: Optional[StrictStr] = None
    display_name: Optional[StrictStr] = None
    description: Optional[StrictStr] = None

    keywords: Optional[List[StrictStr]] = None
    contacts: Optional[List[StrictStr]] = None

    logo_uri: Optional[StrictStr] = None
    policy_uri: Optional[StrictStr] = None
    information_uri: Optional[StrictStr] = None
    organization_uri: Optional[StrictStr] = None

    class Config:
        extra = Extra.ignore


class FederationEntityMetadataModel(InformationalMetadaModel):
    """
    Model for representing an OpenID Federation Entity.

    Reference:
        OpenID Connect Federation 1.0 - Section 5.1.1 Federation Entity
        https://openid.net/specs/openid-federation-1_0.html#name-federation-entity
    """

    federation_fetch_endpoint: Optional[StrictStr] = None
    federation_list_endpoint: Optional[StrictStr] = None
    federation_resolve_endpoint: Optional[StrictStr] = None
    federation_trust_mark_status_endpoint: Optional[StrictStr] = None
    federation_trust_mark_list_endpoint: Optional[StrictStr] = None
    federation_trust_mark_endpoint: Optional[StrictStr] = None
    federation_historical_keys_endpoint: Optional[StrictStr] = None
    endpoint_auth_signing_alg_values_supported: Optional[StrictStr] = None

    class Config:
        extra = Extra.ignore


class MetadataModel(BaseModel):
    federation_entity: Optional[FederationEntityMetadataModel] = None
    openid_relying_party: Optional[dict] = None
    openid_provider: Optional[dict] = None

    class Config:
        extra = Extra.ignore
