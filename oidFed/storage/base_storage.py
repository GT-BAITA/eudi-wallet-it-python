import datetime
from enum import Enum
from typing import Union

from pymongo.results import UpdateResult

from .base_db import BaseDB


class TrustType(Enum):
    X509 = "x509"
    FEDERATION = "federation"


trust_type_map: dict = {
    TrustType.X509: "x509",
    TrustType.FEDERATION: "federation",
}

trust_attestation_field_map: dict = {
    TrustType.X509: "x5c",
    TrustType.FEDERATION: "chain",
}

trust_anchor_field_map: dict = {
    TrustType.X509: "pem", 
    TrustType.FEDERATION: "entity_configuration",
}


class BaseStorage(BaseDB):
    """
    Interface class for storage - OIDC Federation Only.
    """

    def init_session(
        self, document_id: str, session_id: str, state: str, remote_flow_typ: str
    ) -> str:
        """
        Initialize a session for OIDC Federation flow.
        """
        raise NotImplementedError()

    def get_by_session_id(self, session_id: str) -> Union[dict, None]:
        """
        Get a session by session id.
        """
        raise NotImplementedError()
    
    def upsert_session(self, session_id: str, data: dict) -> tuple[str, dict]:
        """
        Upsert a session by session id.
        """
        raise NotImplementedError()
    
    def search_session_by_field(self, field: str, value: str) -> dict:
        """
        Search for a session by a specific field and value.
        """
        raise NotImplementedError()


    def get_trust_attestation(self, entity_id: str) -> Union[dict, None]:
        """
        Get a trust attestation.
        """
        raise NotImplementedError()

    def get_trust_anchor(self, entity_id: str) -> Union[dict, None]:
        """
        Get a trust anchor.
        """
        raise NotImplementedError()

    def has_trust_attestation(self, entity_id: str) -> bool:
        """
        Check if a trust attestation exists.
        """
        raise NotImplementedError()

    def has_trust_anchor(self, entity_id: str) -> bool:
        """
        Check if a trust anchor exists.
        """
        raise NotImplementedError()

    def has_trust_source(self, entity_id: str) -> bool:
        """
        Check if a trust source exists.
        """
        raise NotImplementedError()

    def add_trust_attestation(
        self,
        entity_id: str,
        attestation: list[str],
        exp: datetime,
        trust_type: TrustType,
        jwks: dict,
    ) -> str:
        """
        Add a trust attestation.
        """
        raise NotImplementedError()

    def add_trust_attestation_metadata(
        self, entity_id: str, metadata_type: str, metadata: dict
    ) -> str:
        """
        Add a trust attestation metadata.
        """
        raise NotImplementedError()

    def add_trust_source(self, entity_id: str, trust_source: dict) -> str:
        """
        Add a trust source.
        """
        raise NotImplementedError()

    def get_trust_source(self, entity_id: str) -> Union[dict, None]:
        """
        Get a trust source.
        """
        raise NotImplementedError()

    def add_empty_trust_anchor(self, entity_id: str) -> str:
        """
        Add an empty trust anchor.
        """
        raise NotImplementedError()

    def add_trust_anchor(
        self,
        entity_id: str,
        entity_configuration: str,
        exp: datetime,
        trust_type: TrustType,
    ):
        """
        Add a trust anchor.
        """
        raise NotImplementedError()

    def update_trust_attestation(
        self,
        entity_id: str,
        attestation: list[str],
        exp: datetime,
        trust_type: TrustType,
        jwks: dict,
    ) -> str:
        """
        Update a trust attestation.
        """
        raise NotImplementedError()

    def update_trust_anchor(
        self,
        entity_id: str,
        entity_configuration: str,
        exp: datetime,
        trust_type: TrustType,
    ) -> str:
        """
        Update a trust anchor.
        """
        raise NotImplementedError()


    def add_or_update_trust_attestation(
        self, entity_id: str, attestation: list[str], exp: datetime
    ) -> str:
        """
        Add or update a trust attestation.
        """
        raise NotImplementedError()

    @property
    def is_connected(self) -> bool:
        """
        Check if the storage is connected.
        """
        raise NotImplementedError()