import logging

from oidFed.satosa.backends.config import Config
from oidFed.satosa.backends.OidFed.modules.Oidc import Oidc
from oidFed.trust.handler.federation import FederationHandler

logger = logging.getLogger(__name__)


class OidFed(Oidc):
    def __init__(self, config: Config):
        super().__init__(config)
        self.name = config.name

        self.handler = self.__init_entity_configuration_endpoint(config)

    def __init_entity_configuration_endpoint(self, config: Config) -> FederationHandler:
        """Inicializa o FederationHandler diretamente para endpoints"""

        logger.info("Iniciando configuração do handler de federação")

        federation_config = config.federation

        federation_entity_metadata = {
            "organization_name": federation_config["organization_name"],
            "homepage_uri": federation_config["homepage_uri"],
            "policy_uri": federation_config["policy_uri"],
            "tos_uri": federation_config["tos_uri"],
            "logo_uri": federation_config["logo_uri"],
        }

        handler = FederationHandler(
            metadata=federation_config["metadata"],
            authority_hints=federation_config["authority_hints"],
            trust_anchors=federation_config["trust_anchors"],
            default_sig_alg=federation_config["default_sig_alg"],
            federation_jwks=federation_config["metadata"]["jwks"],
            trust_marks=federation_config["trust_marks"],
            federation_entity_metadata=federation_entity_metadata,
            client_id=federation_config["metadata"]["client_id"],
            httpc_params=config.network,
            cache_ttl=federation_config["cache_ttl"],
            metadata_type=federation_config["metadata_type"],
        )

        endpoints = handler.build_metadata_endpoints(
            backend_name=self.name,
            entity_uri=federation_config["metadata"]["client_id"],
        )

        logger.info("Handler de federação configurado")

        return endpoints
