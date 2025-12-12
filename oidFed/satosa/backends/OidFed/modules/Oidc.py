import logging

from oic import oic
from oic.oic import Client
from oic.oic.message import ProviderConfigurationResponse, RegistrationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.keyio import KeyBundle, KeyJar
from oic.utils.settings import PyoidcSettings

from oidFed.satosa.backends.config import Config

logger = logging.getLogger(__name__)


class Oidc:
    def __init__(self, config: Config):
        self.settings = PyoidcSettings(verify_ssl=config.network["verify_ssl"])
        private = config.federation["metadata"]["jwks"]
        config.federation["metadata"]["private_jwks"] = private
        self.client = self.__create_client(config)

    def __create_client(self, config: Config) -> Client:
        """
        Create a pyoidc client instance.
        :param provider_metadata: provider configuration information
        :type provider_metadata: Mapping[str, Union[str, Sequence[str]]]
        :param client_metadata: client metadata
        :type client_metadata: Mapping[str, Union[str, Sequence[str]]]
        :return: client instance to use for communicating with the configured provider
        :rtype: oic.oic.Client
        """

        logger.info("Iniciando configuração do client oidc")
        logger.info("Configurando as chaves jwk")

        keyjar = KeyJar()

        keybundle1 = KeyBundle(
            keys=config.federation["metadata"]["private_jwks"][0],
            verify_ssl=config.network["verify_ssl"],
        )
        keybundle2 = KeyBundle(
            keys=config.federation["metadata"]["private_jwks"][1],
            verify_ssl=config.network["verify_ssl"],
        )

        keyjar.add_kb(issuer="", kb=keybundle1)
        keyjar.add_kb(issuer="", kb=keybundle2)

        client = oic.Client(
            client_authn_method=CLIENT_AUTHN_METHOD,
            settings=self.settings,
            keyjar=keyjar,
        )

        logger.info("Chaves configuradas")
        logger.debug(f"As chaves são {client.keyjar}")

        if "authorization_endpoint" in config.client["provider_metadata"]:
            client.handle_provider_config(
                ProviderConfigurationResponse(**config.client["provider_metadata"]),
                config.client["provider_metadata"]["issuer"],
            )
        else:
            client.provider_config(config.client["provider_metadata"]["issuer"])

        if not config.client.get("client_secret"):
            config.client["client_secret"] = ""

        if not config.client.get("client_id"):
            config.client["client_id"] = ""

        data = {
            "token_endpoint_auth_method": config.client["token_endpoint_auth_method"],
            "application_name": config.client["application_name"],
            "client_id": config.federation["metadata"]["client_id"],
            "redirect_uris": config.federation["metadata"]["redirect_uris"],
            "subject_type": config.federation["subject_type"],
            "client_secret": config.client["client_secret"],
        }

        logger.debug(f"Registration data {data}")

        if "client_id" in config.federation["metadata"]:
            client.store_registration_info(RegistrationRequest(**data))
        else:
            client.register(
                client.provider_info["registration_endpoint"],
                **data,
            )

        client.subject_type = (
            client.registration_response.get("subject_type")
            or client.provider_info["subject_types_supported"][0]
        )

        logger.info("Configuração do client oidc finalizado")
        return client
