import base64
import hashlib
import logging
import os

from oic import oic, rndstr
from oic.oic.message import ProviderConfigurationResponse, RegistrationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.keyio import KeyBundle, KeyJar

from oidFed.satosa.utils.auth_request import create_signed_request
from oidFed.trust.handler.federation import FederationHandler

logger = logging.getLogger(__name__)

NONCE_KEY = "oidc_nonce"
STATE_KEY = "oidc_state"
CODE_VERIFIER_KEY = "oidc_code_verifier"


class PreRequest:
    def __init__(self, config, settings, name):
        self.config = config
        self.settings = settings
        self.name = name
        self.client = self.__create_client()
        self.handler = self.__init_entity_configuration_endpoint()

    def __create_client(self):
        """
        Create a pyoidc client instance.
        :param provider_metadata: provider configuration information
        :type provider_metadata: Mapping[str, Union[str, Sequence[str]]]
        :param client_metadata: client metadata
        :type client_metadata: Mapping[str, Union[str, Sequence[str]]]
        :return: client instance to use for communicating with the configured provider
        :rtype: oic.oic.Client
        """

        logger.info("========= CONFIGURANDO O CLIENTE OIDC =========")

        keyjar = KeyJar()

        keybundle1 = KeyBundle(
            keys=self.config["federation"]["metadata"]["jwks"][0],
            verify_ssl=self.config["network"]["verify_ssl"],
        )
        keybundle2 = KeyBundle(
            keys=self.config["federation"]["metadata"]["jwks"][1],
            verify_ssl=self.config["network"]["verify_ssl"],
        )

        keyjar.add_kb(issuer="", kb=keybundle1)
        keyjar.add_kb(issuer="", kb=keybundle2)

        client = oic.Client(
            client_authn_method=CLIENT_AUTHN_METHOD,
            settings=self.settings,
            keyjar=keyjar,
        )

        if "authorization_endpoint" in self.config["client"]["provider_metadata"]:
            client.handle_provider_config(
                ProviderConfigurationResponse(
                    **self.config["client"]["provider_metadata"]
                ),
                self.config["client"]["provider_metadata"]["issuer"],
            )
        else:
            client.provider_config(self.config["client"]["provider_metadata"]["issuer"])

        data = {
            "token_endpoint_auth_method": self.config["client"][
                "token_endpoint_auth_method"
            ],
            "application_name": self.config["client"]["application_name"],
            "client_id": self.config["federation"]["metadata"]["client_id"],
            "redirect_uris": self.config["federation"]["metadata"]["redirect_uris"],
            "subject_type": self.config["federation"]["subject_type"],
            "client_secret": self.config["federation"]["client_secret"],
        }

        if "client_id" in self.config["federation"]["metadata"]:
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

        logger.info("========= CLIENTE OIDC CONFIGURADO =========")
        return client

    def __init_entity_configuration_endpoint(self) -> FederationHandler:
        """Inicializa o FederationHandler diretamente para endpoints"""

        logger.info(
            "========= CONFIGURANDO ENDPOINT ENTITY CONFIGURATION (.WELL-KNOWN/OPENID-FEDERATION) ========="
        )

        federation_config = self.config["federation"]
        default_client_id = federation_config["metadata"]["client_id"]

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
            client_id=default_client_id,
            httpc_params=self.config["network"],
            cache_ttl=federation_config["cache_ttl"],
            metadata_type=federation_config["metadata_type"],
        )

        endpoints = handler.build_metadata_endpoints(
            backend_name=self.name, entity_uri=default_client_id
        )

        logger.info("========= ENDPOINT ENTITY CONFIGURATION CONFIGURANDO =========")

        return endpoints

    def pre_request(self, context):

        oidc_nonce = rndstr(32)
        oidc_state = rndstr(32)

        code_verifier, code_challenge = self.__generate_pkce_pair()

        state_data = {
            NONCE_KEY: oidc_nonce,
            STATE_KEY: oidc_state,
            CODE_VERIFIER_KEY: code_verifier,
        }

        context.state[self.name] = state_data

        signed_jwt_request = create_signed_request(
            self, context, oidc_nonce, oidc_state, code_challenge
        )

        pre_request = {
            "nonce": oidc_nonce,
            "state": oidc_state,
            "code_verifier": code_verifier,
            "code_challenge": code_challenge,
            "signed_jwt_request": signed_jwt_request,
        }

        return pre_request

    def __generate_pkce_pair(self):
        """
        Gera par PKCE (code_verifier e code_challenge) - OBRIGATÓRIO para OPs italianos
        """

        code_verifier = (
            base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")
        )

        code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = (
            base64.urlsafe_b64encode(code_challenge).decode("utf-8").rstrip("=")
        )

        return code_verifier, code_challenge
