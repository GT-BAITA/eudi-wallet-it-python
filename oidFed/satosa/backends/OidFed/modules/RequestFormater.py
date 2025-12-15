import base64
import hashlib
import logging
import os

from oic import rndstr
from satosa.exception import SATOSAAuthenticationError

from oidFed.jwt.exceptions import JWSSigningError
from oidFed.jwt.jws_helper import JWSHelper
from oidFed.satosa.backends.config import Config
from oidFed.satosa.backends.OidFed.tools.utils import exp_from_now, iat_now

logger = logging.getLogger(__name__)


NONCE_KEY = "oidc_nonce"
STATE_KEY = "oidc_state"
CODE_VERIFIER_KEY = "oidc_code_verifier"


class RequestFormater:
    def __init__(self, config: Config, context):
        self.config = config
        self.request = self.request_build(context)

    def request_build(self, context) -> dict[str, str]:
        logger.info("Gerando pre request")

        oidc_nonce, oidc_state = self.__generate_nonce_state()
        code_verifier, code_challenge = self.__generate_pkce_pair()

        state_data = {
            NONCE_KEY: oidc_nonce,
            STATE_KEY: oidc_state,
            CODE_VERIFIER_KEY: code_verifier,
        }

        context.state[self.config.name] = state_data

        signed_jwt_request = self.__create_signed_request(
            context, oidc_nonce, oidc_state, code_challenge
        )

        request = {
            "nonce": oidc_nonce,
            "state": oidc_state,
            "code_verifier": code_verifier,
            "code_challenge": code_challenge,
            "signed_jwt_request": signed_jwt_request,
        }

        logger.info("Pre request gerada com sucesso")

        return request

    def __generate_pkce_pair(self) -> tuple[str, str]:
        """
        Gera par PKCE (code_verifier e code_challenge) - OBRIGATÓRIO para OPs italianos
        """

        logger.info("Gerando code verifier e code challenge")

        code_verifier = (
            base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")
        )

        code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = (
            base64.urlsafe_b64encode(code_challenge).decode("utf-8").rstrip("=")
        )

        logger.info("Code verifier e code challenge gerados com sucesso")
        logger.debug(
            f"code verifier: {code_verifier}, code_challenge: {code_challenge}"
        )

        return code_verifier, code_challenge

    def __generate_nonce_state(self) -> tuple[str, str]:
        logger.info("Gerando nonce e state")

        nonce = rndstr(32)
        state = rndstr(32)

        logger.info("Nonce e state gerados com sucesso")
        logger.debug(f"Nonce: {nonce}, state: {state}")

        return nonce, state

    def __create_signed_request(self, context, nonce, state, code_challenge=None):
        """
        Cria JWT signed request para OpenID Federation
        Baseado no RequestHandler do projeto

        :param code_challenge: Code challenge PKCE (opcional) - DEVE ser o mesmo da URL
        """

        request_claims = self.__build_authorization_request_claims(
            nonce, state, code_challenge
        )

        protected_headers = {
            "alg": self.config.jwt["default_sig_alg"],
            "kid": self.config.federation["metadata"]["jwks"]["keys"][0]["kid"],
        }

        try:
            signed_jwt = self.__sign_request_jwt(request_claims, protected_headers)

            logger.debug("Created signed request object JWT")
            return signed_jwt

        except JWSSigningError as e:
            logger.error(f"JWT signing error: {e}")
            raise SATOSAAuthenticationError(
                context.state, f"Failed to sign request object: {e}"
            )
        except Exception as e:
            logger.error(f"Unexpected error signing JWT: {e}")
            raise SATOSAAuthenticationError(
                context.state, f"Failed to create request object: {e}"
            )

    def __sign_request_jwt(self, claims, protected_headers):
        """
        Assina o JWT usando a mesma lógica do RequestHandler - VERSÃO CORRIGIDA
        """
        try:
            logger.debug(f"Signing JWT with algorithm: {protected_headers.get('alg')}")

            helper = JWSHelper(self.config.federation["metadata"]["private_jwks"])

            signed_jwt = helper.sign(
                claims,
                protected=protected_headers,
                signing_algs=self.config.jwt.get("sig_alg_supported", []),
            )

            return signed_jwt

        except JWSSigningError as e:
            logger.error(f"JWS signing failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in JWT signing: {e}")
            raise JWSSigningError(f"JWT signing failed: {str(e)}")

    def __build_authorization_request_claims(self, nonce, state, code_challenge=None):
        """
        Constrói as claims do request object - VERSÃO CORRIGIDA
        """

        if not self.config.client["provider_metadata"].get("authorization_endpoint"):
            self.config.client["provider_metadata"]["authorization_endpoint"] = ""

        claims = {
            "aud": self.config.client["provider_metadata"]["issuer"],
            "client_id": self.config.federation["metadata"]["client_id"],
            "iss": self.config.federation["metadata"]["client_id"],
            "jti": rndstr(),
            "exp": exp_from_now(minutes=5),
            "iat": iat_now(),
            "scope": self.config.client["auth_req_params"]["scope"],
            "redirect_uri": self.config.federation["metadata"]["redirect_uris"][0],
            "response_type": self.config.client["auth_req_params"]["response_type"],
            "nonce": nonce,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": self.config.jwt["default_sig_alg"],
            "response_mode": "form_post",
            "client_metadata": self.config.federation["metadata"],
            "claims": {
                "id_token": {
                    "family_name": {"essential": True},
                    "given_name": {"essential": True},
                },
                "userinfo": {
                    "given_name": None,
                    "family_name": None,
                    "email": None,
                    "https://attributes.eid.gov.it/fiscal_number": None,
                },
            },
        }

        return claims
