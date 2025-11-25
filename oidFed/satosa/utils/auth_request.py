import base64
import hashlib
import logging
import os

from oic import rndstr
from satosa.exception import SATOSAAuthenticationError

from oidFed.jwt.exceptions import JWSSigningError
from oidFed.jwt.jws_helper import JWSHelper
from oidFed.tools.utils import exp_from_now, iat_now

logger = logging.getLogger(__name__)


def create_signed_request(backend_instance, context, nonce, state):
    """
    Cria JWT signed request para OpenID Federation
    Baseado no RequestHandler do projeto
    """
    # Constrói as claims do request object
    request_claims = _build_authorization_request_claims(backend_instance, nonce, state)

    # DEBUG: Log das claims completas
    import json

    logger.debug(
        f"✅ FINAL Request claims: {json.dumps(request_claims, indent=2, ensure_ascii=False)}"
    )

    # Header protegido do JWT
    protected_headers = {
        "alg": backend_instance.config["jwt"]["default_sig_alg"],
        "kid": "9Cquk0X-fNPSdePQIgQcQZtD6J0IjIRrFigW2PPK_-w",
    }

    # Adiciona trust parameters se disponíveis
    trust_params = _get_trust_parameters(backend_instance)
    if trust_params:
        protected_headers.update(trust_params)

    # Assina o JWT
    try:
        signed_jwt = _sign_request_jwt(
            backend_instance, request_claims, protected_headers
        )
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


def _build_authorization_request_claims(backend_instance, nonce, state):
    """
    Constrói as claims do request object - VERSÃO COMPLETA CORRIGIDA
    """
    # Gera PKCE (OBRIGATÓRIO para OPs italianos)
    code_challenge = _generate_code_challenge()

    claims = {
        # Claims OIDC padrão
        "aud": [
            backend_instance.client.provider_info["issuer"],
            backend_instance.client.provider_info["authorization_endpoint"],
        ],
        "client_id": backend_instance.client.client_id,
        "iss": backend_instance.client.client_id,
        "jti": rndstr(),
        "exp": exp_from_now(minutes=5),
        "iat": iat_now(),
        "scope": ["openid"],
        "redirect_uri": backend_instance.client.registration_response["redirect_uris"][
            0
        ],
        "response_type": "code",
        "nonce": nonce,
        "state": state,
        # CORREÇÃO CRÍTICA 2: Adiciona PKCE (OBRIGATÓRIO)
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "response_mode": "form_post",
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
        "prompt": "consent login",
    }

    # Adiciona client_metadata se disponível via trust evaluator
    try:
        if hasattr(backend_instance, "trust_evaluator"):
            client_metadata = backend_instance.trust_evaluator.get_metadata(
                backend_instance.client.client_id
            )
            if client_metadata:
                claims.update({"client_metadata": client_metadata})
    except Exception as e:
        logger.debug(f"Could not get client metadata: {e}")

    return claims


def _generate_code_challenge():
    """
    Gera code challenge para PKCE (igual ao RP funcional)
    """
    # Gera code verifier (48 caracteres como no exemplo funcional)
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")

    # Calcula code challenge (exatamente como no RP funcional)
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = (
        base64.urlsafe_b64encode(code_challenge).decode("utf-8").rstrip("=")
    )

    logger.debug(f"Generated PKCE - Challenge: {code_challenge}")

    return code_challenge


def _sign_request_jwt(backend_instance, claims, protected_headers):
    """
    Assina o JWT usando a mesma lógica do RequestHandler - VERSÃO CORRIGIDA
    """
    try:
        # DEBUG: Log para ver o que está acontecendo
        logger.debug(f"Signing JWT with algorithm: {protected_headers.get('alg')}")
        logger.debug(
            f"Available keys: {[k.get('kid', 'no-kid') for k in backend_instance.config['metadata_jwks']]}"
        )

        # Sempre usa todas as chaves disponíveis e deixa o JWSHelper selecionar
        helper = JWSHelper(backend_instance.config["metadata_jwks"])

        # Assina o JWT
        signed_jwt = helper.sign(
            claims,
            protected=protected_headers,
            signing_algs=backend_instance.config["jwt"].get("sig_alg_supported", []),
        )

        logger.debug("JWT signed successfully")
        return signed_jwt

    except JWSSigningError as e:
        logger.error(f"JWS signing failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in JWT signing: {e}")
        raise JWSSigningError(f"JWT signing failed: {str(e)}")


def _get_trust_parameters(backend_instance):
    """
    Obtém parâmetros de trust para incluir no header JWT
    """
    if (
        hasattr(backend_instance, "trust_evaluator")
        and backend_instance.trust_evaluator.handlers
    ):
        try:
            issuer = backend_instance.client.provider_info["issuer"]
            return backend_instance.trust_evaluator.get_jwt_header_trust_parameters(
                issuer
            )
        except Exception as e:
            logger.debug(f"No trust parameters available: {e}")

    return {}


def _get_scope_string(backend_instance):
    """Converte scope para string formatada"""
    scope = backend_instance.config["client"]["auth_req_params"]["scope"]
    if isinstance(scope, list):
        return " ".join(scope)
    return scope
