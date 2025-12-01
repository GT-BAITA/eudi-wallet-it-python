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


def create_signed_request(backend_instance, context, nonce, state, code_challenge=None):
    """
    Cria JWT signed request para OpenID Federation
    Baseado no RequestHandler do projeto

    :param code_challenge: Code challenge PKCE (opcional) - DEVE ser o mesmo da URL
    """
    # Constrói as claims do request object
    request_claims = _build_authorization_request_claims(
        backend_instance, nonce, state, code_challenge
    )

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


def _build_authorization_request_claims(
    backend_instance, nonce, state, code_challenge=None
):
    """
    Constrói as claims do request object - VERSÃO CORRIGIDA
    """
    # 🆕 CORREÇÃO CRÍTICA: Usar code_challenge fornecido ou gerar um
    if code_challenge:
        # Usar o challenge fornecido (consistente com a URL)
        final_code_challenge = code_challenge
        logger.debug(
            f"✅ PKCE CONSISTENTE - Usando challenge fornecido: {final_code_challenge}"
        )
    else:
        # Gerar novo (fallback - não recomendado)
        final_code_challenge = _generate_code_challenge()
        logger.warning(
            f"⚠️  PKCE INCONSISTENTE - Challenge gerado: {final_code_challenge}"
        )

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
        # 🆕 CORREÇÃO: Usar o challenge correto
        "code_challenge": final_code_challenge,
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

    # ... resto do código permanece igual ...
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


def _generate_code_challenge(code_verifier=None):
    """
    Gera code challenge para PKCE - VERSÃO CONSISTENTE

    :param code_verifier: Code verifier opcional (se None, gera um novo)
    """
    if code_verifier is None:
        # Gera code verifier (48 caracteres como no exemplo funcional)
        code_verifier = (
            base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")
        )

    # 🆕 CORREÇÃO: Usar EXATAMENTE o mesmo método que _generate_pkce_pair
    # Code challenge: SHA-256 + base64url EXATAMENTE como o OP faz
    challenge_bytes = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge_b64 = base64.urlsafe_b64encode(challenge_bytes).decode("ascii")

    # IMPORTANTE: Usar o mesmo método que o OP (.replace) em vez de .rstrip
    code_challenge = code_challenge_b64.replace("=", "")

    logger.debug(f"🔑 _generate_code_challenge:")
    logger.debug(f"   Input verifier: {code_verifier}")
    logger.debug(f"   Output challenge: {code_challenge}")
    logger.debug(f"   Challenge length: {len(code_challenge)}")

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
