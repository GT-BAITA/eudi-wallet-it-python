import logging
from oic import rndstr

from oidFed.tools.utils import iat_now, exp_from_now
from oidFed.jwt.jws_helper import JWSHelper
from oidFed.jwt.exceptions import JWSSigningError

from satosa.exception import SATOSAAuthenticationError

logger = logging.getLogger(__name__)

def create_signed_request(backend_instance, context, nonce, state):
    """
    Cria JWT signed request para OpenID Federation
    Baseado no RequestHandler do projeto
    
    :param backend_instance: Instância do backend OpenIDFederationBackend
    :param context: Contexto SATOSA
    :param nonce: Nonce da requisição
    :param state: State da requisição
    :return: JWT assinado
    """
    # Constrói as claims do request object
    request_claims = _build_authorization_request_claims(backend_instance, nonce, state)
    
    # Header protegido do JWT
    protected_headers = {
        "typ": "oauth-authz-req+jwt",
        "alg": backend_instance.config["jwt"]["default_sig_alg"]
    }
    
    # Adiciona trust parameters se disponíveis
    trust_params = _get_trust_parameters(backend_instance)
    if trust_params:
        protected_headers.update(trust_params)
    
    # Assina o JWT
    try:
        signed_jwt = _sign_request_jwt(backend_instance, request_claims, protected_headers)
        logger.debug("Created signed request object JWT")
        return signed_jwt
    except JWSSigningError as e:
        logger.error(f"JWT signing error: {e}")
        raise SATOSAAuthenticationError(context.state, f"Failed to sign request object: {e}")
    except Exception as e:
        logger.error(f"Unexpected error signing JWT: {e}")
        raise SATOSAAuthenticationError(context.state, f"Failed to create request object: {e}")

def _build_authorization_request_claims(backend_instance, nonce, state):
    """
    Constrói as claims do request object
    """
    claims = {
        # Claims OIDC padrão
        "iss": backend_instance.client.client_id,
        "aud": backend_instance.client.provider_info["issuer"],
        "response_type": backend_instance.config["client"]["auth_req_params"]["response_type"],
        "client_id": backend_instance.client.client_id,
        "redirect_uri": backend_instance.client.registration_response["redirect_uris"][0],
        "scope": _get_scope_string(backend_instance),
        "state": state,
        "nonce": nonce,
        
        # Claims JWT
        "iat": iat_now(),
        "exp": exp_from_now(minutes=5),
        "jti": rndstr(),
    }
    
    # Adiciona client_metadata se disponível via trust evaluator
    try:
        if hasattr(backend_instance, 'trust_evaluator'):
            client_metadata = backend_instance.trust_evaluator.get_metadata(backend_instance.client.client_id)
            if client_metadata:
                # Adiciona metadados relevantes ao request
                claims.update({
                    "client_metadata": client_metadata
                })
    except Exception as e:
        logger.debug(f"Could not get client metadata: {e}")
    
    return claims

def _sign_request_jwt(backend_instance, claims, protected_headers):
    """
    Assina o JWT usando a mesma lógica do RequestHandler
    """
    # Verifica se tem kid ou x5c no header para escolher a chave
    if "kid" in protected_headers or "x5c" in protected_headers:
        # Usa JWSHelper para selecionar a chave apropriada
        helper = JWSHelper(backend_instance.config["metadata_jwks"])
    else:
        # Usa a chave padrão (primeira da lista)
        helper = JWSHelper([backend_instance.config["metadata_jwks"][0]])
    
    # Assina o JWT
    signed_jwt = helper.sign(
        claims,
        protected=protected_headers,
        signing_algs=backend_instance.config["jwt"].get("sig_alg_supported", [])
    )
    
    return signed_jwt

def _get_trust_parameters(backend_instance):
    """
    Obtém parâmetros de trust para incluir no header JWT
    """
    if hasattr(backend_instance, 'trust_evaluator') and backend_instance.trust_evaluator.handlers:
        try:
            issuer = backend_instance.client.provider_info["issuer"]
            return backend_instance.trust_evaluator.get_jwt_header_trust_parameters(issuer)
        except Exception as e:
            logger.debug(f"No trust parameters available: {e}")
    
    return {}

def _get_scope_string(backend_instance):
    """Converte scope para string formatada"""
    scope = backend_instance.config["client"]["auth_req_params"]["scope"]
    if isinstance(scope, list):
        return " ".join(scope)
    return scope