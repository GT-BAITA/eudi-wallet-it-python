import base64
import hashlib
import logging
import os

from oic import rndstr

logger = logging.getLogger(__name__)


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


def _get_scope_string(backend_instance):
    """Converte scope para string formatada"""
    scope = backend_instance.config["client"]["auth_req_params"]["scope"]
    if isinstance(scope, list):
        return " ".join(scope)
    return scope
