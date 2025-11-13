import binascii
import logging
import os
from copy import deepcopy
from typing import Any, Literal, Union

from cryptojwt import JWS
from cryptojwt.jwk.jwk import key_from_jwk_dict

from oidFed.jwk import JWK
from oidFed.jwk.exceptions import KidError
from oidFed.jwk.jwks import find_jwk_by_kid, find_jwk_by_thumbprint
from oidFed.jwt.exceptions import (
    JWSSigningError,
    JWSVerificationError,
    LifetimeException,
)
from oidFed.jwt.helper import (
    JWHelperInterface,
    find_self_contained_key,
    serialize_payload,
    validate_jwt_timestamps_claims,
)
from oidFed.jwt.utils import decode_jwt_header

SerializationFormat = Literal["compact", "json"]

logger = logging.getLogger(__name__)

DEFAULT_SIG_KTY_MAP = {"RSA": "RS256", "EC": "ES256"}
DEFAULT_TOKEN_TIME_TOLERANCE = int(
    os.getenv("PYEUDIW_TOKEN_TIME_TOLERANCE", "60"), base=10
)


class JWSHelper(JWHelperInterface):
    """
    Helper class for working with JWS in OIDC Federation context.
    """

    def sign(
        self,
        plain_dict: Union[dict, str, int, None],
        protected: dict | None = None,
        unprotected: dict | None = None,
        serialization_format: SerializationFormat = "compact",
        signing_kid: str = "",
        kid_in_header: bool = True,
        **kwargs,
    ) -> str:
        """Generate a signed JWS with the given payload and header for OIDC Federation.
        
        Used for signing: entity statements, client registration, trust chains.
        """

        if protected is None:
            protected = {}
        if unprotected is None:
            unprotected = {}

        # Select the signing key
        signing_key = self._select_signing_key((protected, unprotected), signing_kid)

        if signing_key["kty"] == "oct":
            raise JWSSigningError(f"Key {signing_key['kid']} is a symmetric key")

        # Validate key compatibility with header
        _validate_key_with_jws_header(signing_key, protected, unprotected)

        payload = serialize_payload(plain_dict)

        # Select algorithm based on key type
        signing_alg: str = DEFAULT_SIG_KTY_MAP[JWK(signing_key).key.kty]
        protected["alg"] = signing_alg

        # Always use "JWT" type in OIDC Federation
        if "typ" not in protected:
            protected["typ"] = "JWT"

        # Include kid in header if requested
        header_kid = protected.get("kid")
        signer_kid = signing_key.get("kid")
        if kid_in_header and signer_kid:
            protected["kid"] = signer_kid

        # Remove kid from key if not wanted in header
        if not kid_in_header and not header_kid:
            signing_key = deepcopy(signing_key)
            signing_key.pop("kid", None)

        signing_key_jwk = key_from_jwk_dict(signing_key)

        if not signing_key_jwk.priv_key:
            raise JWSSigningError(f"Key {signing_key_jwk.kid} is not a private key")

        # Sign the token
        signer = JWS(payload, alg=signing_alg)
        keys = [signing_key_jwk]

        if serialization_format == "compact":
            try:
                signed = signer.sign_compact(keys, protected=protected, **kwargs)
                return signed
            except Exception as e:
                raise JWSSigningError("Signing error", e)
        
        # JSON serialization (rarely used in OIDC Fed)
        return signer.sign_json(
            keys=keys,
            headers=[(protected, unprotected)],
            flatten=True,
        )

    def _select_signing_key(
        self, 
        headers: tuple[dict, dict], 
        signing_kid: str = "",
    ) -> dict:
        """
        Select a signing key for OIDC Federation tokens.
        """
        if len(self.jwks) == 0:
            raise JWSSigningError("No key available for signature")

        # Case 1: key forced by kid
        if signing_kid:
            signing_key = self.get_jwk_by_kid(signing_kid)
            if not signing_key:
                raise JWSSigningError(f"Key with kid {signing_kid} not available")
            return signing_key.to_dict()
        
        # Case 2: only one key available
        if len(self.jwks) == 1:
            return self.jwks[0].to_dict()

        # Case 3: match by kid in headers
        if signing_key := self._select_key_by_kid(headers):
            return signing_key

        # Case 4: use first signing key (use="sig")
        if signing_key := self._select_key_by_use(use="sig"):
            return signing_key

        raise JWSSigningError("Could not determine signing key")

    def _select_key_by_use(self, use: str) -> dict | None:
        """Select key by intended use (sig/enc)."""
        for key in self.jwks:
            key_d = key.to_dict()
            if use == key_d.get("use", ""):
                return key_d
        return None

    def _select_key_by_kid(self, headers: tuple[dict, dict]) -> dict | None:
        """Select key by kid from headers."""
        if not headers:
            return None
            
        kid = None
        if "kid" in headers[0]:
            kid = headers[0]["kid"]
        elif "kid" in headers[1]:
            kid = headers[1]["kid"]
        
        if kid:
            return find_jwk_by_kid([key.to_dict() for key in self.jwks], kid)
        return None

    def verify(
        self, jwt: str, tolerance_s: int = DEFAULT_TOKEN_TIME_TOLERANCE
    ) -> dict | bytes | str | Any:
        """Verify a JWS token in OIDC Federation context."""

        try:
            header = decode_jwt_header(jwt)
        except (binascii.Error, Exception) as e:
            raise JWSVerificationError(f"Invalid JWS format: {e}")

        verifying_key = self._select_verifying_key(header)
        if not verifying_key:
            raise JWSVerificationError(f"No matching public key for header {header}")

        # Verify kid consistency
        if expected_kid := header.get("kid"):
            obtained_kid = verifying_key.get("kid", None)
            if obtained_kid and (obtained_kid != expected_kid):
                raise JWSVerificationError(
                    KidError(f"Key kid mismatch: {obtained_kid} vs {expected_kid}")
                )

        # Verify signature and claims
        verifier = JWS(alg=header["alg"])

        try:
            msg = verifier.verify_compact(jwt, [key_from_jwk_dict(verifying_key)])

            if isinstance(msg, dict):
                validate_jwt_timestamps_claims(msg, tolerance_s)

            return msg
        except LifetimeException as e:
            raise JWSVerificationError(f"Invalid JWT claims: {e}")
        except Exception as e:
            raise JWSVerificationError(f"Signature verification failed: {e}")

    def _select_verifying_key(self, header: dict) -> dict | None:
        """Select key for verification in OIDC Federation context."""
        available_keys = [key.to_dict() for key in self.jwks]

        # Case 1: find by kid in header
        if "kid" in header:
            if verifying_key := find_jwk_by_kid(available_keys, header["kid"]):
                return verifying_key

        # Case 2: self-contained key matching
        if self_contained_claims_key_pair := find_self_contained_key(header):
            _, candidate_key = self_contained_claims_key_pair
            if hasattr(candidate_key, "thumbprint"):
                if verifying_key := find_jwk_by_thumbprint(
                    available_keys, candidate_key.thumbprint
                ):
                    return verifying_key

        # Case 3: single key available
        if len(self.jwks) == 1:
            return self.jwks[0].to_dict()
            
        return None


def _validate_key_with_header_kid(key: dict, header: dict) -> None:
    """Validate kid consistency between key and header."""
    if (key_kid := key.get("kid")) and (header_kid := header.get("kid")) and (key_kid != header_kid):
        raise Exception(f"Key kid {key_kid} doesn't match header kid {header_kid}")


def _validate_key_with_jws_header(key: dict, protected_jws_header: dict, unprotected_jws_header: dict) -> None:
    """Validate key compatibility with JWS header in OIDC Federation context."""
    header = deepcopy(protected_jws_header)
    header.update(unprotected_jws_header)
    
    # Only validate kid in OIDC Federation (no X.509)
    _validate_key_with_header_kid(key, header)