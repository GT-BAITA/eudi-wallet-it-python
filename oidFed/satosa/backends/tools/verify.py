import base64
import logging
import re
from datetime import datetime, timezone
from ssl import DER_cert_to_PEM_cert, PEM_cert_to_DER_cert

import pem
from cryptojwt.jwk import JWK
from OpenSSL import crypto

from oidFed.satosa.backends.federation.exceptions import JWSVerificationError

LOG_ERROR = "verification failed: {}"

logger = logging.getLogger(__name__)

_BASE64_RE = re.compile(
    "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)


def _check_datetime(exp: datetime | None):
    """
    :type exp: datetime.datetime | None

    :returns: True if chain expiration date is valid else False
    :rtype: bool
    """
    if exp is None:
        return True

    if datetime.now(timezone.utc) > exp:
        message = f"expired chain date -> {exp}"
        logging.warning(LOG_ERROR.format(message))
        return False

    return True


def B64DER_cert_to_DER_cert(cert: str) -> bytes:
    """
    Takes a certificate Base64 encoded DER and returns the
    certificate in DER format.
    """
    return base64.b64decode(cert)


def PEM_cert_to_B64DER_cert(cert: str) -> str:
    """
    Takes a certificate in ANSII PEM format and returns the base64
    encoding of the corresponding DER certificate.
    """
    return base64.b64encode(PEM_cert_to_DER_cert(cert)).decode()


def B64DER_cert_to_PEM_cert(cert: str) -> str:
    """
    Takes a certificate Base64 encoded DER and returns the
    certificate in ANSII PEM format.
    """
    return DER_cert_to_PEM_cert(base64.b64decode(cert))


def to_PEM_cert(cert: str | bytes) -> str:
    """
    This function takes in a certificate with unknown representation
    (allegedly, PEM, DER or Base64 encoded DER) and applies some
    heuristics to convert it to a PEM certificate.

    This function should be treated as UNSAFE and inefficient. Do NOT
    use it unless you do NOT hany prior way to know the actual representation
    format of a certificate
    """
    cert_b = b""

    if isinstance(cert, str):
        if is_pem_format(cert):
            return cert
        else:
            cert_b = cert.encode()
    else:
        cert_b = cert

    if isinstance(cert, bytes) and bytes(cert_b).startswith(
        b"-----BEGIN CERTIFICATE-----"
    ):
        return bytes(cert_b).decode()

    try:
        cert_s = bytes(cert_b).decode()
        if _BASE64_RE.fullmatch(cert_s):
            return B64DER_cert_to_PEM_cert(cert_s)
    except UnicodeError:
        return DER_cert_to_PEM_cert(cert_b)

    raise ValueError("unable to recognize input as a certificate")


def pem_to_pems_list(cert: str) -> list[str]:
    """
    Convert the x509 certificate chain from PEM to multiple PEMs.

    :param der: The x509 certificate chain in PEM format
    :type der: str

    :returns: The x509 certificate chain in PEM format
    :rtype: list[str]
    """
    return [str(cert) for cert in pem.parse(cert)]


def to_pem_list(der_list: list[bytes] | list[str]) -> list[str]:
    """
    If the input is a list of DER certificates, it will be converted to a list of PEM certificates.
    If the input is a list of PEM certificates, it will be returned as is.

    :param der: The x509 certificate chain in DER format
    :type der: list[bytes]

    :returns: The x509 certificate chain in PEM format
    :rtype: list[str]
    """
    return [to_PEM_cert(cert) for cert in der_list]


def is_pem_format(cert: str | bytes) -> bool:
    """
    Check if the certificate is in PEM format.

    :param cert: The certificate
    :type cert: bytes

    :returns: True if the certificate is in PEM format else False
    :rtype: bool
    """
    try:
        crypto.load_certificate(
            crypto.FILETYPE_PEM, cert.encode() if isinstance(cert, str) else cert
        )
        return True
    except crypto.Error as e:
        logging.error(LOG_ERROR.format(e))
        return False


def verify_jws_with_key(jws: str, key: JWK) -> None:
    """
    :raises JWSVerificationError: is signature verification fails for *any* reason
    """
    from oidFed.satosa.backends.federation.schemas.jwt.jws_helper import JWSHelper

    try:
        verifier = JWSHelper(key)
        verifier.verify(jws)
    except Exception as e:
        raise JWSVerificationError(f"error during signature verification: {e}", e)
