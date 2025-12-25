import logging
from datetime import datetime

import satosa.logging_util as lu
from oic.utils.authn.authn_context import UNSPECIFIED
from satosa.exception import SATOSAAuthenticationError
from satosa.internal import AuthenticationInformation, InternalData

logger = logging.getLogger(__name__)


def translate_response(backend_instance, response, issuer):
    """
    Translates oidc response to SATOSA internal response.
    :type response: dict[str, str]
    :type issuer: str
    :type subject_type: str
    :rtype: InternalData

    :param response: Dictioary with attribute name as key.
    :param issuer: The oidc op that gave the repsonse.
    :param subject_type: public or pairwise according to oidc standard.
    :return: A SATOSA internal response.
    """
    auth_info = AuthenticationInformation(UNSPECIFIED, str(datetime.now()), issuer)
    internal_resp = InternalData(auth_info=auth_info)
    internal_resp.attributes = backend_instance.converter.to_internal(
        "openid", response
    )
    internal_resp.subject_id = response["sub"]
    return internal_resp


def check_error_response(response, context):
    """
    Check if the response is an OAuth error response.
    :param response: the OIDC response
    :type response: oic.oic.message
    :raise SATOSAAuthenticationError: if the response is an OAuth error response
    """
    if "error" in response:
        msg = "{name} error: {error} {description}".format(
            name=type(response).__name__,
            error=response["error"],
            description=response.get("error_description", ""),
        )
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        raise SATOSAAuthenticationError(context.state, "Access denied")
