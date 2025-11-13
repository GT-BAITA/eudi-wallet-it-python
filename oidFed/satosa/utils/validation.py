import logging

from satosa.context import Context

from oidFed.satosa.exceptions import InvalidRequestException
from oidFed.tools.content_type import (
    FORM_URLENCODED,
    APPLICATION_JSON,
    is_form_urlencoded,
    is_application_json
)

logger = logging.getLogger(__name__)


def validate_content_type(content_type_header: str, accepted_content_type: str):
    """
    Validate the Content-Type header against expected value.
    Args:
        content_type_header (str): The received Content-Type header.
        accepted_content_type (str): The expected value.
    Raises:
        InvalidRequestException: If the header does not match.
    """
    if (accepted_content_type == FORM_URLENCODED
            and not is_form_urlencoded(content_type_header)):
        logger.error(f"Invalid content-type for check `{FORM_URLENCODED}`: {content_type_header}")
        raise InvalidRequestException("invalid content-type")
    elif (accepted_content_type == APPLICATION_JSON
          and not is_application_json(content_type_header)):
        logger.error(f"Invalid content-type for check `{APPLICATION_JSON}`: {content_type_header}")
        raise InvalidRequestException("invalid content-type")

def validate_request_method(request_method: str, accepted_methods: list[str]):
    """
    Validate that the HTTP method is allowed.
    Args:
        request_method (str): The HTTP method.
        accepted_methods (list[str]): Allowed methods.
    Raises:
        InvalidRequestException: If the method is invalid.
    """
    if request_method is None or request_method.upper() not in accepted_methods:
        logger.error(f"endpoint invoked with wrong request method: {request_method}")
        raise InvalidRequestException("invalid request method")