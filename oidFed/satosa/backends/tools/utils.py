import asyncio
import base64
import datetime
import importlib
import json
import logging
import os
import re
import time
from functools import lru_cache
from secrets import token_hex
from typing import NamedTuple, Type

import requests
import satosa.logging_util as lu
from satosa.exception import SATOSAAuthenticationError

from oidFed.satosa.backends.federation.exceptions import (
    InvalidEntityStatement,
    JWTDecodeError,
    JWTInvalidElementPosition,
)
from oidFed.satosa.backends.federation.schemas.federation.entity_configuration import (
    EntityStatementPayload,
)
from oidFed.satosa.backends.tools.http import http_get_async, http_get_sync

logger = logging.getLogger(__name__)

NONCE_KEY = "oidc_nonce"
JWT_REGEXP = r"^[_\w\-]+\.[_\w\-]+\.[_\w\-]+"
_HttpcParams_T = NamedTuple("_HttpcParams_T", [("ssl", bool), ("timeout", int)])


def make_timezone_aware(
    dt: datetime.datetime,
    tz: datetime.timezone | datetime.tzinfo = datetime.timezone.utc,
) -> datetime.datetime:
    """
    Make a datetime timezone aware.

    :param dt: The datetime to make timezone aware
    :type dt: datetime.datetime
    :param tz: The timezone to use
    :type tz: datetime.timezone | datetime.tzinfo

    :returns: The timezone aware datetime
    :rtype: datetime.datetime
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=tz)
    else:
        raise ValueError("datetime is already timezone aware")


def iat_now() -> int:
    """
    Get the current timestamp in seconds.

    :returns: The current timestamp in seconds
    :rtype: int
    """
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp())


def exp_from_now(minutes: int = 33) -> int:
    """
    Get the expiration timestamp in seconds for the given minutes from now.

    :param minutes: The minutes from now
    :type minutes: int

    :returns: The timestamp in seconds for the given minutes from now
    :rtype: int
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    return int((now + datetime.timedelta(minutes=minutes)).timestamp())


def datetime_from_timestamp(timestamp: int | float) -> datetime.datetime:
    """
    Get a datetime from a timestamp.

    :param value: The timestamp
    :type value: int | float

    :returns: The datetime
    :rtype: datetime.datetime
    """

    return make_timezone_aware(datetime.datetime.fromtimestamp(timestamp))


def timestamp_from_datetime(dt: datetime.datetime) -> int:
    """
    Get a timestamp from a datetime.

    :param dt: The datetime
    :type dt: datetime.datetime

    :returns: The timestamp
    :rtype: int
    """
    return int(dt.timestamp())


def get_http_url(
    urls: list[str] | str, httpc_params: dict, http_async: bool = True
) -> list[requests.Response]:
    """
    Perform an HTTP Request returning the payload of the call.

    :param urls: The url or a list of url where perform the GET HTTP calls
    :type urls: list[str] | str
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict
    :param http_async: if is set to True the operation will be performed in async (deafault True)
    :type http_async: bool

    :returns: A list of responses.
    :rtype: list[dict]
    """
    urls = urls if isinstance(urls, list) else [urls]

    if http_async:
        responses = asyncio.run(http_get_async(urls, httpc_params))  # pragma: no cover
    else:
        responses = http_get_sync(urls, httpc_params)
    return responses


def random_token(n=254) -> str:
    """
    Generate a random token.

    :param n: The length of the token
    :type n: int

    :returns: The random token
    :rtype: str
    """
    return token_hex(n)


def get_dynamic_class(module_name: str, class_name: str) -> Type:
    """
    Get a class type dynamically.

    :param module_name: The name of the module
    :type module_name: str
    :param class_name: The name of the class
    :type class_name: str

    :returns: The class type
    :rtype: Type
    """

    module = importlib.import_module(module_name)
    instance_class = getattr(module, class_name)
    return instance_class


def dynamic_class_loader(
    module_name: str, class_name: str, init_params: dict = {}
) -> object:
    """
    Load a class dynamically.

    :param module_name: The name of the module
    :type module_name: str
    :param class_name: The name of the class
    :type class_name: str
    :param init_params: The parameters to pass to the class constructor
    :type init_params: dict

    :returns: The class instance
    :rtype: object
    """

    dynamic_class = get_dynamic_class(module_name, class_name)
    if callable(dynamic_class):
        storage_instance = dynamic_class(**init_params)
    else:
        raise TypeError(
            f"The class '{class_name}' in module '{module_name}' is not callable."
        )
    return storage_instance


def cacheable_get_http_url(
    cache_ttl: int, url: str, httpc_params: dict, http_async: bool = True
) -> requests.Response:
    """
    Cached HTTP GET with TTL (seconds) implemented via lru_cache.
    The TTL is enforced by rounding a timestamp argument; entries expire after
    up to cache_ttl seconds. Minimum TTL is 1 second.
    Only httpc_params.connection.ssl (bool) and httpc_params.session.timeout (int)
    are supported and required. Non-200 responses will cause the cache to be cleared.
    """

    ssl: bool | None = httpc_params.get("connection", {}).get("ssl", None)
    timeout: int | None = httpc_params.get("session", {}).get("timeout", None)
    if (ssl is None) or (timeout is None):
        raise ValueError(
            f"invalid parameter {httpc_params=}: ['connection']['ssl'] and ['session']['timeout'] MUST be defined"
        )
    curr_time_s = time.time_ns() // 1_000_000_000
    if cache_ttl != 0:
        ttl_timestamp = curr_time_s // cache_ttl
    else:
        ttl_timestamp = curr_time_s
    httpc_p_tuple = _HttpcParams_T(ssl, timeout)
    resp = _lru_cached_get_http_url(
        ttl_timestamp, url, httpc_p_tuple, http_async=http_async
    )

    if resp.status_code != 200:
        _lru_cached_get_http_url.cache_clear()
    return resp


@lru_cache(maxsize=int(os.getenv("PYEUDIW_LRU_CACHE_MAXSIZE", 2048)))
def _lru_cached_get_http_url(
    timestamp: int,
    url: str,
    httpc_params_tuple: _HttpcParams_T,
    http_async: bool = True,
) -> requests.Response:
    """
    Wraps method 'get_http_url' around a ttl cache.
    This is done by including a timestamp in the function argument. For more,
    see the documentation of cacheable_get_http_url.

    Note that dictionary argument cannot be cached due to how lru_cache
    works; hence they are converted to a tuple.

    Moreover, a negative HTTP reponse might be cached. It is caller
    responsability to eventually clear the cache when it happens.
    """

    # explicitly delete dummy argument timestamp since it is only needed for caching lifetime
    del timestamp
    httpc_params = {
        "connection": {
            "ssl": httpc_params_tuple.ssl,
        },
        "session": {"timeout": httpc_params_tuple.timeout},
    }
    resp: list[requests.Response] = get_http_url([url], httpc_params, http_async)
    return resp[0]


def verify_nonce(backend_name, nonce, context):
    """
    Verify the received OIDC 'nonce' from the ID Token.
    :param nonce: OIDC nonce
    :type nonce: str
    :param context: current request context
    :type context: satosa.context.Context
    :raise SATOSAAuthenticationError: if the nonce is incorrect
    """
    backend_state = context.state[backend_name]
    if nonce != backend_state[NONCE_KEY]:
        msg = "Missing or invalid nonce in authn response for state: {}".format(
            backend_state
        )
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        raise SATOSAAuthenticationError(
            context.state, "Missing or invalid nonce in authn response"
        )


def is_es(payload: dict) -> None:
    """
    Determines if payload dict is a Subordinate Entity Statement

    :param payload: the object to determine if is a Subordinate Entity Statement
    :type payload: dict
    """

    try:
        EntityStatementPayload(**payload)
        if payload["iss"] == payload["sub"]:
            _msg = "Invalid Entity Statement: iss and sub cannot be the same"
            raise InvalidEntityStatement(_msg)
    except ValueError as e:
        _msg = f"Invalid Entity Statement: {e}"
        raise InvalidEntityStatement(_msg)


def decode_jwt_element(jwt: str, position: int) -> dict:
    """
    Decodes the element in a determinated position.

    :param jwt: a string that represents the jwt.
    :type jwt: str
    :param position: the position of segment to unpad.
    :type position: int

    :raises JWTInvalidElementPosition: If the JWT element position is greather then one or less of 0
    :raises JWTDecodeError: If the JWT element cannot be decoded.

    :returns: a dict with the content of the decoded section.
    :rtype: dict
    """
    if position < 0:
        raise JWTInvalidElementPosition(f"Cannot accept negative position {position}")

    if position > 2:
        raise JWTInvalidElementPosition(
            f"Cannot accept position greater than 2 {position}"
        )

    try:

        if isinstance(jwt, bytes):
            jwt = jwt.decode()

        splitted_jwt = jwt.split(".")

        if (len(splitted_jwt) - 1) < position:
            raise JWTInvalidElementPosition(
                f"JWT has no element in position {position}"
            )

        b64_data = jwt.split(".")[position]
        data = json.loads(base64_urldecode(b64_data))
        return data
    except JWTInvalidElementPosition as jwtInvalidElementPosition:
        raise jwtInvalidElementPosition
    except Exception as e:
        raise JWTDecodeError(f"Unable to decode JWT element: {e}")


def decode_jwt_header(jwt: str) -> dict:
    """
    Decodes the jwt header.

    :param jwt: a string that represents the jwt.
    :type jwt: str

    :raises JWTDecodeError: If the JWT header cannot be decoded.
    :raises JWTInvalidElementPosition: If the JWT element position is missing

    :returns: a dict with the content of the decoded header.
    :rtype: dict
    """
    return decode_jwt_element(jwt, position=0)


def decode_jwt_payload(jwt: str) -> dict:
    """
    Decodes the jwt payload.

    :param jwt: a string that represents the jwt.
    :type jwt: str

    :raises JWTDecodeError: If the JWT header cannot be decoded.
    :raises JWTInvalidElementPosition: If the JWT element position is missing

    :returns: a dict with the content of the decoded payload.
    :rtype: dict
    """
    return decode_jwt_element(jwt, position=1)


def is_jwt_format(jwt: str) -> bool:
    """
    Check if a string is in JWT format.

    :param jwt: a string that represents the jwt.
    :type jwt: str

    :returns: True if the string is a JWT, False otherwise.
    :rtype: bool
    """

    res = re.match(JWT_REGEXP, jwt)
    return bool(res)


def is_jwe_format(jwt: str):
    """
    Check if a string is in JWE format.

    :param jwt: a string that represents the jwt.
    :type jwt: str

    :returns: True if the string is a JWE, False otherwise.
    :rtype: bool
    """

    if not is_jwt_format(jwt):
        return False

    header = decode_jwt_header(jwt)

    if header.get("enc", None) is None:
        return False

    return True


def base64_urlencode(v: bytes) -> str:
    """Urlsafe base64 encoding without padding symbols

    :returns: the encooded data
    :rtype: str
    """
    return base64.urlsafe_b64encode(v).decode("ascii").strip("=")


def base64_urldecode(v: str) -> bytes:
    """Urlsafe base64 decoding. This function will handle missing
    padding symbols.

    :returns: the decoded data in bytes, format, convert to str use method '.decode("utf-8")' on result
    :rtype: bytes
    """
    padded = f"{v}{'=' * divmod(len(v), 4)[1]}"
    return base64.urlsafe_b64decode(padded)
