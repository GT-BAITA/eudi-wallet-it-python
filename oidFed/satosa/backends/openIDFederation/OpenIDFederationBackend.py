"""
OIDC backend module.
"""

import logging
from datetime import datetime
from urllib.parse import urlparse

import satosa.logging_util as lu
from oic.oauth2.message import SINGLE_OPTIONAL_STRING, SINGLE_REQUIRED_STRING
from oic.oic.message import AccessTokenRequest, AuthorizationResponse
from oic.utils.authn.authn_context import UNSPECIFIED
from oic.utils.settings import PyoidcSettings
from satosa.backends.base import BackendModule
from satosa.backends.oauth import get_metadata_desc_for_oauth_backend
from satosa.exception import (
    SATOSAAuthenticationError,
    SATOSAError,
    SATOSAMissingStateError,
)
from satosa.internal import AuthenticationInformation, InternalData
from satosa.response import Redirect

from oidFed.satosa.backends.openIDFederation.PreRequest import PreRequest

logger = logging.getLogger(__name__)

NONCE_KEY = "oidc_nonce"
STATE_KEY = "oidc_state"
CODE_VERIFIER_KEY = "oidc_code_verifier"

# SOBRESCREVER a classe original
AccessTokenRequest.c_param = {
    "grant_type": SINGLE_REQUIRED_STRING,
    "code": SINGLE_REQUIRED_STRING,
    "redirect_uri": SINGLE_REQUIRED_STRING,
    "client_id": SINGLE_REQUIRED_STRING,
    "client_secret": SINGLE_OPTIONAL_STRING,
    "state": SINGLE_OPTIONAL_STRING,
}


class OpenIDFederationBackend(BackendModule):
    """
    OIDC module
    """

    def __init__(self, auth_callback_func, internal_attributes, config, base_url, name):
        """
        OIDC backend module.
        :param auth_callback_func: Callback should be called by the module after the authorization
        in the backend is done.
        :param internal_attributes: Mapping dictionary between SATOSA internal attribute names and
        the names returned by underlying IdP's/OP's as well as what attributes the calling SP's and
        RP's expects namevice.
        :param config: Configuration parameters for the module.
        :param base_url: base url of the service
        :param name: name of the plugin

        :type auth_callback_func:
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]
        :type config: dict[str, dict[str, str] | list[str]]
        :type base_url: str
        :type name: str
        """
        super().__init__(auth_callback_func, internal_attributes, base_url, name)

        self.auth_callback_func = auth_callback_func
        self.config = config
        oidc_settings = PyoidcSettings(verify_ssl=self.config["network"]["verify_ssl"])

        try:
            self.pre_request_config = PreRequest(
                config=self.config, settings=oidc_settings, name=name
            )
        except Exception as exc:
            msg = {
                "message": f"Failed to initialize client",
                "error": str(exc),
                "client_metadata": self.config["federation"]["metadata"],
                "provider_metadata": self.config["client"]["provider_metadata"],
            }
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.error(logline)
            raise SATOSAAuthenticationError(context.state, msg) from exc

    def start_auth(self, context, request_info):
        """
        See super class method satosa.backends.base#start_auth
        """

        pre_request = self.pre_request_config.pre_request(context)

        args = {
            "scope": self.config["client"]["auth_req_params"]["scope"],
            "response_type": self.config["client"]["auth_req_params"]["response_type"],
            "client_id": self.config["federation"]["metadata"]["client_id"],
            "redirect_uri": self.config["federation"]["metadata"]["redirect_uris"][0],
            "state": pre_request["state"],
            "nonce": pre_request["nonce"],
            "code_challenge": pre_request["code_challenge"],
            "code_challenge_method": "S256",
        }

        args.update(self.config["client"]["auth_req_params"])
        auth_req = self.pre_request_config.client.construct_AuthorizationRequest(
            request_args=args
        )
        auth_req["request"] = pre_request["signed_jwt_request"]
        login_url = auth_req.request(
            self.pre_request_config.client.authorization_endpoint
        )

        return Redirect(login_url)

    def register_endpoints(self):
        """
        Creates a list of all the endpoints this backend module needs to listen to. In this case
        it's the authentication response from the underlying OP that is redirected from the OP to
        the proxy.
        :rtype: Sequence[(str, Callable[[satosa.context.Context], satosa.response.Response]]
        :return: A list that can be used to map the request to SATOSA to this endpoint.
        """

        logger.info(f"========= {self.config["client"]} =========")

        url_map = []

        redirect_path = urlparse(
            self.config["federation"]["metadata"]["redirect_uris"][0]
        ).path
        if not redirect_path:
            raise SATOSAError("Missing path in redirect uri")

        url_map.append(("^%s$" % redirect_path.lstrip("/"), self.response_endpoint))

        if hasattr(self, "pre_request_config") and self.pre_request_config.handler:
            federation_endpoints = self.pre_request_config.handler

            for path, handler in federation_endpoints:

                clean_path = path.lstrip("/")
                url_map.append((f"^{clean_path}$", handler))
                logger.info(f"Endpoint de federação registrado: {clean_path}")
        else:
            logger.warning(
                "Nenhum trust handler configurado para endpoints de federação"
            )

        return url_map

    def _verify_nonce(self, nonce, context):
        """
        Verify the received OIDC 'nonce' from the ID Token.
        :param nonce: OIDC nonce
        :type nonce: str
        :param context: current request context
        :type context: satosa.context.Context
        :raise SATOSAAuthenticationError: if the nonce is incorrect
        """
        backend_state = context.state[self.name]
        if nonce != backend_state[NONCE_KEY]:
            msg = "Missing or invalid nonce in authn response for state: {}".format(
                backend_state
            )
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.debug(logline)
            raise SATOSAAuthenticationError(
                context.state, "Missing or invalid nonce in authn response"
            )

    def _get_tokens(self, authn_response, context):
        """
        :param authn_response: authentication response from OP
        :type authn_response: oic.oic.message.AuthorizationResponse
        :return: access token and ID Token claims
        :rtype: Tuple[Optional[str], Optional[Mapping[str, str]]]
        """
        if "code" in authn_response:
            # CORREÇÃO CRÍTICA: Adiciona PKCE code_verifier no token request
            backend_state = context.state[self.name]
            code_verifier = backend_state.get(CODE_VERIFIER_KEY)

            args = {
                "code": authn_response["code"],
                "redirect_uri": self.pre_request_config.client.registration_response[
                    "redirect_uris"
                ][0],
                "client_id": self.pre_request_config.client.client_id,
                "grant_type": "authorization_code",
            }

            # Adiciona code_verifier se disponível (PKCE)
            if code_verifier:
                args["code_verifier"] = code_verifier
                logger.debug(f"Using PKCE code_verifier: {code_verifier}")

            token_resp = self.pre_request_config.client.do_access_token_request(
                scope="openid",
                state=authn_response["state"],
                request_args=args,
                authn_method=self.pre_request_config.client.registration_response[
                    "token_endpoint_auth_method"
                ],
            )

            self._check_error_response(token_resp, context)
            return token_resp["access_token"], token_resp["id_token"]

        return authn_response.get("access_token"), authn_response.get("id_token")

    def _check_error_response(self, response, context):
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
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.debug(logline)
            raise SATOSAAuthenticationError(context.state, "Access denied")

    def _get_userinfo(self, state, context):
        kwargs = {"method": self.config["client"].get("userinfo_request_method", "GET")}
        userinfo_resp = self.pre_request_config.client.do_user_info_request(
            state=state, **kwargs
        )
        self._check_error_response(userinfo_resp, context)
        return userinfo_resp.to_dict()

    def response_endpoint(self, context, *args):
        """
        Handles the authentication response from the OP.
        :type context: satosa.context.Context
        :type args: Any
        :rtype: satosa.response.Response

        :param context: SATOSA context
        :param args: None
        :return:
        """

        if self.name not in context.state:
            """
            If we end up here, it means that the user returns to the proxy
            without the SATOSA session cookie. This can happen at least in the
            following cases:
            - the user deleted the cookie from the browser
            - the browser of the user blocked the cookie
            - the user has completed an authentication flow, the cookie has
              been removed by SATOSA and then the user used the back button
              of their browser and resend the authentication response, but
              without the SATOSA session cookie
            """
            error = "Received AuthN response without a SATOSA session cookie"
            raise SATOSAMissingStateError(error)

        backend_state = context.state[self.name]
        authn_resp = self.pre_request_config.client.parse_response(
            AuthorizationResponse, info=context.request, sformat="dict"
        )

        if "state" not in authn_resp:
            msg = "Missing state in authn response"
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.debug(logline)
            raise SATOSAAuthenticationError(
                context.state, "Missing state in authn response"
            )

        if backend_state[STATE_KEY] != authn_resp["state"]:
            msg = "Missing or invalid state in authn response for state: {}".format(
                backend_state
            )
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.debug(logline)
            raise SATOSAAuthenticationError(
                context.state, "Missing or invalid state in authn response"
            )

        self._check_error_response(authn_resp, context)
        access_token, id_token_claims = self._get_tokens(authn_resp, context)
        if id_token_claims:
            self._verify_nonce(id_token_claims["nonce"], context)
        else:
            id_token_claims = {}

        userinfo = {}
        if access_token:
            # make userinfo request
            userinfo = self._get_userinfo(authn_resp["state"], context)

        if not id_token_claims and not userinfo:
            msg = "No id_token or userinfo, nothing to do.."
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.error(logline)
            raise SATOSAAuthenticationError(context.state, "No user info available.")

        all_user_claims = dict(list(userinfo.items()) + list(id_token_claims.items()))
        msg = "UserInfo: {}".format(all_user_claims)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        internal_resp = self._translate_response(
            all_user_claims, self.pre_request_config.client.authorization_endpoint
        )
        return self.auth_callback_func(context, internal_resp)

    def _translate_response(self, response, issuer):
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
        internal_resp.attributes = self.converter.to_internal("openid", response)
        internal_resp.subject_id = response["sub"]
        return internal_resp

    def get_metadata_desc(self):
        """
        See satosa.backends.oauth.get_metadata_desc
        :rtype: satosa.metadata_creation.description.MetadataDescription
        """
        return get_metadata_desc_for_oauth_backend(
            self.config["provider_metadata"]["issuer"], self.config
        )
