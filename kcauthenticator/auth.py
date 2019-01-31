import os
import json
import urllib
import base64

from tornado import gen, web
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient, HTTPClientError


from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import maybe_future

from oauthenticator.generic import GenericEnvMixin, GenericLoginHandler, GenericOAuthenticator

from traitlets import (
    Unicode,
    Bool
)

KEYCLOAK_HOST = "localhost"
PORT = 8080
REALM = "master"


def keycloak_url_from_endpoint(endpoint):
    return f"http://{KEYCLOAK_HOST}:{PORT}/auth/realms/{REALM}/protocol/openid-connect/{endpoint}"


def admin_url_from_endpoint(endpoint, *args):
    return f"http://{KEYCLOAK_HOST}:{PORT}/admin/realms/{REALM}/"


class KeycloakEnvMixin(GenericEnvMixin):
    _OAUTH_ACCESS_TOKEN_URL = keycloak_url_from_endpoint("token")
    _OAUTH_AUTHORIZE_URL = keycloak_url_from_endpoint("auth")


class KeycloakLoginHandler(GenericLoginHandler, KeycloakEnvMixin):
    pass


class KeycloakAuthenticator(GenericOAuthenticator):
    """Authenticates users using a Keycloak server.

    User model (if `manage_groups==True`)
    
    .. code-block: pythons

        {
            "name": "",
            "groups": [],
            "auth_state": {
                "access_token": "",
                "oauth_user": {},
                "refresh_token": "",
                "scope": ""
            }
        }

    """
    login_service = "Keycloak"
    realm = Unicode("master")
    login_handler = KeycloakLoginHandler
    token_url = keycloak_url_from_endpoint("token")
    introspect_url = keycloak_url_from_endpoint("introspect")
    userdata_url = keycloak_url_from_endpoint("userinfo")
    username_key = "preferred_username"
    manages_groups = Bool(True)

    group_key = Unicode(
        "groups",
        help="""
        The key in auth_state that lists the groups of the user.
        """
    )

    async def _request_auth(self, handler, data=None):
        """Requests an access token for the logged in user from Keycloak's 
        OpenID-connect API.
        """
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code'
        )
        params.update(self.extra_params)

        if self.token_url:
            url = self.token_url
        else:
            raise ValueError(
                "Please set the OAUTH2_TOKEN_URL environment variable")

        b64key = base64.b64encode(
            bytes(
                "{}:{}".format(self.client_id, self.client_secret),
                "utf8"
            )
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Basic {}".format(b64key.decode("utf8"))
        }
        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          validate_cert=self.tls_verify,
                          # Body is required for a POST...
                          body=urllib.parse.urlencode(params)
                          )

        resp = await maybe_future(http_client.fetch(req))

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']
        refresh_token = resp_json.get('refresh_token', None)
        scope = resp_json.get('scope', '')
        if (isinstance(scope, str)):
                scope = scope.split(' ')

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'scope': scope
        }

    async def _request_userdata(self, access_token):
        """Requests user info form.
        """
        http_client = AsyncHTTPClient()

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Bearer {}".format(access_token)
        }

        if self.userdata_url:
            url = url_concat(self.userdata_url, self.userdata_params)
        else:
            raise ValueError(
                "Please set the OAUTH2_USERDATA_URL environment variable")

        req = HTTPRequest(url,
                          method=self.userdata_method,
                          headers=headers,
                          validate_cert=self.tls_verify,
                          )
        resp = await maybe_future(http_client.fetch(req))
        user_data = json.loads(resp.body.decode('utf8', 'replace'))

        if not user_data.get(self.username_key):
            self.log.error("OAuth user contains no key %s: %s",
                           self.username_key, user_data)
            return

        return user_data

    async def _introspect_auth(self):
        """Introspect token to check whether it is active or not.
        """


    async def refresh_user(self, user):
        """Refresh auth data for a given user

        Allows refreshing or invalidating auth data.

        Args:
            user (User): the user to refresh
            handler (tornado.web.RequestHandler or None): the current request handler
        Returns:
            auth_data (bool or dict):
                Return **True** if auth data for the user is up-to-date
                and no updates are required.

                Return **False** if the user's auth data has expired,
                and they should be required to login again.

                Return a **dict** of auth data if some values should be updated.
                This dict should have the same structure as that returned
                by :meth:`.authenticate()` when it returns a dict.
                Any fields present will refresh the value for the user.
                Any fields not present will be left unchanged.
                This can include updating `.admin` or `.auth_state` fields.
        """
        # Request user data.
        try:
            # Get last saved token.
            access_token = user.get_auth_state()["access_token"]
            user_data = await maybe_future(self._request_userdata(access_token))
        except HTTPClientError as err:
            # If move is unauthorized, token is invalid or expired. 
            # Need to re-authenticate the user.
            if err.code == 401:
                return False
            else:
                raise err
        
        # Check group membership.
        if self.manage_groups:
            groups = self.get_groups(user)

        


    async def get_groups(self, user):
        """Requests te 

        Args:
            user (User): user to pull groups
        Return:
            groups (list): List of groups from authenticator for given user. 
        """
        if self.manage_groups is False:
            raise Exception("The authenticator is not configured to manage groups. ",
                "Set `authenticator.manage_groups = True` in your jupyterhub config ",
                "to enable jupyterhub to source groups from the authenticator provider."
            )

        # Get the the access token from the user's auth state
        access_token = user.get_auth_state()['access_token']
        user_data = self._request_userdata(access_token)
        try:
            groups = user_data.get(self.group_key)
        except KeyError:
            raise Exception("It doesn't look like {}' ".format(self.group_key),
                            "if a valid claim for your auth provider. Have you ",
                            "set up custom claims for groups?")
        return groups

    async def authenticate(self, handler, data=None):
        """Authenticate the user using keycloak's token API."""        
        auth_data = await maybe_future(self._request_auth(handler, data=data))

        # Get user data
        access_token = auth_data.get('access_token')
        user_data = await maybe_future(self._request_userdata(access_token))

        # Build auth_state
        auth_state = auth_data
        auth_state['oauth_user'] = user_data

        # Build user model to be passed to Jupyterhub.
        user_model = {
            'name': user_data.get(self.username_key),
            'auth_state': auth_state
        }

        # If the authenticator handles groups, source it from user data.
        if self.manages_groups:
            user_model['groups'] = user_data.get(self.group_key)

        return user_model


class LocalKeycloakAuthenticator(LocalAuthenticator, KeycloakAuthenticator):
    """A version that mixes in local system user creation"""
    pass
