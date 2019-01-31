import os
import json
import urllib
import base64

from tornado import gen, web
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient


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

    login_service = "Keycloak"
    realm = Unicode("master")
    login_handler = KeycloakLoginHandler
    token_url = keycloak_url_from_endpoint("token")
    userdata_url = keycloak_url_from_endpoint("userinfo")
    username_key = "preferred_username"
    manages_groups = Bool(True)

    group_key = Unicode(
        "groups",
        help="""
        The key in auth_state that lists the groups of the user.
        """
    )

    def _request_auth(self, handler, data=None):
        """Get authorization data from OAuth provider.
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

        {
            'name': oauth_user_data.get(self.username_key),
            'groups': [],
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'oauth_user': oauth_user_data,
                'scope': scope,
            }
        }

    def _request_userdata(self, access_token):
        """Get user data from the `userdata_url`.
        """
        http_client = AsyncHTTPClient()

        # Determine who the logged in user is
        auth_headers = {
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
                          headers=auth_headers,
                          validate_cert=self.tls_verify,
                          )
        resp = await maybe_future(http_client.fetch(req))
        user_data = json.loads(resp.body.decode('utf8', 'replace'))

        if not user_data.get(self.username_key):
            self.log.error("OAuth user contains no key %s: %s",
                           self.username_key, user_data)
            return

        return user_data

    async def refresh_user(self, user):
        # Get last saved authentication.
        access_token = user.get_user_data()["access_token"]

        # Request current data from provider.
        userdata = self._request_userdata(access_token)

    async def get_groups(self, user):
        """Pulls group data for user and stores data in database.

        Args:
            user (User): user to pull groups
        Return:
            groups (list): List of groups from authenticator for given user. 
        """
        # Get the the access token from the user's auth state
        access_token = user.get_auth_state()['access_token']
        user_data = self._request_userdata(access_token)
        try:
            groups = user_data[self.group_key]
        except KeyError:
            raise Exception("It doesn't look like {}' ".format(self.group_key),
                            "if a valid claim for your auth provider. Have you ",
                            "set up custom claims for groups?")
        return groups

    async def authenticate(self, handler, data=None):
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

        oauth_user_data = await maybe_future(self.get_user_data(access_token))

        return {
            'name': oauth_user_data.get(self.username_key),
            'groups': [],
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'oauth_user': oauth_user_data,
                'scope': scope,
            }
        }


class LocalKeycloakAuthenticator(LocalAuthenticator, KeycloakAuthenticator):
    """A version that mixes in local system user creation"""
    pass
