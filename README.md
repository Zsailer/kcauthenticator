# Jupyter Authenticator for KeyCloak

**Do not use! This is still under heavy development and changing rapidly.**

This library provides a `KeycloakAuthenticator` class to authenticate requests to a Jupyterhub. [Keycloak](https://www.keycloak.org/index.html) is an open source identity and access management solution to secure applications and services.

The purpose of this project is to explore the advanced features of Keycloak (specifically, the group, role, and scope assignments and granular permissions) and how they might map onto Jupyterhub. User group membership and roles are sourced from Keycloak (instead of the jupyterhub database).

## Documentation

Using this authenticator requires you to enable `auth_state` in your jupyterhub deployment. You can do this by settings the `enable_auth_state = True` in your JupyterHub config. (See the example configuration below.)

The `auth_state` is encrypted when it gets stored in the JupyterHub database. JHub looks for an encryption key in your environment variables. You'll need to set the `JUPYTERHUB_CRYPT_KEY` variable to be a hex-encrypted 32-byte key:
```
export JUPYTERHUB_CRYPT_KEY=$(openssl rand -hex 32)
``` 
or if you use the [fish](https://fishshell.com/) shell like me: 
```
set -x JUPYTERHUB_CRYPT_KEY (openssl rand -hex 32)
```

If you plan to use KeyCloak to manage *groups* in your JupyterHub, you'll need to set `manage_groups = True` in your configuration. This will add a `"groups"` key to your user model when a user is authenticated. 

**Example `jupyterhub_config.py`**

Here's an example configuration using the `LocalKeycloakAuthenticator` to authenticate KeyCloak users with my local filesystem. JupyterHub groups are sourced from keycloak.

```python
from kcauthenticator import LocalKeycloakAuthenticator

c.JupyterHub.authenticator_class = LocalKeycloakAuthenticator
c.LocalKeycloakAuthenticator.oauth_callback_url = 'http://localhost:8000/hub/oauth_callback'
c.LocalKeycloakAuthenticator.client_id = "jupyterhub"
c.LocalKeycloakAuthenticator.client_secret = "<secret-from-keycloak>"
c.LocalKeycloakAuthenticator.manage_groups = True
c.LocalKeycloakAuthenticator.enable_auth_state = True
``` 