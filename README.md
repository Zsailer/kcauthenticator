# Jupyter Authenticator for KeyCloak

**Do not use! This is still under heavy development and changing rapidly.**

This library provides a `KeycloakAuthenticator` class to authenticate requests to a Jupyterhub. [Keycloak](https://www.keycloak.org/index.html) is an open source identity and access management solution to secure applications and services.

The purpose of this project is to explore the advanced features of Keycloak (specifically, the group, role, and scope assignments and granular permissions) and how they might map onto Jupyterhub. User group membership and roles are sourced from Keycloak (instead of the jupyterhub database).
