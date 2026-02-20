# Generic OIDC Authentication

This guide covers setting up generic OIDC authentication for any OpenID Connect provider (Okta, Entra ID, Keycloak, Dex, Auth0, etc.).

For Google Workspace with Admin SDK group resolution, see [auth-google.md](auth-google.md) instead.

## Overview

In OIDC mode, users authenticate via any OIDC-compliant identity provider. The backend:

1. Discovers the provider's configuration via `/.well-known/openid-configuration`
2. Verifies ID tokens using the provider's JWKS keys
3. Extracts username and groups from configurable token claims
4. Issues a backend token (opaque, stored in SQLite) that the Pulumi CLI uses for subsequent requests
5. Enforces RBAC based on group membership (if configured)

## Prerequisites

- An OIDC-compliant identity provider (Okta, Entra ID, Keycloak, Dex, Auth0, etc.)
- A client application registered with the provider (confidential client with client secret)
- The provider's issuer URL (e.g., `https://login.example.com/realms/myrealm`)

## Quick Start

```bash
./pulumi-backend \
  -auth-mode=oidc \
  -oidc-issuer=https://login.example.com/realms/myrealm \
  -oidc-client-id=pulumi-backend \
  -oidc-client-secret=YOUR_CLIENT_SECRET
```

Then log in:

```bash
# Automatic browser login (recommended)
export PULUMI_CONSOLE_DOMAIN=localhost:8080
pulumi login http://localhost:8080

# Or manual browser login
# Open http://localhost:8080/login, sign in, copy token
export PULUMI_ACCESS_TOKEN=pul-...
pulumi login http://localhost:8080
```

## Configuration

### Required Flags

| Flag | Env | Default | Description |
|---|---|---|---|
| `-oidc-issuer` | `PULUMI_BACKEND_OIDC_ISSUER` | | OIDC provider discovery URL (required) |
| `-oidc-client-id` | `PULUMI_BACKEND_OIDC_CLIENT_ID` | | OAuth2 client ID (required) |
| `-oidc-client-secret` | `PULUMI_BACKEND_OIDC_CLIENT_SECRET` | | OAuth2 client secret (required) |

### Optional Flags

| Flag | Env | Default | Description |
|---|---|---|---|
| `-oidc-allowed-domains` | `PULUMI_BACKEND_OIDC_ALLOWED_DOMAINS` | | Comma-separated allowed email domains |
| `-oidc-scopes` | `PULUMI_BACKEND_OIDC_SCOPES` | `profile,email` | Additional scopes beyond `openid` |
| `-oidc-groups-claim` | `PULUMI_BACKEND_OIDC_GROUPS_CLAIM` | `groups` | Claim key for group memberships |
| `-oidc-username-claim` | `PULUMI_BACKEND_OIDC_USERNAME_CLAIM` | `email` | Claim key for username |
| `-oidc-provider-name` | `PULUMI_BACKEND_OIDC_PROVIDER_NAME` | `SSO` | Display name on the login page |
| `-token-ttl` | `PULUMI_BACKEND_TOKEN_TTL` | `24h` | Backend-issued token lifetime |

### Domain Filtering

Restrict logins to specific email domains:

```bash
./pulumi-backend \
  -auth-mode=oidc \
  -oidc-issuer=https://login.example.com \
  -oidc-client-id=pulumi-backend \
  -oidc-client-secret=SECRET \
  -oidc-allowed-domains=example.com,subsidiary.com
```

Domain filtering checks the email suffix from the username claim (not the Google-specific `hd` claim used in `google` mode).

## Provider-Specific Setup

### Okta

1. Create an "OIDC - Web Application" in Okta Admin > Applications
2. Set sign-in redirect URI to `http://localhost:8080/login/callback` (and `/welcome/cli` for CLI login)
3. Assign users/groups to the application
4. Enable "groups" claim in the ID token (Authorization Server > Claims > Add Claim)

```bash
./pulumi-backend \
  -auth-mode=oidc \
  -oidc-issuer=https://yourorg.okta.com \
  -oidc-client-id=0oa... \
  -oidc-client-secret=... \
  -oidc-provider-name=Okta
```

### Microsoft Entra ID (Azure AD)

1. Register an application in Azure Portal > App registrations
2. Add redirect URIs: `http://localhost:8080/login/callback` and `http://localhost:8080/welcome/cli`
3. Create a client secret under Certificates & secrets
4. Configure optional claims: add `groups` claim to the ID token

```bash
./pulumi-backend \
  -auth-mode=oidc \
  -oidc-issuer=https://login.microsoftonline.com/TENANT_ID/v2.0 \
  -oidc-client-id=APPLICATION_ID \
  -oidc-client-secret=CLIENT_SECRET \
  -oidc-provider-name="Microsoft"
```

### Keycloak

1. Create a client in your realm with "confidential" access type
2. Set valid redirect URIs
3. Add a "Group Membership" mapper to include groups in the ID token

```bash
./pulumi-backend \
  -auth-mode=oidc \
  -oidc-issuer=https://keycloak.example.com/realms/myrealm \
  -oidc-client-id=pulumi-backend \
  -oidc-client-secret=... \
  -oidc-provider-name=Keycloak
```

Keycloak may return groups as objects (`[{"name": "group-name"}]`) — the backend handles both string arrays and object arrays with a `name` field.

### Dex

```bash
./pulumi-backend \
  -auth-mode=oidc \
  -oidc-issuer=https://dex.example.com \
  -oidc-client-id=pulumi-backend \
  -oidc-client-secret=dex-client-secret \
  -oidc-provider-name=SSO
```

## Browser Login

The login page at `/login` shows a "Sign in with {provider-name}" button. The flow:

1. User clicks sign-in on `/login`
2. Redirected to OIDC provider consent screen
3. Provider redirects back with authorization code
4. Backend exchanges code for ID token (server-side)
5. ID token is validated and a backend access token is minted
6. Token displayed on `/login/callback` with copy-to-clipboard

### Automatic CLI Login

The backend implements the same browser login protocol as Pulumi Cloud:

```bash
export PULUMI_CONSOLE_DOMAIN=localhost:8080
pulumi login http://localhost:8080  # opens browser automatically
```

## RBAC with OIDC Groups

Groups from the ID token's claims are stored with the backend token and used for RBAC.

Create `rbac.yaml`:

```yaml
defaultPermission: read
groupRoles:
  - group: "platform-admins"
    permission: admin
  - group: "developers"
    permission: write
stackPolicies:
  - group: "developers"
    stackPattern: "myorg/*/dev-*"
    permission: admin
```

```bash
./pulumi-backend \
  -auth-mode=oidc \
  -oidc-issuer=https://login.example.com \
  -oidc-client-id=pulumi-backend \
  -oidc-client-secret=SECRET \
  -rbac-config=rbac.yaml
```

## Token Lifecycle

- **TTL**: Configurable via `-token-ttl` (default `24h`). Expired tokens are rejected.
- **Refresh token re-validation**: When users log in via browser or CLI, the backend stores the provider's refresh token. Past half the token's TTL, the backend asynchronously re-validates by exchanging the refresh token. If the provider rejects it (user deactivated, consent revoked), the backend token is deleted.
- **Programmatic access**: POST an ID token to `/api/auth/token-exchange` to get a backend token without browser flow.
- **Admin revocation**: `DELETE /api/admin/tokens/{userName}` immediately revokes all tokens for a user.

## Google vs OIDC Mode

| Feature | `google` mode | `oidc` mode |
|---|---|---|
| Provider | Google only | Any OIDC provider |
| Domain check | Google `hd` claim | Email domain suffix |
| Groups | Google Admin SDK (live resolution) | ID token claims (stored at login) |
| Group cache | Server-side via Admin SDK | N/A (from token) |
| DWD/Workload Identity | Supported | N/A |

Use `google` mode when you need Google Workspace group resolution via Admin SDK. Use `oidc` mode for everything else.
