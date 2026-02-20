# JWT Authentication

This guide covers setting up JWT authentication for the Pulumi backend. JWT mode is stateless — the backend validates tokens directly without storing them. Works with self-signed tokens (HMAC shared secret) for simple setups, or with external identity providers (Dex, Keycloak, Auth0, Okta, etc.) for production.

## Overview

In JWT mode:

1. Users provide a JWT — either self-generated (HMAC) or obtained from an identity provider
2. The Pulumi CLI sends the JWT as the access token (`Authorization: token <jwt>`)
3. The backend validates the JWT signature, expiry, and optionally issuer/audience
4. Username and groups are extracted from JWT claims
5. RBAC is enforced based on groups (if configured)

## Supported Key Types

The backend auto-detects the key type from the `-jwt-signing-key` value:

| Key Type | How to provide |
|---|---|
| **HMAC** (HS256/HS384/HS512) | Pass the secret string directly |
| **RSA** (RS256/RS384/RS512) | Pass a path to a PEM file containing the RSA public key |
| **ECDSA** (ES256/ES384/ES512) | Pass a path to a PEM file containing the EC public key |

## Quick Start with HMAC

Simplest setup — shared secret between the token issuer and the backend:

```bash
./pulumi-backend \
  -auth-mode=jwt \
  -jwt-signing-key="my-super-secret-key-at-least-32-chars"
```

Generate a token for testing:

```bash
# Using the `jwt` CLI tool (go install github.com/golang-jwt/jwt/v5/cmd/jwt@latest)
# Or any JWT library

# Python example:
python3 -c "
import jwt, time
token = jwt.encode({
    'sub': 'alice@example.com',
    'groups': ['developers', 'admins'],
    'exp': int(time.time()) + 86400
}, 'my-super-secret-key-at-least-32-chars', algorithm='HS256')
print(token)
"
```

Then use it with Pulumi:

```bash
export PULUMI_ACCESS_TOKEN=<the-jwt-from-above>
pulumi login http://localhost:8080
```

## Setup with RSA Keys

For production, use asymmetric keys. The backend only needs the **public key**.

```bash
# Generate key pair
openssl genrsa -out jwt-private.pem 2048
openssl rsa -in jwt-private.pem -pubout -o jwt-public.pem

# Start backend with public key
./pulumi-backend \
  -auth-mode=jwt \
  -jwt-signing-key=jwt-public.pem
```

## Setup with ECDSA Keys

```bash
# Generate key pair
openssl ecparam -name prime256v1 -genkey -noout -out jwt-ec-private.pem
openssl ec -in jwt-ec-private.pem -pubout -out jwt-ec-public.pem

# Start backend with public key
./pulumi-backend \
  -auth-mode=jwt \
  -jwt-signing-key=jwt-ec-public.pem
```

## Integration with Dex

[Dex](https://dexidp.io/) is an OIDC-compatible identity broker that supports LDAP, SAML, GitHub, Google, and more.

### Dex Configuration

```yaml
issuer: https://dex.example.com

connectors:
  - type: google
    id: google
    name: Google
    config:
      clientID: $GOOGLE_CLIENT_ID
      clientSecret: $GOOGLE_CLIENT_SECRET
      redirectURI: https://dex.example.com/callback

staticClients:
  - id: pulumi-backend
    name: Pulumi Backend
    secret: dex-client-secret
    redirectURIs:
      - http://localhost:8085/callback
```

### Backend Configuration

Use the Dex signing key (or fetch the JWKS URL and extract the public key):

```bash
./pulumi-backend \
  -auth-mode=jwt \
  -jwt-signing-key=/path/to/dex-public-key.pem \
  -jwt-issuer=https://dex.example.com \
  -jwt-audience=pulumi-backend \
  -jwt-username-claim=email \
  -jwt-groups-claim=groups
```

## Integration with Keycloak

### Keycloak Setup

1. Create a realm and client for pulumi-backend
2. Add group membership to the token claims:
   - Client Scopes > groups > Mappers > Add mapper > Group Membership
   - Set claim name to `groups`

### Backend Configuration

```bash
./pulumi-backend \
  -auth-mode=jwt \
  -jwt-signing-key=/path/to/keycloak-realm-public-key.pem \
  -jwt-issuer=https://keycloak.example.com/realms/myrealm \
  -jwt-audience=pulumi-backend \
  -jwt-groups-claim=groups
```

## RBAC with JWT Groups

Create `rbac.yaml`:

```yaml
defaultPermission: read
groupRoles:
  - group: "admins"
    permission: admin
  - group: "developers"
    permission: write
  - group: "viewers"
    permission: read
stackPolicies:
  - group: "developers"
    stackPattern: "myorg/*/dev-*"
    permission: admin
```

Run with RBAC:

```bash
./pulumi-backend \
  -auth-mode=jwt \
  -jwt-signing-key=jwt-public.pem \
  -rbac-config=rbac.yaml
```

Permission levels: `none < read < write < admin`.

## Token Requirements

The backend requires:

- **`exp` claim**: Tokens must have an expiration time
- **Username claim**: Defaults to `sub`, configurable via `-jwt-username-claim`

Optional:

- **Groups claim**: Defaults to `groups`, configurable via `-jwt-groups-claim`. Accepts JSON arrays (`["a", "b"]`) or comma-separated strings (`"a,b"`)
- **`iss` claim**: Validated only if `-jwt-issuer` is set
- **`aud` claim**: Validated only if `-jwt-audience` is set

## All JWT Flags

| Flag | Env | Default | Description |
|---|---|---|---|
| `-jwt-signing-key` | `PULUMI_BACKEND_JWT_SIGNING_KEY` | | HMAC secret or path to PEM public key (required) |
| `-jwt-issuer` | `PULUMI_BACKEND_JWT_ISSUER` | | Expected `iss` claim (optional) |
| `-jwt-audience` | `PULUMI_BACKEND_JWT_AUDIENCE` | | Expected `aud` claim (optional) |
| `-jwt-groups-claim` | `PULUMI_BACKEND_JWT_GROUPS_CLAIM` | `groups` | Claim name for group memberships |
| `-jwt-username-claim` | `PULUMI_BACKEND_JWT_USERNAME_CLAIM` | `sub` | Claim for username |
