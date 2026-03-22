# Google OIDC Authentication

This guide covers setting up Google OIDC authentication with optional group-based RBAC using Google Workspace groups.

## Overview

In Google auth mode, users authenticate via Google OAuth2. The backend:

1. Verifies the Google ID token against Google's public keys
2. Optionally resolves the user's Google Workspace group memberships
3. Issues a backend token (opaque, stored in SQLite) that the Pulumi CLI uses for subsequent requests
4. Enforces RBAC based on group membership (if configured)

## Prerequisites

- A Google Cloud project
- A Google Workspace domain (for group-based RBAC)
- `gcloud` CLI installed and authenticated

## Step 1: Create an OAuth2 Client

```bash
# Create OAuth consent screen (internal = Workspace users only)
# This must be done in the GCP Console:
# APIs & Services > OAuth consent screen > Internal

# Create OAuth client ID (Desktop type for CLI-based login)
# APIs & Services > Credentials > Create Credentials > OAuth client ID
# Application type: Desktop app
```

After creation, download the client secret JSON. The file will be named `client_secret_CLIENT_ID.apps.googleusercontent.com.json`.

Note the **Client ID** and **Client Secret** from the downloaded file.

## Step 2: Configure the Backend

Minimal configuration (no groups, no RBAC):

```bash
./pulumi-backend \
  -auth-mode=google \
  -google-client-id=YOUR_CLIENT_ID.apps.googleusercontent.com \
  -google-allowed-domains=yourdomain.com \
  -token-ttl=24h
```

Or via environment variables:

```bash
export PULUMI_BACKEND_AUTH_MODE=google
export PULUMI_BACKEND_GOOGLE_CLIENT_ID=YOUR_CLIENT_ID.apps.googleusercontent.com
export PULUMI_BACKEND_GOOGLE_ALLOWED_DOMAINS=yourdomain.com
export PULUMI_BACKEND_TOKEN_TTL=24h
./pulumi-backend
```

### Browser Login

To enable browser-based login (sign in with Google button), also provide the OAuth2 client secret:

```bash
./pulumi-backend \
  -auth-mode=google \
  -google-client-id=YOUR_CLIENT_ID.apps.googleusercontent.com \
  -google-client-secret=YOUR_CLIENT_SECRET \
  -google-allowed-domains=yourdomain.com
```

Then open `http://localhost:8080/login` in a browser. After signing in with Google, the page shows your access token with ready-to-use commands:

```bash
export PULUMI_ACCESS_TOKEN=pul-...
pulumi login http://localhost:8080
```

The browser login flow:
1. User clicks "Sign in with Google" on `/login`
2. Google OAuth consent screen → user approves
3. Backend exchanges the authorization code for an ID token (server-side)
4. ID token is validated and a backend access token is minted
5. Token is displayed on `/login/callback` with copy-to-clipboard

Without the client secret, the `/login` page is not available — users must obtain an ID token externally (e.g., via `gcloud auth print-identity-token`) and POST it to `/api/auth/token-exchange`.

### Automatic CLI Login (Zero Copy-Paste)

The backend implements the same browser login protocol as Pulumi Cloud. When configured, `pulumi login` will automatically open your browser for Google sign-in:

```bash
# Set PULUMI_CONSOLE_DOMAIN to point back to your backend
export PULUMI_CONSOLE_DOMAIN=localhost:8080

# Login — browser opens automatically, no token copy-paste needed
pulumi login http://localhost:8080
```

The flow:
1. `pulumi login` starts a temporary local HTTP server and opens `http://localhost:8080/cli-login?cliSessionPort=PORT&cliSessionNonce=NONCE`
2. Backend redirects to Google OAuth consent screen
3. After Google sign-in, backend mints a token and redirects to `http://localhost:PORT/?accessToken=TOKEN&nonce=NONCE`
4. The Pulumi CLI picks up the token automatically — done

For non-localhost deployments, set the domain accordingly:
```bash
export PULUMI_CONSOLE_DOMAIN=pulumi.internal.example.com
pulumi login https://pulumi.internal.example.com
```

You can add `PULUMI_CONSOLE_DOMAIN` to your shell profile to make it permanent.

## Step 3: Set Up Group-Based RBAC (Optional)

To use Google Workspace groups for RBAC, the backend's service account needs permission to read group memberships. Two approaches:

### Option A: Groups Reader Admin Role (recommended, no DWD)

The simplest approach — assign the SA a Workspace admin role that grants group read access. No domain-wide delegation, no SA key files, no admin email configuration.

1. Create a service account (or use an existing one):
   ```bash
   PROJECT_ID=$(gcloud config get project)
   SA_EMAIL=pulumi-backend@${PROJECT_ID}.iam.gserviceaccount.com

   gcloud iam service-accounts create pulumi-backend \
     --display-name="Pulumi Backend" \
     --project=$PROJECT_ID
   ```

2. In [Workspace Admin Console](https://admin.google.com) → Account → Admin roles:
   - Find the **Groups Reader** role (or create a custom role with Groups > Read permission)
   - Assign `pulumi-backend@PROJECT_ID.iam.gserviceaccount.com` to this role

3. No `--google-admin-email` flag needed. The backend uses the SA's own credentials to call the Admin SDK.

**Important:** Admin-role mode requires `-google-allowed-domains` — the first domain is used to scope the Admin SDK Groups.List API call. Without it, the API returns no results because the SA has no implicit Workspace identity.

### Option B: Domain-Wide Delegation (DWD)

Use DWD only when the Groups Reader admin role is not available (e.g., Workspace org policy restrictions preventing admin role assignment to service accounts).

**Keyless DWD (preferred for GCE/GKE):**

```bash
SA_EMAIL=pulumi-backend@${PROJECT_ID}.iam.gserviceaccount.com

gcloud services enable iamcredentials.googleapis.com --project=$PROJECT_ID

# Grant the SA permission to impersonate itself (needed for signJwt)
gcloud iam service-accounts add-iam-policy-binding $SA_EMAIL \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --project=$PROJECT_ID
```

**SA Key File (if keyless is not possible):**

```bash
gcloud iam service-accounts keys create sa-key.json \
  --iam-account=$SA_EMAIL \
  --project=$PROJECT_ID
```

**Enable DWD in Workspace Admin Console:**

1. Go to [admin.google.com](https://admin.google.com) → Security → API Controls → Domain-wide Delegation
2. Click "Add new"
3. Enter the SA's **Client ID** (numeric, found in GCP Console under the SA details)
4. Add scope: `https://www.googleapis.com/auth/admin.directory.group.readonly`
5. Click "Authorize"

### Create Workspace Groups

```bash
gcloud identity groups create \
  --organization=yourdomain.com \
  --group-email-address=platform-admins@yourdomain.com \
  --display-name="Platform Admins"

gcloud identity groups create \
  --organization=yourdomain.com \
  --group-email-address=developers@yourdomain.com \
  --display-name="Developers"

# Add members
gcloud identity groups memberships add \
  --group-email=platform-admins@yourdomain.com \
  --member-email=admin@yourdomain.com

gcloud identity groups memberships add \
  --group-email=developers@yourdomain.com \
  --member-email=dev@yourdomain.com
```

### 3e: Create RBAC Config

Create `rbac.yaml`:

```yaml
defaultPermission: read
groupRoles:
  - group: "platform-admins@yourdomain.com"
    permission: admin
  - group: "developers@yourdomain.com"
    permission: write
stackPolicies:
  - group: "developers@yourdomain.com"
    stackPattern: "myorg/*/dev-*"
    permission: admin
  - group: "platform-admins@yourdomain.com"
    stackPattern: "myorg/*/prod-*"
    permission: admin
```

Permission levels: `none < read < write < admin`.

### Run with Groups + RBAC

**Groups Reader admin role (no DWD):**

```bash
./pulumi-backend \
  -auth-mode=google \
  -google-client-id=YOUR_CLIENT_ID.apps.googleusercontent.com \
  -google-allowed-domains=yourdomain.com \
  -rbac-config=rbac.yaml
```

**Keyless DWD:**

```bash
./pulumi-backend \
  -auth-mode=google \
  -google-client-id=YOUR_CLIENT_ID.apps.googleusercontent.com \
  -google-sa-email=pulumi-backend@PROJECT_ID.iam.gserviceaccount.com \
  -google-admin-email=admin@yourdomain.com \
  -google-allowed-domains=yourdomain.com \
  -rbac-config=rbac.yaml
```

**With SA key file:**

```bash
./pulumi-backend \
  -auth-mode=google \
  -google-client-id=YOUR_CLIENT_ID.apps.googleusercontent.com \
  -google-sa-key=sa-key.json \
  -google-admin-email=admin@yourdomain.com \
  -google-allowed-domains=yourdomain.com \
  -rbac-config=rbac.yaml
```

## GKE / Workload Identity

When running on GKE with Workload Identity:

1. Create a Kubernetes service account and bind it to the GCP SA
2. The pod's ADC will automatically be the GCP SA

```bash
# Bind KSA to GSA
gcloud iam service-accounts add-iam-policy-binding $SA_EMAIL \
  --role="roles/iam.workloadIdentityUser" \
  --member="serviceAccount:${PROJECT_ID}.svc.id.goog[NAMESPACE/KSA_NAME]"
```

**With admin-role mode (recommended):** No additional flags needed beyond `-google-allowed-domains`. The SA auto-detects its email from the GCE metadata server and self-impersonates to obtain the Admin SDK scope.

**With DWD:** Add `-google-sa-email` so the backend can impersonate the SA for keyless DWD via IAM `signJwt`. No SA key file needed.

## All Google Auth Flags

| Flag | Env | Description |
|---|---|---|
| `-google-client-id` | `PULUMI_BACKEND_GOOGLE_CLIENT_ID` | OAuth2 client ID (required) |
| `-google-client-secret` | `PULUMI_BACKEND_GOOGLE_CLIENT_SECRET` | OAuth2 client secret (required for browser login) |
| `-google-sa-key` | `PULUMI_BACKEND_GOOGLE_SA_KEY` | Path to SA JSON key for Admin SDK groups |
| `-google-sa-email` | `PULUMI_BACKEND_GOOGLE_SA_EMAIL` | SA email (auto-detected on GCE for admin-role; required for keyless DWD) |
| `-google-admin-email` | `PULUMI_BACKEND_GOOGLE_ADMIN_EMAIL` | Workspace super-admin email for DWD subject |
| `-google-allowed-domains` | `PULUMI_BACKEND_GOOGLE_ALLOWED_DOMAINS` | Comma-separated allowed hosted domains |
| `-google-transitive-groups` | `PULUMI_BACKEND_GOOGLE_TRANSITIVE_GROUPS` | Resolve nested group memberships |
| `-token-ttl` | `PULUMI_BACKEND_TOKEN_TTL` | Backend-issued token lifetime (default `24h`) |
| `-groups-cache-ttl` | `PULUMI_BACKEND_GROUPS_CACHE_TTL` | Group membership cache TTL (default `5m`) |

## Token Lifecycle

Backend tokens are issued during Google OAuth login and stored in SQLite.

- **TTL**: Configurable via `-token-ttl` (default `24h`). Expired tokens are rejected on use.
- **Refresh token re-validation**: When users log in via the browser (`/login`) or CLI (`/cli-login`), the backend stores Google's OAuth2 refresh token alongside the backend token. On each authenticated request past half the token's TTL, the backend asynchronously re-validates against Google by exchanging the refresh token for a new ID token. If Google rejects the refresh (user deactivated, consent revoked), the backend token is immediately deleted. This follows the same pattern as [Dex's Google connector](https://github.com/dexidp/dex/blob/master/connector/google/google.go).
- **Deactivated users**: With refresh token re-validation, deactivated users are detected within half the token TTL. Without a refresh token (programmatic `POST /api/auth/token-exchange` flow), existing tokens remain valid until they expire.
- **Admin revocation**: Admins can immediately revoke all tokens for a user via `DELETE /api/admin/tokens/{userName}`. List a user's tokens via `GET /api/admin/tokens/{userName}`.
- **Groups cache invalidation**: Admins can force-refresh group memberships via `POST /api/admin/groups-cache/invalidate`. Useful after adding/removing users from Workspace groups — takes effect immediately instead of waiting for the cache TTL.
- **Short TTL**: Use a short `-token-ttl` (e.g. `1h`) for tighter security.

### Admin Endpoints

Requires RBAC admin permission (or single-tenant mode).

```bash
# List a user's tokens
curl -H "Authorization: token $ADMIN_TOKEN" \
  https://pulumi.example.com/api/admin/tokens/user@example.com

# Revoke all tokens for a user
curl -X DELETE -H "Authorization: token $ADMIN_TOKEN" \
  https://pulumi.example.com/api/admin/tokens/user@example.com

# Invalidate groups cache for a specific user (immediate RBAC re-evaluation)
curl -X POST -H "Authorization: token $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userName":"user@example.com"}' \
  https://pulumi.example.com/api/admin/groups-cache/invalidate

# Invalidate entire groups cache
curl -X POST -H "Authorization: token $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  https://pulumi.example.com/api/admin/groups-cache/invalidate
```

## Credential Resolution Order

The groups resolution mode is inferred from the flags you provide:

1. **No `-google-admin-email`** → **admin-role** mode (recommended). SA self-impersonates to get Admin SDK scope. Domain is taken from `-google-allowed-domains`.
2. **`-google-admin-email` + `-google-sa-key`** → **dwd-keyfile** mode. SA key file with DWD, Subject set to admin email.
3. **`-google-admin-email` + `-google-sa-email`** → **dwd-keyless** mode. ADC + IAM impersonate API for keyless DWD.
4. **`-google-admin-email` only** → **dwd-adc** mode. Plain ADC with DWD Subject (works only when ADC is a SA key file).
