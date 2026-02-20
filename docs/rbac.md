# RBAC Configuration

Role-Based Access Control (RBAC) restricts what users can do based on their group memberships. Works with both Google OIDC and JWT authentication modes.

## Overview

RBAC is optional. Without it, all authenticated users have full admin access. When enabled, permissions are determined by:

1. **Default permission** — baseline for all authenticated users
2. **Group roles** — mapped from user's group memberships
3. **Stack policies** — override permissions for specific stack patterns

The highest applicable permission wins.

## Permission Levels

```
none < read < write < admin
```

| Permission | What it allows |
|---|---|
| `none` | Nothing (effectively locked out) |
| `read` | GET operations on stacks, exports, history |
| `write` | Everything in `read` + create stacks, start updates, checkpoint, encrypt/decrypt |
| `admin` | Everything in `write` + delete stacks, cancel updates, rename stacks. When set via `groupRoles`, it also grants **Global Admin** access to `/api/admin/*` endpoints. |

## Config File Format

```yaml
# Default permission for authenticated users with no matching group role.
# Omit or set to "none" to deny by default.
defaultPermission: read

# Map groups to permission levels.
# The highest matching group role applies.
groupRoles:
  - group: "viewers@example.com"
    permission: read
  - group: "developers@example.com"
    permission: write
  - group: "platform-admins@example.com"
    permission: admin

# Override permissions for specific stack patterns.
# Pattern format: "org/project/stack" with glob wildcards.
stackPolicies:
  - group: "developers@example.com"
    stackPattern: "myorg/*/dev-*"
    permission: admin
  - group: "platform-admins@example.com"
    stackPattern: "myorg/*/prod-*"
    permission: admin
```

## Stack Pattern Matching

Stack policies use glob patterns with `*` wildcards:

| Pattern | Matches |
|---|---|
| `myorg/myproject/dev` | Exactly `myorg/myproject/dev` |
| `myorg/*/dev-*` | Any project, stacks starting with `dev-` |
| `myorg/frontend/*` | All stacks in the `frontend` project |
| `*/*/*` | Everything (same as not having the policy) |

When multiple policies match, the highest permission wins.

## Examples

### Deny by Default, Explicit Access

```yaml
defaultPermission: none
groupRoles:
  - group: "engineering"
    permission: write
  - group: "ops"
    permission: admin
```

Users not in `engineering` or `ops` cannot access anything.

### Read-Only Default, Write for Devs

```yaml
defaultPermission: read
groupRoles:
  - group: "developers"
    permission: write
  - group: "admins"
    permission: admin
```

### Environment-Based Policies

```yaml
defaultPermission: read
groupRoles:
  - group: "developers"
    permission: write
  - group: "sre"
    permission: admin
stackPolicies:
  # Devs get admin on dev stacks
  - group: "developers"
    stackPattern: "myorg/*/dev-*"
    permission: admin
  # Only SRE can touch production
  - group: "sre"
    stackPattern: "myorg/*/prod-*"
    permission: admin
```

## Non-Stack Routes

RBAC only applies to stack-scoped operations (routes with `orgName` in the path). Routes like `/api/user`, `/api/user/stacks`, and public endpoints (`/`, `/metrics`, `/api/openapi`) are not subject to RBAC.

## Global vs Scoped Admin

The `admin` permission behaves differently depending on how it is granted:

1. **Global (System) Admin**: Granted via `groupRoles`. This allows the user to act as an administrator over the entire Pulumi Backend instance. It grants access to **all** `admin` level features across all stacks, as well as the system-wide Admin Endpoints.
2. **Scoped (Stack/Org) Admin**: Granted via `stackPolicies`. This allows the user to act as an administrator *only* over the specific stacks matched by the `stackPattern`. They can delete or rename those specific stacks, but they **cannot** access system-wide Admin Endpoints.

You should use `stackPolicies` with `*` wildcards to grant "Organization Admins" or "Project Admins", reserving the `groupRoles: admin` mapping for your actual backend infrastructure operators.

## Admin Endpoints

System-wide Admin endpoints (`/api/admin/*`) require the **Global Admin** permission level. This is determined by:

1. **Single-tenant mode**: All users are global admins automatically.
2. **Google/JWT mode with RBAC**: Users whose group resolves to `admin` permission via `groupRoles` get global admin access. 
3. **Google/JWT mode without RBAC**: Admin endpoints are inaccessible (no way to grant global admin).

Global Admin endpoints include:
- `POST /api/admin/backup` — Create a database SQLite backup safely using `VACUUM INTO`
- `GET /api/admin/tokens/{userName}` — List a user's API tokens (token hash prefix, description, timestamps)
- `DELETE /api/admin/tokens/{userName}` — Revoke all active tokens for a given user

## Enabling RBAC

```bash
./pulumi-backend -rbac-config=rbac.yaml
# or
export PULUMI_BACKEND_RBAC_CONFIG=rbac.yaml
```

RBAC requires an auth mode that provides group information (`google` or `jwt`). In `single-tenant` mode, RBAC configuration is ignored since all users are treated as admin.
