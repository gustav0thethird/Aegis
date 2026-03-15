# Aegis

> **Vendor-agnostic secrets broker and PAM gateway.**
> One API key per team. Any vault. Every action logged, attributed, and queryable.

Aegis is a thin, audited proxy that sits between your applications and your secrets infrastructure. Teams authenticate with a single scoped API key and receive exactly the secrets they are authorised to see — regardless of whether those secrets live in CyberArk, HashiCorp Vault, AWS Secrets Manager, or Conjur. Every fetch, every rotation, and every configuration change is written to an immutable log with structured before/after diffs and full account attribution.

---

## Contents

- [Why Aegis](#why-aegis)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Data Model](#data-model)
- [Request Lifecycle](#request-lifecycle)
- [Concepts](#concepts)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [auth.json](#authjson)
  - [Vendor Configuration Reference](#vendor-configuration-reference)
  - [Environment Variables](#environment-variables)
  - [Runtime Settings](#runtime-settings)
- [API Reference](#api-reference)
  - [Secrets Endpoint](#secrets-endpoint)
  - [Authentication](#authentication)
  - [Objects](#objects)
  - [Registries](#registries)
  - [Teams](#teams)
  - [Users](#users)
  - [Logs](#logs)
  - [Settings](#settings)
- [Admin Panel](#admin-panel)
- [Roles and Access Control](#roles-and-access-control)
- [Key Management](#key-management)
- [Audit and Change Logging](#audit-and-change-logging)
- [SIEM Integration](#siem-integration)
- [Rate Limiting](#rate-limiting)
- [Database Schema](#database-schema)
- [Themes](#themes)
- [Security Model](#security-model)
- [Backup and Recovery](#backup-and-recovery)
- [Health Check](#health-check)

---

## Why Aegis

Most organisations accumulate secrets sprawl over time: applications that talk directly to CyberArk, others that hit Vault, a handful that pull from AWS SSM — each with its own credential logic, its own rotation story, and no centralised visibility. When a safe is renamed, a token expires, or a key leaks, you find out by watching something break in production.

**Aegis solves this by being the only secrets endpoint your applications ever need to know about.**

- Applications present one API key. Aegis resolves it to a team + registry pair and fetches the secrets from whichever upstream vault holds them.
- Admins manage everything through a single panel. Objects can be migrated between vendors without touching application code — just update the object definition.
- Every request is logged with the team identity, the registry accessed, the list of objects fetched, the source IP, and the ITSM change number. There is no way to fetch a secret without leaving a trace.
- API keys are scoped to a specific team-registry assignment. If Team A and Team B both access the same registry, they use different keys. If either key is compromised, only that assignment needs to be rotated — the other team is unaffected.

---

## How It Works

```
Your Application                Aegis                    Upstream Vault
      │                            │                            │
      │  GET /secrets              │                            │
      │  X-API-Key: sk_...         │                            │
      │  X-Change-Number: CHG123   │                            │
      ├───────────────────────────►│                            │
      │                            │  1. Hash key → lookup      │
      │                            │     team + registry        │
      │                            │                            │
      │                            │  2. Enforce change number  │
      │                            │                            │
      │                            │  3. Check rate limit       │
      │                            │     (Redis counter)        │
      │                            │                            │
      │                            │  4. Fetch secrets per      │
      │                            │     vendor (CyberArk,      │
      │                            ├───────────────────────────►│
      │                            │◄───────────────────────────┤
      │                            │     Vault, AWS, Conjur)    │
      │                            │                            │
      │                            │  5. Write audit log        │
      │                            │     (team, registry,       │
      │                            │      objects, IP, CHG#)    │
      │                            │                            │
      │                            │  6. Emit SIEM event        │
      │                            │     (stdout/Splunk/S3/DD)  │
      │                            │                            │
      │  { secret_name: value }    │                            │
      │◄───────────────────────────│                            │
```

---

## Architecture

```mermaid
graph TB
    subgraph Applications
        A1[App / Pipeline]
        A2[CI Runner]
        A3[Service Mesh]
    end

    subgraph Aegis["Aegis (FastAPI + Python)"]
        GW[GET /secrets]
        RL[Rate Limiter]
        AUTH[Key Auth & RBAC]
        FETCH[Secret Fetcher]
        AUDIT[Audit Writer]
        SIEM_E[SIEM Emitter]
        ADMIN[Admin API + Panel]
    end

    subgraph Session["Session Store"]
        REDIS[(Redis)]
    end

    subgraph Persistence["Persistence"]
        PG[(PostgreSQL)]
    end

    subgraph Vaults["Upstream Vaults"]
        CA[CyberArk\nCCP + PVWA]
        HV[HashiCorp Vault\nKV v1/v2]
        AWS[AWS\nSecrets Manager / SSM]
        CO[Conjur\nOSS / Enterprise]
    end

    subgraph SIEM["SIEM Destinations"]
        STDOUT[stdout\nDocker log driver]
        SP[Splunk HEC]
        S3[AWS S3\ngzip + JSONL]
        DD[Datadog\nLogs API]
    end

    A1 & A2 & A3 -->|X-API-Key + X-Change-Number| GW
    GW --> RL
    RL -->|counter check| REDIS
    RL --> AUTH
    AUTH -->|key hash lookup| PG
    AUTH --> FETCH
    FETCH -->|vendor dispatch| CA & HV & AWS & CO
    FETCH --> AUDIT
    AUDIT -->|write audit_log| PG
    AUDIT --> SIEM_E
    SIEM_E --> STDOUT & SP & S3 & DD

    ADMIN -->|session tokens| REDIS
    ADMIN -->|read/write| PG
```

---

## Data Model

```mermaid
erDiagram
    objects {
        text name PK
        text vendor
        text auth_ref
        text path
        text platform
        text safe
        timestamptz created_at
        text created_by
    }

    registries {
        uuid id PK
        text name
        timestamptz created_at
        text created_by
    }

    registry_objects {
        uuid registry_id FK
        text object_name FK
        timestamptz assigned_at
    }

    teams {
        uuid id PK
        text name
        timestamptz created_at
        text created_by
    }

    team_registries {
        uuid team_id FK
        uuid registry_id FK
        timestamptz assigned_at
        text assigned_by
    }

    team_registry_keys {
        uuid id PK
        uuid team_id FK
        uuid registry_id FK
        text key_hash
        text key_preview
        timestamptz created_at
        timestamptz revoked_at
    }

    users {
        uuid id PK
        text username
        text password_hash
        text role
        uuid team_id
        text theme
        timestamptz created_at
        text created_by
    }

    settings {
        text key PK
        text value
        timestamptz updated_at
        text updated_by
    }

    change_log {
        bigint id PK
        timestamptz timestamp
        text action
        text entity_type
        text entity_id
        text entity_name
        text detail
        jsonb diff
        text performed_by
    }

    audit_log {
        bigint id PK
        timestamptz timestamp
        text event
        text outcome
        text change_number
        uuid registry_id
        text registry_name
        uuid team_id
        text team_name
        text[] objects
        text key_preview
        text source_ip
        text user_agent
        text error_detail
    }

    registries ||--o{ registry_objects : contains
    objects ||--o{ registry_objects : "referenced by"
    teams ||--o{ team_registries : "assigned to"
    registries ||--o{ team_registries : "assigned to"
    teams ||--o{ team_registry_keys : "holds"
    registries ||--o{ team_registry_keys : "scopes"
```

---

## Request Lifecycle

```mermaid
sequenceDiagram
    participant App as Application
    participant Aegis as Aegis API
    participant Redis as Redis
    participant DB as PostgreSQL
    participant Vault as Upstream Vault
    participant SIEM as SIEM

    App->>Aegis: GET /secrets<br/>X-API-Key: sk_...<br/>X-Change-Number: CHG123

    Aegis->>DB: SHA-256(key) → team_registry_keys
    DB-->>Aegis: TeamRegistryKey (team + registry)

    alt Key not found or revoked
        Aegis->>DB: Write audit_log (auth.failed)
        Aegis-->>App: 401 Unauthorized
    end

    Aegis->>DB: Read settings (change_number_required)
    alt Change number required but missing
        Aegis->>DB: Write audit_log (secrets.blocked)
        Aegis-->>App: 403 Forbidden
    end

    Aegis->>Redis: INCR rate:key_id / EXPIRE
    alt Rate limit exceeded
        Aegis->>DB: Write audit_log (secrets.blocked)
        Aegis-->>App: 429 Too Many Requests
    end

    Aegis->>DB: Load registry objects
    Aegis->>Vault: Fetch secrets (per vendor)
    Vault-->>Aegis: Secret values

    Aegis->>DB: Write audit_log (secrets.fetched, success)
    Aegis->>SIEM: Emit structured event

    Aegis-->>App: 200 { secret_name: value, ... }
```

---

## Concepts

| Concept | Description |
|---|---|
| **Object** | A pointer to a single secret in an upstream vault. Stores the vendor, the `auth_ref` (which credential set in `auth.json` to use), and the vendor-specific path/safe/object name. Objects are vendor-agnostic from the application's perspective. |
| **Registry** | A named collection of objects. The atomic unit of access control — teams are granted access to registries, not to individual objects. One registry might represent all secrets needed by a particular application or environment. |
| **Team** | A logical grouping of applications or human operators that need the same set of secrets. A team has no credentials of its own — access is expressed through team-registry assignments. |
| **Team-Registry Key** | A unique API key issued when a team is assigned a registry. A team with access to three registries has three separate keys. Every audit log entry traces back to an exact `(team, registry)` pair — not just a registry. |
| **Auth Ref** | A string that maps to a credential block in `auth.json`. For example, `"prod"` might map to the production CyberArk installation. Multiple objects can share the same auth ref; changing the underlying credentials only requires updating `auth.json`. |
| **Change Log** | An immutable, append-only record of every admin mutation. Each entry includes the entity type, the action, a JSONB diff showing exactly which fields changed and their before/after values, and the operator account that performed the action. |
| **Audit Log** | An immutable, append-only record of every `/secrets` request. Captures outcome, team, registry, objects fetched, source IP, user agent, and ITSM change number. Fields are snapshotted at request time so they remain accurate even if the entity is later renamed or deleted. |

---

## Quick Start

### Prerequisites

- Docker ≥ 24 and Docker Compose v2
- One or more supported upstream vaults (CyberArk, HashiCorp Vault, AWS, Conjur)
- Credentials for those vaults ready to drop into `auth.json`

### 1. Clone and configure credentials

```bash
git clone <repo-url> aegis
cd aegis

cp config/auth.json.example config/auth.json
$EDITOR config/auth.json
```

### 2. Set your admin password

Edit `docker-compose.yml`:

```yaml
environment:
  ADMIN_PASSWORD: your-strong-password-here
```

### 3. Start

```bash
docker compose up -d
```

On first start, Aegis will:

1. Wait for PostgreSQL and Redis to be healthy
2. Run all database migrations (`alembic upgrade head`)
3. Seed the default `admin` account using `ADMIN_PASSWORD`
4. Start the API on **http://localhost:8080**

### 4. Open the admin panel

Navigate to **http://localhost:8080** and log in with `admin` / your password.

### 5. Set up your first secret delivery

**Step 1 — Define an object** (what secret and where it lives):

```
Objects → New Object
  Name:     db_password
  Vendor:   vault
  Auth Ref: prod
  Path:     secret/data/myapp/db
```

**Step 2 — Create a registry** (a named collection):

```
Registries → New Registry
  Name: myapp-prod
  → Add Object → db_password
```

**Step 3 — Create a team and assign access:**

```
Teams → New Team
  Name: myapp

Teams → myapp → Assign Registry → myapp-prod
  ↳ Copy the API key from the modal. It is shown exactly once.
```

**Step 4 — Fetch from your application:**

```bash
curl http://localhost:8080/secrets \
  -H "X-API-Key: sk_<your-key>" \
  -H "X-Change-Number: CHG0012345"
```

```json
{
  "db_password": "correct-horse-battery-staple"
}
```

---

## Configuration

### auth.json

Mounted into the container at `AUTH_PATH` (default `/config/auth.json`). Defines named credential sets per vendor. The `auth_ref` field on each object points to a key in this file, allowing multiple objects to share the same credential set.

```json
{
  "cyberark": {
    "prod": {
      "host":        "cyberark.example.com",
      "app_id":      "BrokerApp",
      "auth_safe":   "Broker-Auth-Safe",
      "auth_object": "Broker-ServiceAccount"
    }
  },
  "vault": {
    "prod": {
      "addr":  "https://vault.example.com:8200",
      "token": "s.XXXXXXXXXXXXXXXXXXXX",
      "mount": "secret"
    },
    "dev": {
      "addr":  "http://vault-dev.internal:8200",
      "token": "root"
    }
  },
  "aws": {
    "prod": { "region": "eu-west-1" }
  },
  "conjur": {
    "prod": {
      "host":    "conjur.example.com",
      "account": "myorg",
      "login":   "host/aegis",
      "api_key": "XXXXXXXXXXXXXXXXXXXX"
    }
  }
}
```

> `config/auth.json` is excluded from version control by `.gitignore`. Never commit real credentials. Use `config/auth.json.example` as the committed template.

Updating `auth.json` on disk takes effect on the next `/secrets` request — the file is re-read per request via `load_auth()`. No restart needed.

---

### Vendor Configuration Reference

#### CyberArk (CCP + PVWA)

Aegis uses a two-step authentication flow: CCP retrieves the service account credentials stored in CyberArk, then those credentials are used to log into PVWA and fetch the target secret.

| Field | Description |
|---|---|
| `host` | CyberArk hostname (PVWA + CCP) |
| `app_id` | CCP Application ID |
| `auth_safe` | Safe containing the Aegis service account object |
| `auth_object` | Object name of the Aegis service account in CyberArk |

On the object itself, set:
- `safe` — the safe containing the target secret
- `platform` — the platform ID (e.g. `WinDomainAccount`)
- `path` — the account name / object name in that safe

#### HashiCorp Vault (KV v1 / v2)

| Field | Description |
|---|---|
| `addr` | Vault server address including port |
| `token` | Vault token with read access to the relevant paths |
| `mount` | KV secrets engine mount path (default: `secret`) |

On the object, `path` is the secret path within the mount (e.g. `myapp/db`).

#### AWS (Secrets Manager + SSM + STS)

| Field | Description |
|---|---|
| `region` | AWS region |

Aegis uses the default boto3 credential chain (instance profile, environment variables, `~/.aws/credentials`). For cross-account access, a role ARN can be assumed via STS.

On the object, `path` is the Secrets Manager secret name or SSM parameter path.

#### Conjur (OSS / Enterprise)

| Field | Description |
|---|---|
| `host` | Conjur server hostname |
| `account` | Conjur account name |
| `login` | Host or user identity (e.g. `host/aegis`) |
| `api_key` | API key for the Conjur identity |

On the object, `path` is the Conjur variable path (e.g. `prod/database/password`).

---

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Yes | — | PostgreSQL DSN (`postgresql://user:pass@host/db`) |
| `REDIS_URL` | Yes | — | Redis DSN (`redis://host:6379`) |
| `AUTH_PATH` | Yes | — | Filesystem path to `auth.json` inside the container |
| `ADMIN_PASSWORD` | Yes | — | Bootstrap password for the `admin` account (used on first start only) |
| `RATE_LIMIT_RPM` | No | `60` | Per-key requests per minute. Used as fallback if DB setting is absent. |
| `LOG_DESTINATIONS` | No | `stdout` | Comma-separated SIEM targets. Used as fallback if DB setting is absent. |
| `SPLUNK_HEC_URL` | No | — | Splunk HEC endpoint URL |
| `SPLUNK_HEC_TOKEN` | No | — | Splunk HEC authentication token |
| `S3_LOG_BUCKET` | No | — | S3 bucket name for audit log shipping |
| `S3_LOG_PREFIX` | No | `aegis` | S3 key prefix |
| `DD_API_KEY` | No | — | Datadog API key |
| `DD_SITE` | No | `datadoghq.com` | Datadog intake site (`datadoghq.com` or `datadoghq.eu`) |

---

### Runtime Settings

The following settings are stored in the `settings` table and can be changed live from **Settings → General** in the admin panel without restarting the service. Database values take precedence over environment variables.

| Key | Default | Description |
|---|---|---|
| `change_number_required` | `true` | Require `X-Change-Number` on every `/secrets` request. Set to `false` for non-ITIL environments. |
| `rate_limit_rpm` | `60` | Requests per minute per API key. Enforced via Redis sliding window. |
| `session_ttl_hours` | `8` | Admin session lifetime in hours. Applies to new sessions; existing sessions are not immediately invalidated. |
| `log_retention_days` | `90` | Number of days shown in audit log queries. Records are not deleted — this controls the display window. |
| `siem_destinations` | `stdout` | Active SIEM output targets. Changes take effect on the next audit event. |
| `splunk_hec_url` | — | Splunk HEC URL. Changes take effect immediately. |
| `splunk_hec_token` | — | Splunk HEC token. |
| `s3_log_bucket` | — | S3 bucket for log shipping. |
| `dd_api_key` | — | Datadog API key. |

---

## API Reference

### Secrets Endpoint

The only endpoint your applications need to know about. Does not require an admin session.

#### `GET /secrets`

**Headers**

| Header | Required | Description |
|---|---|---|
| `X-API-Key` | Yes | Team-registry API key. Format: `sk_<base64url>` |
| `X-Change-Number` | Configurable | ITSM change ticket reference (e.g. `CHG0012345`). Required by default; controlled by `change_number_required` setting. |

**Responses**

| Status | Condition |
|---|---|
| `200` | Secrets fetched successfully |
| `401` | API key missing, unknown, or revoked |
| `403` | Change number required but not provided |
| `429` | Rate limit exceeded for this key |
| `500` | Upstream vault fetch failure |

**200 Response**

```json
{
  "db_password":   "correct-horse-battery-staple",
  "api_key":       "sk-prod-abc123",
  "tls_cert_pass": "hunter2"
}
```

**curl example**

```bash
curl https://aegis.internal/secrets \
  -H "X-API-Key: sk_abc123..." \
  -H "X-Change-Number: CHG0012345"
```

---

### Authentication

All `/admin/api/*` endpoints require an active session token with `role=admin`.

Two authentication methods are supported:

**Session token (primary)**

```bash
# 1. Login
TOKEN=$(curl -s -X POST https://aegis.internal/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}' | jq -r .token)

# 2. Use token
curl https://aegis.internal/admin/api/objects \
  -H "Authorization: Bearer $TOKEN"

# 3. Logout
curl -X POST https://aegis.internal/api/logout \
  -H "Authorization: Bearer $TOKEN"
```

**HTTP Basic (curl fallback)**

```bash
curl https://aegis.internal/admin/api/objects \
  -u admin:changeme
```

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/login` | Authenticate. Body: `{ username, password }`. Returns `{ token, username, role, theme }`. |
| `POST` | `/api/logout` | Invalidate current session token. |
| `GET` | `/api/me` | Return current session info. |
| `PUT` | `/api/me/theme` | Update personal theme. Body: `{ theme }`. |
| `GET` | `/api/my-team` | *(user role only)* Read-only view of own team's registries and objects. |

---

### Objects

Objects are the atomic units — each represents a pointer to one secret in one upstream vault.

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/api/objects` | List all objects with registry membership counts. |
| `POST` | `/admin/api/objects` | Create a new object. |
| `PUT` | `/admin/api/objects/{name}` | Update an existing object. All fields replaced. |
| `DELETE` | `/admin/api/objects/{name}` | Delete object. Fails with `409` if the object belongs to any registry. |

**Request / response body**

```json
{
  "name":     "db_password",
  "vendor":   "vault",
  "auth_ref": "prod",
  "path":     "secret/data/myapp/db",
  "platform": null,
  "safe":     null
}
```

| Field | Vendors | Description |
|---|---|---|
| `name` | All | Unique identifier for this object. Used as the key in the `/secrets` response. |
| `vendor` | All | `cyberark` · `vault` · `aws` · `conjur` |
| `auth_ref` | All | Key into `auth.json` for credentials to use when fetching this secret. |
| `path` | Vault, AWS, Conjur | Secret path. For Vault: path within the KV mount. For AWS: secret name. For Conjur: variable path. |
| `platform` | CyberArk | CyberArk platform ID. |
| `safe` | CyberArk, Conjur | CyberArk safe name or Conjur safe name. |

---

### Registries

A registry is a named collection of objects. Teams are granted access to registries — not to individual objects.

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/api/registries` | List all registries with object counts and team assignments. |
| `POST` | `/admin/api/registries` | Create registry. Body: `{ name }`. |
| `DELETE` | `/admin/api/registries/{id}` | Delete registry. |
| `POST` | `/admin/api/registries/{id}/objects` | Add object to registry. Body: `{ object_name }`. |
| `DELETE` | `/admin/api/registries/{id}/objects/{name}` | Remove object from registry. |

---

### Teams

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/api/teams` | List all teams with assigned registries and key previews. |
| `POST` | `/admin/api/teams` | Create team. Body: `{ name }`. |
| `DELETE` | `/admin/api/teams/{id}` | Delete team and revoke all keys. |
| `POST` | `/admin/api/teams/{id}/registries/{reg_id}` | Assign registry to team. Returns `{ new_key: { key, registry_name } }` — the plaintext key is returned **once only**. |
| `DELETE` | `/admin/api/teams/{id}/registries/{reg_id}` | Revoke team access and invalidate all keys for this assignment. |
| `POST` | `/admin/api/teams/{id}/registries/{reg_id}/rotate-key` | Rotate the API key for this team-registry assignment. Returns `{ key }` once only. |

---

### Users

Operator accounts for the admin panel. Distinct from the application-facing API keys.

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/api/users` | List all operator accounts. |
| `POST` | `/admin/api/users` | Create user. Body: `{ username, password, role, team_id? }`. |
| `PUT` | `/admin/api/users/{id}` | Update user. Any subset of `{ username, password, role, team_id }`. |
| `DELETE` | `/admin/api/users/{id}` | Delete user. |

**Roles:** `admin` (full access) · `user` (read-only My Team view)

---

### Logs

#### Change Log

```
GET /admin/api/changelog?page=1&limit=25&entity_type=object&action=updated
```

| Query Param | Description |
|---|---|
| `page` | Page number (default: 1) |
| `limit` | Records per page (default: 25, max: 200) |
| `entity_type` | Filter by `object` · `registry` · `team` · `user` · `settings` |
| `action` | Filter by `created` · `updated` · `deleted` · `key_rotated` · `object_added` · `object_removed` · `registry_assigned` · `registry_unassigned` |

#### Audit Log

```
GET /admin/api/audit?page=1&limit=25&outcome=denied&change_number=CHG123
```

| Query Param | Description |
|---|---|
| `page` | Page number (default: 1) |
| `limit` | Records per page (default: 25, max: 200) |
| `outcome` | Filter by `success` · `denied` · `error` |
| `change_number` | Filter by exact ITSM change number |

---

### Settings

```
GET  /admin/api/settings
PUT  /admin/api/settings   Body: { "key": "value", ... }
```

Only keys listed in `EDITABLE_SETTINGS` are accepted. Unknown keys return `400`.

---

## Admin Panel

Aegis ships a dark, single-page admin panel at `/`. Built with vanilla JS and Tailwind CSS — no build step, no npm, no bundler. One HTML file. Zero client-side dependencies to audit or update.

### Dashboard

- **Stat cards** — total object count, registry count, team count, and audit log event count
- **Recent changes** — last 8 admin mutations with action pill, entity, name, performing account, and timestamp
- **Recent audit** — last 6 `/secrets` requests with outcome, change number, team, registry, and source IP

### Objects

Full CRUD table. Each row shows the vendor pill, auth ref, and how many registries the object belongs to. Click any row to open a **detail drawer** with:
- Edit form for all object fields
- Registry membership list with quick-remove
- Full change history with structured before/after diffs and account attribution

### Registries

Registry table with object count and team access list. Click a registry to open its drawer with:
- Object membership management
- Per-team key previews (first 10 characters) for all teams that have access
- Complete change history

### Teams

Team table with registry assignments. Click a team to open its drawer with:
- Registry assignment management
- Per-registry key preview and **Rotate Key** button
- On assignment: API key shown once in a modal — copy it, it will not be shown again
- Complete change history

### Audit Log

Full audit log table with filters for outcome and change number. Columns: timestamp, event, outcome, change number, team, registry, objects, source IP, user agent.

### Change Log

Full change log table with filters for entity type and action. Columns: timestamp, action pill, entity type pill, entity name, field diffs (before → after), performing account.

### Settings

Three-tab settings panel:

**General**
- Toggle change number enforcement
- Set rate limit (requests per minute)
- Set session TTL
- Set log retention window
- Theme preview and personal theme selection

**SIEM / Logging**
- Enable/disable SIEM destinations (Splunk, S3, Datadog)
- Configure credentials per destination
- All changes take effect immediately without restart

**Users**
- Full user management: create, edit role, assign team, delete
- Password changes for any account

---

## Roles and Access Control

```mermaid
graph LR
    subgraph Operator Roles
        ADMIN[admin\nFull access]
        USER[user\nRead-only — own team]
    end

    subgraph Views
        DASH[Dashboard]
        OBJ[Objects]
        REG[Registries]
        TEAM[Teams]
        AL[Audit Log]
        CL[Change Log]
        SET[Settings]
        MT[My Team]
    end

    ADMIN --> DASH & OBJ & REG & TEAM & AL & CL & SET
    USER --> MT
```

| Role | Panel Access | API Access |
|---|---|---|
| `admin` | All views | All `/admin/api/*` endpoints |
| `user` | My Team (read-only) | `GET /api/my-team` only |

Sessions are stored in Redis as opaque random tokens (`aegis:session:<token>`). The payload includes `user_id`, `username`, `role`, `team_id`, and `theme`. Sessions expire after the configured TTL and are invalidated immediately on logout.

There is no JWT. There is no refresh token. Session state lives entirely in Redis.

---

## Key Management

API keys follow a strict lifecycle:

```mermaid
stateDiagram-v2
    [*] --> Active: Team assigned to registry\n(key issued, shown once)
    Active --> Revoked: Team unassigned from registry\nor team deleted
    Active --> Active: Key rotated\n(new key issued, old key atomically revoked)
    Revoked --> [*]
```

- Keys are generated as `sk_` + 32 bytes of `secrets.token_urlsafe()`.
- Only the SHA-256 hex digest is stored in the database. The plaintext is never persisted.
- The plaintext key is returned once: on assignment (`POST /admin/api/teams/{id}/registries/{reg_id}`) or on rotation (`POST .../rotate-key`). It cannot be retrieved again.
- The admin panel displays only the first 10 characters (`key_preview`) for identification.
- Rotating a key atomically revokes the old key and issues a new one. There is no grace period — the old key stops working immediately.
- A team with access to N registries has N independent keys. Compromising one key does not affect the others.

---

## Audit and Change Logging

### Audit Log

Written on every `/secrets` request regardless of outcome. All fields are snapshotted at request time.

| Field | Type | Description |
|---|---|---|
| `timestamp` | `timestamptz` | UTC time of the request |
| `event` | `text` | `secrets.fetched` · `secrets.blocked` · `auth.failed` |
| `outcome` | `text` | `success` · `denied` · `error` |
| `change_number` | `text` | ITSM reference from `X-Change-Number` header |
| `registry_id` | `uuid` | Registry UUID (snapshotted — survives registry deletion) |
| `registry_name` | `text` | Registry name at time of request |
| `team_id` | `uuid` | Team UUID |
| `team_name` | `text` | Team name at time of request |
| `objects` | `text[]` | Array of object names in the registry |
| `key_preview` | `text` | First 10 characters of the key used |
| `source_ip` | `text` | Client IP address |
| `user_agent` | `text` | Client user agent string |
| `error_detail` | `text` | Error description on failure |

### Change Log

Written on every admin mutation. The `diff` column captures exact field-level changes.

| Field | Type | Description |
|---|---|---|
| `timestamp` | `timestamptz` | UTC time of the action |
| `action` | `text` | See action types below |
| `entity_type` | `text` | `object` · `registry` · `team` · `user` · `settings` |
| `entity_id` | `text` | UUID or name of the affected entity |
| `entity_name` | `text` | Display name (snapshotted) |
| `diff` | `jsonb` | `{ "field": { "from": old_value, "to": new_value } }` |
| `performed_by` | `text` | Username of the operator who made the change |

**Action types**

| Action | Trigger |
|---|---|
| `created` | Entity created |
| `updated` | Entity field(s) modified |
| `deleted` | Entity deleted |
| `key_rotated` | Team-registry API key rotated |
| `object_added` | Object added to registry |
| `object_removed` | Object removed from registry |
| `registry_assigned` | Registry granted to team |
| `registry_unassigned` | Registry access revoked from team |

**Diff example**

```json
{
  "vendor":   { "from": "vault",  "to": "cyberark" },
  "auth_ref": { "from": "dev",    "to": "prod" },
  "path":     { "from": "secret/data/myapp/db", "to": null }
}
```

---

## SIEM Integration

Every `/secrets` request emits a structured JSON event. `stdout` is always on and feeds the Docker log driver or any log shipper attached to the container. Additional targets are enabled via the Settings panel.

### Event Schema

```json
{
  "schema":    "aegis/v1",
  "timestamp": "2026-03-15T10:23:01.123Z",
  "event":     "secrets.fetched",
  "outcome":   "success",
  "request": {
    "change_number": "CHG0012345",
    "source_ip":     "10.0.1.42",
    "user_agent":    "curl/7.88.1"
  },
  "registry": {
    "id":   "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "name": "myapp-prod"
  },
  "objects":      ["db_password", "api_key", "tls_cert_pass"],
  "key_preview":  "sk_abc12345de",
  "error_detail": null,
  "broker": {
    "version": "1.0.0",
    "host":    "aegis-prod-01"
  }
}
```

### Destinations

| Destination | Setting value | Behaviour |
|---|---|---|
| **stdout** | Always on | One JSON line per event. Use with any Docker log driver (`json-file`, `fluentd`, `awslogs`, etc.). |
| **Splunk HEC** | `splunk` | `POST` to HEC endpoint with `sourcetype: aegis`. Requires `splunk_hec_url` and `splunk_hec_token`. |
| **AWS S3** | `s3` | Events are buffered in memory and flushed every 60 seconds as gzip-compressed JSONL. Key format: `{prefix}/YYYY/MM/DD/HH/{timestamp}Z.jsonl.gz`. Requires `s3_log_bucket`. Uses default boto3 credential chain. |
| **Datadog** | `datadog` | `POST` to Datadog Logs API. `ddsource: aegis`, `service: aegis`. Requires `dd_api_key`. |

Adapter failures are logged as warnings and never surface to the application — a SIEM outage does not block secret delivery.

All SIEM credentials changed via the Settings panel take effect on the next request. No restart required.

---

## Rate Limiting

Aegis enforces per-key rate limiting using a Redis sliding window counter.

- The limit is read from the `rate_limit_rpm` database setting on every request (with `RATE_LIMIT_RPM` env var as fallback).
- The counter key is the `team_registry_keys.id` UUID — not the raw key hash — so rotating a key resets the counter.
- When the limit is exceeded, Aegis returns `429 Too Many Requests` and writes a `secrets.blocked` audit event.
- The remaining request count is available internally but not currently exposed in response headers.

To adjust the limit per-team in the future, the rate limit module accepts the RPM as a parameter on each call and is not hardcoded at startup.

---

## Database Schema

All tables created and migrated by Alembic. Migrations run automatically on startup via `alembic upgrade head`.

```
Migration history:
  001 — Initial schema (objects, registries, registry_objects, teams, team_registries)
  002 — Change log table
  003 — Users and settings tables (with default seed data)
  004 — JSONB diff column on change_log
  005 — team_registry_keys table; adds team_id + team_name to audit_log
```

### Table summary

| Table | Purpose |
|---|---|
| `objects` | Secret definitions — vendor, auth_ref, path, safe, platform |
| `registries` | Named collections of objects |
| `registry_objects` | Junction: registry ↔ object |
| `teams` | Application/team metadata |
| `team_registries` | Junction: team ↔ registry (access grants) |
| `team_registry_keys` | Per-assignment API keys (SHA-256 hashed; full history preserved on rotation) |
| `users` | Operator accounts with role, optional team assignment, and theme |
| `settings` | Key/value runtime configuration |
| `change_log` | Immutable admin mutation log with JSONB diffs |
| `audit_log` | Immutable request log; fields snapshotted at request time |

---

## Themes

Each operator account stores a personal theme preference in the database. Applied via a `data-theme` attribute on `<html>`.

| Theme | Character |
|---|---|
| `default` | Dark slate — the standard security tool palette |
| `midnight` | Deep navy — lower eye strain for long sessions |
| `slate` | Cool grey tones |
| `forest` | Dark green accent |
| `contrast` | Maximum contrast — near-black background, bright white accents |

Preview and save from **Settings → General → Theme**.

---

## Security Model

### API Key Security

- Keys are generated using `secrets.token_urlsafe(32)` — 256 bits of cryptographic randomness.
- Only the SHA-256 hex digest is stored. The plaintext is discarded after issuance.
- There is no "reveal key" endpoint. If a key is lost, rotate it.
- Key lookup is an indexed exact-match on the hash — constant time from the database's perspective.
- Keys are prefixed `sk_` to make them identifiable if found in logs or code.

### Session Security

- Admin sessions use `secrets.token_urlsafe(32)` tokens stored in Redis as `aegis:session:<token>`.
- The session payload (`user_id`, `username`, `role`, `team_id`, `theme`) is stored server-side. Clients hold only the opaque token.
- No JWTs. No signing keys to rotate. No `alg:none` attacks.
- Sessions are invalidated immediately on logout — the Redis key is deleted.
- TTL is configurable (default 8 hours). Extending sessions requires re-login.

### Integrity Guarantees

- **Objects cannot be deleted while in use.** Deleting an object that belongs to any registry returns `409 Conflict`. This prevents silent access breakage.
- **Audit and change log records are write-only.** There are no API endpoints that modify or delete log entries.
- **All log fields are snapshotted.** Renaming or deleting a team or registry does not alter historical audit entries.
- **Change numbers are enforced by default.** Every `/secrets` call must reference an approved ITSM change ticket. This enforcement is configurable but the setting change itself is logged.
- **`auth.json` is never stored in the database.** Vault credentials live only on the filesystem, mounted as a Docker volume. They are excluded from version control.

### Passwords

- Operator account passwords are hashed using bcrypt (via the `bcrypt` library directly — not `passlib`, which is incompatible with bcrypt ≥ 4 on Python 3.12).
- The admin bootstrap password (`ADMIN_PASSWORD`) is only used on first startup to seed the initial account. It is not stored — only the bcrypt hash is persisted.

---

## Backup and Recovery

### Backup

```bash
# Dump the database
docker exec aegis-postgres-1 pg_dump -U broker aegis > backup_$(date +%Y%m%d_%H%M%S).sql

# Compress if large
gzip backup_*.sql
```

Run this before any `docker compose down -v` or destructive operation. The `config/auth.json` file should be backed up separately — it is not in the database.

### Restore

```bash
docker compose up -d postgres
docker exec -i aegis-postgres-1 psql -U broker aegis < backup_20260315_120000.sql
docker compose up -d
```

### Rename the database without data loss

If you need to rename the database (e.g. after changing `POSTGRES_DB` in compose):

```bash
# Connect as superuser and rename in-place
docker exec -it aegis-postgres-1 psql -U broker \
  -c "ALTER DATABASE old_name RENAME TO new_name;"

# Then update DATABASE_URL in docker-compose.yml and restart
docker compose up -d broker
```

> Do **not** use `docker compose down -v` to rename — this destroys all data. The `ALTER DATABASE` approach is lossless.

---

## Health Check

```
GET /health
```

Returns `200 OK` with `{"status": "ok"}`. No authentication required.

Used by Docker Compose's `healthcheck` directive and by load balancers or uptime monitors. The endpoint does not exercise the database or Redis — it is intentionally lightweight.

---

## Project Structure

```
aegis/
├── api.py              — FastAPI application, all routes, auth, session management
├── broker.py           — Secret fetcher: groups objects by vendor, dispatches to functions.py
├── functions.py        — Vendor-specific implementations (CyberArk, Vault, AWS, Conjur)
├── models.py           — SQLAlchemy ORM models
├── database.py         — Database session factory
├── rate_limit.py       — Redis-backed per-key rate limiter
├── siem.py             — SIEM adapters (stdout, Splunk, S3, Datadog)
├── apps.py             — Legacy compatibility shim
├── parser.py           — CLI admin tool (aegis-admin)
├── registry.py         — Registry utilities
├── requirements.txt    — Python dependencies
├── Dockerfile          — Container image definition
├── docker-compose.yml  — Local development stack
├── alembic.ini         — Alembic configuration
├── alembic/
│   └── versions/       — Database migration scripts (001–005)
├── static/
│   └── index.html      — Single-file admin panel (vanilla JS + Tailwind CDN)
└── config/
    ├── auth.json        — Vault credentials (gitignored)
    └── auth.json.example — Template for auth.json
```
