# Aegis

> **Vendor-agnostic secrets broker and PAM gateway.**
> Scoped API keys per team. Any vault. Every action logged, attributed, and queryable.
> Teams self-manage their own webhooks, key rotation, and notifications — without filing tickets.

<p align="center">
  <img src="assets/Aegis-logo.png" width="600">
</p>

Aegis is a thin, audited proxy that sits between your applications and your secrets infrastructure. Teams authenticate with a scoped API key (one key per team-registry pair) and receive exactly the secrets they are authorised to see — regardless of whether those secrets live in CyberArk, HashiCorp Vault, AWS Secrets Manager, or Conjur. Every fetch, every rotation, and every configuration change is written to an immutable log with structured before/after diffs and full account attribution.

Designed for scale: 100+ teams, 40 000+ secrets, and a single security team. Team members self-service their own webhook subscriptions, notification channels, and CI/CD key rotation via their own dashboard — the security team manages policy, not operations.

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
  - [User Self-Service API](#user-self-service-api)
  - [Objects](#objects)
  - [Registries](#registries)
  - [Teams](#teams)
  - [Users](#users)
  - [Policies](#policies)
  - [Webhooks (Admin)](#webhooks-admin)
  - [Logs and Exports](#logs-and-exports)
  - [Settings](#settings)
  - [Metrics](#metrics)
- [Admin Panel](#admin-panel)
- [Team Dashboard](#team-dashboard)
- [Team Self-Service Model](#team-self-service-model)
- [Roles and Access Control](#roles-and-access-control)
- [Key Management](#key-management)
- [Policies](#policies-1)
- [Webhooks and Notifications](#webhooks-and-notifications)
- [Inbound Webhooks (CI/CD Integration)](#inbound-webhooks-cicd-integration)
- [Audit and Change Logging](#audit-and-change-logging)
- [SIEM Integration](#siem-integration)
- [Rate Limiting](#rate-limiting)
- [Database Schema](#database-schema)
- [Themes](#themes)
- [Security Model](#security-model)
- [Backup and Recovery](#backup-and-recovery)
- [Health Check](#health-check)
- [Development and Testing](#development-and-testing)
- [Terraform (AWS)](#terraform-aws)
- [Project Structure](#project-structure)

---

## Why Aegis

Most organisations accumulate secrets sprawl over time: applications that talk directly to CyberArk, others that hit Vault, a handful that pull from AWS SSM — each with its own credential logic, its own rotation story, and no centralised visibility. When a safe is renamed, a token expires, or a key leaks, you find out by watching something break in production.

**Aegis solves this by being the only secrets endpoint your applications ever need to know about.**

- Applications present one API key. Aegis resolves it to a team + registry pair and fetches the secrets from whichever upstream vault holds them.
- Admins manage everything through a single panel. Objects can be migrated between vendors without touching application code — just update the object definition.
- Every request is logged with the team identity, the registry accessed, the list of objects fetched, the source IP, and the ITSM change number. There is no way to fetch a secret without leaving a trace.
- API keys are scoped to a specific team-registry assignment. If Team A and Team B both access the same registry, they use different keys. If either key is compromised, only that assignment needs to be rotated — the other team is unaffected.
- Teams can belong to multiple groups of registries. A user can be a member of multiple teams. Multi-team membership is fully supported.
- With the team self-service model, teams configure their own webhook subscriptions, CI/CD rotation triggers, and Slack/Teams/Discord notifications without any involvement from the security team.

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
      │                            │  2. Enforce policy:        │
      │                            │     change number, IP,     │
      │                            │     time window, rate      │
      │                            │                            │
      │                            │  3. Fetch secrets per      │
      │                            │     vendor (CyberArk,      │
      │                            ├───────────────────────────►│
      │                            │◄───────────────────────────┤
      │                            │     Vault, AWS, Conjur)    │
      │                            │                            │
      │                            │  4. Write audit log        │
      │                            │     (team, registry,       │
      │                            │      objects, IP, CHG#)    │
      │                            │                            │
      │                            │  5. Emit SIEM event        │
      │                            │     (stdout/Splunk/S3/DD)  │
      │                            │                            │
      │  { secret_name: value }    │                            │
      │◄───────────────────────────│                            │
```

CI/CD pipelines can also trigger key rotations directly via an auto-generated inbound webhook URL — no admin intervention required.

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
        AUTH[Key Auth & Policy]
        FETCH[Secret Fetcher]
        AUDIT[Audit Writer]
        SIEM_E[SIEM Emitter]
        ADMIN[Admin API + Panel]
        DASH[Team Dashboard]
        WH[Webhook Engine]
        SCHED[Scheduler]
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
        STDOUT[stdout]
        SP[Splunk HEC]
        S3[AWS S3\ngzip JSONL]
        DD[Datadog]
    end

    subgraph Notify["Notifications"]
        SL[Slack]
        MST[MS Teams]
        DIS[Discord]
    end

    A1 & A2 & A3 -->|X-API-Key + X-Change-Number| GW
    GW --> RL
    RL -->|counter check| REDIS
    RL --> AUTH
    AUTH -->|key hash lookup + policy| PG
    AUTH --> FETCH
    FETCH -->|vendor dispatch| CA & HV & AWS & CO
    FETCH --> AUDIT
    AUDIT -->|write audit_log| PG
    AUDIT --> SIEM_E
    SIEM_E --> STDOUT & SP & S3 & DD

    ADMIN -->|session tokens| REDIS
    ADMIN -->|read/write| PG
    DASH -->|session tokens| REDIS
    DASH -->|read own team| PG

    WH -->|HTTP webhook + retry| A1
    WH --> SL & MST & DIS
    SCHED -->|expiry checks| WH

    A2 -->|POST /api/inbound/team-id| WH
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
        text slack_webhook_url
        text ms_teams_webhook_url
        text discord_webhook_url
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
        timestamptz expires_at
        timestamptz revoked_at
    }

    users {
        uuid id PK
        text username
        text password_hash
        text role
        text theme
        timestamptz created_at
        text created_by
    }

    user_teams {
        uuid user_id FK
        uuid team_id FK
        timestamptz created_at
    }

    webhooks {
        uuid id PK
        uuid team_id FK
        text url
        text secret
        boolean signing_enabled
        text[] events
        boolean enabled
        timestamptz created_at
        text created_by
    }

    webhook_log {
        bigint id PK
        uuid webhook_id FK
        uuid team_id
        text event
        text payload
        integer status_code
        boolean success
        integer attempt
        text error
        timestamptz fired_at
    }

    policies {
        uuid id PK
        text entity_type
        uuid entity_id
        text[] ip_allowlist
        time allowed_from
        time allowed_to
        boolean cn_required
        integer rate_limit_rpm
        integer max_key_days
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
    users ||--o{ user_teams : "member of"
    teams ||--o{ user_teams : "has members"
    teams ||--o| webhooks : "configures"
    webhooks ||--o{ webhook_log : "logs"
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

    Aegis->>DB: Load policy (registry + team layers)
    alt Change number required but missing
        Aegis->>DB: Write audit_log (secrets.blocked)
        Aegis-->>App: 403 Forbidden
    end

    alt Source IP not in allowlist
        Aegis->>DB: Write audit_log (secrets.blocked) + fire policy.violated webhook
        Aegis-->>App: 403 Forbidden
    end

    alt Outside allowed time window
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
| **Registry** | A named collection of objects. The atomic unit of access control — teams are granted access to registries, not to individual objects. One registry typically represents all secrets needed by a particular application or environment. |
| **Team** | A logical grouping of applications or human operators that need the same set of secrets. Users may belong to multiple teams. Teams configure their own webhooks, notification channels, and CI/CD integrations independently. |
| **Team ID** | A stable UUID identifying the team. Shown in both the admin panel and the team dashboard. Appears in all webhook payloads so external systems can route events. Use it to configure your inbound webhook URL. |
| **Team-Registry Key** | A unique API key issued when a team is assigned a registry. A team with access to three registries has three separate keys. Every audit log entry traces back to an exact `(team, registry)` pair. |
| **Auth Ref** | A string that maps to a credential block in `auth.json`. For example, `"prod"` might map to the production CyberArk installation. Changing the underlying credentials only requires updating `auth.json`. |
| **Policy** | Per-registry or per-team access control rules: IP allowlist, time-of-day window, change-number enforcement, custom rate limit, and maximum key age. Registry policy takes precedence over team policy, which takes precedence over global settings. |
| **Inbound Webhook** | An auto-generated URL per team (`POST /api/inbound/{team_id}`) that external CI/CD systems POST to in order to trigger Aegis actions (key rotation, ping). Authenticated with the team's HMAC signing secret. |
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

### 2. Configure environment

```bash
make env          # copies .env.example → .env
$EDITOR .env      # set ADMIN_PASSWORD, SECRET_KEY, and any other overrides
```

### 3. Start

```bash
make dev          # docker compose up --build (foreground)
# or
make dev-d        # background
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

> For single-server production deployment see [`docs/deploy-local.md`](docs/deploy-local.md).
> For AWS / hybrid deployment see [`docs/deploy-cloud-hybrid.md`](docs/deploy-cloud-hybrid.md).

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
| `session_ttl_hours` | `8` | Admin session lifetime in hours. |
| `log_retention_days` | `90` | Number of days shown in audit log queries. Records are not deleted — this controls the display window. |
| `siem_destinations` | `stdout` | Active SIEM output targets. Changes take effect on the next audit event. |
| `splunk_hec_url` | — | Splunk HEC URL. |
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
| `X-Change-Number` | Configurable | ITSM change ticket reference (e.g. `CHG0012345`). Required by default; controlled by `change_number_required` setting and per-registry/team policy. |

**Responses**

| Status | Condition |
|---|---|
| `200` | Secrets fetched successfully |
| `401` | API key missing, unknown, or revoked |
| `403` | Change number required but not provided; IP not in allowlist; outside time window |
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
User self-service endpoints (`/api/my-*`, `/api/inbound/*`) require any authenticated session.

Two authentication methods are supported for admin endpoints:

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
| `POST` | `/api/login` | Authenticate. Body: `{ username, password }`. Returns `{ token, username, role, team_ids, theme }`. |
| `POST` | `/api/logout` | Invalidate current session token. |
| `GET` | `/api/me` | Return current session info including `team_ids` array. |
| `PUT` | `/api/me/theme` | Update personal theme. Body: `{ theme }`. |

---

### User Self-Service API

Endpoints available to authenticated users with `role=user`. All scoped to the user's own team(s). Where a user belongs to multiple teams, pass `?team_id=<uuid>` to target a specific one; omit to default to the first team.

#### Teams (read-only)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/my-teams` | All teams the user belongs to, with assigned registries, key previews, and expiry dates. |
| `GET` | `/api/my-team` | Backward-compatible alias — returns the first team only. |

**Response shape (per team):**

```json
{
  "id":         "3fa85f64-5717-...",
  "name":       "myapp",
  "registries": [
    {
      "id":          "uuid",
      "name":        "myapp-prod",
      "key_preview": "sk_abc12345de",
      "expires_at":  "2026-12-31T00:00:00+00:00",
      "objects":     ["db_password", "api_key"]
    }
  ]
}
```

#### Webhooks (self-service)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/my-webhook` | Get current webhook config + notification channels + inbound URL for the team. |
| `PUT` | `/api/my-webhook` | Create or update outgoing webhook and/or notification channels. |
| `DELETE` | `/api/my-webhook` | Remove outgoing webhook. |

**PUT body:**

```json
{
  "url":                 "https://your-service.example.com/webhook",
  "enabled":             true,
  "events":              ["key.expiring_soon", "key.rotated"],
  "signing_enabled":     true,
  "secret":              "optional-override-or-leave-null-to-auto-generate",
  "slack_webhook_url":   "https://hooks.slack.com/services/...",
  "ms_teams_webhook_url": "https://org.webhook.office.com/...",
  "discord_webhook_url": "https://discord.com/api/webhooks/..."
}
```

**GET response:**

```json
{
  "team_id":   "3fa85f64-...",
  "team_name": "myapp",
  "webhook": {
    "id":              "uuid",
    "url":             "https://...",
    "enabled":         true,
    "events":          ["key.rotated"],
    "signing_enabled": true,
    "has_secret":      true
  },
  "notifications": {
    "slack_webhook_url":    "https://hooks.slack.com/...",
    "ms_teams_webhook_url": null,
    "discord_webhook_url":  null
  },
  "inbound_url": "/api/inbound/3fa85f64-..."
}
```

#### Metrics (self-service)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/my-metrics` | Team-scoped JSON metrics: audit counts, key stats, recent activity. |
| `GET` | `/api/my-metrics/prometheus` | Team-scoped Prometheus text metrics — wire into your own Grafana. |

**JSON response:**

```json
{
  "team_id":   "3fa85f64-...",
  "team_name": "myapp",
  "requests": {
    "total":   1240,
    "success": 1237,
    "denied":  2,
    "error":   1
  },
  "keys": {
    "active":        3,
    "revoked":       12,
    "expiring_soon": 1
  },
  "recent_audit": [ ... ]
}
```

**Prometheus format** (`/api/my-metrics/prometheus`):

```
aegis_team_audit_total{team="myapp",outcome="success"} 1237
aegis_team_audit_total{team="myapp",outcome="denied"} 2
aegis_team_keys_total{team="myapp",state="active"} 3
aegis_team_keys_total{team="myapp",state="revoked"} 12
```

#### Inbound Webhook

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/inbound/{team_id}` | Receive an event from CI/CD. Authenticated with team's HMAC signing secret. |

See [Inbound Webhooks (CI/CD Integration)](#inbound-webhooks-cicd-integration) for full documentation.

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
| `path` | Vault, AWS, Conjur | Secret path within the mount/service. |
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
| `GET` | `/admin/api/teams` | List all teams with assigned registries, key previews, members, and notification config. |
| `POST` | `/admin/api/teams` | Create team. Body: `{ name }`. |
| `DELETE` | `/admin/api/teams/{id}` | Delete team and revoke all keys. |
| `POST` | `/admin/api/teams/{id}/registries/{reg_id}` | Assign registry to team. Returns `{ new_key: { key, registry_name } }` — plaintext key returned **once only**. |
| `DELETE` | `/admin/api/teams/{id}/registries/{reg_id}` | Revoke team access and invalidate all keys for this assignment. |
| `POST` | `/admin/api/teams/{id}/registries/{reg_id}/rotate-key` | Rotate the API key. Returns `{ key }` once only. Old key invalidated immediately. |
| `GET` | `/admin/api/teams/{id}/members` | List team members (users assigned to this team). |
| `POST` | `/admin/api/teams/{id}/members` | Add user to team. Body: `{ user_id }`. |
| `DELETE` | `/admin/api/teams/{id}/members/{user_id}` | Remove user from team. |
| `PUT` | `/admin/api/teams/{id}/notifications` | Save Slack/Teams/Discord notification URLs for the team. Body: `{ slack_webhook_url, ms_teams_webhook_url, discord_webhook_url }`. |

**Team response shape:**

```json
{
  "id":         "3fa85f64-5717-...",
  "name":       "myapp",
  "created_at": "2026-01-01T00:00:00+00:00",
  "registries": [ ... ],
  "members": [
    { "id": "uuid", "username": "alice", "role": "user" }
  ],
  "notifications": {
    "slack_webhook_url":    "https://hooks.slack.com/...",
    "ms_teams_webhook_url": null,
    "discord_webhook_url":  null
  }
}
```

---

### Users

Operator accounts for the admin panel. Distinct from the application-facing API keys.

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/api/users` | List all operator accounts with team memberships. |
| `POST` | `/admin/api/users` | Create user. Body: `{ username, password, role, team_ids? }`. |
| `PUT` | `/admin/api/users/{id}` | Update user. Body: any subset of `{ username, password, role, team_ids }`. Supplying `team_ids` replaces all memberships atomically. |
| `DELETE` | `/admin/api/users/{id}` | Delete user. |

**Roles:** `admin` (full access) · `user` (self-service team dashboard)

Users may belong to zero, one, or many teams. A user with `role=user` can view and self-manage any team they are a member of.

---

### Policies

Access control rules per registry or team. Registry policy takes precedence over team policy, which takes precedence over global settings.

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/api/registries/{id}/policy` | Get policy for a registry. |
| `PUT` | `/admin/api/registries/{id}/policy` | Set policy for a registry. |
| `GET` | `/admin/api/teams/{id}/policy` | Get policy for a team. |
| `PUT` | `/admin/api/teams/{id}/policy` | Set policy for a team. |

**Policy body:**

```json
{
  "ip_allowlist":   ["10.0.0.0/8", "192.168.1.0/24"],
  "allowed_from":   "08:00",
  "allowed_to":     "18:00",
  "cn_required":    true,
  "rate_limit_rpm": 120,
  "max_key_days":   90
}
```

All fields are optional; `null` means inherit from the next level (team → global). The `max_key_days` field enforces automatic expiry on newly issued and rotated keys.

---

### Webhooks (Admin)

Admins can manage any team's HTTP webhook configuration.

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/api/teams/{id}/webhook` | Get the team's outgoing webhook config. |
| `PUT` | `/admin/api/teams/{id}/webhook` | Create or update outgoing webhook. Body: `{ url, events, signing_enabled, secret, enabled }`. |
| `DELETE` | `/admin/api/teams/{id}/webhook` | Remove webhook. |
| `GET` | `/admin/api/teams/{id}/webhook/logs` | Delivery history for the team's webhook. |
| `POST` | `/admin/api/teams/{id}/registries/{reg_id}/rotate-key` | Rotate key — triggers `key.rotated` webhook event if subscribed. |

Teams can also self-manage their own webhooks via `PUT /api/my-webhook` without admin involvement.

---

### Logs and Exports

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

```
GET /admin/api/changelog/export
```

Streams a CSV file of the full change log (all pages). Response: `text/csv` with `Content-Disposition: attachment`.

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

```
GET /admin/api/audit/export
```

Streams a CSV file of the full audit log (all pages).

---

### Settings

```
GET  /admin/api/settings
PUT  /admin/api/settings   Body: { "key": "value", ... }
```

Only keys listed in `EDITABLE_SETTINGS` are accepted. Unknown keys return `400`.

**Auth Backends**

```
GET  /admin/api/auth-backends
POST /admin/api/auth-backends/{vendor}/{ref}/test
```

Returns all configured `auth.json` credential sets with secrets masked. The test endpoint verifies connectivity to the upstream vault.

**Sessions**

```
GET    /admin/api/sessions
DELETE /admin/api/sessions/{token_key}
```

Lists all active Redis sessions with user and expiry. `DELETE` immediately revokes a session.

---

### Metrics

```
GET /metrics
```

Prometheus-format metrics for the whole instance. Intended for scraping by your monitoring stack. No authentication (IP-restrict at your proxy).

```
GET /api/my-metrics/prometheus
```

Team-scoped Prometheus metrics. Requires user authentication. Returns only data for the requesting user's team.

**Global metrics (`/metrics`):**

```
aegis_audit_total{outcome="success"} 48293
aegis_audit_total{outcome="denied"} 142
aegis_objects_total 412
aegis_registries_total 87
aegis_teams_total 104
aegis_keys_total{state="active"} 312
aegis_keys_total{state="revoked"} 891
aegis_webhook_deliveries_total{result="success"} 5621
aegis_webhook_deliveries_total{result="failure"} 34
aegis_policy_violations_total 142
```

---

## Admin Panel

Aegis ships a dark, single-page admin panel at `/admin`. Built with vanilla JS and Tailwind CSS — no build step, no npm, no bundler. One HTML file. Fira Code monospace throughout.

### Dashboard

- **Stat cards** — objects, registries, teams, and audit event counts
- **Expiring keys widget** — keys expiring within the next 30 days across all teams
- **Recent changes** — last 8 admin mutations with action pill, entity, performing account, and timestamp
- **Recent audit** — last 6 `/secrets` requests with outcome, change number, team, registry, and source IP

### Objects

Full CRUD table. Each row shows the vendor pill, auth ref, and registry membership count. Click any row to open a **detail drawer** with:
- Edit form for all object fields
- Registry membership list with quick-remove
- Full change history with structured before/after diffs and account attribution

### Registries

Registry table with object count and team access list. Click a registry to open its drawer with:
- Object membership management
- Per-team key previews for all teams that have access
- Complete change history

### Teams

Team table with registry assignments. Click a team to open its drawer with:
- **Team UUID** displayed with a copy button (present in all webhook payloads)
- Registry assignment management — assign/unassign registries, rotate keys
- On assignment: API key shown once in a modal
- **Members** — add/remove user membership; users may belong to multiple teams
- **Notification channels** — configure Slack, MS Teams, and Discord webhook URLs per team
- Outgoing HTTP webhook configuration
- Complete change history

### Audit Log

Full audit log table with filters for outcome and change number. Columns: timestamp, event, outcome, change number, team, registry, objects, source IP, user agent. **Export to CSV** button streams the full log.

### Change Log

Full change log table with filters for entity type and action. Columns: timestamp, action pill, entity type, entity name, field diffs (before → after), performing account. **Export to CSV** button streams the full log.

### Settings

Five-tab settings panel:

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
- Full user management: create, edit role, assign team memberships, delete
- Multi-team assignment via checkbox list
- Password changes for any account

**Auth Backends**
- Read-only view of all `auth.json` credential sets with secrets masked
- Test connectivity button per backend

**Sessions**
- List all active Redis sessions with username, role, and expiry
- Revoke individual sessions immediately

---

## Team Dashboard

The team dashboard at `/dashboard` is available to users with `role=user`. It is a self-contained single-page application with three tabs:

### Overview Tab

- **Stat cards** — registries, active keys, expiring keys, total API requests
- **Team ID** — the team UUID is displayed prominently with a copy button; shown for each team when a user belongs to multiple
- **Registry cards** — one card per assigned registry showing:
  - Key preview (first 10 characters) with active/expired/no-key status
  - Expiry date badge if applicable
  - Object table: name, vendor, path

### Webhooks Tab

Teams configure their own integrations here — no admin involvement required:

- **Inbound webhook URL** — auto-generated based on team ID, with copy button and curl example
- **Outgoing HTTP webhook** — configure endpoint URL, event subscriptions, HMAC signing, and secret
- **Notification channels** — Slack, MS Teams, Discord webhook URLs

### Activity Tab

- Request summary: total, success, denied, error counts
- Active/revoked/expiring key counts
- Last 20 audit events for this team: timestamp, event, outcome, registry, source IP

---

## Team Self-Service Model

Designed for environments with 100+ teams and a single security team. The security team manages the platform (objects, registries, policies, global settings). Individual teams manage their own operations.

**What teams can do without admin involvement:**

| Action | Endpoint |
|---|---|
| View assigned registries and key previews | `GET /api/my-teams` |
| Configure outgoing webhook (event subscriptions) | `PUT /api/my-webhook` |
| Configure Slack/Teams/Discord notifications | `PUT /api/my-webhook` |
| View team-scoped audit and key metrics | `GET /api/my-metrics` |
| Expose team metrics to own Grafana | `GET /api/my-metrics/prometheus` |
| Trigger key rotation from CI/CD | `POST /api/inbound/{team_id}` |

**What requires admin:**

| Action | Why |
|---|---|
| Create/delete teams | Platform structure |
| Assign registries to teams | Access control grant |
| Create/modify objects | Secret pointer management |
| Set policies (IP allowlist, time windows) | Security policy |
| View cross-team audit data | Privacy/privilege boundary |
| Manage users | Account lifecycle |

---

## Roles and Access Control

| Role | Panel | API access |
|---|---|---|
| `admin` | Admin panel (`/admin`) — all views | All `/admin/api/*` endpoints |
| `user` | Team dashboard (`/dashboard`) | `/api/my-*` endpoints for own teams only |

Sessions are stored in Redis as opaque random tokens (`aegis:session:<token>`). The session payload includes `user_id`, `username`, `role`, `team_ids` (array of UUIDs), and `theme`. Sessions expire after the configured TTL and are invalidated immediately on logout.

Users can be members of zero, one, or many teams. A user's `team_ids` list in the session determines which teams they can read and self-manage. Team membership is managed by admins or by the team membership endpoints.

There is no JWT. There is no refresh token. Session state lives entirely in Redis.

---

## Key Management

API keys follow a strict lifecycle:

```mermaid
stateDiagram-v2
    [*] --> Active: Team assigned to registry\n(key issued, shown once)
    Active --> Revoked: Team unassigned\nor team deleted
    Active --> Active: Key rotated\n(new key issued, old key atomically revoked)
    Active --> Expired: max_key_days reached\n(policy enforcement)
    Revoked --> [*]
    Expired --> [*]
```

- Keys are generated as `sk_` + 40 bytes of `secrets.token_urlsafe()` — 320 bits of cryptographic randomness.
- Only the SHA-256 hex digest is stored in the database. The plaintext is never persisted.
- The plaintext key is returned exactly once: on assignment or rotation. It cannot be retrieved again. If lost, rotate it.
- The admin panel and team dashboard display only the first 10 characters (`key_preview`) for identification.
- Rotating a key atomically revokes the old key and issues a new one. There is no grace period — the old key stops working immediately.
- A team with access to N registries has N independent keys. Compromising one key does not affect the others.
- If a policy sets `max_key_days`, the key's `expires_at` is set at issuance. The scheduler checks daily and fires `key.expiring_soon` events 7 days before expiry.
- CI/CD can trigger key rotation via `POST /api/inbound/{team_id}` without admin involvement.

---

## Policies

Policies add fine-grained access control on top of the key authentication layer. They are per-entity (registry or team) and stack: registry policy takes precedence, then team policy, then global settings.

| Policy field | Effect |
|---|---|
| `ip_allowlist` | CIDR list. Requests from IPs outside the list are rejected with `403` and a `policy.violated` webhook event. |
| `allowed_from` / `allowed_to` | Time-of-day window (UTC). Requests outside the window are rejected with `403`. |
| `cn_required` | Override global change-number enforcement for this registry or team. |
| `rate_limit_rpm` | Override the global rate limit for this registry or team. |
| `max_key_days` | Maximum age for keys issued under this registry or team. Enforced at key issuance and rotation. |

Policy enforcement fires a `policy.violated` webhook event so teams are immediately notified of access violations — even if they originate from misconfigurations.

---

## Webhooks and Notifications

Aegis fires events to teams for key lifecycle and policy events. Teams can configure these from their dashboard without admin involvement.

### Events

| Event | Trigger |
|---|---|
| `key.expiring_soon` | A team-registry key will expire within 7 days (checked daily by scheduler) |
| `key.rotated` | A key was rotated (manual or CI/CD-triggered) |
| `key.revoked` | A key was revoked without replacement (registry unassigned, team deleted) |
| `policy.violated` | A request was blocked by an IP allowlist or time-window policy |

### Outgoing HTTP Webhook

Per-team endpoint receiving POSTed JSON events from Aegis.

- Configurable: URL, subscribed events, HMAC-SHA256 signing, enabled/disabled
- Retry: 3 attempts with 0/5/30 second backoff
- Every delivery attempt logged in `webhook_log` with status code, success flag, error, and attempt number
- If signing is enabled, Aegis adds `X-Aegis-Signature: sha256=<hex>` header

**Payload structure:**

```json
{
  "event":       "key.rotated",
  "timestamp":   "2026-03-15T10:23:01.123Z",
  "team":        { "id": "3fa85f64-...", "name": "myapp" },
  "registry":    { "id": "uuid", "name": "myapp-prod" },
  "new_key":     null,
  "key_preview": "sk_abc12345de",
  "reason":      null,
  "detail":      null
}
```

> `new_key` is populated only on `key.rotated` — the new plaintext key. This is the only way to receive the rotated key automatically. Handle this webhook endpoint with the same security rigour as the API key itself.

### Notification Channels

Best-effort delivery to Slack, MS Teams, and Discord. Each channel fires independently — one failure does not block the others. No retry.

| Channel | Format |
|---|---|
| **Slack** | Block Kit message with attachment colour per event type |
| **MS Teams** | MessageCard with themeColor per event type |
| **Discord** | Embed with integer colour per event type |

Colour scheme: `key.expiring_soon` → amber · `key.rotated` → indigo · `key.revoked` / `policy.violated` → red.

Teams configure their channel URLs from the **Webhooks** tab in the team dashboard, or admins configure them via `PUT /admin/api/teams/{id}/notifications`.

---

## Inbound Webhooks (CI/CD Integration)

Every team has an auto-generated inbound webhook URL based on their team ID:

```
POST /api/inbound/{team_id}
Authorization: Bearer <signing_secret>
Content-Type: application/json
```

This URL is displayed in the team dashboard's Webhooks tab — teams copy it and configure their CI/CD pipeline to POST to it. No admin involvement required.

**Authentication:** the team's HMAC signing secret (configured via the Webhooks tab). HMAC signing must be enabled.

### Supported actions

**Ping** — verify connectivity:

```bash
curl -X POST https://aegis.internal/api/inbound/3fa85f64-... \
  -H "Authorization: Bearer <signing_secret>" \
  -H "Content-Type: application/json" \
  -d '{"action": "ping"}'
```

```json
{ "ok": true, "team": "myapp", "message": "pong" }
```

**rotate_key** — rotate the API key for a specific registry:

```bash
curl -X POST https://aegis.internal/api/inbound/3fa85f64-... \
  -H "Authorization: Bearer <signing_secret>" \
  -H "Content-Type: application/json" \
  -d '{"action": "rotate_key", "registry_id": "f47ac10b-..."}'
```

```json
{ "ok": true, "key_preview": "sk_newkey123", "new_key": "sk_newkey123..." }
```

The response includes the new plaintext key. If the team has a `key.rotated` outgoing webhook subscription, that fires simultaneously.

### CI/CD pipeline example

```yaml
# GitHub Actions: rotate key after deploy
- name: Rotate Aegis key
  run: |
    NEW_KEY=$(curl -s -X POST $AEGIS_INBOUND_URL \
      -H "Authorization: Bearer $AEGIS_SIGNING_SECRET" \
      -H "Content-Type: application/json" \
      -d "{\"action\":\"rotate_key\",\"registry_id\":\"$REGISTRY_ID\"}" \
      | jq -r .new_key)
    echo "::add-mask::$NEW_KEY"
    echo "AEGIS_KEY=$NEW_KEY" >> $GITHUB_ENV
```

---

## Audit and Change Logging

### Audit Log

Written on every `/secrets` request regardless of outcome. All fields are snapshotted at request time — renaming a team or registry does not alter historical entries.

| Field | Type | Description |
|---|---|---|
| `timestamp` | `timestamptz` | UTC time of the request |
| `event` | `text` | `secrets.fetched` · `secrets.blocked` · `auth.failed` |
| `outcome` | `text` | `success` · `denied` · `error` |
| `change_number` | `text` | ITSM reference from `X-Change-Number` header |
| `registry_id` | `uuid` | Registry UUID (snapshotted) |
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

**Action types:** `created` · `updated` · `deleted` · `key_rotated` · `object_added` · `object_removed` · `registry_assigned` · `registry_unassigned`

**Diff example:**

```json
{
  "vendor":   { "from": "vault",  "to": "cyberark" },
  "auth_ref": { "from": "dev",    "to": "prod" },
  "path":     { "from": "secret/data/myapp/db", "to": null }
}
```

Both logs are exported to CSV via `GET /admin/api/audit/export` and `GET /admin/api/changelog/export`.

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
  "team": {
    "id":   "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "name": "myapp"
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
| **AWS S3** | `s3` | Events buffered and flushed every 60 seconds as gzip-compressed JSONL. Key format: `{prefix}/YYYY/MM/DD/HH/{timestamp}Z.jsonl.gz`. |
| **Datadog** | `datadog` | `POST` to Datadog Logs API. `ddsource: aegis`, `service: aegis`. Requires `dd_api_key`. |

Adapter failures are logged as warnings and never surface to the application — a SIEM outage does not block secret delivery.

---

## Rate Limiting

Aegis enforces per-key rate limiting using a Redis sliding window counter.

- The limit is read from the `rate_limit_rpm` database setting on every request (with `RATE_LIMIT_RPM` env var as fallback).
- Per-registry and per-team policies can override the global limit.
- The counter key is the `team_registry_keys.id` UUID — rotating a key resets the counter.
- When the limit is exceeded, Aegis returns `429 Too Many Requests` and writes a `secrets.blocked` audit event.

---

## Database Schema

All tables created and migrated by Alembic. Migrations run automatically on startup via `alembic upgrade head`.

```
Migration history:
  001 — Initial schema (objects, registries, registry_objects, teams, team_registries)
  002 — Change log table
  003 — Users and settings tables (with default seed data)
  004 — JSONB diff column on change_log
  005 — team_registry_keys table; team_id + team_name on audit_log
  006 — Policies, webhooks, webhook_log; expires_at on team_registry_keys
  007 — signing_enabled on webhooks (HMAC optional)
  008 — user_teams junction table (many-to-many users ↔ teams);
        slack_webhook_url, ms_teams_webhook_url, discord_webhook_url on teams;
        removes team_id from users
  009 — suspended column on team_registry_keys (key-level suspend/resume without deletion)
  010 — Composite performance indexes (audit_log, team_registry_keys, change_log, policies)
```

### Table summary

| Table | Purpose |
|---|---|
| `objects` | Secret definitions — vendor, auth_ref, path, safe, platform |
| `registries` | Named collections of objects |
| `registry_objects` | Junction: registry ↔ object |
| `teams` | Application/team metadata + notification channel URLs |
| `team_registries` | Junction: team ↔ registry (access grants) |
| `team_registry_keys` | Per-assignment API keys (SHA-256 hashed; history preserved on rotation; optional expiry) |
| `user_teams` | Junction: user ↔ team (many-to-many membership) |
| `users` | Operator accounts with role and theme; no direct team column |
| `webhooks` | Per-team outgoing HTTP webhook config (URL, secret, events, signing) |
| `webhook_log` | Delivery history for every webhook attempt |
| `policies` | Per-registry or per-team access control rules |
| `settings` | Key/value runtime configuration |
| `change_log` | Immutable admin mutation log with JSONB diffs |
| `audit_log` | Immutable request log; fields snapshotted at request time |

---

## Themes

Each operator account stores a personal theme preference. Applied via a `data-theme` attribute on `<html>`.

| Theme | Character |
|---|---|
| `default` | Dark slate — the standard security tool palette |
| `midnight` | Deep navy — lower eye strain for long sessions |
| `slate` | Cool grey tones |
| `forest` | Dark green accent |
| `contrast` | Maximum contrast — near-black background, bright white accents |

Preview and save from **Settings → General → Theme**. Does not affect the team dashboard (which uses a fixed dark theme).

---

## Security Model

### API Key Security

- Keys are generated using `secrets.token_urlsafe(40)` — 320 bits of cryptographic randomness.
- Only the SHA-256 hex digest is stored. The plaintext is discarded after issuance.
- There is no "reveal key" endpoint. If a key is lost, rotate it.
- Key lookup is an indexed exact-match on the hash — constant time from the database's perspective.
- Keys are prefixed `sk_` to make them identifiable if found in logs or code.

### Session Security

- Admin and user sessions use `secrets.token_urlsafe(32)` tokens stored in Redis as `aegis:session:<token>`.
- Session payload (`user_id`, `username`, `role`, `team_ids`, `theme`) is stored server-side. Clients hold only the opaque token.
- No JWTs. No signing keys to rotate. No `alg:none` attacks.
- Sessions are invalidated immediately on logout — the Redis key is deleted.
- Admins can revoke any session from **Settings → Sessions**.
- TTL is configurable (default 8 hours).

### Inbound Webhook Security

- Inbound webhook URLs are authenticated with the team's HMAC signing secret.
- The secret is stored in the `webhooks` table (same as outgoing signing secret).
- HMAC signing must be explicitly enabled — inbound webhooks are rejected if signing is not configured.
- Comparison uses `hmac.compare_digest` — constant-time, not vulnerable to timing attacks.

### Integrity Guarantees

- **Objects cannot be deleted while in use.** Deleting an object that belongs to any registry returns `409 Conflict`.
- **Audit and change log records are write-only.** There are no API endpoints that modify or delete log entries.
- **All log fields are snapshotted.** Renaming or deleting a team or registry does not alter historical audit entries.
- **Change numbers are enforced by default.** Every `/secrets` call must reference an approved ITSM change ticket. This is configurable globally and per-registry/team via policy.
- **`auth.json` is never stored in the database.** Vault credentials live only on the filesystem, mounted as a Docker volume.

### Passwords

- Operator account passwords are hashed using bcrypt (via the `bcrypt` library directly — not `passlib`).
- The admin bootstrap password (`ADMIN_PASSWORD`) is only used on first startup to seed the initial account. Only the bcrypt hash is persisted.

---

## Backup and Recovery

### Backup

```bash
make backup       # dumps dev Postgres to ./backups/aegis_<timestamp>.sql.gz
```

Run this before any `docker compose down -v` or destructive operation. Back up `config/auth.json` separately — it is not stored in the database.

### Restore

```bash
make restore file=backups/aegis_20260315_120000.sql.gz
```

### Rename the database without data loss

```bash
docker exec -it aegis-postgres-1 psql -U broker \
  -c "ALTER DATABASE old_name RENAME TO new_name;"

# Then update DATABASE_URL in docker-compose.yml and restart
docker compose up -d broker
```

> Do **not** use `docker compose down -v` to rename — this destroys all data.

---

## Health Check

```
GET /health
```

Returns `200 OK` with `{"status": "ok", "db": "ok", "redis": "ok"}`. No authentication required.

```
GET /docs
```

Interactive OpenAPI documentation (Swagger UI). Linked from the Settings panel header in the admin panel.

---

## Development and Testing

### Setup

```bash
pip install -r requirements-dev.txt

make dev-d          # start Postgres + Redis in the background
make test-db        # create aegis_test database (run once)
```

### Running tests

```bash
make test           # pytest tests/ -v --tb=short
make test-cov       # same + coverage report
make lint           # ruff check tests/
```

Tests require a running Postgres. The `DATABASE_URL` is automatically overridden to `aegis_test` by the Makefile target — the application database is never touched.

### Test suites

| File | Type | What it covers |
|---|---|---|
| `tests/test_policy.py` | Unit | IP allowlist and time-window policy helpers (16 tests, no DB) |
| `tests/test_broker.py` | Unit | Vendor routing and `auth_cfg` resolution (12 tests, no DB) |
| `tests/test_rate_limit.py` | Unit | Rate limiter with FakeRedis (6 tests, no Redis) |
| `tests/test_secrets.py` | Integration | `GET /secrets` end-to-end: auth, policy, audit log (9 tests, Postgres) |

### CI

Tests run automatically on every push and PR via `.github/workflows/ci.yml`. The workflow spins up a PostgreSQL 16 service container — no external dependencies needed.

---

## Terraform (AWS)

The `terraform/` directory contains a production-ready AWS deployment. It provisions:

| Resource | Detail |
|---|---|
| **VPC** | Dedicated VPC with public/private subnets across two AZs |
| **ECS Fargate** | Containerised broker service; configurable CPU/memory and replica count |
| **RDS Aurora PostgreSQL** | Serverless-compatible Aurora cluster; credentials stored in Secrets Manager |
| **ElastiCache Redis** | Single-shard replication group for sessions and rate limiting |
| **ALB** | HTTPS Application Load Balancer with ACM TLS certificate |
| **IAM** | Least-privilege task execution role with Secrets Manager read |
| **S3** | Optional SIEM log bucket |
| **CloudWatch** | Log group with configurable retention |

### Quick deploy

```bash
make tf-init                     # terraform init

# Create a terraform.tfvars file:
cat > terraform/terraform.tfvars <<EOF
image_uri       = "ghcr.io/<your-org>/secrets-broker:latest"
domain_name     = "aegis.example.com"
admin_password  = "$(openssl rand -hex 16)"
secret_key      = "$(openssl rand -hex 32)"
EOF

make tf-plan                     # review the plan
make tf-apply                    # apply (~5 min)
```

### Outputs

After apply, Terraform prints:

| Output | Use |
|---|---|
| `alb_dns_name` | CNAME your domain here |
| `ecr_repository_url` | Push images here |
| `acm_validation_records` | Add to DNS to validate the TLS certificate |

### Variables

All variables have sensible defaults. Override in `terraform.tfvars` or via `-var`:

| Variable | Default | Notes |
|---|---|---|
| `aws_region` | `us-east-1` | |
| `environment` | `prod` | Used as resource name prefix |
| `db_instance_class` | `db.t3.medium` | RDS Aurora instance size |
| `redis_node_type` | `cache.t3.micro` | ElastiCache node size |
| `fargate_cpu` | `512` | 256 / 512 / 1024 / 2048 / 4096 |
| `fargate_memory` | `1024` | MiB |
| `desired_count` | `2` | ECS task replica count |
| `rate_limit_rpm` | `60` | Default rate limit per API key |
| `log_retention_days` | `30` | CloudWatch log retention |

See `docs/deploy-cloud-hybrid.md` for full deployment guidance including hybrid (on-prem vault + cloud broker) topology.

---

## Project Structure

```
secrets-broker/
├── aegis/                      — Python application package
│   ├── __init__.py
│   ├── api.py                  — FastAPI application: all routes, auth, session management,
│   │                             user self-service, inbound webhooks, metrics, SIEM exports
│   ├── broker.py               — Secret fetcher: groups objects by vendor, dispatches to functions.py
│   ├── database.py             — SQLAlchemy engine, session factory, Base
│   ├── functions.py            — Vendor-specific implementations (CyberArk, Vault, AWS, Conjur)
│   ├── models.py               — ORM models (14 tables)
│   ├── rate_limit.py           — Redis-backed per-key rate limiter
│   ├── scheduler.py            — Background scheduler: key expiry checks, rotation events
│   ├── siem.py                 — SIEM adapters (stdout, Splunk, S3, Datadog)
│   └── webhook.py              — Outgoing webhook delivery (HTTP + retry + HMAC signing)
│                                 + Slack, MS Teams, Discord notification formatters
├── alembic/                    — Alembic migration environment
│   └── versions/               — Migration scripts (001–010)
├── config/
│   ├── auth.json               — Vault credentials (gitignored)
│   ├── auth.json.example       — Template for auth.json
│   └── Caddyfile               — Caddy reverse-proxy config
├── docs/
│   ├── deploy-local.md         — Local Docker Compose deployment guide
│   └── deploy-cloud-hybrid.md  — Cloud / hybrid deployment guide
├── static/
│   ├── index.html              — Admin panel (vanilla JS + Tailwind CDN, single file)
│   ├── dashboard.html          — Team self-service dashboard (Overview | Webhooks | Activity tabs)
│   ├── docs.html               — Interactive OpenAPI documentation (Swagger UI)
│   ├── login.html              — Login page
│   └── 404.html                — Branded 404 page
├── terraform/                  — AWS infrastructure (ECS, RDS, ElastiCache, ALB, IAM, S3)
├── helm/                       — Kubernetes Helm chart
│   └── values.yaml             — Default chart values
├── tests/
│   ├── conftest.py             — pytest fixtures (TestClient, DB, FakeRedis)
│   ├── test_policy.py          — Unit tests: IP allowlist and time-window policy helpers
│   ├── test_broker.py          — Unit tests: vendor routing and auth_cfg resolution
│   ├── test_rate_limit.py      — Unit tests: rate limiter with FakeRedis
│   └── test_secrets.py         — Integration tests: GET /secrets end-to-end
├── .github/
│   ├── dependabot.yml          — Automated dependency updates (pip, docker, terraform, actions)
│   └── workflows/
│       ├── ci.yml              — Lint + integration tests on every push/PR
│       └── release.yml         — Build + push GHCR image + GitHub release on v* tags
├── alembic.ini
├── docker-compose.yml          — Local development stack (Aegis + PostgreSQL + Redis + exporter)
├── docker-compose.prod.yml     — Production stack variant
├── Dockerfile
├── Makefile                    — Dev, test, build, backup, Helm, and Terraform targets
├── requirements.txt            — Runtime Python dependencies
├── requirements-dev.txt        — Dev/test dependencies (pytest, fakeredis, httpx, ruff)
├── .env.example                — Environment variable template (copy to .env)
└── README.md
```
