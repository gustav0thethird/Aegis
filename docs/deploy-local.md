# Aegis — Local & Single-Server Deployment

## Local Development

### Prerequisites

- Docker + Docker Compose v2
- `make`

### First run

```bash
# 1. Copy and configure environment
make env           # creates .env from .env.example
nano .env          # set ADMIN_PASSWORD and SECRET_KEY at minimum

# 2. Add your auth.json (see config/auth.json.example)
cp config/auth.json.example config/auth.json
nano config/auth.json

# 3. Start everything
make dev
```

On first boot the broker automatically runs `alembic upgrade head` before starting.
Postgres, Redis, pgBouncer, and a Prometheus-compatible metrics exporter all start alongside it.

### Access

| Service | URL |
|---------|-----|
| Admin panel | http://localhost:8080/admin |
| User dashboard | http://localhost:8080/dashboard |
| Documentation | http://localhost:8080/docs |
| Postgres exporter metrics | http://localhost:9187/metrics |

Default credentials: username `admin`, password from `ADMIN_PASSWORD` in `.env`.

### Common commands

```bash
make dev-logs       # follow broker logs
make psql           # open psql shell
make redis-cli      # open redis-cli
make migrate        # run pending migrations
make migrate-new name=add_foo   # create a new migration
make backup         # pg_dump to ./backups/
make shell          # shell into broker container
make dev-down       # stop everything
make dev-reset      # stop + wipe all volumes (destructive)
```

---

## Single-Server Production

For a single VPS or bare-metal host — no Kubernetes required. TLS is handled automatically by Caddy.

### Prerequisites

- Docker + Docker Compose v2
- A domain name pointed at your server
- Ports 80 and 443 open

### Setup

```bash
# 1. Clone and configure
git clone https://github.com/gustav0thethird/secrets-broker.git
cd secrets-broker
make env
nano .env   # fill in everything, especially:
            #   AEGIS_DOMAIN=aegis.yourdomain.com
            #   TLS_EMAIL=you@yourdomain.com
            #   POSTGRES_PASSWORD=<strong random value>
            #   ADMIN_PASSWORD=<strong random value>
            #   SECRET_KEY=$(openssl rand -hex 32)

# 2. Configure auth.json with your backend credentials
cp config/auth.json.example config/auth.json
nano config/auth.json

# 3. Build the image and start
docker build -t aegis:latest .
BROKER_IMAGE=aegis:latest make prod
```

Caddy fetches a TLS certificate from Let's Encrypt on first start.
All traffic is HTTPS. HTTP redirects to HTTPS automatically.

### Logs

```bash
make prod-logs      # broker logs
docker compose -f docker-compose.prod.yml logs -f caddy     # TLS / proxy logs
docker compose -f docker-compose.prod.yml logs -f backup    # backup logs
```

### Backups

The `backup` service runs `pg_dump` every 24 hours and writes compressed dumps to a Docker volume.

```bash
# Trigger a manual backup
make backup

# Restore from a dump
make restore file=backups/aegis_20260316_090000.sql.gz
```

Dumps older than `BACKUP_RETAIN_DAYS` (default 30) are pruned automatically.

> **For production backups**, consider copying dumps off-server to S3 or similar.
> The `backup` service container has access to the Docker volume at `/backup` —
> mount an S3-backed volume or add an `aws s3 cp` step to the backup script.

### Updates

```bash
git pull
docker build -t aegis:latest .
docker compose -f docker-compose.prod.yml up -d broker
```

Migrations run automatically on startup.

### Monitoring

The Postgres exporter exposes metrics at `:9187/metrics` (not exposed externally in prod).
Point a Prometheus scrape job at `localhost:9187` from within the server, or add Grafana
alongside the compose stack.

Team-level metrics are available to authenticated users at `/api/my-metrics/prometheus`.
