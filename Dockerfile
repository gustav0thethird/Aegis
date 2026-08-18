FROM python:3.14-slim

LABEL org.opencontainers.image.title="Aegis" \
      org.opencontainers.image.description="Vault Agnostic API Broker Solution" \
      org.opencontainers.image.source="https://github.com/gustav0thethird/Aegis"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aegis/ aegis/
COPY static/ static/
COPY alembic/ alembic/
COPY alembic.ini .
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Run as an unprivileged user so the Kubernetes manifests can assert
# runAsNonRoot alongside a read-only root filesystem.
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin aegis \
    && chown -R aegis:aegis /app
USER 10001

# Required env vars:
#   DATABASE_URL    — postgresql://user:pass@host/dbname
#   REDIS_URL       — redis://host:6379
#   AUTH_PATH       — path to auth.json (mounted volume)
#   ADMIN_PASSWORD  — bootstrap password for the admin account (first start only)
#
# Optional:
#   RUN_MIGRATIONS            — "true" (default) applies migrations on start.
#                               Kubernetes/Argo CD set "false" and migrate once
#                               in a PreSync hook Job instead.
#   LOG_DESTINATIONS          — comma-separated: stdout,splunk,s3,datadog (stdout always on)
#   SPLUNK_HEC_URL            — https://splunk:8088
#   SPLUNK_HEC_TOKEN          — Splunk HEC token
#   S3_LOG_BUCKET             — bucket name
#   S3_LOG_PREFIX             — key prefix (default: secrets-broker)
#   DD_API_KEY                — Datadog API key
#   DD_SITE                   — datadoghq.com or datadoghq.eu
#   RATE_LIMIT_RPM            — requests per minute per key (default: 60)
#   RATE_LIMIT_FAIL_MODE      — open (default) or closed, when Redis is unreachable
#   WEBHOOK_ALLOWED_SCHEMES   — outbound webhook URL schemes (default: https)
#   WEBHOOK_ALLOWED_HOSTS     — outbound webhook host allowlist
#   WEBHOOK_ALLOW_PRIVATE_IPS — permit private webhook targets (development only)

EXPOSE 8080

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "aegis.api:app", "--host", "0.0.0.0", "--port", "8080"]
