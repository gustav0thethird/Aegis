FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aegis/ aegis/
COPY static/ static/
COPY alembic/ alembic/
COPY alembic.ini .

# Required env vars:
#   DATABASE_URL    — postgresql://user:pass@host/dbname
#   REDIS_URL       — redis://host:6379
#   AUTH_PATH       — path to auth.json (mounted volume)
#   ADMIN_PASSWORD  — admin console password
#
# Optional:
#   LOG_DESTINATIONS     — comma-separated: stdout,splunk,s3,datadog (stdout always on)
#   SPLUNK_HEC_URL       — https://splunk:8088
#   SPLUNK_HEC_TOKEN     — Splunk HEC token
#   S3_LOG_BUCKET        — bucket name
#   S3_LOG_PREFIX        — key prefix (default: secrets-broker)
#   DD_API_KEY           — Datadog API key
#   DD_SITE              — datadoghq.com or datadoghq.eu
#   RATE_LIMIT_RPM       — requests per minute per key (default: 60)

EXPOSE 8080

CMD ["sh", "-c", "alembic upgrade head && uvicorn aegis.api:app --host 0.0.0.0 --port 8080"]
