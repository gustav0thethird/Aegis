"""
siem.py — Configurable SIEM log adapters.

One canonical event is built per request and dispatched to all configured destinations.
stdout is always enabled and cannot be disabled — it feeds the Docker log driver.

Config (env vars):
  LOG_DESTINATIONS   — comma-separated: stdout,splunk,s3,datadog  (stdout always on)
  SPLUNK_HEC_URL     — https://splunk-host:8088
  SPLUNK_HEC_TOKEN   — Splunk HEC token
  S3_LOG_BUCKET      — S3 bucket name
  S3_LOG_PREFIX      — S3 key prefix (default: aegis)
  DD_API_KEY         — Datadog API key
  DD_SITE            — datadoghq.com | datadoghq.eu (default: datadoghq.com)
"""

import gzip
import io
import json
import logging
import os
import socket
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import requests

logger = logging.getLogger("aegis.siem")

_HOSTNAME = socket.gethostname()
_VERSION  = "1.0.0"

# S3 batch buffer: list of event dicts, flushed every minute
_s3_buffer: list[dict] = []
_s3_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------

def build_event(
    event: str,
    outcome: str,
    *,
    change_number: str | None = None,
    registry_id: str | None = None,
    registry_name: str | None = None,
    objects: list[str] | None = None,
    key_preview: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    error_detail: str | None = None,
) -> dict:
    return {
        "schema":    "aegis/v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event":     event,
        "outcome":   outcome,
        "request": {
            "change_number": change_number,
            "source_ip":     source_ip,
            "user_agent":    user_agent,
        },
        "registry": {
            "id":   registry_id,
            "name": registry_name,
        },
        "objects":      objects or [],
        "key_preview":  key_preview,
        "error_detail": error_detail,
        "broker": {
            "version": _VERSION,
            "host":    _HOSTNAME,
        },
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def emit(event: dict, config: dict | None = None) -> None:
    """Dispatch event to all configured destinations. Never raises.

    config — optional dict with runtime-overrides (read from DB by api.py):
      destinations, splunk_hec_url, splunk_hec_token,
      s3_log_bucket, s3_log_prefix, dd_api_key, dd_site
    Falls back to env vars for any missing key.
    """
    cfg = config or {}
    _emit_stdout(event)

    dest_str = cfg.get("destinations") or os.environ.get("LOG_DESTINATIONS", "stdout")
    destinations = {d.strip().lower() for d in dest_str.split(",")}

    if "splunk" in destinations:
        _safe(_emit_splunk, event, cfg)
    if "s3" in destinations:
        _safe(_buffer_s3, event, cfg)
    if "datadog" in destinations:
        _safe(_emit_datadog, event, cfg)


def _safe(fn, event, cfg=None):
    try:
        fn(event, cfg or {})
    except Exception as exc:
        logger.warning("SIEM adapter %s failed: %s", fn.__name__, exc)


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------

def _emit_stdout(event: dict) -> None:
    print(json.dumps(event), flush=True)


def _emit_splunk(event: dict, cfg: dict) -> None:
    url   = (cfg.get("splunk_hec_url") or os.environ["SPLUNK_HEC_URL"]).rstrip("/") + "/services/collector/event"
    token = cfg.get("splunk_hec_token") or os.environ["SPLUNK_HEC_TOKEN"]
    payload = {"event": event, "sourcetype": "aegis", "source": _HOSTNAME}
    resp = requests.post(
        url,
        headers={"Authorization": f"Splunk {token}"},
        json=payload,
        timeout=5,
        verify=True,
    )
    resp.raise_for_status()


def _buffer_s3(event: dict, cfg: dict) -> None:
    with _s3_lock:
        _s3_buffer.append((event, cfg))


def flush_s3() -> None:
    """Call periodically (e.g. every 60s) to write buffered events to S3."""
    import boto3

    with _s3_lock:
        if not _s3_buffer:
            return
        batch = list(_s3_buffer)
        _s3_buffer.clear()

    now = datetime.now(timezone.utc)

    for event, cfg in batch:
        bucket = cfg.get("s3_log_bucket") or os.environ["S3_LOG_BUCKET"]
        prefix = cfg.get("s3_log_prefix") or os.environ.get("S3_LOG_PREFIX", "aegis")
        key = f"{prefix}/{now:%Y/%m/%d/%H}/{now:%Y%m%dT%H%M%S}Z.jsonl.gz"
        body = json.dumps(event).encode()
        compressed = gzip.compress(body)
        boto3.client("s3").put_object(Bucket=bucket, Key=key, Body=compressed, ContentEncoding="gzip")
        logger.info("Flushed event to s3://%s/%s", bucket, key)


def _emit_datadog(event: dict, cfg: dict) -> None:
    site    = cfg.get("dd_site") or os.environ.get("DD_SITE", "datadoghq.com")
    api_key = cfg.get("dd_api_key") or os.environ["DD_API_KEY"]
    url     = f"https://http-intake.logs.{site}/api/v2/logs"
    payload = {
        **event,
        "ddsource": "aegis",
        "service":  "aegis",
        "ddtags":   f"env:{os.environ.get('ENV', 'production')},host:{_HOSTNAME}",
    }
    resp = requests.post(
        url,
        headers={"DD-API-KEY": api_key, "Content-Type": "application/json"},
        json=[payload],
        timeout=5,
    )
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Background S3 flush thread
# ---------------------------------------------------------------------------

def start_s3_flush_thread(interval_seconds: int = 60) -> None:
    """Start a daemon thread that flushes the S3 buffer on an interval."""
    def _loop():
        import time
        while True:
            time.sleep(interval_seconds)
            try:
                flush_s3()
            except Exception as exc:
                logger.warning("S3 flush failed: %s", exc)

    t = threading.Thread(target=_loop, daemon=True, name="siem-s3-flush")
    t.start()
