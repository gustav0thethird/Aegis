#!/bin/sh
set -e

# Database migrations are opt-out rather than unconditional.
#
# Running `alembic upgrade head` on every container start is fine for a single
# instance (docker compose, a one-task ECS service) but wrong the moment there
# is more than one replica: every pod races to migrate the same database at the
# same time. Kubernetes and Argo CD deployments therefore set
# RUN_MIGRATIONS=false and run migrations exactly once, in a PreSync hook Job
# that must succeed before the new pods roll out.
#
# The default stays "true" so existing single-instance deployments behave
# exactly as they did before this entrypoint existed.

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
    echo "[entrypoint] applying database migrations"
    alembic upgrade head
else
    echo "[entrypoint] skipping migrations (RUN_MIGRATIONS=${RUN_MIGRATIONS})"
fi

exec "$@"
