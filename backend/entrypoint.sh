#!/usr/bin/env sh
set -e

echo "Running Alembic database migrations..."
alembic upgrade head

echo "Executing idempotent baseline policy seed..."
python -m app.db.seed

echo "Starting ASGI server..."
exec "$@"
