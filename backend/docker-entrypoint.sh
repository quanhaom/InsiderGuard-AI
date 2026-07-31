#!/bin/sh
set -e

echo "Initializing database tables..."

python -m scripts.init_db

echo "Starting InsiderGuard API..."

exec python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload