#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f .env ]]; then
  echo "Missing .env. Copy .env.example to .env and configure secrets first." >&2
  exit 1
fi

docker compose config >/dev/null
docker compose build
docker compose up -d --remove-orphans
docker compose ps

echo "Waiting for backend health endpoint..."
for attempt in {1..30}; do
  if curl --fail --silent http://localhost:8000/health >/dev/null; then
    echo "RAJAWALI deployment is healthy."
    exit 0
  fi
  sleep 2
done

echo "Backend did not become healthy in time." >&2
docker compose logs --tail=80 backend
exit 1