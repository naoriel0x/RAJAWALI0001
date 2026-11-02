#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"

set -a
source "$ROOT_DIR/.env"
set +a

: "${POSTGRES_DB:=rajawali}"
: "${POSTGRES_USER:=rajawali}"
: "${POSTGRES_PASSWORD:=rajawali_secret}"
: "${REDIS_PASSWORD:=redis_secret}"

export PGPASSWORD="$POSTGRES_PASSWORD"
docker compose exec -T postgres pg_dump \
  --clean --if-exists --no-owner --no-privileges \
  -U "$POSTGRES_USER" "$POSTGRES_DB" > "$BACKUP_DIR/postgres_${TIMESTAMP}.sql"
unset PGPASSWORD

docker compose exec -T redis redis-cli -a "$REDIS_PASSWORD" --no-auth-warning BGSAVE >/dev/null
docker compose cp redis:/data/dump.rdb "$BACKUP_DIR/redis_${TIMESTAMP}.rdb"

find "$BACKUP_DIR" -type f -mtime +"${BACKUP_RETENTION_DAYS:-14}" -delete
echo "Backup written to $BACKUP_DIR"