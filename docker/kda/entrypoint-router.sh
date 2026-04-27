#!/bin/bash
if [ "$NAEF_MODE" = "s3" ]; then
    echo "[NAEF] Running in S3 (distributed) mode"
    cp /app/sync-s3.sh /app/sync.sh
    exec /app/entrypoint-s3.sh
else
    echo "[NAEF] Running in local (docker-compose) mode"
    cp /app/sync-local.sh /app/sync.sh
    exec /app/entrypoint-local.sh
fi
