#!/bin/bash
if [ "$NAEF_MODE" = "s3" ]; then
    echo "[NAEF] Running in S3 (distributed) mode"
    exec /app/entrypoint-s3.sh
else
    echo "[NAEF] Running in local (docker-compose) mode"
    exec /app/entrypoint-local.sh
fi
