#!/bin/bash
echo "=== NAEF TEBS Server Starting ==="

MU=${TEBS_MU:-5}
BUCKET=${S3_BEACON_BUCKET:-naef-beacon}

echo "Beacon interval: ${MU}s"
echo "S3 bucket: ${BUCKET}"

# Symlink beacon files to shared volume
ln -sf /app/beacon/tebs_beacon.log /app/tebs_beacon.log 2>/dev/null
ln -sf /app/beacon/tebs_key.bin /app/tebs_key.bin 2>/dev/null
ln -sf /app/beacon/tebs_pubkey.hex /app/tebs_pubkey.hex 2>/dev/null
ln -sf /app/beacon/tebs_mu.txt /app/tebs_mu.txt 2>/dev/null

# S3 sync loop in background
(
    while true; do
        if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -f /app/beacon/tebs_beacon.log ]; then
            aws s3 cp /app/beacon/tebs_beacon.log "s3://${BUCKET}/tebs_beacon.log" --quiet 2>/dev/null
            aws s3 cp /app/beacon/tebs_pubkey.hex "s3://${BUCKET}/tebs_pubkey.hex" --quiet 2>/dev/null
            aws s3 cp /app/beacon/tebs_mu.txt "s3://${BUCKET}/tebs_mu.txt" --quiet 2>/dev/null
        fi
        sleep 5
    done
) &

cd /app
./tebs mu=$MU

echo "=== NAEF TEBS Server Stopped ==="
