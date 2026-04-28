#!/bin/bash
# KDA Sync: Downloads beacon from S3, uploads artifacts to S3
# Uses 'aws s3 sync' for efficient incremental uploads

NAEF_DIR="/app/NAEF"
BEACON_BUCKET=${S3_BEACON_BUCKET:-naef-beacon}
EXCHANGE_BUCKET=${S3_EXCHANGE_BUCKET:-naef-exchange}

echo "[KDA-SYNC] Starting S3 sync loop..."
echo "[KDA-SYNC] Beacon bucket: s3://${BEACON_BUCKET}"
echo "[KDA-SYNC] Exchange bucket: s3://${EXCHANGE_BUCKET}"

while true; do
    # Download beacon from TEBS S3 bucket
    aws s3 cp "s3://${BEACON_BUCKET}/tebs_beacon.log" /app/tebs_beacon.log --quiet 2>/dev/null
    aws s3 cp "s3://${BEACON_BUCKET}/tebs_pubkey.hex" /app/tebs_pubkey.hex --quiet 2>/dev/null
    aws s3 cp "s3://${BEACON_BUCKET}/tebs_mu.txt" /app/tebs_mu.txt --quiet 2>/dev/null

    # Upload init.json
    if [ -f "$NAEF_DIR/init.json" ]; then
        aws s3 cp "$NAEF_DIR/init.json" "s3://${EXCHANGE_BUCKET}/init.json" --quiet 2>/dev/null
    fi

    # Sync entire NAEF directory to S3 (only uploads new/changed files)
    if [ -d "$NAEF_DIR" ]; then
        aws s3 sync "$NAEF_DIR/" "s3://${EXCHANGE_BUCKET}/" \
            --exclude "*/private_key.pem" \
            --exclude "*/vrf_key.bin" \
            --exclude "*/vrf_pubkey.hex" \
            --exclude "dsmtp/*" \
            --quiet 2>/dev/null
    fi

    sleep 2
done
