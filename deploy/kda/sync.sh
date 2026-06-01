#!/bin/bash
# KDA Sync v3: Per-domain parallel uploads + beacon download
# Reliable at scale - no inotifywait dependency

NAEF_DIR="/app/NAEF"
BEACON_BUCKET=${S3_BEACON_BUCKET:-naef-beacon}
EXCHANGE_BUCKET=${S3_EXCHANGE_BUCKET:-naef-exchange}
MAX_PARALLEL=${KDA_SYNC_PARALLEL:-20}

echo "[KDA-SYNC] Starting per-domain sync..."
echo "[KDA-SYNC] Beacon: s3://${BEACON_BUCKET}"
echo "[KDA-SYNC] Exchange: s3://${EXCHANGE_BUCKET}"
echo "[KDA-SYNC] Max parallel: ${MAX_PARALLEL}"

# Sync a single domain folder to S3
sync_domain() {
    local domain_dir="$1"
    local dname=$(basename "$domain_dir")
    aws s3 sync "$domain_dir" "s3://${EXCHANGE_BUCKET}/${dname}/" \
        --exclude "private_key.pem" \
        --exclude "vrf_key.bin" \
        --exclude "vrf_pubkey.hex" \
        --quiet 2>/dev/null
}

while true; do
    # Download beacon
    aws s3 cp "s3://${BEACON_BUCKET}/tebs_beacon.log" /app/tebs_beacon.log --quiet 2>/dev/null
    aws s3 cp "s3://${BEACON_BUCKET}/tebs_pubkey.hex" /app/tebs_pubkey.hex --quiet 2>/dev/null
    aws s3 cp "s3://${BEACON_BUCKET}/tebs_mu.txt" /app/tebs_mu.txt --quiet 2>/dev/null

    # Upload init.json
    if [ -f "$NAEF_DIR/init.json" ]; then
        aws s3 cp "$NAEF_DIR/init.json" "s3://${EXCHANGE_BUCKET}/init.json" --quiet 2>/dev/null
    fi

    # Upload metrics
    if [ -d "$NAEF_DIR/metrics" ]; then
        aws s3 sync "$NAEF_DIR/metrics/" "s3://${EXCHANGE_BUCKET}/metrics/" --quiet 2>/dev/null
    fi

    # Per-domain parallel sync
    if [ -d "$NAEF_DIR" ]; then
        count=0
        for domain_dir in "$NAEF_DIR"/*/; do
            [ -d "$domain_dir" ] || continue
            dname=$(basename "$domain_dir")
            [[ "$dname" == "metrics" || "$dname" == "dsmtp" ]] && continue
            sync_domain "$domain_dir" &
            count=$((count + 1))
            if [ $count -ge $MAX_PARALLEL ]; then
                wait
                count=0
            fi
        done
        wait
    fi

    sleep 2
done
