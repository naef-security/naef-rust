#!/bin/bash
# VDA Sync v2: Per-domain parallel downloads
# Each domain syncs independently, reducing S3 API overhead

NAEF_DIR="/app/NAEF"
EXCHANGE_BUCKET=${S3_EXCHANGE_BUCKET:-naef-exchange}
MAX_PARALLEL=${VDA_SYNC_PARALLEL:-10}

echo "[VDA-SYNC] Starting per-domain sync..."
echo "[VDA-SYNC] Exchange bucket: s3://${EXCHANGE_BUCKET}"
echo "[VDA-SYNC] Max parallel: ${MAX_PARALLEL}"

# Download init.json and get domain list
download_init() {
    aws s3 cp "s3://${EXCHANGE_BUCKET}/init.json" "$NAEF_DIR/init.json" --quiet 2>/dev/null
}

# Sync a single domain's files
sync_domain() {
    local domain_name="$1"
    local dest="$NAEF_DIR/${domain_name}"
    mkdir -p "$dest"

    # Sync only this domain's folder
    aws s3 sync "s3://${EXCHANGE_BUCKET}/${domain_name}/" "$dest/" --quiet 2>/dev/null

    # Log new files
    for f in "$dest"/*/*.txt "$dest"/*/*.pem; do
        [ -f "$f" ] || continue
        local marker="${f}.synced"
        if [ ! -f "$marker" ]; then
            local rel="${f#$NAEF_DIR/}"
            echo "[VDA-SYNC] Received ${rel}"
            touch "$marker"
        fi
    done
}

# Upload metrics
upload_metrics() {
    if [ -d "$NAEF_DIR/metrics" ]; then
        aws s3 sync "$NAEF_DIR/metrics/" "s3://${EXCHANGE_BUCKET}/metrics/" --quiet 2>/dev/null
    fi
}

# Main loop
while true; do
    # Get init.json
    download_init

    # Read domain list from init.json
    if [ -f "$NAEF_DIR/init.json" ]; then
        domains=$(python3 -c "
import json,sys
try:
    with open('$NAEF_DIR/init.json') as f:
        for e in json.load(f):
            print(e['domain'].replace('.','_'))
except: pass
" 2>/dev/null)
    else
        # Fallback: list from S3
        domains=$(aws s3 ls "s3://${EXCHANGE_BUCKET}/" 2>/dev/null | awk '/PRE/{print $2}' | tr -d '/' | grep -v metrics)
    fi

    # Sync domains in parallel batches
    count=0
    for domain_name in $domains; do
        sync_domain "$domain_name" &
        count=$((count + 1))
        if [ $count -ge $MAX_PARALLEL ]; then
            wait
            count=0
        fi
    done
    wait

    # Upload metrics
    upload_metrics

    sleep 2
done
