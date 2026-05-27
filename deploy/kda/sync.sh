#!/bin/bash
# KDA Sync v2: Immediate upload on file creation + beacon download
# Uses inotifywait for push-based uploads (no polling for uploads)

NAEF_DIR="/app/NAEF"
BEACON_BUCKET=${S3_BEACON_BUCKET:-naef-beacon}
EXCHANGE_BUCKET=${S3_EXCHANGE_BUCKET:-naef-exchange}

EXCLUDE_PATTERNS="private_key.pem|vrf_key.bin|vrf_pubkey.hex"

echo "[KDA-SYNC] Starting push-based sync..."
echo "[KDA-SYNC] Beacon: s3://${BEACON_BUCKET}"
echo "[KDA-SYNC] Exchange: s3://${EXCHANGE_BUCKET}"

# Upload a single file to S3
upload_file() {
    local filepath="$1"
    local fname=$(basename "$filepath")

    # Skip excluded files
    if echo "$fname" | grep -qE "$EXCLUDE_PATTERNS"; then
        return
    fi

    # Skip dsmtp folder
    if echo "$filepath" | grep -q "/dsmtp/"; then
        return
    fi

    # Compute S3 key (relative to NAEF_DIR)
    local s3_key="${filepath#$NAEF_DIR/}"
    aws s3 cp "$filepath" "s3://${EXCHANGE_BUCKET}/${s3_key}" --quiet 2>/dev/null &
}

# Background: beacon download loop (lightweight, just 3 small files)
beacon_loop() {
    while true; do
        aws s3 cp "s3://${BEACON_BUCKET}/tebs_beacon.log" /app/tebs_beacon.log --quiet 2>/dev/null
        aws s3 cp "s3://${BEACON_BUCKET}/tebs_pubkey.hex" /app/tebs_pubkey.hex --quiet 2>/dev/null
        aws s3 cp "s3://${BEACON_BUCKET}/tebs_mu.txt" /app/tebs_mu.txt --quiet 2>/dev/null
        sleep 2
    done
}

# Background: upload init.json periodically
init_loop() {
    while true; do
        if [ -f "$NAEF_DIR/init.json" ]; then
            aws s3 cp "$NAEF_DIR/init.json" "s3://${EXCHANGE_BUCKET}/init.json" --quiet 2>/dev/null
        fi
        sleep 5
    done
}

# Background: metrics upload
metrics_loop() {
    while true; do
        if [ -d "$NAEF_DIR/metrics" ]; then
            aws s3 sync "$NAEF_DIR/metrics/" "s3://${EXCHANGE_BUCKET}/metrics/" --quiet 2>/dev/null
        fi
        sleep 10
    done
}

# Start background loops
beacon_loop &
init_loop &
metrics_loop &

# Initial sync of any existing files (catch up after restart)
if [ -d "$NAEF_DIR" ]; then
    echo "[KDA-SYNC] Initial sync of existing files..."
    aws s3 sync "$NAEF_DIR/" "s3://${EXCHANGE_BUCKET}/" \
        --exclude "*/private_key.pem" \
        --exclude "*/vrf_key.bin" \
        --exclude "*/vrf_pubkey.hex" \
        --exclude "dsmtp/*" \
        --quiet 2>/dev/null
    echo "[KDA-SYNC] Initial sync complete."
fi

# Watch for new/modified files and upload immediately
echo "[KDA-SYNC] Watching for file changes..."
inotifywait -m -r -e close_write -e create --format '%w%f' "$NAEF_DIR" 2>/dev/null | while read filepath; do
    [ -f "$filepath" ] || continue
    upload_file "$filepath"
done

# Fallback if inotifywait not available: poll-based with per-domain sync
if [ $? -ne 0 ]; then
    echo "[KDA-SYNC] inotifywait not available, falling back to per-domain sync..."
    while true; do
        if [ -d "$NAEF_DIR" ]; then
            for domain_dir in "$NAEF_DIR"/*/; do
                [ -d "$domain_dir" ] || continue
                dname=$(basename "$domain_dir")
                [[ "$dname" == "metrics" || "$dname" == "dsmtp" ]] && continue
                aws s3 sync "$domain_dir" "s3://${EXCHANGE_BUCKET}/${dname}/" \
                    --exclude "private_key.pem" \
                    --exclude "vrf_key.bin" \
                    --exclude "vrf_pubkey.hex" \
                    --quiet 2>/dev/null &
            done
            wait
        fi
        sleep 2
    done
fi
