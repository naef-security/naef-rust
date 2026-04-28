#!/bin/bash
# VDA Sync: Downloads artifacts from S3 exchange bucket

NAEF_DIR="/app/NAEF"
EXCHANGE_BUCKET=${S3_EXCHANGE_BUCKET:-naef-exchange}

echo "[VDA-SYNC] Starting S3 sync loop..."
echo "[VDA-SYNC] Exchange bucket: s3://${EXCHANGE_BUCKET}"

while true; do
    # Download init.json
    aws s3 cp "s3://${EXCHANGE_BUCKET}/init.json" "$NAEF_DIR/init.json" --quiet 2>/dev/null

    # List all domain folders in S3
    domains=$(aws s3 ls "s3://${EXCHANGE_BUCKET}/" 2>/dev/null | awk '/PRE/{print $2}' | tr -d '/')

    for domain_name in $domains; do
        # List epoch folders
        epochs=$(aws s3 ls "s3://${EXCHANGE_BUCKET}/${domain_name}/" 2>/dev/null | awk '/PRE/{print $2}' | tr -d '/')

        for epoch_id in $epochs; do
            [[ "$epoch_id" =~ ^[0-9]+$ ]] || continue

            dest="$NAEF_DIR/${domain_name}/${epoch_id}"
            mkdir -p "$dest"

            # Sync all files for this epoch
            aws s3 sync "s3://${EXCHANGE_BUCKET}/${domain_name}/${epoch_id}/" "$dest/" --quiet 2>/dev/null

            # Log new files
            for f in "$dest"/*.txt; do
                [ -f "$f" ] || continue
                fname=$(basename "$f")
                marker="$dest/.synced_${fname}"
                if [ ! -f "$marker" ]; then
                    echo "[VDA-SYNC] Received ${domain_name}/${epoch_id}/${fname}"
                    touch "$marker"
                fi
            done
        done
    done

    # Upload VDA metrics to S3
    if [ -d "$NAEF_DIR/metrics" ]; then
        aws s3 sync "$NAEF_DIR/metrics/" "s3://${EXCHANGE_BUCKET}/metrics/" --quiet 2>/dev/null
    fi

    sleep 2
done
