#!/bin/bash
# VDA Sync: Copies artifacts from exchange volume to VDA's local NAEF/
# In production, this would download from S3 or pull via API

NAEF_DIR="/app/NAEF"
EXCHANGE_DIR="/app/exchange"

echo "[VDA-SYNC] Starting sync loop..."

while true; do
    # Sync init.json
    if [ -f "$EXCHANGE_DIR/init.json" ]; then
        cp "$EXCHANGE_DIR/init.json" "$NAEF_DIR/init.json" 2>/dev/null
    fi

    # For each domain folder in exchange, sync to local NAEF
    if [ -d "$EXCHANGE_DIR" ]; then
        for domain_dir in "$EXCHANGE_DIR"/*/; do
            [ -d "$domain_dir" ] || continue
            domain_name=$(basename "$domain_dir")

            for epoch_dir in "$domain_dir"*/; do
                [ -d "$epoch_dir" ] || continue
                epoch_id=$(basename "$epoch_dir")

                [[ "$epoch_id" =~ ^[0-9]+$ ]] || continue

                dest="$NAEF_DIR/$domain_name/$epoch_id"
                mkdir -p "$dest"

                # Sync all files from exchange to local
                for f in "$epoch_dir"*; do
                    [ -f "$f" ] || continue
                    fname=$(basename "$f")
                    if [ ! -f "$dest/$fname" ]; then
                        cp "$f" "$dest/$fname"
                        echo "[VDA-SYNC] Received $domain_name/$epoch_id/$fname"
                    fi
                done
            done
        done
    fi

    sleep 2
done
