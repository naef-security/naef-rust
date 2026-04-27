#!/bin/bash
# KDA Sync: Copies artifacts from KDA's NAEF/ to the exchange volume
# In production, this would upload to S3 or push via API

NAEF_DIR="/app/NAEF"
EXCHANGE_DIR="/app/exchange"
BEACON_DIR="/app/beacon"

echo "[KDA-SYNC] Starting sync loop..."

while true; do
    # Sync init.json so VDA knows domain configs
    if [ -f "$NAEF_DIR/init.json" ]; then
        cp "$NAEF_DIR/init.json" "$EXCHANGE_DIR/init.json" 2>/dev/null
    fi

    # Sync beacon log from TEBS
    if [ -f "$BEACON_DIR/tebs_beacon.log" ]; then
        cp "$BEACON_DIR/tebs_beacon.log" /app/tebs_beacon.log 2>/dev/null
    fi
    if [ -f "$BEACON_DIR/tebs_mu.txt" ]; then
        cp "$BEACON_DIR/tebs_mu.txt" /app/tebs_mu.txt 2>/dev/null
    fi
    if [ -f "$BEACON_DIR/tebs_pubkey.hex" ]; then
        cp "$BEACON_DIR/tebs_pubkey.hex" /app/tebs_pubkey.hex 2>/dev/null
    fi

    # For each domain folder, sync disclosure artifacts to exchange
    if [ -d "$NAEF_DIR" ]; then
        for domain_dir in "$NAEF_DIR"/*/; do
            [ -d "$domain_dir" ] || continue
            domain_name=$(basename "$domain_dir")

            for epoch_dir in "$domain_dir"*/; do
                [ -d "$epoch_dir" ] || continue
                epoch_id=$(basename "$epoch_dir")

                # Skip non-numeric folders (like dsmtp)
                [[ "$epoch_id" =~ ^[0-9]+$ ]] || continue

                dest="$EXCHANGE_DIR/$domain_name/$epoch_id"
                mkdir -p "$dest"

                # Sync files that VDA needs
                for f in epr.txt kdr.txt commitment.txt permute.txt dpr.txt; do
                    if [ -f "$epoch_dir/$f" ] && [ ! -f "$dest/$f" ]; then
                        cp "$epoch_dir/$f" "$dest/$f"
                        echo "[KDA-SYNC] Copied $domain_name/$epoch_id/$f"
                    fi
                done

                # Sync fragment files (fdr_*.txt, ebr_*.txt)
                for f in "$epoch_dir"/fdr_*.txt "$epoch_dir"/ebr_*.txt; do
                    [ -f "$f" ] || continue
                    fname=$(basename "$f")
                    if [ ! -f "$dest/$fname" ]; then
                        cp "$f" "$dest/$fname"
                        echo "[KDA-SYNC] Copied $domain_name/$epoch_id/$fname"
                    fi
                done
            done
        done
    fi

    sleep 2
done
