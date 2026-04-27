#!/bin/bash
# KDA Sync: Downloads beacon from S3, uploads artifacts to S3

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

    # Upload init.json to exchange
    if [ -f "$NAEF_DIR/init.json" ]; then
        aws s3 cp "$NAEF_DIR/init.json" "s3://${EXCHANGE_BUCKET}/init.json" --quiet 2>/dev/null
    fi

    # Upload disclosure artifacts per domain/epoch
    if [ -d "$NAEF_DIR" ]; then
        for domain_dir in "$NAEF_DIR"/*/; do
            [ -d "$domain_dir" ] || continue
            domain_name=$(basename "$domain_dir")

            for epoch_dir in "$domain_dir"*/; do
                [ -d "$epoch_dir" ] || continue
                epoch_id=$(basename "$epoch_dir")
                [[ "$epoch_id" =~ ^[0-9]+$ ]] || continue

                s3_dest="s3://${EXCHANGE_BUCKET}/${domain_name}/${epoch_id}"

                # Upload disclosure files
                for f in epr.txt kdr.txt commitment.txt permute.txt dpr.txt; do
                    if [ -f "$epoch_dir/$f" ]; then
                        aws s3 cp "$epoch_dir/$f" "${s3_dest}/$f" --quiet 2>/dev/null
                    fi
                done

                # Upload fragment files
                for f in "$epoch_dir"/fdr_*.txt "$epoch_dir"/ebr_*.txt; do
                    [ -f "$f" ] || continue
                    fname=$(basename "$f")
                    aws s3 cp "$f" "${s3_dest}/$fname" --quiet 2>/dev/null
                done
            done
        done
    fi

    sleep 2
done
