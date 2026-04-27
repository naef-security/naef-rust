#!/bin/bash
echo "=== NAEF KDA Server Starting ==="
echo "Beacon: s3://${S3_BEACON_BUCKET:-naef-beacon}"
echo "Exchange: s3://${S3_EXCHANGE_BUCKET:-naef-exchange}"
echo ""

# Start S3 sync in background
/app/sync.sh &
SYNC_PID=$!
echo "KDA-SYNC started (PID: $SYNC_PID)"

# Wait for beacon to be available
echo "Waiting for TEBS beacon..."
while [ ! -f /app/tebs_beacon.log ]; do
    sleep 2
done
echo "Beacon available. Starting KDA Service..."

cd /app
./kda-service

kill $SYNC_PID 2>/dev/null
wait $SYNC_PID 2>/dev/null
echo "=== NAEF KDA Server Stopped ==="
