#!/bin/bash
echo "=== NAEF VDA Container Starting ==="
echo "Working directory: $(pwd)"
echo ""

# Start sync in background
/app/sync.sh &
SYNC_PID=$!
echo "VDA-SYNC started (PID: $SYNC_PID)"

# Wait for init.json
echo "Waiting for init.json from KDA..."
while [ ! -f /app/NAEF/init.json ]; do
    sleep 2
done
echo "init.json received. Starting VDA Service..."

cd /app
./vda-service

kill $SYNC_PID 2>/dev/null
wait $SYNC_PID 2>/dev/null
echo "=== NAEF VDA Container Stopped ==="
