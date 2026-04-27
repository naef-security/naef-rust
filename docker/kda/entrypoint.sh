#!/bin/bash
echo "=== NAEF KDA Container Starting ==="
echo "Working directory: $(pwd)"
echo ""

# Start sync in background
/app/sync.sh &
SYNC_PID=$!
echo "KDA-SYNC started (PID: $SYNC_PID)"

# Start kda-service
echo "Starting KDA Service..."
cd /app
./kda-service

kill $SYNC_PID 2>/dev/null
wait $SYNC_PID 2>/dev/null
echo "=== NAEF KDA Container Stopped ==="
