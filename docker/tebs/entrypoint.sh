#!/bin/bash
echo "=== NAEF TEBS Container Starting ==="
echo "Working directory: $(pwd)"
echo "Beacon directory: /app/beacon"
echo ""

# TEBS writes beacon log to the shared beacon volume
cd /app

# Default mu=5, can be overridden via TEBS_MU env var
MU=${TEBS_MU:-5}
echo "Starting TEBS with mu=${MU}s..."

# Symlink beacon files to shared volume
ln -sf /app/beacon/tebs_beacon.log /app/tebs_beacon.log 2>/dev/null
ln -sf /app/beacon/tebs_key.bin /app/tebs_key.bin 2>/dev/null
ln -sf /app/beacon/tebs_pubkey.hex /app/tebs_pubkey.hex 2>/dev/null
ln -sf /app/beacon/tebs_mu.txt /app/tebs_mu.txt 2>/dev/null

# Run tebs with output files going to beacon volume
./tebs mu=$MU

echo "=== NAEF TEBS Container Stopped ==="
