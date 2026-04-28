#!/bin/bash
# NAEF Full Reset Script
# Clears all data across TEBS, KDA, VDA servers and S3 buckets

set -e

TEBS_IP="13.126.249.119"
KDA_IP="13.233.244.51"
VDA_IP="13.206.187.2"
KEY="naef-key.pem"
S3_BEACON="naef-beacon"
S3_EXCHANGE="naef-exchange"

echo "=== NAEF Full Reset ==="
echo ""
echo "This will:"
echo "  - Stop all containers on all 3 servers"
echo "  - Delete all Docker volumes (NAEF data, exchange, beacon)"
echo "  - Clear S3 buckets (beacon + exchange)"
echo "  - Restart fresh containers"
echo ""
read -p "Are you sure? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo "[1/7] Stopping VDA..."
ssh -i $KEY ubuntu@$VDA_IP "cd naef-rust && sudo docker compose -f deploy/vda/docker-compose.yml down -v" 2>&1 || true

echo ""
echo "[2/7] Stopping KDA..."
ssh -i $KEY ubuntu@$KDA_IP "cd naef-rust && sudo docker compose -f deploy/kda/docker-compose.yml down -v" 2>&1 || true

echo ""
echo "[3/7] Stopping TEBS..."
ssh -i $KEY ubuntu@$TEBS_IP "cd naef-rust && sudo docker compose -f deploy/tebs/docker-compose.yml down -v" 2>&1 || true

echo ""
echo "[4/7] Clearing S3 beacon bucket..."
aws s3 rm s3://$S3_BEACON/ --recursive 2>&1 || true

echo ""
echo "[5/7] Clearing S3 exchange bucket..."
aws s3 rm s3://$S3_EXCHANGE/ --recursive 2>&1 || true

echo ""
echo "[6/7] Starting services..."
echo "  Starting TEBS..."
ssh -i $KEY ubuntu@$TEBS_IP "cd naef-rust && sudo docker compose -f deploy/tebs/docker-compose.yml up -d" 2>&1

echo "  Starting KDA..."
ssh -i $KEY ubuntu@$KDA_IP "cd naef-rust && sudo docker compose -f deploy/kda/docker-compose.yml up -d" 2>&1

echo "  Starting VDA..."
ssh -i $KEY ubuntu@$VDA_IP "cd naef-rust && sudo docker compose -f deploy/vda/docker-compose.yml up -d" 2>&1

echo ""
echo "[7/7] Verifying..."
sleep 5
echo "  TEBS:"
ssh -i $KEY ubuntu@$TEBS_IP "cd naef-rust && sudo docker compose -f deploy/tebs/docker-compose.yml ps --format '  {{.Name}}: {{.Status}}'" 2>&1
echo "  KDA:"
ssh -i $KEY ubuntu@$KDA_IP "cd naef-rust && sudo docker compose -f deploy/kda/docker-compose.yml ps --format '  {{.Name}}: {{.Status}}'" 2>&1
echo "  VDA:"
ssh -i $KEY ubuntu@$VDA_IP "cd naef-rust && sudo docker compose -f deploy/vda/docker-compose.yml ps --format '  {{.Name}}: {{.Status}}'" 2>&1

echo ""
echo "=== Reset Complete ==="
echo ""
echo "Next steps:"
echo "  1. Initialize domain:"
echo "     ssh -i $KEY ubuntu@$KDA_IP \"cd naef-rust && sudo docker compose -f deploy/kda/docker-compose.yml exec naef-kda ./kda init <domain> <epoch> <selector> <fragments> <fah>\""
echo ""
echo "  2. View logs:"
echo "     ssh -i $KEY ubuntu@$TEBS_IP \"cd naef-rust && sudo docker compose -f deploy/tebs/docker-compose.yml logs -f\""
echo "     ssh -i $KEY ubuntu@$KDA_IP \"cd naef-rust && sudo docker compose -f deploy/kda/docker-compose.yml logs -f\""
echo "     ssh -i $KEY ubuntu@$VDA_IP \"cd naef-rust && sudo docker compose -f deploy/vda/docker-compose.yml logs -f\""
