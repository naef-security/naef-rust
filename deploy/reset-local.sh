#!/bin/bash
# NAEF Local Reset - Clears all local Docker data

echo "=== NAEF Local Reset ==="
echo ""
echo "This will stop all containers and delete all volumes."
read -p "Are you sure? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo "Stopping containers..."
docker-compose down -v 2>/dev/null || docker compose down -v 2>/dev/null

echo ""
echo "Removing any orphan containers..."
docker rm -f naef-tebs naef-kda naef-vda 2>/dev/null || true

echo ""
echo "=== Reset Complete ==="
echo ""
echo "To start fresh:"
echo "  docker-compose up -d"
echo "  docker-compose exec naef-kda ./kda init <domain> <epoch> <selector> <fragments> <fah>"
