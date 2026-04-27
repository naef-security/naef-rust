# NAEF Docker Deployment

## Architecture

Three separate containers simulating three independent institutions:

```
Institution A (Domain Operator)     Institution B (Verification)     Institution C (Beacon)
┌─────────────────────────┐        ┌──────────────────────┐        ┌──────────────┐
│  naef-kda               │        │  naef-vda            │        │  naef-tebs   │
│  - kda-service          │        │  - vda-service       │        │  - tebs      │
│  - dsmtp                │        │                      │        │              │
│  - kda (CLI)            │        │  - vda (CLI)         │        │              │
└────────┬────────────────┘        └──────────┬───────────┘        └──────┬───────┘
         │                                    │                           │
    kda-data/                            vda-data/                   beacon-data/
         │                                    │                           │
         └──────── exchange-data ─────────────┘                           │
                   (KDA writes → VDA reads)                               │
                                                                          │
         └──────────────── beacon-data (read-only) ──────────────────────┘
```

## Quick Start

```bash
# 1. Configure KDA credentials
cp .env docker/config/kda/.env
# Edit docker/config/kda/.env with your SES credentials

# 2. Initialize domain (run once before starting services)
#    This creates NAEF/init.json which the services need
docker-compose run --rm naef-kda ./kda init example.com 30 naef._domainkey.example.com 5 3

# 3. Start all services
docker-compose up -d

# 4. View logs
docker-compose logs -f naef-tebs    # Beacon service
docker-compose logs -f naef-kda     # KDA service
docker-compose logs -f naef-vda     # VDA service

# 5. Send a DKIM-signed email (from KDA container)
docker-compose exec naef-kda ./dsmtp SendMail example.com 30 recipient@gmail.com --api

# 6. Stop all services
docker-compose down
```

## Volumes

| Volume | Owner | Purpose |
|--------|-------|---------|
| kda-data | KDA | Private keys, fragments, DSMTP configs |
| vda-data | VDA | Decrypted fragments, reconstructed keys |
| exchange-data | KDA→VDA | Disclosure artifacts (fdr, ebr, dpr, epr, kdr) |
| beacon-data | TEBS | Beacon log, shared read-only with KDA |

## Environment Variables

### TEBS
- `TEBS_MU` - Beacon interval in seconds (default: 5)

### KDA
- All SES/SMTP variables from `.env`
- `AWS_ACCESS_KEY_ID` - For SES API mode
- `AWS_SECRET_ACCESS_KEY` - For SES API mode

## Production Deployment

Replace shared volumes with:
- `exchange-data` → S3 bucket or REST API
- `beacon-data` → Public TEBS HTTP API
- `kda-data` → EFS or local SSD
- `vda-data` → EFS or local SSD

Each container can be deployed to separate AWS accounts/regions:
- TEBS → Public ECS Fargate task
- KDA → Domain operator's AWS account (ECS/EC2)
- VDA → Verification authority's AWS account (ECS/EC2)
