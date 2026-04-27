# NAEF Distributed Deployment

## Modes

### Local Mode (single machine, docker-compose)
```bash
cd src-rust/
docker-compose up -d
docker-compose exec naef-kda ./kda init brandgetgo.com 30 naef._domainkey.brandgetgo.com 5 3
```

### Distributed Mode (3 separate servers via S3)

#### Prerequisites
1. Create 2 S3 buckets:
   - `naef-beacon` (TEBS writes, KDA reads)
   - `naef-exchange` (KDA writes, VDA reads)

2. Create 3 IAM users with policies:
   - **TEBS IAM**: `s3:PutObject` on `naef-beacon/*`
   - **KDA IAM**: `s3:GetObject` on `naef-beacon/*`, `s3:PutObject` + `s3:ListBucket` on `naef-exchange/*`
   - **VDA IAM**: `s3:GetObject` + `s3:ListBucket` on `naef-exchange/*`

#### Server 1: TEBS (Trusted Beacon)
```bash
cd deploy/tebs/
cp .env.example .env
# Edit .env with AWS credentials
docker-compose up -d
docker-compose logs -f
```

#### Server 2: KDA (Domain Operator)
```bash
cd deploy/kda/
cp .env.example .env
# Edit .env with AWS + SES credentials
docker-compose up -d

# Initialize domain
docker-compose exec naef-kda ./kda init brandgetgo.com 30 naef._domainkey.brandgetgo.com 5 3

# Send email
docker-compose exec naef-kda ./dsmtp SendMail brandgetgo.com 30 recipient@gmail.com --api

docker-compose logs -f
```

#### Server 3: VDA (Verification Authority)
```bash
cd deploy/vda/
cp .env.example .env
# Edit .env with AWS credentials
docker-compose up -d
docker-compose logs -f
```

## Architecture

```
Server 1 (TEBS)              Server 2 (KDA)              Server 3 (VDA)
┌──────────────┐            ┌──────────────┐            ┌──────────────┐
│  tebs        │            │  kda-service │            │  vda-service │
│              │            │  dsmtp       │            │              │
└──────┬───────┘            └──────┬───────┘            └──────┬───────┘
       │                           │                           │
       │  s3://naef-beacon/        │  s3://naef-exchange/      │
       │  (beacon log)             │  (disclosure artifacts)   │
       └──────────►────────────────┘──────────►────────────────┘
```

## S3 Bucket Structure

```
s3://naef-beacon/
  tebs_beacon.log
  tebs_pubkey.hex
  tebs_mu.txt

s3://naef-exchange/
  init.json
  brandgetgo_com/
    30/
      epr.txt
      kdr.txt
      commitment.txt
      fdr_1.txt ... fdr_5.txt
      ebr_1.txt ... ebr_5.txt
      dpr.txt
    60/
      ...
```

## Switching Modes

The same Docker image supports both modes via `NAEF_MODE` environment variable:
- `NAEF_MODE=local` (default) — uses Docker shared volumes
- `NAEF_MODE=s3` — uses S3 buckets for communication

No code changes or rebuilds needed to switch modes.
