# NAEF Distributed Deployment

## Deployment Modes

NAEF supports two deployment modes using the same Docker images:

- **Local mode** (`NAEF_MODE=local`): All services on a single machine using shared Docker volumes.
- **Distributed mode** (`NAEF_MODE=s3`): Each service on a separate server, communicating through S3 buckets.

## Architecture

```
Server 1 (TEBS)              Server 2 (KDA)              Server 3 (VDA)
Trusted Beacon               Domain Operator              Verification Authority

+--------------+            +--------------+            +--------------+
|  tebs        |            |  kda-service |            |  vda-service |
|              |            |  dsmtp       |            |              |
+------+-------+            +------+-------+            +------+-------+
       |                           |                           |
       |  s3://naef-beacon/        |  s3://naef-exchange/      |
       |  (beacon log)             |  (disclosure artifacts)   |
       +----------->---------------+----------->---------------+
```

## Prerequisites

1. Two S3 buckets:
   - Beacon bucket (TEBS writes, KDA reads)
   - Exchange bucket (KDA writes, VDA reads)

2. Three IAM users with least-privilege policies:
   - TEBS: `s3:PutObject` on beacon bucket
   - KDA: `s3:GetObject` on beacon bucket; `s3:PutObject`, `s3:GetObject`, `s3:ListBucket` on exchange bucket
   - VDA: `s3:GetObject`, `s3:ListBucket` on exchange bucket

3. Three server instances with Docker installed.

## Setup

### Server 1: TEBS

```
cd deploy/tebs
cp .env.example .env
# Configure AWS credentials and beacon interval
docker compose up -d
docker compose logs -f
```

### Server 2: KDA

```
cd deploy/kda
cp .env.example .env
# Configure AWS credentials and SES credentials
docker compose up -d
docker compose exec naef-kda ./kda init <domain> <epoch_interval> <selector> [num_fragments] [fah]
docker compose logs -f
```

### Server 3: VDA

```
cd deploy/vda
cp .env.example .env
# Configure AWS credentials
docker compose up -d
docker compose logs -f
```

Start services in order: TEBS first, then KDA, then VDA.

## S3 Bucket Structure

```
s3://<beacon-bucket>/
  tebs_beacon.log
  tebs_pubkey.hex
  tebs_mu.txt

s3://<exchange-bucket>/
  init.json
  <domain>/
    <epoch_id>/
      epr.txt
      kdr.txt
      commitment.txt
      fdr_1.txt ... fdr_N.txt
      ebr_1.txt ... ebr_N.txt
      dpr.txt
```

## Environment Variables

### TEBS
| Variable | Description |
|----------|-------------|
| `TEBS_MU` | Beacon interval in seconds |
| `S3_BEACON_BUCKET` | S3 bucket for beacon data |
| `AWS_ACCESS_KEY_ID` | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `AWS_DEFAULT_REGION` | AWS region |

### KDA
| Variable | Description |
|----------|-------------|
| `S3_BEACON_BUCKET` | S3 bucket for beacon data (read) |
| `S3_EXCHANGE_BUCKET` | S3 bucket for disclosure artifacts (write) |
| `Mail_SMTP_HOST` | SES SMTP endpoint |
| `MAIL_SMTP_USERNAME` | SES SMTP username |
| `MAIL_SMTP_PASSWORD` | SES SMTP password |
| `AWS_ACCESS_KEY_ID` | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `AWS_DEFAULT_REGION` | AWS region |

### VDA
| Variable | Description |
|----------|-------------|
| `S3_EXCHANGE_BUCKET` | S3 bucket for disclosure artifacts (read) |
| `AWS_ACCESS_KEY_ID` | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `AWS_DEFAULT_REGION` | AWS region |

## Operations

### Add a domain
```
docker compose exec naef-kda ./kda init <domain> <epoch_interval> <selector> [num_fragments] [fah]
```

### Send email
```
docker compose exec naef-kda ./dsmtp SendMail <domain> <epoch_id> <recipient> --api
```

### View logs
```
docker compose logs -f
```

### Restart
```
docker compose restart
```

### Stop
```
docker compose down
```

## Switching Modes

The `NAEF_MODE` environment variable controls the communication method:
- `local` (default): Docker shared volumes
- `s3`: S3 buckets

No code changes or image rebuilds are required to switch modes.
