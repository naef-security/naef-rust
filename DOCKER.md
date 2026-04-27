# NAEF Local Docker Deployment

## Architecture

Three containers simulating independent institutions on a single machine:

```
Container: naef-kda          Container: naef-vda          Container: naef-tebs
(Domain Operator)            (Verification Authority)     (Trusted Beacon)

  kda-service                  vda-service                  tebs
  dsmtp                                                    

  kda-data/                    vda-data/                    beacon-data/
       |                            |                            |
       +---- exchange-data ---------+                            |
       |     (KDA writes,                                        |
       |      VDA reads)                                         |
       +---------------- beacon-data (read-only) ----------------+
```

## Quick Start

```
docker-compose build
docker-compose up -d
docker-compose exec naef-kda ./kda init <domain> <epoch_interval> <selector> [num_fragments] [fah]
```

## Volumes

| Volume | Owner | Description |
|--------|-------|-------------|
| kda-data | KDA | Private keys, fragments, DSMTP signing material |
| vda-data | VDA | Decrypted fragments, reconstructed keys |
| exchange-data | KDA to VDA | Disclosure artifacts (read-only for VDA) |
| beacon-data | TEBS | Beacon log (read-only for KDA) |

## Commands

```
docker-compose logs -f naef-tebs
docker-compose logs -f naef-kda
docker-compose logs -f naef-vda

docker-compose exec naef-kda ./kda <command>
docker-compose exec naef-kda ./dsmtp <command>
docker-compose exec naef-vda ./vda <command>

docker-compose down
```

## Notes

- The local deployment uses shared Docker volumes to simulate inter-service communication.
- In production, replace shared volumes with S3 buckets. See `deploy/README.md`.
- No HTTP or RPC communication exists between services. All communication is file-based.
