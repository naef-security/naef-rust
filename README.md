# NAEF: Non-Attributable Email Framework

NAEF is a deployment-compatible architecture that extends existing DKIM-based systems with a three-plane architecture, i.e., the Mail Delivery Plane, Attribution Control Plane (ACP), and Disclosure Control Plane (DCP). NAEF comprises three independent services: Trusted Epoch Beacon Service (TEBS), Key Disclosure Agent (KDA), and Verifiable Disclosure Authority (VDA). NAEF enables post-expiry cryptographic non-attribution without modifying existing email mechanisms, introduces a key lifecycle management through discrete time epochs. For each epoch, a unique signing key pair is generated and used to sign outgoing emails with epoch-specific keys. Upon epoch conclusion, the private key is disclosed through a verifiable fragmentation and reconstruction protocol, allowing any third party verification.

## Overview

NAEF introduces a structured approach to DKIM key lifecycle management through discrete time epochs. Each epoch generates a unique signing key pair, enabling domain operators to sign outgoing emails with epoch-specific keys. After an epoch concludes, the private key is disclosed through a verifiable fragmentation and reconstruction protocol, allowing any party to retroactively verify or forge signatures for that epoch.

The framework comprises four independent services:

- **TEBS** (Trusted Epoch Beacon Service) -- Generates publicly verifiable beacon values that anchor the temporal progression of epochs.
- **KDA** (Key Disclosure Agent) -- Manages epoch key generation, fragmentation, and disclosure for email-sending domains.
- **VDA** (Verifiable Disclosure Authority) -- Independently verifies key disclosure by decrypting fragments and reconstructing epoch private keys.
- **DSMTP** (DKIM-Signed Mail Transfer Program) -- Sends DKIM-signed emails using epoch-specific RSA keys via Amazon Simple Email Service (SES).

## Architecture

```
TEBS                    KDA                         VDA
(Beacon Service)        (Domain Operator)           (Verifiable Disclosure Authority)
                                                    
  beacon value -------> fragment encryption         
                        key derivation (VRF)        
                                                    
                        EPR: Epoch key generation   
                        EKA: Key activation         
                        KDR: Disclosure commitment  
                        FDR: Encrypted fragments -----> Decrypt fragments
                        DPR: Disclosure publication ---> Reconstruct key
                                                        Verify commitment
                        DSMTP: DKIM-signed email    
```

## Protocol Messages

| Message | Full Name | Description |
|---------|-----------|-------------|
| EPR | Epoch Public Registration | Generates RSA-4096 and VRF key pairs for a new epoch |
| EKA | Epoch Key Activation | Activates the epoch key and produces DKIM signing material |
| KDR | Key Disclosure Request | Creates a SHA3-256 commitment to the disclosure |
| FDR | Fragment Disclosure Record | Encrypts one fragment of the private key using a VRF-derived key |
| EBR | Epoch Beacon Record | Records the TEBS beacon value used for fragment encryption |
| DPR | Disclosure Publication Request | Publishes the final beacon and permutation order |

## Cryptographic Primitives

- RSA-4096 for DKIM signing and commitment encryption
- Ed25519-based VRF for deterministic key derivation from beacon values
- AES-256-CBC for symmetric fragment encryption
- SHA3-256 for disclosure commitments
- Ed25519 for TEBS beacon signatures

## Key Features

- **Forward Attribution Horizon (FAH)**: Pre-generates future epoch keys so the mail service always has signing keys available, decoupling key generation from key disclosure.
- **Beacon-Anchored Fragmentation**: Each fragment is encrypted with a key derived from a TEBS beacon value via a VRF, creating a verifiable temporal chain.
- **Fragment Chaining**: Fragment N+1 carries the beacon details needed to decrypt fragment N, enforcing sequential disclosure.
- **Per-Domain Multi-Epoch**: Supports multiple domains with independent epoch intervals, fragment counts, and FAH values.
- **Verified DKIM Signing**: Produces DKIM signatures (rsa-sha256, relaxed/simple) that pass verification at major email providers.

## Public Interfaces for Verification

The following artifacts are publicly accessible for independent verification after an epoch's embargo period concludes:

- **TEBS Beacon Log**: Signed beacon values with timestamps, verifiable via the TEBS public key.
- **Epoch Commitment (KDR)**: SHA3-256 hash commitment published before fragment disclosure begins.
- **Encrypted Fragments (FDR)**: AES-256-CBC encrypted key fragments with associated beacon records.
- **Disclosure Publication (DPR)**: Final beacon value and fragment permutation order enabling reconstruction.
- **Reconstructed Private Key**: The full DKIM private key, verifiable against the original public key and commitment.

Any party with access to the disclosure artifacts and TEBS beacon history can independently reconstruct the epoch private key and verify that the disclosure matches the pre-committed hash.

NAEF additionally exposes two publicly accessible interfaces for real-world deniability:

- **ASQ** (Attribution Status Query): Allows any third party to determine whether a given email message signature remains attributable or has become deniable, without performing any cryptographic verification.
- **PSG** (Public Signature Generation): Allows any third party to request a valid signature for an arbitrary message under a disclosed domain–epoch pair, without performing cryptographic computations.

After disclosure, signatures under a given epoch are computationally indistinguishable from publicly generated signatures and therefore cannot serve as reliable proof of authorship. The PSG interface demonstrates practical forgeability by producing valid signatures on demand, establishing real-world deniability.

## Building

```
cargo build --release
```

Binaries are produced in `target/release/`:
- `kda`, `kda-service`, `vda`, `vda-service`, `tebs`, `dsmtp`

## Configuration

Copy `.env.example` to `.env` and configure Amazon Simple Email Service (SES) credentials:

```
cp .env.example .env
```

Initialize a domain:

```
./kda init <domain> <epoch_interval_sec> <selector> [num_fragments] [fah]
```

## Usage

### Local Deployment (Docker Compose)

```
docker-compose up -d
docker-compose exec naef-kda ./kda init example.com 30 naef._domainkey.example.com 5 3
```

### Distributed Deployment (3 Servers via S3)

See `deploy/README.md` for instructions on deploying TEBS, KDA, and VDA on separate servers communicating through S3 buckets.

### Sending Email

```
./dsmtp SendMail <domain> <epoch_id> <recipient> --api
```

### CLI Reference

```
./kda        # Key Disclosure Agent commands
./vda        # Verifiable Disclosure Authority commands
./tebs help  # Trusted Epoch Beacon Service commands
./dsmtp      # DKIM-signed email commands
```

## Project Structure

```
src/
  kda.rs            Key Disclosure Agent
  kda_service.rs    KDA continuous service with FAH
  vda.rs            Verifiable Disclosure Authority
  vda_service.rs    VDA continuous service
  tebs.rs           Trusted Epoch Beacon Service
  dsmtp.rs          DKIM-signed email sender
  crypt.rs          Cryptographic primitives

docker/             Local deployment scripts
deploy/             Distributed deployment (S3-based)
```

## License

This software is provided for research and evaluation purposes.
