# NAEF Experimental Runs

## Infrastructure

| Service | Instance Type | vCPUs | Memory | Region |
|---------|--------------|-------|--------|--------|
| TEBS | t3.small | 2 | 2 GB | ap-south-1 |
| KDA | t3.xlarge | 4 | 16 GB | ap-south-1 |
| VDA | t3.xlarge | 4 | 16 GB | ap-south-1 |

- OS: Ubuntu 22.04 LTS, Linux 6.8 kernel
- Deployment: Docker containers (Rust 2021 edition, release mode), S3-mediated communication
- S3 Buckets: `naef-beacon`, `naef-exchange`

## Cryptographic Parameters

| Parameter | Value |
|-----------|-------|
| DKIM Keys | RSA-4096 (fresh per epoch) |
| Fragment Encryption | AES-256-CBC |
| Key Derivation | Ed25519-based VRF |
| Commitment | SHA3-256 + RSA-4096 encrypted wrapping |
| Beacon Signature | Ed25519-signed SHA3-256 hash |
| Beacon Interval (μ) | 5 seconds |
| Forward Attribution Horizon (FAH) | 3 epochs |

---

## Campaign 1: Fragment Count Scaling

**Directory**: `Campaign1_FragmentCountScaling/`

| Parameter | Value |
|-----------|-------|
| Domains | 100 (10 per fragment category) |
| Fragment categories (k) | 2, 3, 4, 5, 6, 10, 12, 15, 20, 30 |
| Epoch interval (τ) | 900s (15 min), constant |
| Run duration | 40.6 hours |
| Total epoch disclosures | 15,586 |
| Sustained throughput | 384 epochs/hour (6.4/min) |

**Files**:
- `kda_metrics.csv` — Per-operation KDA timing data
- `vda_metrics.csv` — Per-operation VDA timing data
- `plot_analysis.py` — Colab-compatible 4-panel analysis script

---

## Campaign 2: Epoch Interval Scaling

**Directory**: `Campaign2_EpochIntervalScaling/`

| Parameter | Value |
|-----------|-------|
| Domains | 80 (10 per interval category) |
| Epoch intervals (τ) | 5, 6, 10, 12, 15, 20, 30, 60 minutes |
| Fragment count (k) | 10, constant |
| Run duration | 46.5 hours |
| Total epoch disclosures | 18,787 |
| Sustained throughput | 404 epochs/hour (6.7/min) |

**Files**:
- `kda_metrics.csv` — Per-operation KDA timing data
- `vda_metrics.csv` — Per-operation VDA timing data
- `epoch_lifecycle_formatted.csv` — End-to-end epoch timing data
- `init.json` — Domain configuration (80 domains)
- `build_lifecycle.py` — Builds lifecycle CSV from raw metrics
- `plot_analysis.py` — Colab-compatible 4-panel analysis script

---

## Combined Analysis

**Directory**: `analysis/`

- `combine_figures.py` — Generates 8-panel combined figure from both campaigns
- `naef_combined_analysis.png` — Output figure (regenerated from source PNGs)
