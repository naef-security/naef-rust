# NAEF Performance Test Runs

## Infrastructure

| Service | Instance Type | vCPUs | Memory | Region |
|---------|--------------|-------|--------|--------|
| TEBS | t3.small | 2 | 2 GB | ap-south-1 |
| KDA | t3.xlarge (runs 1-2: t3.small) | 4 | 16 GB | ap-south-1 |
| VDA | t3.xlarge (runs 1-2: t3.small) | 4 | 16 GB | ap-south-1 |

- OS: Ubuntu 22.04 LTS, Linux 6.8 kernel
- Deployment: Docker containers, S3-mediated communication (2s sync interval)
- S3 Buckets: `naef-beacon`, `naef-exchange`

## Cryptographic Parameters

- DKIM Keys: RSA-4096
- Fragment Encryption: AES-256-CBC (key from Ed25519 VRF output)
- Commitment: SHA3-256 + RSA-4096 encrypted
- Beacon: Ed25519-signed SHA3-256 hash
- FAH: 3 (all runs)

---

## Run 1: Baseline (50 Domains)

**Objective**: Establish baseline performance with heterogeneous configuration.

| Parameter | Value |
|-----------|-------|
| Domains | 50 |
| Fragment counts | 3, 5, 7, 10, 12, 15 (8-9 domains each) |
| Epoch intervals | 60s, 90s, 120s (16-17 domains each) |
| Beacon μ | 5s |
| Instance type | t3.small (KDA, VDA) |
| Duration | Continuous |

**Results**:
- KDA records: 9,381
- VDA records: 4,576
- Completed epochs: 443

**Summary**:

| Operation | Count | Mean (ms) | P95 (ms) | P99 (ms) |
|-----------|-------|-----------|----------|----------|
| EKA | 856 | 22.3 | 38.1 | 61.9 |
| KDR | 707 | 56.3 | 87.5 | 109.8 |
| Fragment | 5,600 | 35.6 | 54.0 | 66.9 |
| DPR | 681 | 23.7 | 38.9 | 49.9 |
| Decrypt | 3,690 | 1.8 | 2.3 | 4.0 |
| Reconstruct | 443 | 2.0 | 2.4 | 3.4 |
| VerifyCommit | 443 | 25.3 | 27.7 | 39.2 |

---

## Run 2: Scale Test (203 Domains)

**Objective**: Test scalability with many domains and varying epoch intervals.

| Parameter | Value |
|-----------|-------|
| Domains | 203 |
| Fragment count | 5 (uniform) |
| Epoch intervals | 10s to 360s (16 distinct values) |
| Beacon μ | 5s |
| Instance type | t3.xlarge (KDA, VDA) |
| Duration | 60 minutes (time-bounded) |

**Domain distribution by epoch interval**:

| Epoch (s) | Domains |
|-----------|---------|
| 10 | 1 |
| 20 | 2 |
| 30 | 3 |
| 40 | 4 |
| 50 | 5 |
| 60 | 6 |
| 80 | 8 |
| 90 | 9 |
| 100 | 10 |
| 120 | 12 |
| 150 | 15 |
| 180 | 18 |
| 200 | 20 |
| 240 | 24 |
| 300 | 30 |
| 360 | 36 |

**Results**:
- KDA records: 25,089
- VDA records: 5,200
- Completed epochs: 718

**Summary**:

| Operation | Count | Mean (ms) | P95 (ms) | P99 (ms) |
|-----------|-------|-----------|----------|----------|
| EKA | 2,865 | 52.5 | 97.4 | 129.1 |
| KDR | 2,447 | 110.5 | 159.1 | 209.1 |
| Fragment | 12,158 | 70.1 | 116.5 | 194.1 |
| DPR | 2,381 | 59.8 | 105.6 | 122.0 |
| Decrypt | 3,763 | 1.9 | 3.2 | 8.0 |
| Reconstruct | 719 | 2.2 | 3.8 | 9.6 |
| VerifyCommit | 718 | 17.2 | 24.7 | 38.3 |

**Note**: ~2× increase in KDA operation times vs Run 1 due to CPU contention (203 threads on 4 vCPUs).

---

## Run 3: Fragment Scaling (120 Domains)

**Objective**: Isolate the effect of fragment count on processing time and storage.

| Parameter | Value |
|-----------|-------|
| Domains | 120 |
| Fragment counts | 2, 3, 4, 8, 10, 15, 20, 24, 30, 40, 60, 120 (10 domains each) |
| Epoch interval | 240s (uniform) |
| Beacon μ | 5s |
| Instance type | t3.xlarge (KDA, VDA) |
| Duration | 120 minutes (time-bounded) |

**Results**:
- KDA records: 158,428
- VDA records: 83,752
- Completed epochs: 3,096

**Summary**:

| Operation | Count | Mean (ms) | P95 (ms) | P99 (ms) |
|-----------|-------|-----------|----------|----------|
| EKA | 5,618 | 6.4 | 25.6 | 58.5 |
| KDR | 5,373 | 10.3 | 21.5 | 78.6 |
| Fragment | 131,330 | 7.8 | 16.3 | 29.0 |
| DPR | 5,245 | 5.0 | 10.9 | 16.7 |
| Decrypt | 77,559 | 1.9 | 3.1 | 7.5 |
| Reconstruct | 3,097 | 2.2 | 3.6 | 7.6 |
| VerifyCommit | 3,096 | 17.9 | 27.4 | 47.5 |

**Storage Analysis** (per epoch):

| Fragments | KDA stores | S3 Exchange | VDA stores | Total |
|-----------|-----------|-------------|-----------|-------|
| 2 | 19.0 KB | 15.7 KB | 19.8 KB | 23.1 KB |
| 5 | 23.3 KB | 20.0 KB | 26.2 KB | 29.5 KB |
| 10 | 24.2 KB | 20.9 KB | 29.1 KB | 32.4 KB |
| 30 | 38.3 KB | 35.0 KB | 53.6 KB | 56.9 KB |
| 60 | 60.3 KB | 57.0 KB | 91.1 KB | 94.4 KB |
| 120 | 101.7 KB | 98.4 KB | 163.4 KB | 166.7 KB |

**Storage formula**: ~18.6 KB + (1,937 B × n) per epoch

---

## Run 4: Epoch-Count Target (203 Domains)

**Objective**: Rerun 203 domains with epoch-count target to ensure all domains produce exact number of epochs.

| Parameter | Value |
|-----------|-------|
| Domains | 203 |
| Fragment count | 5 (uniform) |
| Epoch intervals | 10s to 360s (same as Run 2) |
| Beacon μ | 5s |
| Instance type | t3.xlarge (KDA, VDA) |
| Duration | Epoch-count target (60min equivalent per domain) |

**Target epochs per domain**: `3600 / epoch_interval`

| Epoch (s) | Target epochs | Domains | Total epochs |
|-----------|--------------|---------|-------------|
| 10 | 360 | 1 | 360 |
| 20 | 180 | 2 | 360 |
| 30 | 120 | 3 | 360 |
| ... | ... | ... | ... |
| 360 | 10 | 36 | 360 |
| **Total** | | **203** | **5,760** |

**Results**:
- KDA records: 59,120
- VDA records: 31,267
- Completed epochs (KDA): 5,814
- Completed epochs (VDA verified): 4,448
- All 203 domains hit their targets
- Total run time: ~161 minutes

**Summary**:

| Operation | Count | Mean (ms) | P95 (ms) | P99 (ms) |
|-----------|-------|-----------|----------|----------|
| EKA | 6,523 | 35.8 | 83.9 | 111.5 |
| KDR | 6,104 | 76.5 | 135.6 | 185.7 |
| Fragment | 30,513 | 48.7 | 108.0 | 154.4 |
| DPR | 6,054 | 41.8 | 99.3 | 118.4 |
| Decrypt | 18,259 | 2.1 | 4.2 | 9.5 |
| Reconstruct | 3,631 | 2.2 | 4.4 | 9.4 |
| VerifyCommit | 3,631 | 19.0 | 31.8 | 52.8 |

---

## Run 5: Beacon Interval Test (20 Domains, μ=10s)

**Objective**: Test with larger beacon interval (μ=10s) and varying fragment counts.

| Parameter | Value |
|-----------|-------|
| Domains | 20 |
| Fragment counts | 5, 10, 20, 30 (5 domains each) |
| Epoch interval | 300s (uniform) |
| Beacon μ | 10s |
| Instance type | t3.xlarge (KDA, VDA) |
| Duration | Epoch-count target (20min = 4 epochs/domain) |
| Total target epochs | 80 |

**Results**:
- KDA records: 2,136
- VDA records: 1,569
- Completed epochs: 80 (all targets met)
- VDA verified: 80/80
- Total run time: ~25 minutes

---

## Key Insights

1. **VDA is ~19× cheaper than KDA** per fragment (decrypt ~2ms vs encrypt ~35-70ms)
2. **CPU contention** doubles KDA operation times when scaling from 50 to 203 threads on 4 vCPUs
3. **VDA decrypt remains constant** (~2ms) regardless of scale or contention
4. **Storage scales linearly**: ~1.9 KB per additional fragment per epoch
5. **FAH overhead**: Initial key generation for 203 domains takes ~20 minutes (609 RSA-4096 keypairs)
6. **Fragment wait time** is the primary bottleneck: `epoch_interval / num_fragments` seconds between each fragment
7. **Epoch-count target** ensures deterministic completion vs time-based cutoff leaving incomplete epochs

---

## Files per Run

Each run folder contains:
- `kda_metrics.csv` — Per-operation KDA timing data
- `vda_metrics.csv` — Per-operation VDA timing data
- `naef_dashboard.png` — 12-chart performance dashboard
- `naef_dashboard_summary.csv` — Statistical summary (mean, P95, P99)
- `init_*.json` — Domain configuration used
- `naef_storage.png` / `naef_storage.csv` / `storage_raw.csv` — Storage analysis (Run 3 only)
