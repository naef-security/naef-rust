#!/usr/bin/env python3
"""
NAEF Storage Analysis - Three-party breakdown (KDA, S3 Exchange, VDA)
"""

import csv
import os
import sys
import argparse
from collections import defaultdict
from pathlib import Path

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("Error: pip3 install matplotlib numpy")
    sys.exit(1)

plt.rcParams.update({
    'font.size': 8, 'font.family': 'serif', 'axes.labelsize': 8,
    'axes.titlesize': 9, 'xtick.labelsize': 7, 'ytick.labelsize': 7,
    'legend.fontsize': 6, 'figure.dpi': 150, 'savefig.dpi': 300,
})


def classify_file(fname):
    """Classify a file into owner (kda/shared/vda) and category."""
    if fname == 'private_key.pem': return 'kda', 'private_key'
    if fname.startswith('vrf_'): return 'kda', 'vrf'
    if fname == 'public_key.pem': return 'shared', 'public_key'
    if fname == 'epr.txt': return 'shared', 'epr'
    if fname == 'eka.txt': return 'shared', 'eka'
    if fname == 'kdr.txt': return 'shared', 'kdr'
    if fname == 'commitment.txt': return 'shared', 'commitment'
    if fname == 'dpr.txt': return 'shared', 'dpr'
    if fname == 'permute.txt': return 'shared', 'permute'
    if fname.startswith('fdr_'): return 'shared', 'fdr'
    if fname.startswith('ebr_'): return 'shared', 'ebr'
    if fname.startswith('decrypt_'): return 'vda', 'decrypt'
    if fname == 'recon.txt': return 'vda', 'recon'
    if fname == 'verified.txt': return 'vda', 'verified'
    return 'other', 'other'


def scan_naef_dir(naef_dir, init_path=None):
    """Scan NAEF directory and collect file sizes per epoch."""
    domain_nf = {}
    if init_path and os.path.exists(init_path):
        import json
        with open(init_path) as f:
            for entry in json.load(f):
                domain_nf[entry['domain'].replace('.', '_')] = int(entry['num_fragments'])

    epochs = []
    for domain_dir in sorted(Path(naef_dir).iterdir()):
        if not domain_dir.is_dir() or domain_dir.name in ('metrics', 'dsmtp'):
            continue
        domain_name = domain_dir.name
        nf = domain_nf.get(domain_name, 0)

        for epoch_dir in sorted(domain_dir.iterdir()):
            if not epoch_dir.is_dir():
                continue
            epoch_id = epoch_dir.name
            files = {}
            owners = {'kda': 0, 'shared': 0, 'vda': 0, 'other': 0}
            total = 0
            for f in epoch_dir.iterdir():
                if f.is_file() and not f.name.startswith('.'):
                    size = f.stat().st_size
                    owner, cat = classify_file(f.name)
                    files[cat] = files.get(cat, 0) + size
                    owners[owner] = owners.get(owner, 0) + size
                    total += size
            if total > 0:
                epochs.append({
                    'domain': domain_name,
                    'epoch_id': epoch_id,
                    'num_fragments': nf,
                    'files': files,
                    'owners': owners,
                    'total': total,
                })
    return epochs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--naef-dir', help='Path to NAEF directory')
    parser.add_argument('--init', help='Path to init.json')
    parser.add_argument('--output', default='naef_storage.png')
    args = parser.parse_args()

    if args.naef_dir:
        epochs = scan_naef_dir(args.naef_dir, args.init)
    else:
        print("Provide --naef-dir")
        sys.exit(1)

    if not epochs:
        print("No epoch data found")
        sys.exit(1)

    # Only include fully complete epochs (KDA disclosed + VDA verified)
    complete = [e for e in epochs if 'dpr' in e['files'] and 'verified' in e['files']]
    kda_only_complete = [e for e in epochs if 'dpr' in e['files']]
    print(f"Total epochs: {len(epochs)}, KDA complete: {len(kda_only_complete)}, KDA+VDA complete: {len(complete)}")

    if not complete:
        print("No fully complete epochs (need both dpr.txt and verified.txt)")
        complete = kda_only_complete
        if not complete:
            print("No complete epochs at all")
            sys.exit(1)

    # Group by fragment count
    by_nf = defaultdict(list)
    for e in complete:
        by_nf[e['num_fragments']].append(e)

    nf_sorted = sorted(by_nf.keys())
    print(f"Fragment counts: {nf_sorted}")

    # === CSV with three-party breakdown ===
    csv_path = args.output.replace('.png', '.csv')
    with open(csv_path, 'w') as f:
        f.write("num_fragments,num_epochs,kda_only_bytes,shared_bytes,vda_only_bytes,kda_stores_bytes,s3_stores_bytes,vda_stores_bytes,total_bytes\n")
        for nf in nf_sorted:
            group = by_nf[nf]
            kda_only = np.mean([e['owners'].get('kda', 0) for e in group])
            shared = np.mean([e['owners'].get('shared', 0) for e in group])
            vda_only = np.mean([e['owners'].get('vda', 0) for e in group])
            f.write(f"{nf},{len(group)},{kda_only:.0f},{shared:.0f},{vda_only:.0f},"
                    f"{kda_only+shared:.0f},{shared:.0f},{shared+vda_only:.0f},{kda_only+shared+vda_only:.0f}\n")
    print(f"Storage table saved to {csv_path}")

    colors = ['#2196F3', '#FF9800', '#4CAF50', '#F44336', '#9C27B0',
              '#00BCD4', '#795548', '#607D8B', '#E91E63', '#3F51B5']

    # === Charts ===
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    fig.suptitle('NAEF Storage Analysis', fontsize=14, fontweight='bold', y=1.02)

    # (a) Three-party storage by fragment count
    ax = axes[0]
    x = np.arange(len(nf_sorted))
    w = 0.25
    kda_stores = [np.mean([e['owners'].get('kda', 0) + e['owners'].get('shared', 0) for e in by_nf[nf]]) / 1024 for nf in nf_sorted]
    s3_stores = [np.mean([e['owners'].get('shared', 0) for e in by_nf[nf]]) / 1024 for nf in nf_sorted]
    vda_stores = [np.mean([e['owners'].get('shared', 0) + e['owners'].get('vda', 0) for e in by_nf[nf]]) / 1024 for nf in nf_sorted]
    ax.bar(x - w, kda_stores, w, label='KDA', color='#2196F3', alpha=0.8)
    ax.bar(x, s3_stores, w, label='S3 Exchange', color='#FF9800', alpha=0.8)
    ax.bar(x + w, vda_stores, w, label='VDA', color='#4CAF50', alpha=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels([str(nf) for nf in nf_sorted], rotation=45, ha='right')
    ax.set_xlabel('Number of Fragments')
    ax.set_ylabel('Storage per Epoch (KB)')
    ax.set_title('(a) Storage by Service')
    ax.legend(fontsize=7)
    ax.grid(True, alpha=0.2, axis='y')

    # (b) Stacked breakdown by file type
    ax = axes[1]
    categories = ['private_key', 'vrf', 'public_key', 'epr', 'eka', 'kdr', 'commitment',
                   'fdr', 'ebr', 'dpr', 'permute', 'decrypt', 'recon', 'verified']
    cat_labels = ['Private Key (KDA)', 'VRF Keys (KDA)', 'Public Key', 'EPR', 'EKA', 'KDR',
                  'Commitment', 'FDR (fragments)', 'EBR (beacons)', 'DPR', 'Permute',
                  'Decrypt (VDA)', 'Recon (VDA)', 'Verified (VDA)']
    bottom = np.zeros(len(nf_sorted))
    for i, cat in enumerate(categories):
        vals = [np.mean([e['files'].get(cat, 0) for e in by_nf[nf]]) / 1024 for nf in nf_sorted]
        if max(vals) > 0.01:
            ax.bar(x, vals, 0.6, bottom=bottom, label=cat_labels[i], color=colors[i % len(colors)], alpha=0.8)
            bottom += np.array(vals)
    ax.set_xticks(x)
    ax.set_xticklabels([str(nf) for nf in nf_sorted], rotation=45, ha='right')
    ax.set_xlabel('Number of Fragments')
    ax.set_ylabel('Storage per Epoch (KB)')
    ax.set_title('(b) Storage Breakdown by File Type')
    ax.legend(fontsize=4, ncol=2)
    ax.grid(True, alpha=0.2, axis='y')

    # (c) Scaling lines
    ax = axes[2]
    totals = [np.mean([e['total'] for e in by_nf[nf]]) / 1024 for nf in nf_sorted]
    ax.plot(nf_sorted, kda_stores, 'o-', color='#2196F3', linewidth=1.5, markersize=4, label='KDA stores')
    ax.plot(nf_sorted, s3_stores, 's--', color='#FF9800', linewidth=1, markersize=3, label='S3 Exchange')
    ax.plot(nf_sorted, vda_stores, '^--', color='#4CAF50', linewidth=1, markersize=3, label='VDA stores')
    ax.plot(nf_sorted, totals, 'd-', color='#9C27B0', linewidth=1.5, markersize=4, label='Total (all parties)')
    ax.set_xlabel('Number of Fragments')
    ax.set_ylabel('Storage per Epoch (KB)')
    ax.set_title('(c) Storage Scaling by Service')
    ax.legend(fontsize=7)
    ax.grid(True, alpha=0.2)

    plt.tight_layout()
    plt.savefig(args.output, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Charts saved to {args.output}")

    # Print summary table
    print(f"\n{'n':>4} {'Epochs':>6} {'KDA-only':>10} {'Shared':>10} {'VDA-only':>10} {'KDA stores':>11} {'S3':>10} {'VDA stores':>11} {'Total':>10}")
    print('-' * 95)
    for nf in nf_sorted:
        group = by_nf[nf]
        kda_only = np.mean([e['owners'].get('kda', 0) for e in group])
        shared = np.mean([e['owners'].get('shared', 0) for e in group])
        vda_only = np.mean([e['owners'].get('vda', 0) for e in group])
        print(f"{nf:>4} {len(group):>6} {kda_only/1024:>9.1f}K {shared/1024:>9.1f}K {vda_only/1024:>9.1f}K "
              f"{(kda_only+shared)/1024:>10.1f}K {shared/1024:>9.1f}K {(shared+vda_only)/1024:>10.1f}K {(kda_only+shared+vda_only)/1024:>9.1f}K")

    # Storage formulas
    if len(nf_sorted) > 1:
        kda_vals = [np.mean([e['owners'].get('kda', 0) for e in by_nf[nf]]) for nf in nf_sorted]
        shared_vals = [np.mean([e['owners'].get('shared', 0) for e in by_nf[nf]]) for nf in nf_sorted]
        vda_vals = [np.mean([e['owners'].get('vda', 0) for e in by_nf[nf]]) for nf in nf_sorted]
        print(f"\n=== Storage Summary ===")
        print(f"KDA-only (constant): {np.mean(kda_vals)/1024:.1f} KB (private key + VRF)")
        shared_per_frag = [(shared_vals[i] - shared_vals[0]) / (nf_sorted[i] - nf_sorted[0]) if nf_sorted[i] != nf_sorted[0] else 0 for i in range(1, len(nf_sorted))]
        vda_per_frag = [(vda_vals[i] - vda_vals[0]) / (nf_sorted[i] - nf_sorted[0]) if nf_sorted[i] != nf_sorted[0] else 0 for i in range(1, len(nf_sorted))]
        print(f"Shared per-fragment: ~{np.mean(shared_per_frag):.0f} B/fragment")
        print(f"VDA per-fragment: ~{np.mean(vda_per_frag):.0f} B/fragment")
        total_vals = [kda_vals[i] + shared_vals[i] + vda_vals[i] for i in range(len(nf_sorted))]
        total_per_frag = [(total_vals[i] - total_vals[0]) / (nf_sorted[i] - nf_sorted[0]) if nf_sorted[i] != nf_sorted[0] else 0 for i in range(1, len(nf_sorted))]
        base = total_vals[0] / 1024
        print(f"Total formula: ~{base:.1f} KB + ({np.mean(total_per_frag):.0f} B x n) per epoch")


if __name__ == '__main__':
    main()
