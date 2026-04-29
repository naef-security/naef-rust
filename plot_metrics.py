#!/usr/bin/env python3
"""
NAEF Metrics Dashboard - 8 Charts (4x2 grid)
"""

import csv
import os
import sys
import argparse
from collections import defaultdict

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("Error: pip3 install matplotlib numpy")
    sys.exit(1)

plt.rcParams.update({
    'font.size': 8,
    'font.family': 'serif',
    'axes.labelsize': 8,
    'axes.titlesize': 9,
    'xtick.labelsize': 7,
    'ytick.labelsize': 7,
    'legend.fontsize': 6,
    'figure.dpi': 150,
    'savefig.dpi': 300,
})

COLORS = ['#2196F3', '#4CAF50', '#FF9800', '#F44336', '#9C27B0', '#00BCD4', '#795548', '#607D8B', '#E91E63', '#3F51B5']


def read_csv(path):
    with open(path, 'r') as f:
        return list(csv.DictReader(f))


def parse_kda(rows):
    return [{
        'timestamp': int(r['timestamp']),
        'domain': r['domain'],
        'epoch_id': r['epoch_id'],
        'operation': r['operation'],
        'duration_ms': float(r['duration_ms']),
        'num_fragments': int(r.get('num_fragments') or '5'),
        'fah': int(r.get('fah') or '5'),
    } for r in rows]


def parse_vda(rows):
    return [{
        'timestamp': int(r['timestamp']),
        'domain': r['domain'],
        'epoch_id': r['epoch_id'],
        'operation': r['operation'],
        'duration_ms': float(r['duration_ms']),
        'num_fragments': int(r.get('num_fragments') or '5'),
    } for r in rows]


def norm(op):
    if op.startswith('fragment_'): return 'fragment'
    if op.startswith('decrypt_'): return 'decrypt'
    if op.startswith('fah_epr'): return 'epr'
    if op.startswith('fah_eka'): return 'eka'
    return op


def get_vals(kda, vda, op):
    return ([d['duration_ms'] for d in kda if norm(d['operation']) == op] +
            [d['duration_ms'] for d in vda if norm(d['operation']) == op])


def get_e2e_times(kda, vda):
    kda_start = {}
    for d in kda:
        key = (d['domain'], d['epoch_id'])
        if key not in kda_start or d['timestamp'] < kda_start[key]['ts']:
            kda_start[key] = {'ts': d['timestamp'], 'nf': d['num_fragments']}

    vda_end = {}
    for d in vda:
        if d['operation'] == 'verify_commit':
            key = (d['domain'], d['epoch_id'])
            vda_end[key] = d['timestamp']

    e2e = {}
    for key in set(kda_start.keys()) & set(vda_end.keys()):
        e2e[key] = {
            'duration_s': vda_end[key] - kda_start[key]['ts'],
            'domain': key[0],
            'epoch_id': key[1],
            'nf': kda_start[key]['nf'],
        }
    return e2e


def plot_cdf(ax, values, color, label=None):
    if not values:
        return
    sorted_v = np.sort(values)
    cdf = np.arange(1, len(sorted_v) + 1) / len(sorted_v)
    ax.plot(sorted_v, cdf, linewidth=1.5, color=color, label=label)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kda', default='kda_metrics.csv')
    parser.add_argument('--vda', default='vda_metrics.csv')
    parser.add_argument('--output', default='naef_dashboard.png')
    args = parser.parse_args()

    kda = parse_kda(read_csv(args.kda)) if os.path.exists(args.kda) else []
    vda = parse_vda(read_csv(args.vda)) if os.path.exists(args.vda) else []
    e2e = get_e2e_times(kda, vda)
    print(f"Loaded {len(kda)} KDA, {len(vda)} VDA, {len(e2e)} E2E records")

    fig, axes = plt.subplots(2, 4, figsize=(22, 10))
    fig.suptitle('NAEF Protocol Performance Dashboard', fontsize=16, fontweight='bold', y=0.995)

    # =========================================================
    # (a) KDA Epoch Lifecycle Stacked Bar by Fragment Count
    # =========================================================
    ax = axes[0][0]
    frag_configs = sorted(set(d['num_fragments'] for d in kda))
    lc_ops = ['eka', 'kdr', 'fragment', 'dpr']
    lc_colors = ['#81C784', '#FFB74D', '#E57373', '#BA68C8']
    lc_labels = ['EKA', 'KDR', 'Fragment', 'DPR']
    bar_d = {op: [] for op in lc_ops}
    for nf in frag_configs:
        for op in lc_ops:
            vals = [d['duration_ms'] for d in kda if norm(d['operation']) == op and d['num_fragments'] == nf]
            bar_d[op].append(np.mean(vals) if vals else 0)
    x = np.arange(len(frag_configs))
    bottom = np.zeros(len(frag_configs))
    for i, op in enumerate(lc_ops):
        ax.bar(x, bar_d[op], 0.5, bottom=bottom, label=lc_labels[i], color=lc_colors[i], alpha=0.8)
        bottom += np.array(bar_d[op])
    ax.set_xticks(x)
    ax.set_xticklabels([f'n={nf}' for nf in frag_configs])
    ax.set_xlabel('Number of Fragments')
    ax.set_ylabel('Mean Processing Time (ms)')
    ax.set_title('(a) KDA Epoch Cost by Number of Fragments')
    ax.legend(fontsize=6)
    ax.grid(True, alpha=0.2, axis='y')

    # =========================================================
    # (b) VDA Reconstruction Stacked Bar by Fragment Count
    # =========================================================
    ax = axes[0][1]
    vda_fcs = sorted(set(d['num_fragments'] for d in vda))
    vda_ops = ['decrypt', 'reconstruct', 'verify_commit']
    vda_colors = ['#00BCD4', '#795548', '#607D8B']
    vda_labels = ['Decrypt (total)', 'Reconstruct', 'VerifyCommit']
    vda_bar = {op: [] for op in vda_ops}
    for nf in vda_fcs:
        for op in vda_ops:
            if op == 'decrypt':
                ep_sums = defaultdict(float)
                ep_counts = defaultdict(int)
                for d in vda:
                    if norm(d['operation']) == 'decrypt' and d['num_fragments'] == nf:
                        ep_sums[(d['domain'], d['epoch_id'])] += d['duration_ms']
                        ep_counts[(d['domain'], d['epoch_id'])] += 1
                complete = [v for k, v in ep_sums.items() if ep_counts[k] == nf]
                vda_bar[op].append(np.mean(complete) if complete else 0)
            else:
                vals = [d['duration_ms'] for d in vda if norm(d['operation']) == op and d['num_fragments'] == nf]
                vda_bar[op].append(np.mean(vals) if vals else 0)
    x = np.arange(len(vda_fcs))
    bottom = np.zeros(len(vda_fcs))
    for i, op in enumerate(vda_ops):
        ax.bar(x, vda_bar[op], 0.5, bottom=bottom, label=vda_labels[i], color=vda_colors[i], alpha=0.8)
        bottom += np.array(vda_bar[op])
    ax.set_xticks(x)
    ax.set_xticklabels([f'n={nf}' for nf in vda_fcs])
    ax.set_xlabel('Number of Fragments')
    ax.set_ylabel('Mean Total Processing Time (ms)')
    ax.set_title('(b) VDA Reconstruction Cost')
    ax.legend(fontsize=6)
    ax.grid(True, alpha=0.2, axis='y')

    # =========================================================
    # (c) CDF: KDA Operations
    # =========================================================
    ax = axes[0][2]
    kda_cdf_ops = ['eka', 'kdr', 'fragment', 'dpr']
    kda_cdf_labels = ['EKA', 'KDR', 'Fragment', 'DPR']
    for i, (op, label) in enumerate(zip(kda_cdf_ops, kda_cdf_labels)):
        vals = get_vals(kda, [], op)
        plot_cdf(ax, vals, COLORS[i], label)
    ax.set_xlabel('Processing Time (ms)')
    ax.set_ylabel('CDF')
    ax.set_title('(c) CDF: KDA Processing Time')
    ax.legend(loc='lower right', fontsize=7)
    ax.grid(True, alpha=0.2)

    # =========================================================
    # (d) CDF: VDA Operations
    # =========================================================
    ax = axes[0][3]
    vda_cdf_ops = ['decrypt', 'reconstruct', 'verify_commit']
    vda_cdf_labels = ['Decrypt', 'Reconstruct', 'VerifyCommit']
    for i, (op, label) in enumerate(zip(vda_cdf_ops, vda_cdf_labels)):
        vals = get_vals([], vda, op)
        plot_cdf(ax, vals, COLORS[i + 4], label)
    ax.set_xlabel('Processing Time (ms)')
    ax.set_ylabel('CDF')
    ax.set_title('(d) CDF: VDA Processing Time')
    ax.legend(loc='lower right', fontsize=7)
    ax.grid(True, alpha=0.2)

    # =========================================================
    # (e) KDA Processing Scaling
    # =========================================================
    ax = axes[1][0]
    ep_frag = defaultdict(lambda: {'total': 0, 'nf': 0, 'count': 0})
    for d in kda:
        if norm(d['operation']) == 'fragment':
            key = (d['domain'], d['epoch_id'])
            ep_frag[key]['total'] += d['duration_ms']
            ep_frag[key]['nf'] = d['num_fragments']
            ep_frag[key]['count'] += 1
    fx, fy = [], []
    for val in ep_frag.values():
        if val['count'] == val['nf'] and val['nf'] > 0:
            fx.append(val['nf'])
            fy.append(val['total'])
    if fx:
        ax.scatter(fx, fy, alpha=0.5, s=20, c='#F44336', edgecolors='black', linewidth=0.3)
        if len(set(fx)) > 1:
            z = np.polyfit(fx, fy, 1)
            p = np.poly1d(z)
            xl = np.linspace(min(fx), max(fx), 100)
            ax.plot(xl, p(xl), 'k--', alpha=0.7, linewidth=1, label=f'{z[0]:.2f} ms/frag')
            ax.legend(fontsize=7)
    ax.set_xlabel('Number of Fragments')
    ax.set_ylabel('Total KDA Processing Time (ms)')
    ax.set_title('(e) KDA Processing Scaling')
    ax.grid(True, alpha=0.2)

    # =========================================================
    # (f) VDA Processing Scaling
    # =========================================================
    ax = axes[1][1]
    ep_dec = defaultdict(lambda: {'total': 0, 'nf': 0, 'count': 0})
    for d in vda:
        if norm(d['operation']) == 'decrypt':
            key = (d['domain'], d['epoch_id'])
            ep_dec[key]['total'] += d['duration_ms']
            ep_dec[key]['nf'] = d['num_fragments']
            ep_dec[key]['count'] += 1
    dx, dy = [], []
    for val in ep_dec.values():
        if val['count'] == val['nf'] and val['nf'] > 0:
            dx.append(val['nf'])
            dy.append(val['total'])
    if dx:
        ax.scatter(dx, dy, alpha=0.5, s=20, c='#00BCD4', edgecolors='black', linewidth=0.3)
        if len(set(dx)) > 1:
            z = np.polyfit(dx, dy, 1)
            p = np.poly1d(z)
            xl = np.linspace(min(dx), max(dx), 100)
            ax.plot(xl, p(xl), 'k--', alpha=0.7, linewidth=1, label=f'{z[0]:.2f} ms/frag')
            ax.legend(fontsize=7)
    ax.set_xlabel('Number of Fragments')
    ax.set_ylabel('Total VDA Processing Time (ms)')
    ax.set_title('(f) VDA Processing Scaling')
    ax.grid(True, alpha=0.2)

    # =========================================================
    # (g) KDA vs VDA Processing per Epoch (all domains)
    # =========================================================
    ax = axes[1][2]
    kda_ep = defaultdict(float)
    for d in kda:
        if norm(d['operation']) in ('fragment', 'kdr', 'dpr'):
            kda_ep[(d['domain'], d['epoch_id'])] += d['duration_ms']
    vda_ep = defaultdict(float)
    for d in vda:
        if norm(d['operation']) in ('decrypt', 'reconstruct'):
            vda_ep[(d['domain'], d['epoch_id'])] += d['duration_ms']
    common = sorted(set(kda_ep.keys()) & set(vda_ep.keys()))
    if common:
        x = np.arange(len(common))
        kt = [kda_ep[k] for k in common]
        vt = [vda_ep[k] for k in common]
        ax.bar(x, kt, label='KDA (fragmentation)', color='#2196F3', alpha=0.8)
        ax.bar(x, vt, bottom=kt, label='VDA (reconstruction)', color='#4CAF50', alpha=0.8)
        ax.legend(fontsize=6)
        step = max(1, len(common) // 10)
        ax.set_xticks(x[::step])
        ax.set_xticklabels([str(i+1) for i in x[::step]])
    ax.set_xlabel('Epoch Index')
    ax.set_ylabel('Total Processing Time (ms)')
    ax.set_title('(g) KDA vs VDA Processing per Epoch')
    ax.grid(True, alpha=0.2, axis='y')

    # =========================================================
    # (h) CDF: Combined KDA + VDA Time per Epoch
    # =========================================================
    ax = axes[1][3]
    kda_ep_cdf = defaultdict(float)
    for d in kda:
        if norm(d['operation']) not in ('epr', 'epoch_total') and not d['operation'].startswith('fah_'):
            kda_ep_cdf[(d['domain'], d['epoch_id'])] += d['duration_ms']
    vda_ep_cdf = defaultdict(float)
    vda_complete = set()
    for d in vda:
        vda_ep_cdf[(d['domain'], d['epoch_id'])] += d['duration_ms']
        if d['operation'] == 'verify_commit':
            vda_complete.add((d['domain'], d['epoch_id']))
    common_cdf = set(kda_ep_cdf.keys()) & vda_complete
    if common_cdf:
        combined = [kda_ep_cdf[k] + vda_ep_cdf[k] for k in common_cdf]
        plot_cdf(ax, combined, '#9C27B0', 'KDA + VDA')
        plot_cdf(ax, [kda_ep_cdf[k] for k in common_cdf], '#2196F3', 'KDA only')
        plot_cdf(ax, [vda_ep_cdf[k] for k in common_cdf], '#4CAF50', 'VDA only')
        ax.legend(loc='lower right', fontsize=7)
    ax.set_xlabel('Total Processing Time (ms)')
    ax.set_ylabel('CDF')
    ax.set_title('(h) CDF: KDA + VDA Processing per Epoch')
    ax.grid(True, alpha=0.2)

    plt.tight_layout(rect=[0, 0, 1, 0.98])
    plt.savefig(args.output, dpi=300)
    plt.close()
    print(f"Dashboard saved to {args.output}")

    # Save summary CSV
    csv_path = args.output.replace('.png', '_summary.csv')
    ops_list = ['eka', 'kdr', 'fragment', 'dpr', 'decrypt', 'reconstruct', 'verify_commit']
    op_names = ['EKA', 'KDR', 'Fragment', 'DPR', 'Decrypt', 'Reconstruct', 'VerifyCommit']
    with open(csv_path, 'w') as f:
        f.write("Operation,Count,Mean_ms,Median_ms,P95_ms,P99_ms,Min_ms,Max_ms,Std_ms\n")
        for op, name in zip(ops_list, op_names):
            vals = get_vals(kda, vda, op)
            if vals:
                f.write(f"{name},{len(vals)},{np.mean(vals):.2f},{np.median(vals):.2f},"
                        f"{np.percentile(vals,95):.2f},{np.percentile(vals,99):.2f},"
                        f"{np.min(vals):.2f},{np.max(vals):.2f},{np.std(vals):.2f}\n")
        if e2e:
            ev = [v['duration_s'] for v in e2e.values()]
            f.write(f"E2E_seconds,{len(ev)},{np.mean(ev):.1f},{np.median(ev):.1f},"
                    f"{np.percentile(ev,95):.1f},{np.percentile(ev,99):.1f},"
                    f"{np.min(ev):.1f},{np.max(ev):.1f},{np.std(ev):.1f}\n")
    print(f"Summary saved to {csv_path}")


if __name__ == '__main__':
    main()
