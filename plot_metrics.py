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


def get_epoch_totals(data, op):
    """Sum per-fragment ops into per-epoch totals. For non-fragment ops, return individual values."""
    if op in ('fragment', 'decrypt'):
        ep = defaultdict(float)
        ep_nf = {}
        for d in data:
            if norm(d['operation']) == op:
                key = (d['domain'], d['epoch_id'])
                ep[key] += d['duration_ms']
                ep_nf[key] = d['num_fragments']
        return list(ep.values()), ep_nf
    else:
        return [d['duration_ms'] for d in data if norm(d['operation']) == op], {}


def get_epoch_totals_by_nf(data, op, nf):
    """Get per-epoch totals filtered by fragment count."""
    if op in ('fragment', 'decrypt'):
        ep = defaultdict(float)
        for d in data:
            if norm(d['operation']) == op and d['num_fragments'] == nf:
                ep[(d['domain'], d['epoch_id'])] += d['duration_ms']
        return list(ep.values())
    else:
        return [d['duration_ms'] for d in data if norm(d['operation']) == op and d['num_fragments'] == nf]


def get_epoch_totals_by_domains(data, op, domain_set):
    """Get per-epoch totals filtered by domain set."""
    if op in ('fragment', 'decrypt'):
        ep = defaultdict(float)
        for d in data:
            if norm(d['operation']) == op and d['domain'] in domain_set:
                ep[(d['domain'], d['epoch_id'])] += d['duration_ms']
        return list(ep.values())
    else:
        return [d['duration_ms'] for d in data if norm(d['operation']) == op and d['domain'] in domain_set]


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


def read_domain_intervals(kda_csv_path):
    """Read epoch_interval per domain from init.json next to the CSV, or from init_*.json.
    Picks the file whose domains best match the domains in the CSV."""
    import os, glob
    base = os.path.dirname(kda_csv_path) or '.'
    # Get domains from CSV
    csv_domains = set()
    try:
        with open(kda_csv_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                csv_domains.add(row['domain'])
    except:
        pass
    best = {}
    best_overlap = 0
    for p in [os.path.join(base, 'NAEF', 'init.json')] + sorted(glob.glob(os.path.join(base, 'init_*.json'))):
        if os.path.exists(p):
            try:
                import json
                with open(p) as f:
                    data = json.load(f)
                candidate = {entry['domain']: int(entry['epoch_interval']) for entry in data}
                overlap = len(set(candidate.keys()) & csv_domains)
                if overlap > best_overlap:
                    best = candidate
                    best_overlap = overlap
            except:
                pass
    return best


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kda', default='kda_metrics.csv')
    parser.add_argument('--vda', default='vda_metrics.csv')
    parser.add_argument('--output', default='naef_dashboard.png')
    args = parser.parse_args()

    kda = parse_kda(read_csv(args.kda)) if os.path.exists(args.kda) else []
    vda = parse_vda(read_csv(args.vda)) if os.path.exists(args.vda) else []
    e2e = get_e2e_times(kda, vda)
    domain_intervals = read_domain_intervals(args.kda)
    print(f"Loaded {len(kda)} KDA, {len(vda)} VDA, {len(e2e)} E2E records, {len(domain_intervals)} domain intervals")

    fig, axes = plt.subplots(3, 4, figsize=(22, 15))
    fig.suptitle('NAEF Protocol Performance Dashboard', fontsize=16, fontweight='bold', y=0.995)

    # =========================================================
    # (a) KDA Operation Processing Time
    # =========================================================
    ax = axes[0][0]
    lc_ops = ['eka', 'kdr', 'fragment', 'dpr']
    lc_colors = ['#81C784', '#FFB74D', '#E57373', '#BA68C8']
    lc_labels = ['EKA', 'KDR', 'Fragment (total)', 'DPR']
    frag_configs = sorted(set(d['num_fragments'] for d in kda))
    if len(frag_configs) > 1:
        n_ops = len(lc_ops)
        n_fcs = len(frag_configs)
        total_w = 0.8
        w = total_w / n_ops
        x = np.arange(n_fcs)
        for i, op in enumerate(lc_ops):
            means, mins, maxs = [], [], []
            for nf in frag_configs:
                vals = get_epoch_totals_by_nf(kda, op, nf)
                m = np.mean(vals) if vals else 0
                means.append(m)
                mins.append(m - np.percentile(vals, 5) if vals else 0)
                maxs.append(np.percentile(vals, 95) - m if vals else 0)
            offset = (i - (n_ops - 1) / 2) * w
            ax.bar(x + offset, means, w, yerr=[mins, maxs], capsize=2, label=lc_labels[i],
                   color=lc_colors[i], alpha=0.8, ecolor='black', error_kw={'linewidth': 0.8})
        ax.set_xticks(x)
        ax.set_xticklabels([f'n={nf}' for nf in frag_configs])
        ax.set_xlabel('Number of Fragments')
        ax.legend(fontsize=6)
    else:
        means, mins, maxs = [], [], []
        for op in lc_ops:
            vals, _ = get_epoch_totals(kda, op)
            m = np.mean(vals) if vals else 0
            means.append(m)
            mins.append(m - np.percentile(vals, 5) if vals else 0)
            maxs.append(np.percentile(vals, 95) - m if vals else 0)
        x = np.arange(len(lc_ops))
        ax.bar(x, means, 0.5, yerr=[mins, maxs], capsize=4, color=lc_colors, alpha=0.8, ecolor='black', error_kw={'linewidth': 0.8})
        ax.set_xticks(x)
        ax.set_xticklabels(lc_labels)
    ax.set_ylabel('Processing Time (ms)')
    ax.set_title('(a) KDA Operation Processing Time')
    ax.grid(True, alpha=0.2, axis='y')

    # =========================================================
    # (b) VDA Operation Processing Time
    # =========================================================
    ax = axes[0][1]
    vda_ops = ['decrypt', 'reconstruct', 'verify_commit']
    vda_colors = ['#00BCD4', '#795548', '#607D8B']
    vda_labels = ['Decrypt (total)', 'Reconstruct', 'VerifyCommit']
    vda_fcs = sorted(set(d['num_fragments'] for d in vda))
    if len(vda_fcs) > 1:
        n_ops = len(vda_ops)
        n_fcs = len(vda_fcs)
        total_w = 0.8
        w = total_w / n_ops
        x = np.arange(n_fcs)
        for i, op in enumerate(vda_ops):
            means, mins, maxs = [], [], []
            for nf in vda_fcs:
                vals = get_epoch_totals_by_nf(vda, op, nf)
                m = np.mean(vals) if vals else 0
                means.append(m)
                mins.append(m - np.percentile(vals, 5) if vals else 0)
                maxs.append(np.percentile(vals, 95) - m if vals else 0)
            offset = (i - (n_ops - 1) / 2) * w
            ax.bar(x + offset, means, w, yerr=[mins, maxs], capsize=2, label=vda_labels[i],
                   color=vda_colors[i], alpha=0.8, ecolor='black', error_kw={'linewidth': 0.8})
        ax.set_xticks(x)
        ax.set_xticklabels([f'n={nf}' for nf in vda_fcs])
        ax.set_xlabel('Number of Fragments')
        ax.legend(fontsize=6)
    else:
        means, mins, maxs = [], [], []
        for op in vda_ops:
            vals, _ = get_epoch_totals(vda, op)
            m = np.mean(vals) if vals else 0
            means.append(m)
            mins.append(m - np.percentile(vals, 5) if vals else 0)
            maxs.append(np.percentile(vals, 95) - m if vals else 0)
        x = np.arange(len(vda_ops))
        ax.bar(x, means, 0.5, yerr=[mins, maxs], capsize=4, color=vda_colors, alpha=0.8, ecolor='black', error_kw={'linewidth': 0.8})
        ax.set_xticks(x)
        ax.set_xticklabels(vda_labels)
    ax.set_ylabel('Processing Time (ms)')
    ax.set_title('(b) VDA Operation Processing Time')
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
    # (e) KDA Processing Time by Epoch Interval
    # =========================================================
    ax = axes[1][0]
    lc_ops_e = ['eka', 'kdr', 'fragment', 'dpr']
    lc_colors_e = ['#81C784', '#FFB74D', '#E57373', '#BA68C8']
    lc_labels_e = ['EKA', 'KDR', 'Fragment (total)', 'DPR']
    if domain_intervals:
        ei_set = sorted(set(domain_intervals.values()))
        if len(ei_set) > 1:
            n_ops = len(lc_ops_e)
            total_w = 0.8
            w = total_w / n_ops
            x = np.arange(len(ei_set))
            for i, op in enumerate(lc_ops_e):
                means, mins, maxs = [], [], []
                for ei in ei_set:
                    ei_domains = {d for d, v in domain_intervals.items() if v == ei}
                    vals = get_epoch_totals_by_domains(kda, op, ei_domains)
                    m = np.mean(vals) if vals else 0
                    means.append(m)
                    mins.append(m - np.percentile(vals, 5) if vals else 0)
                    maxs.append(np.percentile(vals, 95) - m if vals else 0)
                offset = (i - (n_ops - 1) / 2) * w
                ax.bar(x + offset, means, w, yerr=[mins, maxs], capsize=2, label=lc_labels_e[i],
                       color=lc_colors_e[i], alpha=0.8, ecolor='black', error_kw={'linewidth': 0.8})
            ax.set_xticks(x)
            ax.set_xticklabels([f'{ei}s' for ei in ei_set], rotation=45, ha='right')
            ax.set_xlabel('Epoch Interval')
            ax.legend(fontsize=6)
    ax.set_ylabel('Processing Time (ms)')
    ax.set_title('(e) KDA Processing Time by Epoch Interval')
    ax.grid(True, alpha=0.2, axis='y')

    # =========================================================
    # (f) VDA Processing Time by Epoch Interval
    # =========================================================
    ax = axes[1][1]
    vda_ops_f = ['decrypt', 'reconstruct', 'verify_commit']
    vda_colors_f = ['#00BCD4', '#795548', '#607D8B']
    vda_labels_f = ['Decrypt (total)', 'Reconstruct', 'VerifyCommit']
    if domain_intervals:
        ei_set = sorted(set(domain_intervals.values()))
        if len(ei_set) > 1:
            n_ops = len(vda_ops_f)
            total_w = 0.8
            w = total_w / n_ops
            x = np.arange(len(ei_set))
            for i, op in enumerate(vda_ops_f):
                means, mins, maxs = [], [], []
                for ei in ei_set:
                    ei_domains = {d for d, v in domain_intervals.items() if v == ei}
                    vals = get_epoch_totals_by_domains(vda, op, ei_domains)
                    m = np.mean(vals) if vals else 0
                    means.append(m)
                    mins.append(m - np.percentile(vals, 5) if vals else 0)
                    maxs.append(np.percentile(vals, 95) - m if vals else 0)
                offset = (i - (n_ops - 1) / 2) * w
                ax.bar(x + offset, means, w, yerr=[mins, maxs], capsize=2, label=vda_labels_f[i],
                       color=vda_colors_f[i], alpha=0.8, ecolor='black', error_kw={'linewidth': 0.8})
            ax.set_xticks(x)
            ax.set_xticklabels([f'{ei}s' for ei in ei_set], rotation=45, ha='right')
            ax.set_xlabel('Epoch Interval')
            ax.legend(fontsize=6)
    ax.set_ylabel('Processing Time (ms)')
    ax.set_title('(f) VDA Processing Time by Epoch Interval')
    ax.grid(True, alpha=0.2, axis='y')

    # =========================================================
    # (g) CDF: KDA by Epoch Interval
    # =========================================================
    ax = axes[1][2]
    if domain_intervals:
        ei_set = sorted(set(domain_intervals.values()))
        if len(ei_set) > 1:
            for i, ei in enumerate(ei_set):
                ei_domains = {d for d, v in domain_intervals.items() if v == ei}
                vals = [d['duration_ms'] for d in kda if norm(d['operation']) in ('eka','kdr','fragment','dpr') and d['domain'] in ei_domains]
                plot_cdf(ax, vals, COLORS[i % len(COLORS)], f'{ei}s')
            ax.legend(loc='lower right', fontsize=5, ncol=2)
    ax.set_xlabel('Processing Time (ms)')
    ax.set_ylabel('CDF')
    ax.set_title('(g) CDF: KDA by Epoch Interval')
    ax.grid(True, alpha=0.2)

    # =========================================================
    # (h) CDF: VDA by Epoch Interval
    # =========================================================
    ax = axes[1][3]
    if domain_intervals:
        ei_set = sorted(set(domain_intervals.values()))
        if len(ei_set) > 1:
            for i, ei in enumerate(ei_set):
                ei_domains = {d for d, v in domain_intervals.items() if v == ei}
                vals = [d['duration_ms'] for d in vda if d['domain'] in ei_domains]
                plot_cdf(ax, vals, COLORS[i % len(COLORS)], f'{ei}s')
            ax.legend(loc='lower right', fontsize=5, ncol=2)
    ax.set_xlabel('Processing Time (ms)')
    ax.set_ylabel('CDF')
    ax.set_title('(h) CDF: VDA by Epoch Interval')
    ax.grid(True, alpha=0.2)

    # =========================================================
    # (i) KDA Processing Scaling
    # =========================================================
    ax = axes[2][0]
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
    ax.set_title('(i) KDA Processing Scaling')
    ax.grid(True, alpha=0.2)

    # =========================================================
    # (j) VDA Processing Scaling
    # =========================================================
    ax = axes[2][1]
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
        ax.set_ylim(0, np.percentile(dy, 99.5) * 1.1)
    ax.set_xlabel('Number of Fragments')
    ax.set_ylabel('Total VDA Processing Time (ms)')
    ax.set_title('(j) VDA Processing Scaling')
    ax.grid(True, alpha=0.2)

    # =========================================================
    # (k) KDA vs VDA Processing per Epoch (all domains)
    # =========================================================
    ax = axes[2][2]
    kda_ep = defaultdict(float)
    kda_ep_nf = {}
    for d in kda:
        if norm(d['operation']) in ('fragment', 'kdr', 'dpr'):
            key = (d['domain'], d['epoch_id'])
            kda_ep[key] += d['duration_ms']
            kda_ep_nf[key] = d['num_fragments']
    vda_ep = defaultdict(float)
    for d in vda:
        if norm(d['operation']) in ('decrypt', 'reconstruct'):
            vda_ep[(d['domain'], d['epoch_id'])] += d['duration_ms']
    common = sorted(set(kda_ep.keys()) & set(vda_ep.keys()),
                    key=lambda k: (kda_ep_nf.get(k, 0), k))
    if common:
        x = np.arange(len(common))
        kt = [kda_ep[k] for k in common]
        vt = [vda_ep[k] for k in common]
        ax.bar(x, kt, label='KDA (fragmentation)', color='#2196F3', alpha=0.8)
        ax.bar(x, vt, bottom=kt, label='VDA (reconstruction)', color='#4CAF50', alpha=0.8)
        ax.legend(fontsize=6)
        # Add fragment count group separators and labels
        nf_groups = []
        prev_nf = None
        for i, k in enumerate(common):
            nf = kda_ep_nf.get(k, 0)
            if nf != prev_nf:
                if prev_nf is not None:
                    ax.axvline(x=i - 0.5, color='gray', linewidth=0.5, linestyle='--', alpha=0.5)
                nf_groups.append((i, nf))
                prev_nf = nf
        for start, nf in nf_groups:
            ax.text(start + 1, min(2000, max(kt)) * 0.95, f'n={nf}', fontsize=5, color='gray', ha='left')
        ax.set_xticks([])
        ax.set_ylim(0, 2000)
    ax.set_xlabel('Epochs (grouped by fragment count)')
    ax.set_ylabel('Total Processing Time (ms)')
    ax.set_title('(k) KDA vs VDA Processing per Epoch')
    ax.grid(True, alpha=0.2, axis='y')

    # =========================================================
    # (l) CDF: Combined KDA + VDA Time per Epoch
    # =========================================================
    ax = axes[2][3]
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
    ax.set_title('(l) CDF: KDA + VDA Processing per Epoch')
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
