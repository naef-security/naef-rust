import csv
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))
MAX_FRAGS = 30

def fmt_ts(val):
    if not val:
        return ''
    if val > 2000000000 or val < 1000000000:
        return ''
    return datetime.fromtimestamp(val, tz=IST).strftime('%m/%d/%Y %H:%M:%S')

# First pass: collect per (domain, epoch_id) data
data = {}  # key -> {epr, kdr, dpr, frags: {n: (ts, dur)}}

with open('kda_metrics.csv', 'r') as f:
    reader = csv.reader(f)
    next(reader)
    for row in reader:
        if len(row) != 7:
            continue
        try:
            ts = int(row[0])
            if ts > 2000000000 or ts < 1000000000:
                continue
            domain = row[1]
            epoch_id = row[2]
            op = row[3]
            duration = float(row[4])
            num_frags = int(row[5])
        except (ValueError, IndexError):
            continue

        key = (domain, epoch_id)
        if key not in data:
            data[key] = {'epr': None, 'kdr': None, 'dpr': None, 'nf': num_frags, 'frags': {}}

        if op in ('fah_epr', 'epr'):
            if data[key]['epr'] is None or ts < data[key]['epr']:
                data[key]['epr'] = ts
                data[key]['nf'] = num_frags
        elif op == 'kdr':
            if data[key]['kdr'] is None or ts > data[key]['kdr']:
                data[key]['kdr'] = ts
        elif op == 'dpr':
            if data[key]['dpr'] is None or ts > data[key]['dpr']:
                data[key]['dpr'] = ts
        elif op.startswith('fragment_'):
            try:
                n = int(op.split('_')[1])
                if 1 <= n <= MAX_FRAGS:
                    data[key]['frags'][n] = (ts, duration)
            except ValueError:
                pass

# VDA pass
vda_verify = {}
with open('vda_metrics.csv', 'r') as f:
    reader = csv.reader(f)
    next(reader)
    for row in reader:
        if len(row) < 5:
            continue
        try:
            ts = int(row[0])
            if ts > 2000000000 or ts < 1000000000:
                continue
            domain = row[1]
            epoch_id = row[2]
            op = row[3]
        except (ValueError, IndexError):
            continue
        key = (domain, epoch_id)
        if op == 'verify_commit':
            if key not in vda_verify or ts > vda_verify[key]:
                vda_verify[key] = ts

# Write output
all_keys = sorted(
    [k for k in data if data[k]['epr'] is not None],
    key=lambda x: (x[0], int(x[1]) if x[1].isdigit() else 0)
)

with open('epoch_lifecycle_formatted.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    header = ['domain', 'epoch_id', 'num_fragments', 'epoch_start_time', 'kdr_sent_time']
    for i in range(1, MAX_FRAGS + 1):
        header.extend([f'fdr_{i}_time', f'fdr_{i}_duration'])
    header.extend(['dpr_sent_time', 'verify_complete_time'])
    writer.writerow(header)

    for key in all_keys:
        d = data[key]
        row = [key[0], key[1], d['nf'], fmt_ts(d['epr']), fmt_ts(d['kdr'])]
        for i in range(1, MAX_FRAGS + 1):
            if i in d['frags']:
                fdr_ts = d['frags'][i][0]
                # Compute duration as time since previous reference point
                if i == 1:
                    prev_ts = d['kdr']
                else:
                    prev_ts = d['frags'][i-1][0] if (i-1) in d['frags'] else None
                if prev_ts and fdr_ts:
                    diff_s = fdr_ts - prev_ts
                    duration_fmt = f'{diff_s // 60}:{diff_s % 60:02d}'
                else:
                    duration_fmt = ''
                row.extend([fmt_ts(fdr_ts), duration_fmt])
            else:
                row.extend(['', ''])
        row.extend([fmt_ts(d['dpr']), fmt_ts(vda_verify.get(key, ''))])
        writer.writerow(row)

print(f"Done. {len(all_keys)} rows written to epoch_lifecycle_formatted.csv")
