"""Month-by-month replay of the 2025 backtest for the page.

For each ranking, the 500 CVEs it chose from the 2025 pool, when each became
rankable (its snapshot month) and, for the ones CISA later listed, the date it
was added. Nothing here is used to fit or select a model.
"""
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'pipeline'))
from evaluate import ranked_indices  # noqa: E402

METHODS = [('cvss', 'CVSS first', 'CVSS first'),
           ('epss', 'EPSS first', 'EPSS first'),
           ('rule', 'Exploit code first, then EPSS', 'Exploit code first, then EPSS'),
           ('ours', 'Slow Burn', 'tiered_lightgbm_description')]


def build(predictions, data_dir):
    p = pd.read_parquet(predictions)
    kev = pd.read_csv(data_dir / 'known_exploited.csv', usecols=['cve_id', 'vendor', 'product', 'date_added'])
    vul = pd.read_csv(data_dir / 'vulnerabilities.csv', usecols=['cve_id', 'published'])
    p = p.merge(vul, on='cve_id', how='left').merge(kev, on='cve_id', how='left')
    p['published'] = p.published.astype(str).str[:10]
    p['kev_date'] = p.date_added.where(p.label == 1)
    signal = p['Exploit code first, then EPSS'] >= 1
    out = {'split': '2024_to_2025', 'pool': int(len(p)), 'positives': int(p.label.sum()),
           'start': '2025-01-01', 'end': '2025-12-31', 'methods': []}
    chosen = {}
    for key, name, col in METHODS:
        order = ranked_indices(p.cve_id, p[col])[:500]
        top = p.iloc[order]
        chosen[key] = dict(zip(top.cve_id, range(1, 501)))
        out['methods'].append({
            'key': key, 'name': name, 'hits': int(top.label.sum()),
            'items': [{'cve_id': r.cve_id, 'rank': i + 1, 'snapshot_month': r.snapshot_month,
                       'published': r.published, 'kev_date': None if pd.isna(r.kev_date) else r.kev_date}
                      for i, r in enumerate(top.itertuples())]})
    pos = p[p.label == 1].sort_values('kev_date')
    out['later_exploited'] = [{'cve_id': r.cve_id, 'published': r.published, 'snapshot_month': r.snapshot_month,
                               'kev_date': r.kev_date, 'vendor': r.vendor, 'product': r.product,
                               'public_exploit_signal': bool(s),
                               'rank_in': {k: chosen[k].get(r.cve_id) for k in chosen}}
                              for r, s in zip(pos.itertuples(), signal[pos.index])]
    return out


if __name__ == '__main__':
    pred = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'artifacts/cache/backtest_predictions.parquet'
    res = build(pred, ROOT / 'data')
    (ROOT / 'artifacts/replay_2025.json').write_text(json.dumps(res, indent=1))
    print({m['name']: m['hits'] for m in res['methods']}, 'positives', res['positives'])
