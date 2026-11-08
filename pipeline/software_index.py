"""Current product evidence for browser-only inventory review, never prediction.

Uses only the supplied files and the frozen full-score cache. CPE prerequisite
platforms (vulnerable=N) are omitted. No package ecosystem is inferred from a
CPE product name. Existing heuristic identities are retained as weaker evidence.
"""
from pathlib import Path
import csv
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pandas as pd
from functools import lru_cache
from pipeline.publication import display_description


@lru_cache(maxsize=None)
def prohibited(text):
    return display_description(text)[1] != "sanitized description"

FIELDS = ['version', 'update', 'version_start_including', 'version_start_excluding',
          'version_end_including', 'version_end_excluding']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build():
    board = pd.read_csv(ROOT / 'data/scoreboard_2026.csv', dtype=str, keep_default_na=False)
    scores = pd.read_parquet(ROOT / 'artifacts/cache/scores_2026_full.parquet')
    assert len(scores) == len(board) and scores.cve_id.is_unique
    assert set(scores.cve_id) == set(board.cve_id)
    frozen = pd.read_csv(ROOT / 'artifacts/scores_2026_top5000.csv')
    assert scores.cve_id.head(5000).tolist() == frozen.cve_id.tolist()
    assert scores.cve_id.head(500).tolist() == pd.read_csv(ROOT / 'artifacts/top500.csv').cve_id.tolist()
    months = board.set_index('cve_id').snapshot_month.to_dict()
    cves = [[r.cve_id, i + 1, float(r.score), months[r.cve_id]] for i, r in enumerate(scores.itertuples())]
    lookup = {row[0]: i for i, row in enumerate(cves)}
    products = {}
    covered = set()
    cpe_rows = 0
    cpe_pairs = set()
    with (ROOT / 'data/affected_products.csv').open(newline='') as stream:
        for row in csv.DictReader(stream):
            if row['cve_id'] not in lookup or row['vulnerable'] != 'Y':
                continue
            if not row['vendor'] or not row['product'] or prohibited(row['vendor'] + ' ' + row['product']):
                continue
            key = (row['vendor'], row['product'], 'cpe')
            item = (lookup[row['cve_id']], *(row[field] for field in FIELDS))
            products.setdefault(key, set()).add(item)
            covered.add(row['cve_id'])
            cpe_pairs.add((row['cve_id'], row['vendor'].lower(), row['product'].lower()))
            cpe_rows += 1
    for file, vendor, product in [('scores_2026_top5000.csv', 'vendor_identity', 'product_identity'),
                                   ('product_watch_2026.csv', 'vendor', 'product')]:
        with (ROOT / 'artifacts' / file).open(newline='') as stream:
            for row in csv.DictReader(stream):
                v, p = row.get(vendor, ''), row.get(product, '')
                if not v or not p or v == 'unmapped' or prohibited(v + ' ' + p):
                    continue
                if (row['cve_id'], v.lower(), p.lower()) in cpe_pairs:
                    continue
                products.setdefault((v, p, 'identity'), set()).add((lookup[row['cve_id']], '', '', '', '', '', ''))
    products = [{'vendor': v, 'product': p, 'source': source, 'affected': sorted(values)}
                for (v, p, source), values in sorted(products.items())]
    matched = {item[0] for product in products for item in product['affected']}
    # Intern repeated ranges and omit CVEs with no published matching identity.
    positions = {old: new for new, old in enumerate(sorted(matched))}
    cves = [cves[old] for old in sorted(matched)]
    ranges = sorted({tuple(item[1:]) for product in products for item in product['affected']})
    range_index = {value: i for i, value in enumerate(ranges)}
    for product in products:
        product['affected'] = [[positions[item[0]], range_index[tuple(item[1:])]] for item in product['affected']]
    sources = ['data/scoreboard_2026.csv', 'data/affected_products.csv',
               'artifacts/cache/scores_2026_full.parquet', 'artifacts/scores_2026_top5000.csv',
               'artifacts/product_watch_2026.csv']
    return {'schema_version': 1,
            'coverage': {'benchmark_cves': len(board), 'cpe_cves': len(covered),
                         'identity_cves': len(matched), 'vulnerable_cpe_rows': cpe_rows,
                         'product_groups': len(products)},
            'provenance': {name: sha(ROOT / name) for name in sources},
            'cve_columns': ['cve_id', 'rank', 'score', 'snapshot_month'],
            'affected_columns': ['cve_index', 'range_index'],
            'range_columns': FIELDS, 'ranges': ranges,
            'limitations': ['Current product evidence is for asset review, not a snapshot-safe ranking feature.',
                            'CPE names do not establish a package ecosystem. Missing matches do not establish safety.',
                            'Only vulnerable=Y rows are included. Confirm deployment conditions and vendor guidance.'],
            'cves': cves, 'products': products}


if __name__ == '__main__':
    value = build()
    path = ROOT / 'artifacts/software_index_2026.json'
    path.write_text(json.dumps(value, separators=(',', ':'), ensure_ascii=True) + '\n')
    print(value['coverage'], 'bytes', path.stat().st_size)
