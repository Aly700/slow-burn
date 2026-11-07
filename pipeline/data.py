"""Read-only data loading and point-in-time cohort construction."""
from pathlib import Path
import hashlib
import json
import sys
from functools import lru_cache

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data'
ARTIFACTS = ROOT / 'artifacts'
CACHE = ARTIFACTS / 'cache'
FLAGS = ['exploitdb', 'metasploit', 'nuclei', 'poc_github']
END = '2025-12-31'
CACHE_SCHEMA = 2


def input_hashes():
    files = {}
    for path in sorted(DATA.glob('*.csv')):
        digest = hashlib.sha256()
        with path.open('rb') as fh:
            for block in iter(lambda: fh.read(8 * 1024 * 1024), b''):
                digest.update(block)
        files[path.name] = {'sha256': digest.hexdigest(), 'bytes': path.stat().st_size}
    return files


@lru_cache(maxsize=1)
def ensure_cache():
    CACHE.mkdir(parents=True, exist_ok=True)
    files = input_hashes()
    source = {}
    for name in ['data.py', 'features.py']:
        source[name] = hashlib.sha256((ROOT / 'pipeline' / name).read_bytes()).hexdigest()
    expected = {'schema': CACHE_SCHEMA, 'inputs': files, 'preprocessing': source}
    path = CACHE / 'provenance.json'
    old = json.loads(path.read_text()) if path.exists() else None
    if old != expected:
        # Only derived tabular caches are invalidated; embedding caches hash their actual input text.
        for pattern in ['cohort_*.parquet', 'historical_signals.parquet', 'vulnerabilities.parquet',
                        'history_features.parquet', 'history_features_ids.json', 'shifted_june_history.parquet',
                        'suspect_external_metadata.parquet']:
            for cached in CACHE.glob(pattern):
                cached.unlink()
        write_json(path, expected)
    write_json(CACHE / 'input_manifest.json', files)
    return files


def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, allow_nan=False) + '\n')


def snapshot_month(published, june_shift=False):
    months = published.astype(str).str[:7]
    if june_shift:
        months = months.where(~months.str.endswith('-06'), months.str[:4] + '-07')
    return months


def month_end(months):
    return pd.to_datetime(months + '-01').dt.to_period('M').dt.end_time.dt.normalize()


def assign_outcomes(frame, cutoff=END, horizon_days=None):
    out = frame.copy()
    snap = month_end(out.snapshot_month)
    added = pd.to_datetime(out.date_added, errors='coerce')
    cutoff = pd.Timestamp(cutoff)
    endpoint = pd.Series(cutoff, index=out.index)
    if horizon_days is not None:
        endpoint = pd.concat([endpoint, snap + pd.Timedelta(days=horizon_days)], axis=1).min(axis=1)
    out['eligible'] = ~added.le(snap)
    out['label'] = (added.gt(snap) & added.le(endpoint)).astype('int8')
    out['followup_days'] = (cutoff - snap).dt.days
    out['event_lag_days'] = (added - snap).dt.days
    return out


def training_rows(frame, cutoff, min_followup=90, horizon_days=None):
    out = assign_outcomes(frame, cutoff, horizon_days)
    return out.loc[out.eligible & out.followup_days.ge(min_followup)].copy()


def vulnerabilities():
    ensure_cache()
    path = CACHE / 'vulnerabilities.parquet'
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        pd.read_csv(DATA / 'vulnerabilities.csv', dtype=str, keep_default_na=False).to_parquet(path, index=False)
    return pd.read_parquet(path)


def kev():
    k = pd.read_csv(DATA / 'known_exploited.csv', dtype=str, keep_default_na=False)
    assert k.cve_id.is_unique
    assert k.date_added.max() <= END, 'Label file exceeds the permitted cutoff'
    v = vulnerabilities()[['cve_id', 'assigner']]
    return k.merge(v, on='cve_id', how='left', validate='one_to_one').fillna('')


def historical_signals():
    path = CACHE / 'historical_signals.parquet'
    if not path.exists():
        v = vulnerabilities()
        ids = set(v.loc[v.published.str[:4].isin(['2024', '2025']), 'cve_id'])
        parts = []
        for year in [2024, 2025]:
            for chunk in pd.read_csv(DATA / f'exploit_signals_{year}.csv', chunksize=300_000):
                parts.append(chunk.loc[chunk.cve_id.isin(ids)])
        signals = pd.concat(parts, ignore_index=True)
        assert not signals.duplicated(['cve_id', 'month']).any()
        signals.to_parquet(path, index=False)
    return pd.read_parquet(path)


def cohort(year, june_shift=False):
    ensure_cache()
    path = CACHE / f'cohort_{year}_{"shift" if june_shift else "natural"}.parquet'
    if path.exists():
        return pd.read_parquet(path)
    v = vulnerabilities()
    if year == 2026:
        board = pd.read_csv(DATA / 'scoreboard_2026.csv')
        assert board.cve_id.is_unique and len(board) == 72670
        out = board.merge(v.drop(columns=['published']), on='cve_id', how='left', validate='one_to_one')
        out['date_added'] = ''
        out['signal_observed'] = out.epss.notna().astype('int8')
        out['epss_first'] = np.nan
        out['epss_first_month'] = ''
        expected = snapshot_month(out.published, june_shift=True)
        assert out.snapshot_month.equals(expected)
    else:
        out = v.loc[v.published.str.startswith(str(year))].copy()
        out['snapshot_month'] = snapshot_month(out.published, june_shift)
        s = historical_signals()
        selected = s.rename(columns={'month': 'snapshot_month'})
        out = out.merge(selected, on=['cve_id', 'snapshot_month'], how='left', validate='one_to_one')
        out['signal_observed'] = out.in_kev.notna().astype('int8')
        out = out.merge(kev()[['cve_id', 'date_added']], on='cve_id', how='left', validate='one_to_one')
        early = s.merge(out[['cve_id', 'snapshot_month']], on='cve_id', how='inner')
        early = early.loc[early.month.le(early.snapshot_month) & early.epss.notna()]
        first = early.sort_values(['month', 'cve_id']).drop_duplicates('cve_id')
        first = first[['cve_id', 'epss', 'month']].rename(columns={'epss': 'epss_first', 'month': 'epss_first_month'})
        out = out.merge(first, on='cve_id', how='left', validate='one_to_one')
        out = assign_outcomes(out)
        disagreements = int((out.eligible & out.in_kev.fillna(0).eq(1)).sum())
        out = out.loc[out.eligible & out.in_kev.fillna(0).eq(0)].copy()
        print(f'{year}: {len(out):,} eligible; {int(out.label.sum())} outcomes through {END}; '
              f'{disagreements} extra exclusions from monthly KEV flags', flush=True)
    out[FLAGS] = out[FLAGS].fillna(0).astype('int8')
    out['epss'] = pd.to_numeric(out.epss, errors='coerce')
    out['any_exploit'] = out[FLAGS].max(axis=1)
    out = out.sort_values('cve_id').reset_index(drop=True)
    out.to_parquet(path, index=False)
    return out


def manifest():
    return ensure_cache()


if __name__ == '__main__':
    for yr in [2024, 2025, 2026]:
        f = cohort(yr)
        print(yr, f.groupby('snapshot_month').size().to_dict(), flush=True)
    manifest()
