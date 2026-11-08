"""Fixed-capacity repair simulation against the supplied 2025 KEV dates.

Design fixed before the first real-data run:
* Scores never update. Backlog arrives at snapshot-month END; first service is
  the NEXT month. January is empty; December arrivals cannot finish in 2025.
* Each month selects up to C remaining jobs, using evaluate.ranked_indices:
  descending frozen score, then ascending CVE ID. Unused capacity expires.
  Listed CVEs remain eligible: outcomes never influence the repair order.
* Primary completion is the last calendar date of the service month. The
  sensitivity uses its first date with the SAME selections. Before is strict
  (completion date < KEV date); same-day completion counts as after/on.
* Capacities are 10, 25, 42, 100. No initial backlog or pre-2025 service.
* 1,000 paired bootstrap draws, seed 2026, sample 12 complete snapshot-month
  blocks with replacement. Original calendar dates and within-block scores
  stay fixed. Repeated blocks are independent copies consuming capacity;
  omitted blocks disappear. Rerun the full backlog per draw. Compare Slow
  Burn with the maximum before-count across all three baselines IN THAT DRAW.
  Report both timing conventions. No fitting, selection or design tuning.
* KEV dates proxy confirmation, not first attack. Repairs take equal effort.
  These are development data, and 55 positives give noisy uncertainty.
"""
from pathlib import Path
import heapq
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd
from pipeline.evaluate import ranked_indices
from pipeline.replay import METHODS

ROOT = Path(__file__).resolve().parents[1]
MONTHS = [f'2025-{m:02d}' for m in range(1, 13)]
CAPACITIES = (10, 25, 42, 100)
SEED = 2026
DRAWS = 1000
STARTS = pd.to_datetime([m + '-01' for m in MONTHS])
ENDS = STARTS + pd.offsets.MonthEnd(0)


def prepare(p, column):
    if not p.snapshot_month.isin(MONTHS).all():
        raise ValueError('Only 2025 snapshot months are supported')
    if not np.isfinite(p[column].to_numpy(dtype=float)).all():
        raise ValueError('Ranking scores must be finite')
    order = ranked_indices(p.cve_id, p[column])
    month = np.array([MONTHS.index(m) for m in p.snapshot_month])
    # Global order is equivalent to ranking each available backlog. A heap
    # merges the sorted month streams without repeatedly sorting the pool.
    return [order[month[order] == m] for m in range(12)], np.argsort(order)


def schedule(prepared, capacity, weights):
    if not isinstance(capacity, int) or capacity <= 0:
        raise ValueError('Capacity must be a positive integer')
    groups, rank = prepared
    heap, fixed = [], []
    for month in range(12):
        source = month - 1
        if source >= 0 and weights[source] and len(groups[source]):
            row = groups[source][0]
            heapq.heappush(heap, (int(rank[row]), source, 0, int(weights[source])))
        left = capacity
        while heap and left:
            _, source, cursor, copies = heapq.heappop(heap)
            row = int(groups[source][cursor])
            count = min(left, copies)
            fixed.append((row, month, count))
            left -= count
            copies -= count
            if not copies:
                cursor += 1
                copies = int(weights[source])
            if cursor < len(groups[source]):
                row = groups[source][cursor]
                heapq.heappush(heap, (int(rank[row]), source, cursor, copies))
    return fixed


def simulate(p, column, capacity, weights=None):
    return schedule(prepare(p, column), capacity,
                    np.ones(12, dtype=int) if weights is None else weights)


def summarize(p, fixed, timing):
    dates = STARTS if timing == 'start' else ENDS
    kev = pd.to_datetime(p.kev_date)
    positive = kev.notna().to_numpy()
    completion = np.full(len(p), np.datetime64('NaT', 'ns'), dtype='datetime64[ns]')
    for row, month, copies in fixed:
        if copies != 1 or not pd.isna(completion[row]):
            raise ValueError('Detailed summaries require the original unique pool')
        completion[row] = dates[month].to_datetime64()
    done = ~np.isnat(completion)
    before = positive & done & (completion < kev.to_numpy())
    ahead = (kev.to_numpy()[before] - completion[before]) / np.timedelta64(1, 'D')
    return {
        'before': int(before.sum()),
        'after': int((positive & done & ~before).sum()),
        'never': int((positive & ~done).sum()),
        'median_days_ahead': float(np.median(ahead)) if len(ahead) else None,
        'fixed_total': int(done.sum()),
        'monthly': [{'month': month,
                     'confirmed': int((kev <= ENDS[m]).sum()),
                     'before': int((before & (completion <= ENDS[m].to_datetime64())).sum()),
                     'fixed_total': int((done & (completion <= ENDS[m].to_datetime64())).sum())}
                    for m, month in enumerate(MONTHS)],
        'positive_outcomes': [
            {'cve_id': str(p.iloc[i].cve_id), 'snapshot_month': str(p.iloc[i].snapshot_month),
             'published': str(p.iloc[i].published) if 'published' in p else None,
             'kev_date': kev.iloc[i].strftime('%Y-%m-%d'),
             'completed': str(completion[i])[:10] if done[i] else None,
             'outcome': 'before' if before[i] else 'after' if done[i] else 'never'}
            for i in np.flatnonzero(positive)]}


def month_draws(iterations=DRAWS):
    rng = np.random.default_rng(SEED)
    return np.array([np.bincount(draw, minlength=12)
                     for draw in rng.integers(0, 12, (iterations, 12))])


def bootstrap_summary(counts):
    delta = counts[:, 3] - counts[:, :3].max(axis=1)
    return {'ahead': float(np.mean(delta > 0)), 'tied': float(np.mean(delta == 0)),
            'behind': float(np.mean(delta < 0)),
            'delta_95_percentile_interval': [float(v) for v in np.quantile(delta, [.025, .975])]}


def load_pool(predictions, data_dir):
    # Same source columns, date normalization and label mask as replay.build.
    p = pd.read_parquet(predictions)
    kev = pd.read_csv(data_dir / 'known_exploited.csv', usecols=['cve_id', 'vendor', 'product', 'date_added'])
    vul = pd.read_csv(data_dir / 'vulnerabilities.csv', usecols=['cve_id', 'published'])
    p = p.merge(vul, on='cve_id', how='left', validate='one_to_one').merge(
        kev, on='cve_id', how='left', validate='one_to_one')
    p['published'] = p.published.astype(str).str[:10]
    p['kev_date'] = p.date_added.where(p.label == 1)
    assert len(p) == 48039 and int(p.label.sum()) == 55
    assert p.cve_id.is_unique and p.published.str.startswith('2025-').all()
    dates = pd.to_datetime(p.kev_date)
    snapshot_end = pd.to_datetime(p.snapshot_month + '-01') + pd.offsets.MonthEnd(0)
    assert dates.notna().equals(p.label.eq(1))
    assert (dates[p.label.eq(1)] > snapshot_end[p.label.eq(1)]).all()
    assert dates.dropna().le(pd.Timestamp('2025-12-31')).all()
    first_month = vul.merge(kev, on='cve_id', validate='one_to_one')
    first_month = first_month[first_month.published.astype(str).str.startswith('2025')]
    first_month_end = pd.to_datetime(first_month.published.astype(str).str[:7] + '-01') + pd.offsets.MonthEnd(0)
    excluded = first_month[pd.to_datetime(first_month.date_added) <= first_month_end]
    assert len(excluded) == 110 and set(excluded.cve_id).isdisjoint(p.cve_id)
    return p


def crosscheck(p, replay):
    assert replay['pool'] == len(p) and replay['positives'] == int(p.label.sum())
    actual = {r.cve_id: (r.published, r.snapshot_month, r.kev_date)
              for r in p[p.label.eq(1)].itertuples()}
    expected = {r['cve_id']: (r['published'], r['snapshot_month'], r['kev_date'])
                for r in replay['later_exploited']}
    assert actual == expected
    for key, _, col in METHODS:
        method = next(m for m in replay['methods'] if m['key'] == key)
        top = p.iloc[ranked_indices(p.cve_id, p[col])[:500]]
        assert top.cve_id.tolist() == [r['cve_id'] for r in method['items']]
        assert int(top.label.sum()) == method['hits']


def build(predictions, data_dir, replay_path=None):
    p = load_pool(predictions, data_dir)
    replay_path = replay_path or ROOT / 'artifacts/replay_2025.json'
    crosscheck(p, json.loads(replay_path.read_text()))
    prepared = [prepare(p, col) for _, _, col in METHODS]
    draws = month_draws()
    kev = pd.to_datetime(p.kev_date).to_numpy(dtype='datetime64[D]')
    success = {timing: np.array([date.to_datetime64().astype('datetime64[D]') < kev for date in dates])
               for timing, dates in [('end', ENDS), ('start', STARTS)]}
    capacities = []
    for capacity in CAPACITIES:
        methods = []
        for (key, name, _), ready in zip(METHODS, prepared):
            fixed = schedule(ready, capacity, np.ones(12, dtype=int))
            methods.append({'key': key, 'name': name,
                            **{t: summarize(p, fixed, t) for t in ['end', 'start']}})
        counts = {t: np.zeros((DRAWS, 4), dtype=int) for t in ['end', 'start']}
        for draw, weights in enumerate(draws):
            for method, ready in enumerate(prepared):
                fixed = schedule(ready, capacity, weights)
                if fixed:
                    rows, months, copies = np.array(fixed).T
                    for timing in counts:
                        counts[timing][draw, method] = np.sum(success[timing][months, rows] * copies)
        capacities.append({'capacity': capacity, 'annual_budget': capacity * 12,
                           'methods': methods,
                           'bootstrap': {t: {
                               'observed_delta': methods[3][t]['before'] - max(m[t]['before'] for m in methods[:3]),
                               **bootstrap_summary(counts[t])} for t in counts}})
        print('Computed monthly capacity', capacity, flush=True)
    return {'schema_version': 1, 'split': '2024_to_2025', 'pool': len(p), 'positives': 55,
            'excluded_first_month': 110, 'start': '2025-01-01', 'end': '2025-12-31',
            'design': {'arrival': 'Snapshot month end; first eligible service is the following month.',
                       'priority': 'Frozen score descending, then cve_id ascending, using evaluate.ranked_indices.',
                       'completion': 'End of service month; sensitivity completes the same selections at month start.',
                       'before': 'Completion date strictly earlier than KEV date; after includes the same date.',
                       'capacity': 'Equal effort; unused monthly slots expire; no pre-2025 backlog. Listed rows remain in the backlog.',
                       'chart': 'Cumulative eventual before-listing successes by completion month; confirmation curve counts the 55 pool KEV dates.',
                       'budget_42': '42 per month is about the yearly 500 benchmark budget (504 slots). January has no eligible rows, so at most 462 are used.'},
            'uncertainty': {'iterations': DRAWS, 'seed': SEED, 'blocks': 12,
                            'method': 'Paired month-block bootstrap; sample 12 snapshot cohorts with replacement, retaining original calendar dates. Repeated cohorts consume repeated capacity. Rerun backlog; compare with the best baseline in each draw.',
                            'limitation': 'Only 55 positives and 12 month blocks: noisy. Conditional on fitted scores; excludes model-selection uncertainty and does not simulate future years.'},
            'limits': ['KEV date proxies confirmation and can lag real attacks.',
                       'Equal effort per fix; no asset inventory, patch availability or partial repairs.',
                       '2025 development data; no untouched validation. Current CVSS is a retrospective reference.',
                       '110 publication-month listings are outside this pool. Later KEV absence is unobserved, not safe.'],
            'capacities': capacities}


def run(predictions=None):
    result = build(predictions or ROOT / 'artifacts/cache/backtest_predictions.parquet', ROOT / 'data')
    (ROOT / 'artifacts/race_2025.json').write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    return result


if __name__ == '__main__':
    run()
