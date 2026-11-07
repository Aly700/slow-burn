"""Forward backtests, ablations and workload-equivalent ranking metrics."""
from pathlib import Path
import json
import hashlib
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, brier_score_loss

from pipeline.data import ARTIFACTS, CACHE, assign_outcomes, cohort, kev, training_rows, write_json
from pipeline.embed import all_rows, embeddings
from pipeline.features import history_features, make_features
from pipeline.models import RECIPES, FittedModel

RATE = 500 / 72670
BASELINES = ['CVSS first', 'EPSS first', 'Exploit code first, then EPSS']


def ranked_indices(ids, scores):
    return np.lexsort((np.asarray(ids, dtype=str), -np.asarray(scores, dtype=float)))


def ranking_metrics(rows, scores, name, probabilities=False):
    y = rows.label.to_numpy()
    order = ranked_indices(rows.cve_id, scores)
    k = min(500, len(y))
    budget = max(1, int(np.floor(len(y) * RATE + .5)))
    hits = int(y[order[:k]].sum())
    scaled = int(y[order[:budget]].sum())
    positives = int(y.sum())
    result = {'name': name, 'pool': len(y), 'positives': positives, 'hits_at_500': hits,
              'precision_at_500': hits / k, 'recall_at_500': hits / positives if positives else 0.,
              'scaled_budget': budget, 'hits_at_scaled_budget': scaled,
              'precision_at_scaled_budget': scaled / budget,
              'recall_at_scaled_budget': scaled / positives if positives else 0.,
              'average_precision': float(average_precision_score(y, scores)) if positives else 0.}
    if probabilities:
        result['brier_score'] = float(brier_score_loss(y, scores))
        result['mean_probability'] = float(np.mean(scores))
    return result


def baseline_scores(rows):
    epss = rows.epss.fillna(0).to_numpy()
    return {'CVSS first': pd.to_numeric(rows.cvss3_score, errors='coerce').fillna(-1).to_numpy(),
            'EPSS first': epss, 'Exploit code first, then EPSS': rows.any_exploit.to_numpy() + epss}


def prepared():
    rows = all_rows()
    path = CACHE / 'history_features.parquet'
    id_path = CACHE / 'history_features_ids.json'
    ordered_ids = hashlib.sha256('\n'.join(rows.cve_id + '|' + rows.snapshot_month).encode()).hexdigest()
    if path.exists():
        h = pd.read_parquet(path)
        assert len(h) == len(rows)
        assert json.loads(id_path.read_text())['ordered_ids_sha256'] == ordered_ids
    else:
        h = history_features(rows, kev())
        h.to_parquet(path, index=False)
        write_json(id_path, {'ordered_ids_sha256': ordered_ids})
    blocks = {b: make_features(rows, kev(), b, h) for b in ['signals', 'strict', 'text', 'full']}
    return rows, h, blocks


def splits(rows):
    a = rows.loc[rows.published.str.startswith('2024')]
    b = rows.loc[rows.published.str.startswith('2025')]
    return [
        ('2024_to_2025', training_rows(a, '2024-12-31'), assign_outcomes(b, '2025-12-31'), '2024-12-31', '2025-12-31'),
        ('forward_2025_h2', training_rows(pd.concat([a, b]), '2025-06-30'),
         assign_outcomes(b.loc[b.snapshot_month.between('2025-07', '2025-09')], '2025-12-31'),
         '2025-06-30', '2025-12-31'),
        ('forward_2024_q4', training_rows(a, '2024-09-30'),
         assign_outcomes(a.loc[a.snapshot_month.ge('2024-10')], '2025-06-30'),
         '2024-09-30', '2025-06-30'),
    ]


def month_budgets(rows, total):
    sizes = rows.groupby('snapshot_month').size()
    raw = sizes / sizes.sum() * total
    budgets = np.floor(raw).astype(int)
    remaining = total - int(budgets.sum())
    for month in (raw - budgets).sort_values(ascending=False, kind='stable').index[:remaining]:
        budgets.loc[month] += 1
    return budgets


def monthly_metrics(rows, ours, baseline):
    temp = rows.copy()
    temp['ours'] = ours
    temp['baseline'] = baseline
    budgets = month_budgets(temp, 500)
    result = []
    for month, part in temp.groupby('snapshot_month'):
        k = int(budgets[month])
        scaled_k = max(1, int(np.floor(len(part) * RATE + .5)))
        result.append({'month': month, 'pool': len(part), 'positives': int(part.label.sum()),
                       'budget': k, 'scaled_budget': scaled_k,
                       'ours_hits': int(part.iloc[ranked_indices(part.cve_id, part.ours)[:k]].label.sum()),
                       'baseline_hits': int(part.iloc[ranked_indices(part.cve_id, part.baseline)[:k]].label.sum()),
                       'ours_hits_scaled': int(part.iloc[ranked_indices(part.cve_id, part.ours)[:scaled_k]].label.sum()),
                       'baseline_hits_scaled': int(part.iloc[ranked_indices(part.cve_id, part.baseline)[:scaled_k]].label.sum()),
                       'followup_days': int(part.followup_days.iloc[0]),
                       'signals_missing': int(part.signal_observed.eq(0).sum())})
    return result


def paired_month_bootstrap(rows, ours, baseline, iterations=1000):
    # Resample complete months; rank again at the same workload fraction in each draw.
    rng = np.random.default_rng(2026)
    months = rows.snapshot_month.unique()
    groups = [np.flatnonzero(rows.snapshot_month.to_numpy() == m) for m in months]
    deltas = []
    for _ in range(iterations):
        idx = np.concatenate([groups[i] for i in rng.integers(0, len(groups), len(groups))])
        k = max(1, int(np.floor(len(idx) * RATE + .5)))
        y = rows.label.to_numpy()[idx]
        ids = rows.cve_id.to_numpy()[idx]
        a = int(y[ranked_indices(ids, ours[idx])[:k]].sum())
        b = int(y[ranked_indices(ids, baseline[idx])[:k]].sum())
        deltas.append(a - b)
    return {'method': 'paired month bootstrap; equal-workload budget; fixed fitted models',
            'iterations': iterations, 'seed': 2026,
            'delta_hits_95_percentile_interval': [float(x) for x in np.quantile(deltas, [.025, .975])],
            'fraction_delta_positive': float(np.mean(np.array(deltas) > 0)),
            'limitation': 'Only 12 months; does not include model selection or retraining uncertainty.'}


def run(include_embeddings=True):
    rows, history, blocks = prepared()
    emb = {kind: embeddings(rows, kind) for kind in ['identity', 'description']} if include_embeddings else {}
    recipes = [r for r in RECIPES if not r.embedding or include_embeddings]
    results, predictions = [], {}
    for name, train, test, cutoff, endpoint in splits(rows):
        assert set(train.cve_id).isdisjoint(test.cve_id)
        assert train.snapshot_month.max() < test.snapshot_month.min()
        assert train.followup_days.ge(90).all()
        methods = [ranking_metrics(test, s, n) for n, s in baseline_scores(test).items()]
        predictions[name] = baseline_scores(test)
        for recipe in recipes:
            # The encoder was released in December 2024, after this historical split.
            if name == 'forward_2024_q4' and recipe.embedding:
                continue
            x = blocks[recipe.block]
            train_emb = emb[recipe.embedding][train.index] if recipe.embedding else None
            test_emb = emb[recipe.embedding][test.index] if recipe.embedding else None
            fitted = FittedModel(recipe).fit(x.loc[train.index], train.label, train_emb)
            scores = fitted.predict(x.loc[test.index], test_emb)
            predictions[name][recipe.name] = scores
            methods.append(ranking_metrics(test, scores, recipe.name, probabilities=True))
            print(name, recipe.name, methods[-1]['hits_at_500'], methods[-1]['hits_at_scaled_budget'], flush=True)
        results.append({'name': name, 'train_pool': len(train), 'train_positives': int(train.label.sum()),
                        'train_label_cutoff': cutoff, 'train_snapshot_max': str(train.snapshot_month.max()),
                        'test_label_cutoff': endpoint, 'test_pool': len(test), 'test_positives': int(test.label.sum()),
                        'methods': methods})
    eligible = [r.name for r in recipes if r.block in ['strict', 'signals'] and not r.no_history]
    # Use two complementary budgets, average across the two 2025 forward evaluations.
    # A two-hit indifference band favors the lower-dimensional, unblended model.
    def quality(name):
        values = []
        for split in results[:2]:
            m = next(x for x in split['methods'] if x['name'] == name)
            values.append((m['hits_at_500'] + m['hits_at_scaled_budget']) / (2 * split['test_positives']))
        return float(np.mean(values))
    qualities = {name: quality(name) for name in eligible}
    best = max(eligible, key=lambda name: qualities[name])
    tolerance = 1 / results[0]['test_positives']
    near = [r for r in recipes if r.name in eligible and qualities[r.name] >= qualities[best] - tolerance]
    chosen = min(near, key=lambda r: (bool(r.embedding), bool(r.blend), r.algorithm != 'logistic', r.block != 'signals')).name
    test = splits(rows)[0][2]
    ours = predictions['2024_to_2025'][chosen]
    baseline = predictions['2024_to_2025'][BASELINES[-1]]
    mature_mask = test.followup_days.ge(90).to_numpy()
    mature = test.loc[mature_mask]
    fixed = assign_outcomes(mature, '2025-12-31', horizon_days=90)
    sensitivity = []
    for name, part in [('mature_90_days_minimum', mature), ('fixed_90_day_endpoint', fixed)]:
        sensitivity.append({'name': name, 'methods': [ranking_metrics(part, score[mature_mask], method, method not in BASELINES)
                            for method, score in predictions['2024_to_2025'].items()]})
    ablations = []
    names = {'signals only': 'logistic_signals', 'no text (strict)': 'logistic_strict',
             'no embeddings (keywords and history)': 'logistic_text',
             'no vendor or assigner history': 'logistic_no_history',
             'description embeddings and keywords': 'logistic_description',
             'identity embeddings only': 'logistic_identity',
             'vendor CVSS and CWE audit': 'logistic_full_audit'}
    for label, method in names.items():
        m = next((m for m in results[0]['methods'] if m['name'] == method), None)
        if m:
            ablations.append({**m, 'name': label, 'recipe': method})
    result = {'pool': '2025-published CVEs; publication-month end; exclude prior KEV from catalog or snapshot flag',
              'label': 'KEV date_added after snapshot month and through 2025-12-31; non-KEV is unobserved, not proven safe',
              'selected_model': chosen, 'methods': results[0]['methods'], 'splits': results,
              'monthly': monthly_metrics(test, ours, baseline), 'ablations': ablations,
              'censoring_sensitivity': sensitivity,
              'selection': {'rule': 'Mean recall across literal and equal-workload budgets in two forward 2025 evaluations; within 1/55 prefer simpler',
                            'scores': qualities, 'warning': 'Development comparisons; test-year model selection is optimistic. H2 overlaps the primary test.'},
              'scaling': {'scoreboard_pool': 72670, 'scoreboard_budget': 500, 'fraction': RATE,
                          'formula': 'round(pool_size * 500 / 72670)',
                          'note': 'Literal 500 is also shown. Monthly budgets partition 500 by cohort size; not 500 per month.'},
              'censoring': {'training_minimum_followup_days': 90,
                            'excluded_2025_immature': int((~mature_mask).sum()),
                            'note': 'Primary includes censored late rows for seed comparability; mature and fixed-90-day results are separate. December has zero follow-up.'},
              'uncertainty': paired_month_bootstrap(test, ours, baseline),
              'tie_break': 'Descending score, then cve_id ascending; CVSS baseline uses current scores only for benchmark reference',
              'baseline_caveat': 'Current CVSS is an explicitly unsafe reference, never a strict production feature.'}
    write_json(ARTIFACTS / 'backtest.json', result)
    pred = test[['cve_id', 'snapshot_month', 'label', 'followup_days']].copy()
    for name, score in predictions['2024_to_2025'].items():
        pred[name] = score
    pred.to_parquet(CACHE / 'backtest_predictions.parquet', index=False)
    write_json(CACHE / 'selected_recipe.json', next(r.__dict__ for r in recipes if r.name == chosen))
    print('Selected:', chosen, flush=True)
    return result


if __name__ == '__main__':
    run(include_embeddings='--without-embeddings' not in sys.argv)
