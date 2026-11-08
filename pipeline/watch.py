"""A separately validated review queue for vulnerabilities without snapshot tool flags."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from pipeline.data import ARTIFACTS, CACHE, ROOT, FLAGS, assign_outcomes, training_rows, write_json
from pipeline.embed import MODEL_ID, REVISION, embeddings
from pipeline.evaluate import prepared, ranked_indices, splits
from pipeline.features import production_allowlist, clean_description
from pipeline.models import FittedModel, Recipe
from pipeline.watch_registry import BUDGETS, CANDIDATES, POLICY, PROTECTED, SEEDS

SELECTION_PATH = ROOT / 'pipeline' / 'watch_selection.json'
WATCH_PATH = ARTIFACTS / 'watch_2026_top100.csv'
STORY_TITLE = 'A separate watch list for the blind spot'


def frozen_artifacts():
    for name, expected in PROTECTED.items():
        actual = hashlib.sha256((ARTIFACTS / name).read_bytes()).hexdigest()
        assert actual == expected, f'Frozen submission artifact changed: {name}'


def no_signal(rows):
    return rows.loc[rows[[*FLAGS, 'any_exploit']].eq(0).all(axis=1)].copy()


def pool_summary(rows, labels=True):
    n = len(rows)
    out = {'rows': n, 'snapshot_min': str(rows.snapshot_month.min()), 'snapshot_max': str(rows.snapshot_month.max()),
           'missing_snapshot_observations': int(rows.signal_observed.eq(0).sum())}
    if labels:
        hits = int(rows.label.sum())
        out.update(positives=hits, base_rate=hits/n if n else 0.,
                   missing_snapshot_positive_rows=int(rows.loc[rows.signal_observed.eq(0)].label.sum()),
                   fewer_than_90_days=int(rows.followup_days.lt(90).sum()))
    return out


def metrics(rows, scores, name):
    y = rows.label.to_numpy()
    order = ranked_indices(rows.cve_id, scores)
    n, positives = len(rows), int(y.sum())
    budgets = []
    for requested in BUDGETS:
        k = min(requested, n)
        hits = int(y[order[:k]].sum())
        expected = k * positives / n if n else 0.
        budgets.append({'budget': requested, 'reviewed': k, 'hits': hits,
                        'precision': hits/k if k else 0., 'recall': hits/positives if positives else 0.,
                        'random_expected_hits': expected, 'lift_over_random': hits/expected if expected else None})
    return {'name': name, 'pool': n, 'positives': positives, 'budgets': budgets,
            'average_precision': float(average_precision_score(y, scores)) if positives else 0.}


def validation_choice(validation, results):
    if not validation.published.str.startswith('2024').all():
        raise ValueError('Watch recipe selection must use only 2024 validation rows')
    order = {r.name: r for r in CANDIDATES}
    return min(results, key=lambda m: (-sum(x['hits'] for x in m['budgets']),
                                      -m['average_precision'], bool(order[m['name']].embedding),
                                      order[m['name']].algorithm != 'logistic', m['name']))['name']


def watch_features(blocks):
    x = blocks['text'].drop(columns=[*FLAGS, 'any_exploit', 'exploit_count'])
    production_allowlist(x.columns, allow_text=True)
    return x


def select_on_2024(rows, x, embedding):
    earlier = no_signal(rows.loc[rows.published.str.startswith('2024')])
    train = training_rows(earlier, '2024-06-30')
    validation = assign_outcomes(earlier.loc[earlier.snapshot_month.between('2024-07', '2024-09')], '2024-12-31')
    assert train.snapshot_month.max() < validation.snapshot_month.min()
    assert set(train.cve_id).isdisjoint(validation.cve_id)
    assert train.followup_days.ge(90).all() and validation.followup_days.ge(90).all()
    assert train.label.nunique() == 2
    results = []
    for recipe in CANDIDATES:
        model = FittedModel(recipe).fit(x.loc[train.index], train.label, embedding[train.index] if recipe.embedding else None)
        scores = model.predict(x.loc[validation.index], embedding[validation.index] if recipe.embedding else None)
        result = metrics(validation, scores, recipe.name)
        results.append(result)
        print('2024 validation', recipe.name, [m['hits'] for m in result['budgets']], flush=True)
    chosen = validation_choice(validation, results)
    registry_hash = hashlib.sha256((ROOT / 'pipeline' / 'watch_registry.py').read_bytes()).hexdigest()
    return {'policy': POLICY, 'registry_sha256': registry_hash, 'train': pool_summary(train),
            'validation': pool_summary(validation), 'candidates': results, 'selected_recipe': chosen,
            'selection_year': 2024, 'test_used_for_selection': False,
            'input_manifest': json.loads((CACHE / 'input_manifest.json').read_text())}


def bootstrap(rows, ours, epss, iterations=1000):
    rng = np.random.default_rng(2026)
    groups = [np.flatnonzero(rows.snapshot_month.to_numpy() == m) for m in rows.snapshot_month.unique()]
    deltas = {k: [] for k in BUDGETS}
    workload = {k: [] for k in BUDGETS}
    ids, labels = rows.cve_id.to_numpy(), rows.label.to_numpy()
    for _ in range(iterations):
        ix = np.concatenate([groups[i] for i in rng.integers(0, len(groups), len(groups))])
        a = np.cumsum(labels[ix][ranked_indices(ids[ix], ours[ix])])
        b = np.cumsum(labels[ix][ranked_indices(ids[ix], epss[ix])])
        for k in BUDGETS:
            literal = min(k, len(ix))
            scaled = min(len(ix), max(1, int(np.floor(k * len(ix) / len(rows) + .5))))
            deltas[k].append(int(a[literal-1] - b[literal-1]))
            workload[k].append(int(a[scaled-1] - b[scaled-1]))
    def summary(values):
        values = np.asarray(values)
        return {'delta_hits_95_percentile_interval': np.quantile(values, [.025, .975]).tolist(),
                'fraction_positive': float((values > 0).mean()), 'fraction_negative': float((values < 0).mean())}
    return {'method': 'paired month bootstrap against EPSS; fixed fitted model', 'iterations': iterations,
            'seed': 2026, 'months': len(groups),
            'budgets': [{'budget': k, 'literal': summary(deltas[k]), 'workload_fraction': summary(workload[k])} for k in BUDGETS],
            'limitation': 'Few months and positives; excludes fitting and selection uncertainty. Workload sensitivity scales each budget by resampled/original pool size.'}


def baseline_ties(rows, scores):
    order = ranked_indices(rows.cve_id, scores)
    result = []
    for budget in BUDGETS:
        cutoff = scores[order[min(budget, len(rows))-1]]
        above = scores > cutoff
        tied = scores == cutoff
        fixed_hits = int(rows.loc[above].label.sum())
        tied_hits = int(rows.loc[tied].label.sum())
        slots = min(budget, len(rows)) - int(above.sum())
        result.append({'budget': budget, 'cutoff_score': float(cutoff), 'strictly_above_rows': int(above.sum()),
                       'strictly_above_hits': fixed_hits, 'boundary_tie_rows': int(tied.sum()),
                       'boundary_tie_positives': tied_hits, 'slots_from_boundary': slots,
                       'hits_range_from_tie_order': [fixed_hits + max(0, slots - (int(tied.sum()) - tied_hits)),
                                                    fixed_hits + min(slots, tied_hits)],
                       'expected_hits_with_random_boundary_order': fixed_hits + slots*tied_hits/int(tied.sum())})
    return result


def mixed_allocations(full_test, control_scores, watch_test, watch_scores):
    public = full_test.any_exploit.eq(1).to_numpy()
    order = ranked_indices(full_test.cve_id, control_scores)
    public_order = order[public[order]]
    watch_order = ranked_indices(watch_test.cve_id, watch_scores)
    control = full_test.iloc[order[:500]]
    result = [{'name': 'frozen submitted model', 'budget': 500, 'feasible': True,
               'exploit_tier_rows': int(control.any_exploit.sum()), 'watch_rows': int(control.any_exploit.eq(0).sum()),
               'hits': int(control.label.sum()),
               'no_signal_hits': int(control.loc[control.any_exploit.eq(0)].label.sum())}]
    for public_budget, watch_budget in [(450, 50), (400, 100)]:
        if len(public_order) < public_budget:
            result.append({'name': f'{public_budget} exploit + {watch_budget} watch', 'budget': 500,
                           'feasible': False, 'available_exploit_rows': len(public_order),
                           'reason': 'Not enough exploit-tier rows to implement this allocation at the stated 500 budget.'})
            continue
        first = full_test.iloc[public_order[:public_budget]]
        second = watch_test.iloc[watch_order[:watch_budget]]
        assert set(first.cve_id).isdisjoint(second.cve_id)
        assert len(first) + len(second) == 500
        result.append({'name': f'{public_budget} exploit + {watch_budget} watch', 'budget': 500, 'feasible': True,
                       'exploit_tier_rows': len(first), 'watch_rows': len(second),
                       'hits': int(first.label.sum() + second.label.sum()), 'no_signal_hits': int(second.label.sum()),
                       'delta_vs_frozen': int(first.label.sum() + second.label.sum() - control.label.sum())})
    return result


def export_watch(recipe, rows, history, x, embedding):
    from pipeline.run import CONTRACT_COLUMNS, reasons_for
    from pipeline.publication import display_description
    train = no_signal(training_rows(rows.loc[rows.published.str[:4].isin(['2024', '2025'])], '2025-12-31'))
    target = no_signal(rows.loc[rows.published.str.startswith('2026')])
    model = FittedModel(recipe).fit(x.loc[train.index], train.label, embedding[train.index] if recipe.embedding else None)
    probability = model.predict(x.loc[target.index], embedding[target.index] if recipe.embedding else None)
    order = ranked_indices(target.cve_id, probability)[:100]
    best = target.iloc[order].copy()
    p, terms, base, names = model.predict(x.loc[best.index], embedding[best.index] if recipe.embedding else None, contributions=True)
    np.testing.assert_array_equal(p, probability[order])
    best['rank'] = np.arange(1, 101)
    best['score'] = p
    best['reasons'] = reasons_for(best, history, x, terms, names)
    display = best.description.map(clean_description).map(display_description)
    best['description'] = display.map(lambda pair: pair[0])
    best['description_source'] = display.map(lambda pair: pair[1])
    best['explanation_base_log_odds'] = base
    best['explanation_omitted_log_odds'] = [float(t.sum() - sum(r['contribution'] for r in json.loads(reason)))
                                          for t, reason in zip(terms, best.reasons)]
    best['vendor_identity'] = history.loc[best.index, 'text_vendor_identity']
    best['vendor_prior_kev'] = history.loc[best.index, 'text_vendor_prior_kev'].astype(int)
    best['product_identity'] = history.loc[best.index, 'text_product_identity']
    best['product_prior_kev'] = history.loc[best.index, 'text_product_prior_kev'].astype(int)
    best['entity_source'] = history.loc[best.index, 'entity_source']
    best['score_horizon'] = 'later KEV inclusion conditional on no snapshot tool flags; historical variable follow-up'
    best['queue_purpose'] = 'exploratory watch review; held-out performance is in findings.json'
    extras = ['vendor_identity', 'vendor_prior_kev', 'product_identity', 'product_prior_kev', 'entity_source',
              'score_horizon', 'description_source', 'explanation_base_log_odds', 'explanation_omitted_log_odds', 'queue_purpose']
    best[CONTRACT_COLUMNS + extras].to_csv(WATCH_PATH, index=False)
    return {'training': pool_summary(train), 'target': pool_summary(target, labels=False),
            'features_used': names, 'recipe': recipe.__dict__, 'seed': 2026,
            'ibm_technology': f'{MODEL_ID} revision {REVISION}; description embeddings on MPS; train-only PCA' if recipe.embedding else None,
            'calibration': 'Conditional variable-follow-up estimate; not a calibrated attack probability or guarantee of safety.',
            'artifact_sha256': hashlib.sha256(WATCH_PATH.read_bytes()).hexdigest(),
            'top100_vendors': best.vendor_identity.replace('', 'unmapped').value_counts().head(15).to_dict()}


def apply_findings(result):
    path = ARTIFACTS / 'findings.json'
    f = json.loads(path.read_text())
    primary = result['splits'][0]
    chosen = primary['methods'][0]
    at500 = next(m for m in chosen['budgets'] if m['budget'] == 500)
    epss = next(m for m in primary['methods'][1]['budgets'] if m['budget'] == 500)
    positives = primary['test']['positives']
    sentence = (f"A separately trained watch list found {at500['hits']} of {positives} later KEV additions with no snapshot tool flags "
                f"in its first 500 reviews, versus {epss['hits']} for EPSS and {at500['random_expected_hits']:.2f} expected at random; "
                "the 2026 watch queue is separate from the submitted top 500.")
    if at500['hits'] == 0:
        product = next(c for c in result['profile']['contrasts'] if c['name'] == 'product_prior_kev_any')
        sentence = (f"Prior product history marked {product['no_signal_positives']} of {positives} blind-spot positives "
                    f"but only {product['pool_share']:.1%} of the no-signal pool, a descriptive review cue; "
                    "the preregistered watch model still found none in 500 reviews, so the 2026 queue remains exploratory.")
    story = {'title': STORY_TITLE, 'sentence': sentence,
             'numbers': {'no_signal_pool': primary['test']['rows'], 'no_signal_positives': positives,
                         'watch_hits_at_500': at500['hits'], 'epss_hits_at_500': epss['hits'],
                         'random_expected_at_500': at500['random_expected_hits'], 'review_budget': 500},
             'source_script': 'pipeline/watch.py'}
    product = next(c for c in result['profile']['contrasts'] if c['name'] == 'product_prior_kev_any')
    story['numbers'].update(prior_product_positives=product['no_signal_positives'],
                            prior_product_pool=product['no_signal_pool'], prior_product_pool_share=product['pool_share'])
    f['blind_spot'] = result
    f['story'] = [story] + [entry for entry in f.get('story', []) if entry['title'] != STORY_TITLE]
    write_json(path, f)
    root_readme = ROOT / 'README.md'
    text = root_readme.read_text()
    prefix = '- **A separate watch queue.**'
    line = f'{prefix} {sentence} [Watch list](artifacts/watch_2026_top100.csv).'
    lines = [item for item in text.splitlines() if not item.startswith(prefix)]
    position = next(i for i, item in enumerate(lines) if item.startswith('- **The blind spot.**')) + 1
    lines.insert(position, line)
    updated = '\n'.join(lines) + '\n'
    if updated != text:
        root_readme.write_text(updated)


def run():
    frozen_artifacts()
    rows, history, blocks = prepared()
    x = watch_features(blocks)
    embedding = embeddings(rows, 'description')
    selection = select_on_2024(rows, x, embedding)
    registered = json.loads(SELECTION_PATH.read_text())
    assert selection == registered, 'The committed 2024-only selection must reproduce before 2025 scoring'
    recipe = next(r for r in CANDIDATES if r.name == selection['selected_recipe'])
    original = json.loads((ARTIFACTS / 'backtest.json').read_text())
    control_recipe = Recipe(**json.loads((ARTIFACTS / 'model_card.json').read_text())['recipe'])
    evaluated, mixed = [], []
    for name, full_train, full_test, cutoff, endpoint in splits(rows)[:2]:
        train, test = no_signal(full_train), no_signal(full_test)
        assert train.snapshot_month.max() < test.snapshot_month.min()
        assert set(train.cve_id).isdisjoint(test.cve_id)
        assert train.followup_days.ge(90).all()
        model = FittedModel(recipe).fit(x.loc[train.index], train.label, embedding[train.index] if recipe.embedding else None)
        scores = model.predict(x.loc[test.index], embedding[test.index] if recipe.embedding else None)
        epss = test.epss.fillna(0).to_numpy()
        cvss = pd.to_numeric(test.cvss3_score, errors='coerce').fillna(-1).to_numpy()
        methods = [metrics(test, scores, recipe.name), metrics(test, epss, 'EPSS first'), metrics(test, cvss, 'CVSS first (current, descriptive reference)')]
        print('Watch test', name, [m['hits'] for m in methods[0]['budgets']], flush=True)
        random = [{'budget': k, 'expected_hits': min(k, len(test))*int(test.label.sum())/len(test),
                   'expected_precision': float(test.label.mean())} for k in BUDGETS]
        seed_methods = []
        if recipe.algorithm == 'lightgbm':
            seed_methods.append({'seed': 2026, **methods[0]})
            for seed in SEEDS[1:]:
                fitted = FittedModel(recipe, seed=seed).fit(x.loc[train.index], train.label, embedding[train.index] if recipe.embedding else None)
                p = fitted.predict(x.loc[test.index], embedding[test.index] if recipe.embedding else None)
                seed_methods.append({'seed': seed, **metrics(test, p, recipe.name)})
        seed_ranges = [{'budget': k, 'min_hits': min(m['budgets'][j]['hits'] for m in seed_methods),
                        'max_hits': max(m['budgets'][j]['hits'] for m in seed_methods)}
                       for j, k in enumerate(BUDGETS)] if seed_methods else []
        evaluated.append({'name': name, 'train_label_cutoff': cutoff, 'test_label_cutoff': endpoint,
                          'train': pool_summary(train), 'test': pool_summary(test), 'full_test': pool_summary(full_test),
                          'methods': methods, 'random_expectation': random,
                          'baseline_ties': {'tie_break': 'score descending, cve_id ascending',
                                            'epss': baseline_ties(test, epss), 'cvss': baseline_ties(test, cvss),
                                            'note': 'Current CVSS contains large boundary ties; a different tie order can change the observed count without changing severity scores.'},
                          'bootstrap_vs_epss': bootstrap(test, scores, epss),
                          'seed_stability': {'production_seed': 2026, 'methods': seed_methods, 'ranges': seed_ranges,
                                             'note': 'Seeds are diagnostic only; no best-seed or test-year selection.'}})
        prediction = test[['cve_id', 'snapshot_month', 'label', 'followup_days']].copy()
        prediction['watch_score'] = scores
        prediction.to_parquet(CACHE / f'watch_predictions_{name}.parquet', index=False)
        control_x = blocks[control_recipe.block]
        control = FittedModel(control_recipe).fit(control_x.loc[full_train.index], full_train.label,
                    embedding[full_train.index] if control_recipe.embedding else None)
        control_p = control.predict(control_x.loc[full_test.index], embedding[full_test.index] if control_recipe.embedding else None)
        control_scores = control.ranking_score(control_x.loc[full_test.index], control_p)
        allocation = mixed_allocations(full_test, control_scores, test, scores)
        expected = next(m['hits_at_500'] for s in original['splits'] if s['name'] == name
                        for m in s['methods'] if m['name'] == control_recipe.name)
        assert allocation[0]['hits'] == expected, 'Frozen comparison must reproduce'
        mixed.append({'split': name, 'adopted': False, 'allocations': allocation})
    from pipeline.watch_profile import profile
    full_2025 = splits(rows)[0][2]
    result = {'selected_recipe': recipe.name, 'policy': POLICY, 'selection': selection,
              'pool_definition': POLICY['pool'], 'splits': evaluated,
              'profile': profile(full_2025, history), 'mixed_allocations': mixed,
              'artifact_path': str(WATCH_PATH.relative_to(ROOT)), 'final_model': export_watch(recipe, rows, history, x, embedding),
              'validation_status': 'negative: no held-out hits at any tested budget on either split' if all(
                  m['hits'] == 0 for split in evaluated for m in split['methods'][0]['budgets']) else 'held-out results reported; exploratory watch queue',
              'protected_artifacts_sha256': PROTECTED,
              'limitations': ['Only three training positives and eight validation positives in the inner 2024 split.',
                             'The shared feature family was developed in earlier work that inspected 2025 results. This round freezes the watch recipes before their 2025 evaluation; it does not create a wholly untouched project-wide holdout.',
                             'The two 2025 evaluation sets overlap; the secondary is a later-cutoff refit, not independent replication.',
                             'Random expectation is below one hit at every tested budget; zero observed hits shows no demonstrated gain, not proof that the pool has no learnable signal.',
                             'No flag includes missing snapshot observations; it does not prove exploit code was absent.',
                             'Current sanitized description wording and heuristic identity retain revision/matching risk.',
                             'Current CWE/CVSS data are descriptive only and cannot justify a time-safe predictive gain.',
                             'The main submission is frozen; mixed allocations are comparisons for a separate decision.'],
              'generator': 'pipeline/watch.py', 'profile_generator': 'pipeline/watch_profile.py'}
    apply_findings(result)
    frozen_artifacts()
    watch_checks()
    return result


def watch_checks():
    from scipy.special import expit
    from pipeline.run import CONTRACT_COLUMNS
    from pipeline.data import DATA
    frozen_artifacts()
    watch = pd.read_csv(WATCH_PATH, keep_default_na=False)
    assert len(watch) == 100 and watch.cve_id.is_unique
    assert list(watch.columns[:len(CONTRACT_COLUMNS)]) == CONTRACT_COLUMNS
    assert watch['rank'].tolist() == list(range(1, 101))
    assert watch[[*FLAGS, 'any_exploit']].eq(0).all().all()
    assert watch.score.between(0, 1).all() and watch.score.is_monotonic_decreasing
    source = pd.read_csv(DATA / 'scoreboard_2026.csv').set_index('cve_id').loc[watch.cve_id]
    assert source[FLAGS].eq(0).all().all()
    assert source.snapshot_month.tolist() == watch.snapshot_month.tolist()
    assert source.published.tolist() == watch.published.tolist()
    assert np.allclose(source.epss, pd.to_numeric(watch.epss, errors='coerce'), equal_nan=True)
    from pipeline.publication import display_description
    assert watch.description.map(clean_description).eq(watch.description).all()
    assert watch.description.map(lambda value: display_description(value)[0]).eq(watch.description).all()
    top = pd.read_csv(ARTIFACTS / 'top500.csv')
    assert set(watch.cve_id).isdisjoint(top.cve_id)
    terms = []
    for value in watch.reasons:
        reasons = json.loads(value)
        assert 1 <= len(reasons) <= 5
        assert all({'feature', 'label', 'value', 'contribution'} <= r.keys() for r in reasons)
        terms.append(sum(r['contribution'] for r in reasons))
    reconstructed = expit(watch.explanation_base_log_odds + watch.explanation_omitted_log_odds + terms)
    assert np.allclose(reconstructed, watch.score, atol=1e-10)
    f = json.loads((ARTIFACTS / 'findings.json').read_text())
    result = f['blind_spot']
    assert result['selection'] == json.loads(SELECTION_PATH.read_text())
    assert result['selected_recipe'] == result['selection']['selected_recipe']
    assert result['final_model']['artifact_sha256'] == hashlib.sha256(WATCH_PATH.read_bytes()).hexdigest()
    production_allowlist(result['final_model']['features_used'], allow_text=True)
    profile = result['profile']
    primary = result['splits'][0]
    assert profile['no_signal_pool'] == primary['test']['rows']
    assert profile['no_signal_positives'] == primary['test']['positives']
    assert profile['no_signal_pool'] + profile['with_signal_pool'] == primary['full_test']['rows']
    assert profile['no_signal_positives'] + profile['with_signal_positives'] == primary['full_test']['positives']
    for table in profile['tables'].values():
        for key in ['no_signal_pool', 'no_signal_positives', 'with_signal_positives']:
            assert sum(row[key] for row in table['rows']) == profile[key]
    assert f['story'][0]['title'] == STORY_TITLE
    assert f['story'][0]['numbers']['watch_hits_at_500'] == primary['methods'][0]['budgets'][-1]['hits']
    print('Watch checks: 100 no-signal rows; reasons reconstruct scores; submitted artifacts unchanged', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--select-only', action='store_true', help='Freeze the four-recipe comparison using only 2024 outcomes')
    args = parser.parse_args()
    if args.select_only:
        frozen_artifacts()
        rows, _, blocks = prepared()
        selection = select_on_2024(rows, watch_features(blocks), embeddings(rows, 'description'))
        write_json(SELECTION_PATH, selection)
        print('Frozen watch recipe:', selection['selected_recipe'], flush=True)
        frozen_artifacts()
        return
    run()


if __name__ == '__main__':
    main()
