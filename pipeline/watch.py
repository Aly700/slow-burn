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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--select-only', action='store_true', help='Freeze the four-recipe comparison using only 2024 outcomes')
    args = parser.parse_args()
    frozen_artifacts()
    rows, history, blocks = prepared()
    x = watch_features(blocks)
    embedding = embeddings(rows, 'description')
    selection = select_on_2024(rows, x, embedding)
    if args.select_only:
        write_json(SELECTION_PATH, selection)
        print('Frozen watch recipe:', selection['selected_recipe'], flush=True)
        frozen_artifacts()
        return
    raise RuntimeError('Evaluation is enabled only after the training-year choice is committed')


if __name__ == '__main__':
    main()
