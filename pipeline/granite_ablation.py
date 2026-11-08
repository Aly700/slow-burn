"""Paired Granite removal using the frozen recipe, splits and five seeds.

Run only after committing this file and granite_ablation_design.json. No judged
artifact is written. The primary references use the original predictions; the
seed-2026 refit must recover their exact selected-model ranking.
"""
from pathlib import Path
from dataclasses import replace
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import numpy as np
import pandas as pd
from pipeline.data import ARTIFACTS, CACHE, write_json
from pipeline.embed import embeddings
from pipeline.evaluate import BASELINES, baseline_scores, prepared, ranked_indices, splits
from pipeline.models import RECIPES, FittedModel

DESIGN_PATH = ROOT / 'pipeline/granite_ablation_design.json'
DESIGN = json.loads(DESIGN_PATH.read_text())


def paired_recipes():
    selected = next(r for r in RECIPES if r.name == DESIGN['model'])
    return selected, replace(selected, name=selected.name + '_without_granite', embedding='')


def hit_counts(rows, scores, budgets):
    labels = rows.label.to_numpy()[ranked_indices(rows.cve_id, scores)]
    return [int(labels[:budget].sum()) for budget in budgets]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run():
    design_commit = subprocess.check_output(
        ['git', 'log', '--diff-filter=A', '-1', '--format=%H', '--', str(DESIGN_PATH.relative_to(ROOT))],
        cwd=ROOT, text=True).strip()
    if not design_commit:
        raise RuntimeError('Commit the comparison design before running it.')
    for path in [DESIGN_PATH, Path(__file__)]:
        committed = subprocess.check_output(['git', 'show', f'HEAD:{path.relative_to(ROOT)}'], cwd=ROOT)
        assert committed == path.read_bytes(), 'Commit comparison code before running it'
    frozen = {p.name: sha(p) for p in ARTIFACTS.iterdir() if p.is_file() and p.name != 'granite_ablation_2025.json'}
    backtest = json.loads((ARTIFACTS / 'backtest.json').read_text())
    assert backtest['selected_model'] == DESIGN['model']
    assert backtest['seed_stability']['production_seeds'] == [DESIGN['primary_seed']]
    assert backtest['seed_stability']['seeds'] == DESIGN['seeds']
    prediction_path = ROOT / DESIGN['reference_predictions']
    original = pd.read_parquet(prediction_path)
    rows, _, blocks = prepared()
    embedding = embeddings(rows, 'description')
    on, off = paired_recipes()
    results = []
    for name, train, test, cutoff, endpoint in splits(rows)[:2]:
        assert name in DESIGN['splits']
        assert set(train.cve_id).isdisjoint(test.cve_id)
        assert train.followup_days.ge(90).all()
        assert train.snapshot_month.max() < test.snapshot_month.min()
        reference = original if name == DESIGN['splits'][0] else test
        if name == DESIGN['splits'][0]:
            assert test.cve_id.tolist() == original.cve_id.tolist()
            assert test.label.tolist() == original.label.tolist()
        methods = []
        for key, label, recipe in [('ours', 'Slow Burn', on), ('without_granite', 'Without Granite', off)]:
            measurements = []
            for seed in DESIGN['seeds']:
                x = blocks[recipe.block]
                model = FittedModel(recipe, seed=seed).fit(
                    x.loc[train.index], train.label, embedding[train.index] if recipe.embedding else None)
                probability = model.predict(x.loc[test.index], embedding[test.index] if recipe.embedding else None)
                score = model.ranking_score(x.loc[test.index], probability)
                counts = hit_counts(test, score, DESIGN['budgets'])
                if key == 'ours' and seed == DESIGN['primary_seed']:
                    if name == DESIGN['splits'][0]:
                        assert np.array_equal(ranked_indices(test.cve_id, score), ranked_indices(original.cve_id, original[on.name]))
                        counts = hit_counts(original, original[on.name], DESIGN['budgets'])
                    selected_counts = counts
                if seed == DESIGN['primary_seed']:
                    primary = counts
                measurements.append({'seed': seed, 'hits': counts})
                print(name, key, seed, counts, flush=True)
            methods.append({'key': key, 'name': label, 'hits': primary, 'seeds': measurements,
                            'seed_range': [[min(s['hits'][i] for s in measurements), max(s['hits'][i] for s in measurements)]
                                           for i in range(len(DESIGN['budgets']))]})
        scores = {b: original[b] for b in BASELINES} if name == DESIGN['splits'][0] else baseline_scores(test)
        for key, label in [('rule', BASELINES[2]), ('epss', BASELINES[1]), ('cvss', BASELINES[0])]:
            counts = hit_counts(reference, scores[label], DESIGN['budgets'])
            methods.append({'key': key, 'name': label, 'hits': counts,
                            'seed_range': [[n, n] for n in counts], 'seeds': []})
        if name == DESIGN['splits'][0]:
            replay = json.loads((ARTIFACTS / 'replay_2025.json').read_text())
            for method in methods:
                if method['key'] == 'without_granite':
                    continue
                recorded = next(m for m in replay['methods'] if m['key'] == method['key'])
                assert method['hits'] == [sum(bool(item['kev_date']) for item in recorded['items'][:k]) for k in DESIGN['budgets']]
        results.append({'split': name, 'train_cutoff': cutoff, 'outcome_cutoff': endpoint,
                        'train_rows': len(train), 'train_positives': int(train.label.sum()),
                        'pool': len(test), 'positives': int(test.label.sum()), 'methods': methods})
    out = {'schema_version': 1, 'design_commit': design_commit, 'design': DESIGN,
           'budgets': DESIGN['budgets'], 'splits': results,
           'provenance': {'design_sha256': sha(DESIGN_PATH), 'script_sha256': sha(Path(__file__)),
                          'backtest_sha256': sha(ARTIFACTS / 'backtest.json'),
                          'predictions_sha256': sha(prediction_path),
                          'inputs': json.loads((CACHE / 'input_manifest.json').read_text())},
           'limitations': [DESIGN['interpretation'],
                           'All-2025 includes right-censored late rows; the second split overlaps it.',
                           'Current sanitized descriptions retain revision risk. Removing embeddings retains keywords and description-derived identity history.',
                           'Current CVSS is a retrospective reference, not a time-safe model feature.',
                           'The frozen submission and selected configuration are unchanged.']}
    assert all(sha(ARTIFACTS / name) == digest for name, digest in frozen.items())
    write_json(ARTIFACTS / 'granite_ablation_2025.json', out)
    return out


if __name__ == '__main__':
    run()
