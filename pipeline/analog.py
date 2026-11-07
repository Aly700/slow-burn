"""Historical January–September benchmark analog, including June → July."""
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd

from pipeline.data import ARTIFACTS, CACHE, assign_outcomes, cohort, kev, training_rows, write_json
from pipeline.embed import embeddings
from pipeline.evaluate import prepared, baseline_scores, ranking_metrics
from pipeline.features import history_features, make_features
from pipeline.models import FittedModel, Recipe, RECIPES


def run():
    original, old_history, _ = prepared()
    shifted = pd.concat([cohort(2024, june_shift=True), cohort(2025, june_shift=True)], ignore_index=True)
    lookup = pd.Series(original.index.to_numpy(), index=original.cve_id)
    source_index = shifted.cve_id.map(lookup).to_numpy()
    h = old_history.loc[source_index].copy().set_axis(shifted.index)
    changed = shifted.published.str[5:7].eq('06')
    cache = CACHE / 'shifted_june_history.parquet'
    if cache.exists():
        replacement = pd.read_parquet(cache)
        assert replacement.index.equals(shifted.index[changed])
    else:
        replacement = history_features(shifted.loc[changed], kev())
        replacement.to_parquet(cache)
    h.loc[changed] = replacement
    recipe = Recipe(**json.loads((CACHE / 'selected_recipe.json').read_text()))
    backtest = json.loads((ARTIFACTS / 'backtest.json').read_text())
    a = shifted.loc[shifted.published.str.startswith('2024') & shifted.snapshot_month.le('2024-09')]
    b = shifted.loc[shifted.published.str.startswith('2025') & shifted.snapshot_month.le('2025-09')]
    train = training_rows(a, '2024-11-04')
    test = assign_outcomes(b, '2025-11-04')
    methods = [ranking_metrics(test, s, n) for n, s in baseline_scores(test).items()]
    # This sensitivity is not another selection gate. Show every qualifying recipe
    # without embeddings so an adverse calendar result cannot be hidden.
    candidates = [r for r in RECIPES if r.name == recipe.name or
                  (not r.embedding and backtest['selection']['gates'].get(r.name, {}).get('passes_all_four'))]
    blocks = {}
    for candidate in candidates:
        if candidate.block not in blocks:
            blocks[candidate.block] = make_features(shifted, kev(), candidate.block, h)
        x = blocks[candidate.block]
        embed = embeddings(original, candidate.embedding)[source_index] if candidate.embedding else None
        model = FittedModel(candidate).fit(x.loc[train.index], train.label, embed[train.index] if embed is not None else None)
        probability = model.predict(x.loc[test.index], embed[test.index] if embed is not None else None)
        score = model.ranking_score(x.loc[test.index], probability)
        methods.append(ranking_metrics(test, score, candidate.name, probabilities=True, probability_values=probability))
    result = {'name': 'exact_calendar_analog_2025',
              'snapshot_rule': 'Published January–September; publication-month end except June shifted to July',
              'train_label_cutoff': '2024-11-04', 'test_label_cutoff': '2025-11-04',
              'train_pool': len(train), 'train_positives': int(train.label.sum()),
              'pool': len(test), 'positives': int(test.label.sum()),
              'minimum_test_followup_days': int(test.followup_days.min()),
              'selected_model': recipe.name, 'methods': methods,
              'note': 'Matches the benchmark calendar shape and November 4 endpoint. Training still requires 90 days follow-up. Reports the selected recipe and all other qualifying recipes without embeddings; does not select among them.'}
    path = ARTIFACTS / 'backtest.json'
    backtest['exact_calendar_analog'] = result
    write_json(path, backtest)
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    run()
