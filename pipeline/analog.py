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
from pipeline.models import FittedModel, Recipe


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
    x = make_features(shifted, kev(), recipe.block, h)
    a = shifted.loc[shifted.published.str.startswith('2024') & shifted.snapshot_month.le('2024-09')]
    b = shifted.loc[shifted.published.str.startswith('2025') & shifted.snapshot_month.le('2025-09')]
    train = training_rows(a, '2024-11-04')
    test = assign_outcomes(b, '2025-11-04')
    embed = embeddings(original, recipe.embedding)[source_index] if recipe.embedding else None
    model = FittedModel(recipe).fit(x.loc[train.index], train.label, embed[train.index] if embed is not None else None)
    score = model.predict(x.loc[test.index], embed[test.index] if embed is not None else None)
    result = {'name': 'exact_calendar_analog_2025',
              'snapshot_rule': 'Published January–September; publication-month end except June shifted to July',
              'train_label_cutoff': '2024-11-04', 'test_label_cutoff': '2025-11-04',
              'train_pool': len(train), 'train_positives': int(train.label.sum()),
              'pool': len(test), 'positives': int(test.label.sum()),
              'minimum_test_followup_days': int(test.followup_days.min()),
              'methods': [ranking_metrics(test, s, n) for n, s in baseline_scores(test).items()] +
                         [ranking_metrics(test, score, recipe.name, probabilities=True)],
              'note': 'Matches the benchmark calendar shape and November 4 endpoint. Training still requires 90 days follow-up.'}
    path = ARTIFACTS / 'backtest.json'
    backtest = json.loads(path.read_text())
    backtest['exact_calendar_analog'] = result
    write_json(path, backtest)
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    run()
