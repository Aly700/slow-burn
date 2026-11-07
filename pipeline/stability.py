"""Five fixed seeds on both required historical splits."""
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np

from pipeline.data import ARTIFACTS, CACHE, write_json
from pipeline.embed import embeddings
from pipeline.evaluate import BASELINES, baseline_scores, prepared, ranking_metrics, splits
from pipeline.models import RECIPES, FittedModel, select_recipe

SEEDS = [2026, 2027, 2028, 2029, 2030]


def assess(recipe, rows, blocks, embedding):
    results, averages = [], {}
    below = False
    for name, train, test, _, _ in splits(rows)[:2]:
        x = blocks[recipe.block]
        train_emb = embedding[train.index] if embedding is not None else None
        test_emb = embedding[test.index] if embedding is not None else None
        reference = ranking_metrics(test, baseline_scores(test)[BASELINES[-1]], BASELINES[-1])
        methods, probabilities = [], []
        for seed in SEEDS:
            model = FittedModel(recipe, seed=seed).fit(x.loc[train.index], train.label, train_emb)
            probability = model.predict(x.loc[test.index], test_emb)
            probabilities.append(probability)
            score = model.ranking_score(x.loc[test.index], probability)
            method = ranking_metrics(test, score, recipe.name, True, probability)
            methods.append({'seed': seed, **method})
            print(name, seed, method['hits_at_500'], method['hits_at_scaled_budget'], flush=True)
        average = np.mean(probabilities, axis=0)
        averages[name] = average
        mean_method = ranking_metrics(test, model.ranking_score(x.loc[test.index], average),
                                      recipe.name + '_seed_average', True, average)
        ranges = {key: [min(m[key] for m in methods), max(m[key] for m in methods)]
                  for key in ['hits_at_500', 'hits_at_scaled_budget']}
        crosses = any(ranges[key][0] < reference[key] for key in ranges)
        below |= crosses
        results.append({'split': name, 'rule': reference, 'seeds': methods, 'hit_ranges': ranges,
                        'any_seed_below_rule': crosses, 'probability_average': mean_method})
    result = {'base_model': recipe.name, 'seeds': SEEDS, 'splits': results,
              'average_required': below, 'production_seeds': SEEDS if below else [SEEDS[0]],
              'policy': 'If any seed falls below the rule at either budget on either required split, average all five probabilities before applying the tier policy.',
              'randomness': 'Refit both randomized training-only PCA and LightGBM; no row or feature subsampling is enabled.',
              'limitation': 'Seed variability measures fitting randomness, not new-data uncertainty or model-selection optimism.'}
    write_json(CACHE / 'seed_stability.json', result)
    return result, averages


if __name__ == '__main__':
    b = json.loads((ARTIFACTS / 'backtest.json').read_text())
    recipes = [r for r in RECIPES if r.name in b['selection']['gates']]
    chosen = select_recipe(recipes, b['selection']['gates'], b['selection']['feature_counts'])
    recipe = next(r for r in recipes if r.name == chosen)
    rows, _, blocks = prepared()
    embedding = embeddings(rows, recipe.embedding) if recipe.embedding else None
    result, _ = assess(recipe, rows, blocks, embedding)
    print(json.dumps(result, indent=2))
