"""Predeclared original-vector comparison; no layout coordinates or test-year anchors."""
import numpy as np
import pandas as pd
from scipy.stats import rankdata

from pipeline.data import CACHE, END, assign_outcomes
from pipeline.embed import all_rows, embeddings
from pipeline.features import clean_description
from pipeline.map_embeddings import anchor_vectors, comparison_anchors
from pipeline.watch import no_signal

ITERATIONS = 10000
SEED = 2026


def semantic_text_mask(rows):
    return rows.description.fillna('').map(clean_description).ne('')


def passes_story_thresholds(primary, sensitivity):
    return bool(primary['probability_positive_is_closer'] > .5 and primary['permutation']['one_sided_p'] <= .01 and
                sensitivity['probability_positive_is_closer'] > .5 and sensitivity['permutation']['one_sided_p'] <= .05)


def closest_past(query, anchors):
    query = np.array(query, dtype=np.float64, copy=True)
    anchors = np.array(anchors, dtype=np.float64, copy=True)
    query /= np.linalg.norm(query, axis=1, keepdims=True)
    anchors /= np.linalg.norm(anchors, axis=1, keepdims=True)
    distances, neighbours = [], []
    for start in range(0, len(query), 4096):
        similarity = np.clip(query[start:start+4096] @ anchors.T, -1, 1)
        index = np.argmax(similarity, axis=1)
        neighbours.extend(index)
        distances.extend(1-similarity[np.arange(len(index)), index])
    return np.asarray(distances), np.asarray(neighbours)


def neighbour_test(rows, distances, iterations=ITERATIONS):
    distances = np.asarray(distances)
    labels = rows.label.to_numpy().astype(bool)
    positives, negatives = int(labels.sum()), int((~labels).sum())
    assert positives > 0 and negatives > 0 and np.isfinite(distances).all()
    ranks = rankdata(-distances, method='average')
    offset = positives*(positives+1)/2
    denominator = positives*negatives
    observed = float((ranks[labels].sum()-offset)/denominator)
    groups = [np.flatnonzero(rows.snapshot_month.to_numpy() == month) for month in sorted(rows.snapshot_month.unique())]
    sizes = [int(labels[group].sum()) for group in groups]
    rng = np.random.default_rng(SEED)
    null = np.empty(iterations)
    for i in range(iterations):
        rank_sum = sum(ranks[rng.choice(group, size=size, replace=False)].sum()
                       for group, size in zip(groups, sizes) if size)
        null[i] = (rank_sum-offset)/denominator
    def summary(part):
        return {'mean': float(part.mean()), 'median': float(np.median(part)),
                'quartiles': np.quantile(part, [.25, .75]).tolist()}
    return {'rows': len(rows), 'positives': positives, 'non_listed_by_cutoff': negatives,
            'probability_positive_is_closer': observed,
            'interpretation': 'Probability a randomly chosen later-listed CVE has a nearer past-listed neighbour than a randomly chosen non-listed CVE, with half credit for tied distances.',
            'positive_cosine_distance': summary(distances[labels]), 'non_listed_cosine_distance': summary(distances[~labels]),
            'permutation': {'method': 'Permute labels within snapshot months, preserving each month’s positive count.',
                            'iterations': iterations, 'seed': SEED, 'null_mean': float(null.mean()),
                            'null_95_percentile_interval': np.quantile(null, [.025, .975]).tolist(),
                            'one_sided_p': float((1+np.sum(null >= observed))/(iterations+1))}}


def run():
    rows = all_rows()
    vectors = embeddings(rows, 'description')
    anchors, anchor_embedding, _ = anchor_vectors()
    past = comparison_anchors(anchors)
    queries = assign_outcomes(rows.loc[rows.published.str.startswith('2025')], END)
    assert set(queries.cve_id).isdisjoint(past.cve_id)
    distances, nearest = closest_past(vectors[queries.index], anchor_embedding[past.index])
    blind = no_signal(queries)
    blind_mask = queries.index.isin(blind.index)
    primary = neighbour_test(queries, distances)
    sensitivity = neighbour_test(blind, distances[blind_mask])
    evidence = queries[['cve_id', 'snapshot_month', 'label', 'any_exploit', 'followup_days']].copy()
    evidence['nearest_prior_cve'] = past.iloc[nearest].cve_id.to_numpy()
    evidence['nearest_prior_date'] = past.iloc[nearest].date_added.to_numpy()
    evidence['cosine_distance'] = distances
    valid_queries = queries.loc[semantic_text_mask(queries)]
    valid_past = past.loc[semantic_text_mask(past)]
    valid_distances, valid_nearest = closest_past(vectors[valid_queries.index], anchor_embedding[valid_past.index])
    valid_blind = no_signal(valid_queries)
    valid_primary = neighbour_test(valid_queries, valid_distances)
    valid_sensitivity = neighbour_test(valid_blind, valid_distances[valid_queries.index.isin(valid_blind.index)])
    evidence['has_sanitized_text'] = semantic_text_mask(queries)
    evidence.loc[valid_queries.index, 'nonempty_nearest_prior_cve'] = valid_past.iloc[valid_nearest].cve_id.to_numpy()
    evidence.loc[valid_queries.index, 'nonempty_nearest_prior_date'] = valid_past.iloc[valid_nearest].date_added.to_numpy()
    evidence.loc[valid_queries.index, 'nonempty_cosine_distance'] = valid_distances
    evidence.to_parquet(CACHE / 'map_neighbours_2025.parquet', index=False)
    original_gate = passes_story_thresholds(primary, sensitivity)
    valid_gate = passes_story_thresholds(valid_primary, valid_sensitivity)
    validity = {'post_hoc': True,
                'reason': 'Incident stripping can leave empty text, which cannot support semantic similarity and may create a revision proxy. Exclude empty queries and anchors; preserve the original predeclared results.',
                'anchor_count': len(valid_past), 'excluded_anchors': len(past)-len(valid_past),
                'excluded_primary_rows': len(queries)-len(valid_queries),
                'excluded_primary_positives': int(queries.label.sum()-valid_queries.label.sum()),
                'excluded_no_signal_rows': len(blind)-len(valid_blind),
                'excluded_no_signal_positives': int(blind.label.sum()-valid_blind.label.sum()),
                'primary_2025': valid_primary, 'no_signal_sensitivity': valid_sensitivity,
                'guard_passed': valid_gate}
    return {'space': 'Original normalized 384-dimensional Granite description vectors; map coordinates are not used.',
            'anchor_definition': 'Published in 2024 and entered KEV by 2024-12-31; fixed before every 2025 query snapshot.',
            'anchor_count': len(past), 'anchor_latest_date': past.date_added.max(), 'label_cutoff': END,
            'primary_2025': primary, 'no_signal_sensitivity': sensitivity,
            'predeclared_gate_passed': original_gate, 'empty_text_audit': validity,
            'story_qualifies': original_gate and valid_gate,
            'fewer_than_90_days': int(queries.followup_days.lt(90).sum()),
            'predeclared_in': 'pipeline/MAP_PLAN.md',
            'limitations': ['Association is not evidence of top-500 ranking improvement or a causal mechanism.',
                           'Descriptions are current revisions with explicit incident wording removed; residual revision and matching language remain.',
                           'Shared product names and description templates can explain proximity; CVEs within a family are not independent.',
                           'Month-stratified label permutation assumes exchangeability within months and does not remove vendor/product confounding.',
                           'Non-listing is not proof of no exploitation; late-2025 outcomes are censored.',
                           'The 2025 cohort was inspected in earlier project work; this check was specified before computing its distances.'],
            'generator': 'pipeline/map_neighbors.py'}
