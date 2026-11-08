"""Render the product-watch and Granite-map handoff from generated evidence."""
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.data import ROOT, ARTIFACTS


def run():
    findings = json.loads((ARTIFACTS / 'findings.json').read_text())
    product = findings['blind_spot']['product_watch']
    space = findings['map']
    comparison = space['neighbour_check']
    old, target = product['historical_2025'], product['target_2026']
    lines = ['# Round-four model report', '',
             'The submitted top500 and selected model are unchanged. This round adds a complete product review queue and a descriptive map of Granite text similarity.', '',
             '## Product watch', '',
             f"Artifact: `{product['artifact_path']}` ({target['rows']:,} rows; {target['pool_share']:.1%} of the {target['no_signal_pool']:,}-row no-signal scoreboard pool).", '',
             f"On 2025, a list of **{old['rows']:,} rows held {old['positives']} of {old['no_signal_positives']}** no-signal positives ({old['recall']:.1%} recall). Its later-listing rate was {old['rate']:.3%}, versus {old['base_rate']:.3%} in the full no-signal pool: {old['lift']:.2f} times the base rate. This is descriptive coverage at the complete review size, not a top-500 result.", '',
             product['definition'], '', product['sort'], '',
             '| Match support | 2025 rows | 2026 rows |', '|---|---:|---:|']
    for name, definition in product['confidence']['definitions'].items():
        lines.append(f"| {name} | {old['confidence_counts'].get(name, 0):,} | {target['confidence_counts'].get(name, 0):,} |")
    lines.extend(['', product['confidence']['kind'], ''])
    for name, definition in product['confidence']['definitions'].items():
        lines.extend([f'- `{name}`: {definition}'])
    lines.extend(['', 'Each row carries the newest qualifying KEV CVE and date for the same product alias counted in the profile. Reviewers can confirm the affected product and version against their own inventory. The counts do not establish asset exposure, identity correctness, or urgency.', '',
                  *['- '+note for note in product['limitations']], '', '## What the map shows', '',
                  f"Artifact: `{space['artifact_path']}`; **{space['rows']:,} points**, **{space['bytes']:,} bytes**, {space['named_rows']:,} sparse CVE IDs.", '',
                  '| Overlay | Points |', '|---|---:|'])
    for name, count in space['counts'].items():
        lines.append(f'| {name} | {count:,} |')
    lines.extend(['', f"Historical anchors by publication year: {space['anchor_publication_years']}. First-month additions are included. Embedding reuse: {space['embedding_reuse']}.", '',
                  f"Granite: `{space['embedding']['model']}`, revision `{space['embedding']['revision']}`. Each point uses a {space['embedding']['dimensions']}-dimensional normalized embedding of sanitized description text, capped at {space['embedding']['max_tokens']} tokens. The complete map retains {space['embedding']['empty_sanitized_descriptions']} empty sanitized descriptions; their positions have no technical meaning.", '',
                  'UMAP uses cosine distance, 30 neighbours, minimum distance 0.1, spread 1, spectral initialization, 500 epochs, seed 2026 and one worker. It fits the complete cohort for a navigable view of local language similarity. HDBSCAN finds visual regions with minimum cluster size 150 and minimum samples 15; unassigned points stay visible. Labels are contrasting mean TF-IDF terms, not manually selected security categories. UMAP was chosen over openTSNE for its direct cosine graph and tractable full-cohort fit; a different layout could place the same descriptions differently.', '',
                  f"There are {space['clusters']} regions and {space['unassigned_rows']:,} unassigned points ({space['unassigned_rows']/space['rows']:.1%}). Exact versions: {space['layout']['versions']}.", '',
                  f"UMAP fits {space['layout']['unique_vector_rows']:,} distinct vectors and expands back to all rows ({space['layout']['duplicate_vector_rows']:,} repeated vectors). This avoids the pinned version's duplicate-row reproducibility issue; coincident points and all counts are retained. The amendment is recorded in the plan and does not affect the neighbour check.", '',
                  '| Largest region | Total | 2026 | Top500 | Past KEV | Product watch |', '|---|---:|---:|---:|---:|---:|'])
    for region in sorted(space['cluster_summaries'], key=lambda r: -r['rows'])[:15]:
        c = region['counts']
        lines.append(f"| {region['label']} | {region['rows']:,} | {c['is_2026']:,} | {c['in_top500']} | {c['is_past_exploited']} | {c['in_product_watch']:,} |")
    lines.extend(['', '## Independent quantitative check', '', comparison['space'], '', comparison['anchor_definition'], '',
                  f"Reference anchors: {comparison['anchor_count']}; latest catalog date: {comparison['anchor_latest_date']}. Test labels stop at {comparison['label_cutoff']}. The full test contains {comparison['fewer_than_90_days']:,} rows with less than 90 days follow-up.", '',
                  '| Cohort | Rows | Later positives | Probability positive is closer | Permutation mean | Null 95% interval | One-sided p |', '|---|---:|---:|---:|---:|---|---:|'])
    for name in ['primary_2025', 'no_signal_sensitivity']:
        r = comparison[name]
        p = r['permutation']
        low, high = p['null_95_percentile_interval']
        lines.append(f"| {name} | {r['rows']:,} | {r['positives']} | {r['probability_positive_is_closer']:.2%} | {p['null_mean']:.2%} | {low:.2%}–{high:.2%} | {p['one_sided_p']:.6f} |")
    lines.extend(['', comparison['primary_2025']['interpretation'], '',
                  comparison['primary_2025']['permutation']['method'] + f" {comparison['primary_2025']['permutation']['iterations']:,} permutations, seed {comparison['primary_2025']['permutation']['seed']}; the null interval is not a confidence interval for the observed effect.", '',
                  '| Cohort | Positive median cosine distance | Non-listed median cosine distance |', '|---|---:|---:|'])
    for name in ['primary_2025', 'no_signal_sensitivity']:
        r = comparison[name]
        lines.append(f"| {name} | {r['positive_cosine_distance']['median']:.5f} | {r['non_listed_cosine_distance']['median']:.5f} |")
    audit = comparison['empty_text_audit']
    lines.extend(['', f"The predeclared story gate {'passed' if comparison['predeclared_gate_passed'] else 'did not pass'}. The gate and comparison were written in `pipeline/MAP_PLAN.md` before these distances were computed.", '',
                  '### Empty-text validity audit', '', audit['reason'], '',
                  f"This is an explicitly post-hoc check prompted by data inspection. It removes {audit['excluded_primary_rows']} queries including {audit['excluded_primary_positives']} positives from the full pool, {audit['excluded_no_signal_rows']} queries including {audit['excluded_no_signal_positives']} positives from the no-signal pool, and {audit['excluded_anchors']} empty anchors. It retains {audit['anchor_count']} reference anchors. The exclusion and repeated thresholds were written in the plan before computing the filtered results.", '',
                  '| Nonempty-text cohort | Rows | Later positives | Probability positive is closer | Permutation mean | Null 95% interval | One-sided p |', '|---|---:|---:|---:|---:|---|---:|'])
    for name in ['primary_2025', 'no_signal_sensitivity']:
        r = audit[name]
        p = r['permutation']
        low, high = p['null_95_percentile_interval']
        lines.append(f"| {name} | {r['rows']:,} | {r['positives']} | {r['probability_positive_is_closer']:.2%} | {p['null_mean']:.2%} | {low:.2%}–{high:.2%} | {p['one_sided_p']:.6f} |")
    lines.extend(['', f"The stricter validity guard {'passed' if audit['guard_passed'] else 'did not pass'}; {'one map story uses these nonempty-text numbers' if comparison['story_qualifies'] else 'no map story was added'}. Both original and filtered results remain in findings. This guards against an empty-text proxy but does not prove that remaining descriptions were available at their historical snapshots.", '',
                  'With 10,000 permutations, the smallest reportable p-value is 1/10,001 (about 0.0001); no stronger significance claim is supported by this run.', '',
                  'Similarity association and top-budget prediction answer different questions. This comparison does not overturn the earlier zero-hit watch model or authorize any change to the submission.', '',
                  '## What it does not show', '', *['- '+note for note in space['limitations']],
                  *['- '+note for note in comparison['limitations']], '',
                  '## Handoff and reproduction', '',
                  'Round-four verification included a full pipeline rebuild, all temporal and artifact gates, the browser decoder, and visual inspection. After the duplicate-vector correction, two fresh layout fits produced byte-identical map exports. The empty-text audit left that map file unchanged. Existing findings, submission files, replay, root README and previously locked package versions were preserved.', '',
                  '- Product queue: `uv run python -I pipeline/product_watch.py`.',
                  '- Map, comparison and local preview: `uv run python -I pipeline/space_map.py`.',
                  '- Everything, with replay last: `uv run python -I pipeline/run.py --all`.',
                  '- Temporal and artifact gates: `uv run python -I pipeline/checks.py --artifacts`.',
                  '- This report: `uv run python -I pipeline/capability_report.py`.', '',
                  'The browser decoder, byte order, flags, sparse IDs and coordinate scaling are implemented in `web/src/graniteMap.ts`. A local preview is in `artifacts/cache/map_preview.png`. No cache or preview is committed.', '',
                  f"Product CSV SHA-256: `{product['artifact_sha256']}`.", '', f"Map SHA-256: `{space['artifact_sha256']}`.", ''])
    path = ROOT / '.lane' / 'model-REPORT-4.md'
    path.parent.mkdir(exist_ok=True)
    path.write_text('\n'.join(lines))
    print(path)


if __name__ == '__main__':
    run()
