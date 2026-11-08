"""Render the local handoff report entirely from regenerated artifacts."""
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.data import ROOT, ARTIFACTS


def metric_table(methods):
    lines = ['| Method | Hits / 500 | Precision | Recall | Equal-workload budget | Hits at that budget |',
             '|---|---:|---:|---:|---:|---:|']
    for m in methods:
        lines.append(f"| {m['name']} | {m['hits_at_500']} | {m['precision_at_500']:.2%} | {m['recall_at_500']:.2%} | {m['scaled_budget']} | {m['hits_at_scaled_budget']} |")
    return '\n'.join(lines)


def run():
    b = json.loads((ARTIFACTS / 'backtest.json').read_text())
    f = json.loads((ARTIFACTS / 'findings.json').read_text())
    card = json.loads((ARTIFACTS / 'model_card.json').read_text())
    lines = ['# Model report', '', f"Selected recipe: **{card['model']}**. Final fit: {card['training_pool']:,} mature rows and {card['training_positives']} later KEV additions.", '',
             'The production feature allowlist excludes CPEs, severity/weakness enrichment, missingness, references and undated ransomware annotations. Sanitized text is eligible with disclosed residual revision risk, and no-text models remain audit references. Historical labels are available at each training cutoff. The assigning organization is assumed stable; no field-level source history can prove this assumption.', '',
             f"Ranking policy: {b['ranking_policy']}. Selection: {b['selection']['rule']}. Simplicity order: {b['selection']['simplicity_order']}.", '',
             '## Results', '', 'These are historical development results, not a measured 2026 score. The selected-model comparison is optimistic because recipe selection used these forward evaluations.', '']
    if card['recipe']['no_history']:
        lines.extend(['The selected recipe excludes all numeric vendor, product and assigner history. It uses snapshot signals, publication timing and sanitized description features. Vendor history remains a contextual finding and a reported alternative, rather than a term in this ranking.', ''])
    for s in b['splits']:
        lines.extend([f"### {s['name']}", '',
                      f"Training: {s['train_pool']:,} rows, {s['train_positives']} positives, labels through {s['train_label_cutoff']}. Test: {s['test_pool']:,} rows, {s['test_positives']} positives, labels through {s['test_label_cutoff']}.", '',
                      metric_table(s['methods']), ''])
    if 'exact_calendar_analog' in b:
        s = b['exact_calendar_analog']
        lines.extend(['### Exact calendar analog', '', s['snapshot_rule'] + '; outcomes through ' + s['test_label_cutoff'] + '.', '', metric_table(s['methods']), ''])
        a = next(m for m in s['methods'] if m['name'] == card['model'])
        r = next(m for m in s['methods'] if m['name'] == 'Exploit code first, then EPSS')
        lines.extend([f"Selected recipe versus rule: {a['hits_at_500']} versus {r['hits_at_500']} at literal 500, and {a['hits_at_scaled_budget']} versus {r['hits_at_scaled_budget']} at the scaled budget of {a['scaled_budget']}. This additional sensitivity is outside the two required selection splits; it must be disclosed alongside their results.", ''])
    lines.extend(['## Ablations', '', metric_table(b['ablations']), ''])
    for s in b.get('matched_tiered_ablations', []):
        lines.extend([f"### Matched tiered ablations: {s['split']}", '',
                      'Same logistic regularization and public-tool-first policy; only the named feature family changes.', '',
                      metric_table(s['methods']), ''])
    stability = b.get('seed_stability')
    if stability:
        lines.extend(['## Seed stability', '', stability['policy'], '', stability['randomness'], '',
                      f"Production seeds: {stability['production_seeds']}; probability averaging required: {stability['average_required']}.", '',
                      '| Split | Seed | Hits / 500 | Scaled budget | Hits at scaled budget |', '|---|---:|---:|---:|---:|'])
        for s in stability['splits']:
            for m in s['seeds']:
                lines.append(f"| {s['split']} | {m['seed']} | {m['hits_at_500']} | {m['scaled_budget']} | {m['hits_at_scaled_budget']} |")
        for s in stability['splits']:
            lines.extend(['', f"{s['split']}: ranges {s['hit_ranges']}; any seed below rule: {s['any_seed_below_rule']}.", ''])
    lines.extend(['## Per-month results', '', 'Monthly budgets partition 500 across months by pool size; each month is ranked separately, so their hits need not sum to the global top-500 count. Equal-workload budgets use the benchmark selection fraction.', ''])
    for entry in b.get('monthly_by_split', []):
        lines.extend([f"### {entry['split']}", '', '| Month | Pool | Positives | Budget | Ours | Rule | Scaled budget | Ours scaled | Rule scaled |',
                      '|---|---:|---:|---:|---:|---:|---:|---:|---:|'])
        for m in entry['months']:
            lines.append(f"| {m['month']} | {m['pool']} | {m['positives']} | {m['budget']} | {m['ours_hits']} | {m['baseline_hits']} | {m['scaled_budget']} | {m['ours_hits_scaled']} | {m['baseline_hits_scaled']} |")
        lines.append('')
    lines.extend(['## Censoring and uncertainty', '', b['censoring']['note'], ''])
    for s in b['censoring_sensitivity']:
        methods = [m for m in s['methods'] if m['name'] in [card['model'], 'CVSS first', 'EPSS first', 'Exploit code first, then EPSS']]
        lines.extend([f"### {s['name']}", '', metric_table(methods), ''])
    for entry in b.get('split_uncertainty', []):
        u = entry['bootstrap']
        lines.extend([f"{entry['split']}: paired month bootstrap delta at literal 500 {u['literal_500']['delta_hits_95_percentile_interval']}; equal workload {u['delta_hits_95_percentile_interval']} (95% percentile intervals). Positive deltas occur in {u['literal_500']['fraction_delta_positive']:.1%} of literal-500 resamples and {u['fraction_delta_positive']:.1%} of equal-workload resamples; negative deltas occur in {u['literal_500']['fraction_delta_negative']:.1%} and {u['fraction_delta_negative']:.1%}, respectively.", ''])
    lines.extend([f"Paired month bootstrap, equal workload, selected model minus exploit-first: {b['uncertainty']['delta_hits_95_percentile_interval']} hits (95% percentile interval). {b['uncertainty']['limitation']}", '',
                  '## Leak audit', '', 'Each row adds one suspect block to the same strict model on the primary forward split. Values show hits@500 and signed change. No gain is not evidence of safety.', '',
                  '| Excluded block | Logistic hits (change) | LightGBM hits (change) |', '|---|---:|---:|'])
    for row in card['features_excluded']:
        if 'methods' in row:
            a, c = row['methods']
            lines.append(f"| {row['name']} | {a['hits_at_500']} ({a['delta_hits_at_500']:+}) | {c['hits_at_500']} ({c['delta_hits_at_500']:+}) |")
    lines.extend(['', '## Three demo findings', '', 'Regenerated by `pipeline/findings.py`; exact numbers and upstream scripts are recorded in `findings.json`.', ''])
    for i, story in enumerate(f['story'], 1):
        lines.append(f"{i}. **{story['title']}:** {story['sentence']}")
    lines.extend(['', '## What the 2026 top 500 looks like', ''])
    profile = f.get('top500_profile_2026', {})
    for title, key in [('Resolved vendors', 'vendors'), ('Vendors inferred from assigner only', 'vendors_from_assigner'), ('Current CWE display metadata', 'cwe_current_display_only'),
                       ('Snapshot tool flags', 'flags'), ('Snapshot months', 'snapshot_months')]:
        lines.extend([f'### {title}', '', '| Value | Count |', '|---|---:|'])
        for name, count in profile.get(key, {}).items():
            lines.append(f'| {name} | {count} |')
        lines.append('')
    lines.extend(['## IBM technology', '', *card['ibm_technology'], '',
                  f"Role in the selected model: {card['ibm_in_selected_model']}.", '',
                  '## Reproduction and handoff', '',
                  '`uv run python -I pipeline/run.py --all` regenerates all five contract artifacts; `uv run python -I pipeline/checks.py --artifacts` validates temporal invariants, row counts, score ranges, reasons and column order. `uv run python -I pipeline/report.py` writes this report. See `pipeline/README.md` and `research/model-research.md` for provenance and method decisions.', '',
                  '## Next work', '',
                  'Obtain authenticated publication-time descriptions and CNA score versions, then re-evaluate semantic features. Acquire additional historical years with matching signals and labels to reserve a truly untouched temporal test. Model delayed catalog inclusion with explicit survival/censoring methods, validate calibration at fixed horizons, and incorporate asset exposure before operational patch decisions. Do not obtain 2026 outcomes before submission.', ''])
    path = ROOT / 'artifacts' / 'cache' / 'model-report.md'
    path.parent.mkdir(exist_ok=True)
    path.write_text('\n'.join(lines))
    print(path)


if __name__ == '__main__':
    run()
