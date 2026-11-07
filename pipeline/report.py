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
    lines = ['# Model lane report', '', f"Selected recipe: **{card['model']}**. Final fit: {card['training_pool']:,} mature rows and {card['training_positives']} later KEV additions.", '',
             'The production feature allowlist excludes current descriptions, CPEs, severity/weakness enrichment, missingness, references and undated ransomware annotations. Historical labels are available at each training cutoff. The assigning organization is assumed stable; no field-level source history can prove this assumption.', '',
             '## Results', '', 'These are historical development results, not a measured 2026 score. The selected-model comparison is optimistic because recipe selection used these forward evaluations.', '']
    for s in b['splits']:
        lines.extend([f"### {s['name']}", '',
                      f"Training: {s['train_pool']:,} rows, {s['train_positives']} positives, labels through {s['train_label_cutoff']}. Test: {s['test_pool']:,} rows, {s['test_positives']} positives, labels through {s['test_label_cutoff']}.", '',
                      metric_table(s['methods']), ''])
    if 'exact_calendar_analog' in b:
        s = b['exact_calendar_analog']
        lines.extend(['### Exact calendar analog', '', s['snapshot_rule'] + '; outcomes through ' + s['test_label_cutoff'] + '.', '', metric_table(s['methods']), ''])
    lines.extend(['## Ablations', '', metric_table(b['ablations']), '', '## Censoring and uncertainty', '', b['censoring']['note'], ''])
    for s in b['censoring_sensitivity']:
        methods = [m for m in s['methods'] if m['name'] in [card['model'], 'CVSS first', 'EPSS first', 'Exploit code first, then EPSS']]
        lines.extend([f"### {s['name']}", '', metric_table(methods), ''])
    lines.extend([f"Paired month bootstrap, equal workload, selected model minus exploit-first: {b['uncertainty']['delta_hits_95_percentile_interval']} hits (95% percentile interval). {b['uncertainty']['limitation']}", '',
                  '## Leak audit', '', 'Each row adds one suspect block to the same strict model on the primary forward split. Values show hits@500 and signed change. No gain is not evidence of safety.', '',
                  '| Excluded block | Logistic hits (change) | LightGBM hits (change) |', '|---|---:|---:|'])
    for row in card['features_excluded']:
        if 'methods' in row:
            a, c = row['methods']
            lines.append(f"| {row['name']} | {a['hits_at_500']} ({a['delta_hits_at_500']:+}) | {c['hits_at_500']} ({c['delta_hits_at_500']:+}) |")
    clock = f['two_clocks']
    public = next(s for s in f['signals'] if s['name'] == 'any_exploit present at snapshot')
    wp = f['deprioritize'][0]
    lines.extend(['', '## Three demo findings', '',
                  f"1. Two catalog clocks: {clock['first_month']} of {clock['kev_2025_total']} 2025-published KEV entries ({clock['first_month_share']:.1%}) were already listed by publication-month end and cannot be won by this benchmark. The remaining {clock['later']} took a median {clock['later_lag_days']['median']:g} days after snapshot. This is listing delay, not first-attack delay.",
                  f"2. Public-tool signals: {public['hits']} later additions among {public['n']:,} flagged rows ({public['rate']:.2%}), a {public['lift']:.1f}× lift over the {f['base_rate_2025']:.3%} pool rate. Flags alone are incomplete; absence is not safety.",
                  f"3. Catalog scope matters: WordPress wording appears in {wp['n']:,} rows ({wp['share_of_pool']:.1%} of the pool), with {wp['hits']} observed later KEV additions. That is a task-specific queue distinction, not a claim that these vulnerabilities are harmless.", '',
                  '## What the 2026 top 500 looks like', ''])
    profile = f.get('top500_profile_2026', {})
    for title, key in [('Vendors inferred from assigner', 'vendors_from_assigner'), ('Current CWE display metadata', 'cwe_current_display_only'),
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
    path = ROOT / '.lane' / 'model-REPORT.md'
    path.parent.mkdir(exist_ok=True)
    path.write_text('\n'.join(lines))
    print(path)


if __name__ == '__main__':
    run()
