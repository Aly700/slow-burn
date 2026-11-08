"""Render the round-three handoff from the frozen experiment and generated findings."""
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.data import ROOT, ARTIFACTS


def run():
    f = json.loads((ARTIFACTS / 'findings.json').read_text())
    w = f['blind_spot']
    selection = w['selection']
    lines = ['# Round-three model report', '', f"Watch recipe: **{w['selected_recipe']}**. Submitted top500 and the main selected model remain unchanged.", '',
             f"Result: **{w['validation_status']}**.", '',
             '## Approach and rejected alternative', '',
             'Four recipes were declared in code and committed before dedicated 2025 scoring. A training-year time split selected one recipe; every subsequent 2025 result uses that choice. No competing watch recipe was scored on 2025. The existing full-pool model is used only as the frozen mixed-allocation control.', '',
             'Rejected alternative: choosing whichever existing full-pool ranking happened to perform best inside the 2025 no-signal pool; that would choose using the test outcomes.', '',
             selection['policy']['pool'], '', selection['policy']['selection'], '', selection['policy']['encoder_timing'], '',
             '## Selection and cohorts', '',
             '| Cohort | Rows | Positives | Missing snapshot rows | Missing snapshot positives |', '|---|---:|---:|---:|---:|']
    cohorts = [('2024 inner training', selection['train']), ('2024 inner validation', selection['validation'])]
    for split in w['splits']:
        cohorts.extend([(split['name'] + ' training', split['train']), (split['name'] + ' test', split['test'])])
    cohorts.append(('2026 production training', w['final_model']['training']))
    for name, c in cohorts:
        lines.append(f"| {name} | {c['rows']:,} | {c['positives']} | {c['missing_snapshot_observations']} | {c['missing_snapshot_positive_rows']} |")
    target = w['final_model']['target']
    lines.extend(['', f"2026 no-signal scoring pool: {target['rows']:,} rows; outcomes are unknown. {selection['policy']['unavailable_2023']}", '',
                  '| 2024 validation recipe | Hits / 100 | Hits / 250 | Hits / 500 | Average precision |', '|---|---:|---:|---:|---:|'])
    for m in selection['candidates']:
        hits = [r['hits'] for r in m['budgets']]
        lines.append(f"| {m['name']} | {hits[0]} | {hits[1]} | {hits[2]} | {m['average_precision']:.5f} |")
    lines.extend(['', '## Held-out watch results', ''])
    for split in w['splits']:
        lines.extend([f"### {split['name']}", '',
                      f"Train outcomes stop at {split['train_label_cutoff']}; test outcomes stop at {split['test_label_cutoff']}. The test has {split['test']['fewer_than_90_days']:,} rows with less than 90 days follow-up.", '',
                      '| Ranking | Budget | Hits | Precision | Recall | Random expectation | Lift over random |', '|---|---:|---:|---:|---:|---:|---:|'])
        for m in split['methods']:
            for b in m['budgets']:
                lift = 'undefined' if b['lift_over_random'] is None else f"{b['lift_over_random']:.2f}"
                lines.append(f"| {m['name']} | {b['budget']} | {b['hits']} | {b['precision']:.2%} | {b['recall']:.2%} | {b['random_expected_hits']:.3f} | {lift} |")
        for b in split['random_expectation']:
            lines.append(f"| Uniform random expectation | {b['budget']} | {b['expected_hits']:.3f} expected | {b['expected_precision']:.3%} expected | — | {b['expected_hits']:.3f} | 1.00 |")
        tie = next(t for t in split['baseline_ties']['cvss'] if t['budget'] == 500)
        lines.extend(['', f"CVSS uses deterministic CVE-id tie-breaking. At 500, its boundary score {tie['cutoff_score']:g} has {tie['boundary_tie_rows']:,} tied rows with {tie['boundary_tie_positives']} positives competing for {tie['slots_from_boundary']} slots; possible hits under other tie orders are {tie['hits_range_from_tie_order']}. This explains why an earlier exploratory sort can give a different count.", ''])
        lines.extend(['', '| Bootstrap budget | Delta hits 95% interval vs EPSS | Positive resamples | Negative resamples |', '|---|---|---:|---:|'])
        for b in split['bootstrap_vs_epss']['budgets']:
            u = b['literal']
            lines.append(f"| {b['budget']} | {u['delta_hits_95_percentile_interval']} | {u['fraction_positive']:.1%} | {u['fraction_negative']:.1%} |")
        lines.extend(['', split['bootstrap_vs_epss']['limitation'], '', '| Seed | Hits / 100 | Hits / 250 | Hits / 500 |', '|---|---:|---:|---:|'])
        for m in split['seed_stability']['methods']:
            hits = [r['hits'] for r in m['budgets']]
            lines.append(f"| {m['seed']} | {hits[0]} | {hits[1]} | {hits[2]} |")
        lines.extend(['', f"Seed ranges: {split['seed_stability']['ranges']}. {split['seed_stability']['note']}", ''])
    lines.extend(['## Mixed allocations — report only', '', '| Split | Allocation | Hits | No-signal hits | Feasible |', '|---|---|---:|---:|---|'])
    infeasible = []
    for split in w['mixed_allocations']:
        for a in split['allocations']:
            lines.append(f"| {split['split']} | {a['name']} | {a.get('hits', '—')} | {a.get('no_signal_hits', '—')} | {a['feasible']} |")
            if not a['feasible']:
                infeasible.append(f"{split['split']} {a['name']}: {a['reason']} Available exploit-tier rows: {a['available_exploit_rows']}.")
    lines.extend(['', *infeasible, ''])
    p = w['profile']
    lines.extend(['', '## Profile and actionable contrasts', '',
                  f"No-signal pool: {p['no_signal_pool']:,} rows, {p['no_signal_positives']} later additions ({p['base_rate']:.3%}). Signal-bearing pool: {p['with_signal_pool']:,} rows, {p['with_signal_positives']} later additions ({p['with_signal_base_rate']:.2%}).", ''])
    for c in p['actionable_contrasts']:
        lines.extend([f"**{c['name']}**: {c['no_signal_positives']} of the {p['no_signal_positives']} no-signal positives ({c['positive_share']:.1%}), against {c['no_signal_pool']:,} of {p['no_signal_pool']:,} pool rows ({c['pool_share']:.1%}); conditional event rate {c['rate']:.3%}, pool base rate {c['base_rate']:.3%}, lift {c['lift']:.2f}. Risk: {c['leak_risk']}.", '', c['action'], ''])
    for name, table in p['tables'].items():
        lines.extend([f'### {name}', '', table['risk'], '', f"| Category | No-signal positives / {p['no_signal_positives']} | With-signal positives / {p['with_signal_positives']} | No-signal pool rows | No-signal event rate |", '|---|---:|---:|---:|---:|'])
        for row in table['rows']:
            lines.append(f"| {row['value']} | {row['no_signal_positives']} | {row['with_signal_positives']} | {row['no_signal_pool']:,} | {row['no_signal_rate']:.3%} |")
        lines.append('')
    lines.extend(['### Days to KEV listing', '', '| Group | Count | Median from publication | Median from snapshot |', '|---|---:|---:|---:|'])
    for name, lag in p['days_to_kev'].items():
        lines.append(f"| {name} | {lag['n']} | {lag['publication_to_kev']['50%']:g} | {lag['snapshot_to_kev']['50%']:g} |")
    lines.extend(['', '## What worried us', '', *['- ' + note for note in w['limitations']], *['- ' + note for note in p['limitations']], '',
                  '## Handoff', '', f"Artifact: `{w['artifact_path']}`. Hash: `{w['final_model']['artifact_sha256']}`.", '',
                  f"Production uses {w['final_model']['training']['rows']:,} mature no-signal training rows and {w['final_model']['training']['positives']} positives; {w['final_model']['calibration']}", '',
                  str(w['final_model']['ibm_technology']), '',
                  f"Top-100 vendor matches: {w['final_model']['top100_vendors']}.", '',
                  'Use the separate queue to review the matched product, affected versions and local asset exposure. The held-out results do not support replacing any part of the existing patch queue with these scores. A follow-up study should add earlier publication snapshots and archived field revisions, then validate a frozen recipe on a new cohort.', '',
                  'Run `uv run python -I pipeline/watch.py` for this artifact and findings, or `uv run python -I pipeline/run.py --all` for the full dependency-ordered rebuild. Run `uv run python -I pipeline/checks.py --artifacts` for gates. This report is regenerated by `pipeline/watch_report.py`.', ''])
    path = ROOT / '.lane' / 'model-REPORT-3.md'
    path.parent.mkdir(exist_ok=True)
    path.write_text('\n'.join(lines))
    print(path)


if __name__ == '__main__':
    run()
