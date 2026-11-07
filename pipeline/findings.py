"""Regenerate every numeric discovery and selected-list summary from local data."""
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd

from pipeline.data import ARTIFACTS, CACHE, FLAGS, cohort, kev, month_end, vulnerabilities, historical_signals, write_json
from pipeline.evaluate import BASELINES, prepared
from pipeline.features import EXPLOIT_CLAIM, KEYWORDS


def rate_interval(hits, n):
    if not n:
        return [0., 1.]
    z = 1.96
    p = hits / n
    center = (p + z*z/(2*n)) / (1 + z*z/n)
    width = z * np.sqrt(p*(1-p)/n + z*z/(4*n*n)) / (1 + z*z/n)
    return [float(max(0, center-width)), float(min(1, center+width))]


def run():
    backtest = json.loads((ARTIFACTS / 'backtest.json').read_text())
    rows, history, _ = prepared()
    pool = rows.loc[rows.published.str.startswith('2025')].copy()
    pool['label'] = pool.label.astype(int)
    base = float(pool.label.mean())
    signals = []
    def signal(name, mask, risk, note=''):
        part = pool.loc[mask]
        n, hits = len(part), int(part.label.sum())
        signals.append({'name': name, 'n': n, 'hits': hits, 'rate': hits/n if n else 0.,
                        'lift': (hits/n)/base if n else 0., 'leak_risk': risk,
                        'rate_95_wilson_interval': rate_interval(hits, n), 'note': note})
    for flag in ['any_exploit', 'exploitdb', 'metasploit', 'nuclei', 'poc_github']:
        signal(f'{flag} present at snapshot', pool[flag].eq(1), 'low')
    signal('Vendor has earlier KEV entries (assigner identity)', history.loc[pool.index].vendor_prior_kev.gt(0), 'low',
           'Only known vendor domains are matched; third-party assigning organizations are not treated as vendors.')
    signal('CVE reserved before publication year', pool.cve_id.str[4:8].lt('2025'), 'low')
    text = pool.description.fillna('')
    signal('Current description mentions exploitation', text.str.contains(EXPLOIT_CLAIM), 'high', 'Excluded from production; text has no historical timestamp.')
    labels = {'remote_code': 'Remote code or command execution wording', 'unauthenticated': 'Unauthenticated access wording',
              'traversal': 'Path traversal wording', 'deserialization': 'Deserialization wording',
              'edge_device': 'Edge device wording', 'privilege_escalation': 'Privilege escalation wording',
              'wordpress': 'WordPress wording', 'xss': 'Cross-site scripting wording'}
    for feature, label in labels.items():
        signal(label, text.str.contains(KEYWORDS[feature], case=False, regex=True), 'medium',
               'Descriptive analysis only; current text may differ from publication text.')
    all_2025 = vulnerabilities().loc[lambda f: f.published.str.startswith('2025')]
    linked = all_2025.merge(kev()[['cve_id', 'date_added']], on='cve_id', how='inner')
    end = month_end(linked.published.str[:7])
    added = pd.to_datetime(linked.date_added)
    early_mask = added.le(end)
    later = linked.loc[~early_mask].copy()
    lag_snapshot = (pd.to_datetime(later.date_added) - month_end(later.published.str[:7])).dt.days
    lag_publish = (pd.to_datetime(later.date_added) - pd.to_datetime(later.published)).dt.days
    buckets = [(1, 30, '0-30 days'), (31, 60, '31-60 days'), (61, 90, '61-90 days'),
               (91, 180, '91-180 days'), (181, 365, '181-365 days'), (366, 10000, '366+ days')]
    histogram = [{'bucket': label, 'n': int(lag_snapshot.between(lo, hi).sum())} for lo, hi, label in buckets]
    def summary(values):
        return {'min': int(values.min()), 'median': float(values.median()), 'max': int(values.max())}
    chosen = next(m for m in backtest['methods'] if m['name'] == backtest['selected_model'])
    baselines = {key: next(m['hits_at_500'] for m in backtest['methods'] if m['name'] == name)
                 for key, name in zip(['cvss_first', 'epss_first', 'exploit_then_epss'], BASELINES)}
    wordpress = next(s for s in signals if s['name'] == 'WordPress wording')
    original_pool = all_2025.merge(kev()[['cve_id', 'date_added']], on='cve_id', how='left')
    original_pool['snapshot_month'] = original_pool.published.str[:7]
    original_pool = original_pool.loc[~pd.to_datetime(original_pool.date_added).le(month_end(original_pool.snapshot_month))].copy()
    original_pool = original_pool.merge(historical_signals().rename(columns={'month': 'snapshot_month'}),
                                         on=['cve_id', 'snapshot_month'], how='left')
    original_pool['rule_score'] = original_pool[FLAGS].fillna(0).max(axis=1) + original_pool.epss.fillna(0)
    original_top = original_pool.sort_values(['rule_score', 'cve_id'], ascending=[False, True]).head(500)
    mismatches = original_pool.loc[original_pool.in_kev.eq(1), ['cve_id', 'snapshot_month']].to_dict('records')
    findings = {
        'headline': {'ours_hits_top500_2025_backtest': chosen['hits_at_500'], 'baselines_2025_backtest': baselines,
                     'benchmark_2026_reference': {'cvss_first': 7, 'epss_first': 6, 'exploit_then_epss': 8},
                     'pool_2025': len(pool), 'positives_2025': int(pool.label.sum()),
                     'ours_hits_equal_workload': chosen['hits_at_scaled_budget'], 'equal_workload_budget': chosen['scaled_budget'],
                     'comparison_note': '2025 is a development backtest. The 2026 reference is organizer-supplied; our 2026 hit count is unknown.'},
        'two_clocks': {'kev_2025_total': len(linked), 'first_month': int(early_mask.sum()), 'later': len(later),
                       'later_lag_days': summary(lag_snapshot), 'lag_hist': histogram,
                       'lag_origin': 'End of publication month to KEV addition',
                       'publication_to_kev_lag_days': summary(lag_publish),
                       'first_month_share': float(early_mask.mean()),
                       'added_before_publication': int(added.lt(pd.to_datetime(linked.published)).sum()),
                       'note': 'These are catalog clocks, not first-attack timestamps. First-month entries are excluded from the ranking benchmark.'},
        'signals': signals,
        'deprioritize': [{'name': 'WordPress descriptions in this KEV-ranking task', 'n': wordpress['n'],
                          'hits': wordpress['hits'], 'share_of_pool': wordpress['n']/len(pool),
                          'rate_95_wilson_interval': wordpress['rate_95_wilson_interval'],
                          'note': 'Zero observed later additions is not zero exploitation risk. Do not defer exposed business-critical assets on this finding alone.'}],
        'base_rate_2025': base,
        'censoring': backtest['censoring'],
        'data_quality': {'seed_pool': len(original_pool), 'current_pool': len(pool),
                         'snapshot_catalog_disagreements': mismatches,
                         'exploit_rule_hits_with_catalog_only_eligibility': int(original_top.date_added.notna().sum()),
                         'exploit_rule_hits_with_conservative_eligibility': baselines['exploit_then_epss'],
                         'difference': 'Exclude snapshot in_kev=1 even when the frozen catalog disagrees. This removes a high-ranked unlabelled row and changes the exploit-first top-500 cutoff.'},
    }
    path = ARTIFACTS / 'scores_2026_top5000.csv'
    if path.exists():
        selected = pd.read_csv(path, keep_default_na=False).head(500)
        if 'vendor_identity' in selected:
            findings['top500_profile_2026'] = {
                'vendors_from_assigner': selected.vendor_identity.replace('', 'unmapped').value_counts().head(20).to_dict(),
                'assigners': selected.assigner.value_counts().head(15).to_dict(),
                'cwe_current_display_only': selected.cwe_ids.replace('', 'unassigned').value_counts().head(15).to_dict(),
                'flags': {f: int(selected[f].sum()) for f in ['any_exploit', 'exploitdb', 'metasploit', 'nuclei', 'poc_github']},
                'snapshot_months': selected.snapshot_month.value_counts().sort_index().to_dict(),
                'epss_median': float(selected.epss.replace('', np.nan).astype(float).median()),
                'note': 'CWE and CVSS in the display CSV are current descriptive metadata and do not enter the strict model.'}
    write_json(ARTIFACTS / 'findings.json', findings)
    print('Findings:', len(linked), 'first month:', int(early_mask.sum()), 'later:', len(later),
          'median snapshot lag:', lag_snapshot.median(), flush=True)
    return findings


if __name__ == '__main__':
    run()
