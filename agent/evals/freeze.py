"""Freeze deterministic historical cases before running inference. No network sources."""
import csv
import hashlib
import json
from pathlib import Path

from agent.data import DataTools

BASE = Path(__file__).resolve().parent


def main():
    path = BASE / 'heldout_2025.json'
    if path.exists():
        raise SystemExit('Holdout already frozen; do not replace it after inspecting results.')
    data = DataTools()
    rows = data.rows("""
        SELECT v.cve_id,v.published,v.description,v.assigner,v.cvss3_score,v.attack_vector,v.cwe_ids,
               s.epss,s.exploitdb,s.metasploit,s.nuclei,s.poc_github,k.date_added
        FROM vulnerabilities v JOIN exploit_signals_2025 s USING(cve_id)
        LEFT JOIN known_exploited k USING(cve_id)
        WHERE v.published BETWEEN '2025-01-01' AND '2025-09-30'
          AND s.month='2025-09' AND s.in_kev='0'
          AND (k.date_added IS NULL OR k.date_added>'2025-09-30')
    """)
    stable = lambda r: hashlib.sha256(('triage-holdout-v1:' + r['cve_id']).encode()).hexdigest()
    positives = sorted([r for r in rows if r['date_added'] and r['date_added'] <= '2025-12-31'], key=stable)
    negatives = sorted([r for r in rows if not r['date_added']], key=stable)
    if len(positives) < 15 or len(negatives) < 15:
        raise SystemExit('Insufficient cases for a balanced 30-case holdout')
    chosen = sorted(positives[:15] + negatives[:15], key=stable)
    cases = [{'cve_id': r['cve_id'], 'snapshot_month': '2025-09', 'published': r['published'],
              'added_to_kev_by_2025_12_31': bool(r['date_added']), 'date_added': r['date_added']} for r in chosen]
    manifest = {'frozen_at': __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
                'snapshot_end': '2025-09-30', 'outcome_end': '2025-12-31',
                'selection': '15 positives and 15 right-censored controls, ordered by SHA256(triage-holdout-v1:CVE ID); published in 2025, observed outside KEV at snapshot.',
                'population': len(rows), 'population_positives': len(positives),
                'held_out_from': 'Prompt development and example briefings. No fine-tuning. Not a model-training exclusion guarantee.',
                'negative_label': 'Not recorded in the provided KEV by 2025-12-31; does not imply never exploited.',
                'cases': cases}
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    fields = ['rank','cve_id','published','snapshot_month','score','epss','any_exploit','exploitdb','metasploit','nuclei','poc_github','cvss3_score','attack_vector','cwe_ids','assigner','description','reasons','ranking_kind']
    with (BASE / 'heldout_scores_2025.csv').open('w') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for i, r in enumerate(chosen, 1):
            epss = float(r['epss']) if r['epss'] else None
            any_exploit = int(any(r[k] == '1' for k in ['exploitdb','metasploit','nuclei','poc_github']))
            reasons = [{'feature': 'epss', 'label': 'Snapshot EPSS', 'value': epss, 'contribution': 0.0},
                       {'feature': 'any_exploit', 'label': 'Any public exploit or scanner flag', 'value': any_exploit, 'contribution': 0.0}]
            score_row = {k: r.get(k) for k in fields}
            score_row.update(ranking_kind='evaluation_reasons_only', rank=i, snapshot_month='2025-09', score=epss or 0, any_exploit=any_exploit, reasons=json.dumps(reasons))
            writer.writerow(score_row)
    print(json.dumps({'cases': len(cases), 'positive': 15, 'negative': 15, 'manifest_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
