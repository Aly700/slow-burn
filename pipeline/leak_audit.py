"""Measure historical score inflation from fields with unproven timestamps."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd

from pipeline.data import ARTIFACTS, CACHE, DATA, kev, write_json
from pipeline.evaluate import prepared, ranking_metrics, splits
from pipeline.features import EXPLOIT_CLAIM, normalized, strict_allowlist
from pipeline.models import FittedModel, Recipe


def suspect_blocks(rows, history, full):
    blocks = {}
    def numeric(name):
        return pd.to_numeric(rows[name], errors='coerce')
    blocks['nvd_status'] = pd.get_dummies(rows.nvd_status, prefix='status', dtype=float)
    blocks['n_affected_cpes'] = pd.DataFrame({'cpes_log': np.log1p(numeric('n_affected_cpes').fillna(0))})
    blocks['n_references'] = pd.DataFrame({'references_log': np.log1p(numeric('n_references').fillna(0))})
    blocks['blank_severity_scores'] = pd.DataFrame({'cvss_missing': numeric('cvss3_score').isna().astype(float)})
    blocks['current_cvss_and_vectors'] = pd.concat([
        pd.DataFrame({'current_cvss': numeric('cvss3_score').fillna(5)}),
        pd.get_dummies(rows[['attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction']].fillna(''), dtype=float)], axis=1)
    blocks['vendor_supplied_cvss'] = full[[c for c in full if c.startswith('vendor_cvss')]]
    blocks['current_cwe'] = full[[c for c in full if c.startswith('cwe_')]]
    blocks['raw_exploitation_wording'] = pd.DataFrame({'exploitation_claim': rows.description.fillna('').str.contains(EXPLOIT_CLAIM).astype(float)})
    blocks['ransomware_annotations'] = pd.DataFrame({'ransomware_prior': np.log1p(history.vendor_prior_ransomware_audit)})
    blocks['last_modified'] = pd.DataFrame({'modified_ordinal': pd.to_datetime(rows.last_modified).map(pd.Timestamp.toordinal)})
    blocks['first_observed_epss'] = pd.DataFrame({'first_epss_log': np.log10(rows.epss_first.fillna(0).clip(lower=1e-6))})
    path = CACHE / 'suspect_external_metadata.parquet'
    if path.exists():
        extra = pd.read_parquet(path)
        assert len(extra) == len(rows)
    else:
        ids = set(rows.cve_id)
        cpe_parts = []
        for chunk in pd.read_csv(DATA / 'affected_products.csv', usecols=['cve_id', 'vendor', 'product', 'vulnerable'],
                                 dtype=str, chunksize=300_000, keep_default_na=False):
            cpe_parts.append(chunk.loc[chunk.cve_id.isin(ids) & chunk.vulnerable.eq('Y'), ['cve_id', 'vendor', 'product']])
        cpes = pd.concat(cpe_parts).drop_duplicates()
        cpes['vendor_key'] = cpes.vendor.map(normalized)
        cpe_by_id = cpes.groupby('cve_id').vendor_key.agg(set)
        extra = pd.DataFrame(index=rows.index)
        extra['cpe_coverage'] = rows.cve_id.isin(cpe_by_id.index).astype(float)
        extra['cpe_vendor_prior'] = 0.
        k = kev()
        k['vendor_key'] = k.vendor.map(normalized)
        for month, ix in rows.groupby('snapshot_month').groups.items():
            end = (pd.Timestamp(month + '-01') + pd.offsets.MonthEnd()).strftime('%Y-%m-%d')
            counts = k.loc[k.date_added.le(end)].vendor_key.value_counts().to_dict()
            extra.loc[ix, 'cpe_vendor_prior'] = rows.loc[ix, 'cve_id'].map(
                lambda c: max((counts.get(v, 0) for v in cpe_by_id.get(c, set())), default=0)).to_numpy()
        news_counts = {}
        pattern = (r'bleepingcomputer|thehackernews|securityweek|therecord\.media|darkreading|'
                   r'mandiant|unit42|securelist|talosintelligence|crowdstrike|sentinelone|'
                   r'rapid7\.com/blog|microsoft\.com/security/blog|threatpost|trendmicro\.com.*research')
        for chunk in pd.read_csv(DATA / 'references.csv', usecols=['cve_id', 'url'], dtype=str,
                                 chunksize=300_000, keep_default_na=False):
            part = chunk.loc[chunk.cve_id.isin(ids) & chunk.url.str.contains(pattern, case=False, regex=True)]
            for cve, count in part.cve_id.value_counts().items():
                news_counts[cve] = news_counts.get(cve, 0) + int(count)
        extra['news_references'] = rows.cve_id.map(news_counts).fillna(0).astype(float)
        extra.to_parquet(path, index=False)
    blocks['affected_products_coverage'] = extra[['cpe_coverage']]
    blocks['affected_products_identity'] = np.log1p(extra[['cpe_vendor_prior']])
    blocks['news_threat_references'] = np.log1p(extra[['news_references']])
    return blocks


WHY = {
    'nvd_status': 'Current analysis status reflects prioritization after exploitation; explicitly prohibited.',
    'n_affected_cpes': 'Current enrichment count reflects post-snapshot analysis; explicitly prohibited.',
    'n_references': 'Current reference count can increase after incidents; explicitly prohibited.',
    'blank_severity_scores': 'Missingness reveals current analysis coverage; explicitly prohibited.',
    'current_cvss_and_vectors': 'NIST/CISA scores and vector components lack historical timestamps.',
    'vendor_supplied_cvss': 'Vendor provenance is safer than NIST provenance but does not establish when this value was supplied; masking also reveals coverage.',
    'current_cwe': 'Weakness assignments can be added during current NIST enrichment; no source/timestamp.',
    'raw_exploitation_wording': 'Current descriptions can explicitly disclose later exploitation.',
    'ransomware_annotations': 'The frozen catalog dates inclusion, but does not date ransomware-flag updates.',
    'last_modified': 'Current record modification time postdates the decision and is not a publication attribute.',
    'first_observed_epss': 'Historical monthly first observation is date-safe, but equivalent 2026 history is unavailable; no future backfill is allowed.',
    'affected_products_coverage': 'Whether a CPE exists reveals current analysis coverage.',
    'affected_products_identity': 'A correct product identity does not make its current CPE availability historical.',
    'news_threat_references': 'Current news/research references may have been added after the incident; explicitly prohibited.',
}


def run():
    rows, history, blocks = prepared()
    train, test = splits(rows)[0][1:3]
    x = blocks['strict']
    strict_allowlist(x.columns)
    suspects = suspect_blocks(rows, history, blocks['full'])
    results = []
    baseline = {}
    for algorithm in ['logistic', 'lightgbm']:
        fit = FittedModel(Recipe('audit_base', algorithm)).fit(x.loc[train.index], train.label)
        score = fit.predict(x.loc[test.index])
        baseline[algorithm] = ranking_metrics(test, score, algorithm)
    for name, extra in suspects.items():
        assert len(extra) == len(x)
        combined = pd.concat([x, extra], axis=1).astype('float32')
        methods = []
        for algorithm in ['logistic', 'lightgbm']:
            fit = FittedModel(Recipe('audit', algorithm)).fit(combined.loc[train.index], train.label)
            metrics = ranking_metrics(test, fit.predict(combined.loc[test.index]), algorithm)
            metrics['delta_hits_at_500'] = metrics['hits_at_500'] - baseline[algorithm]['hits_at_500']
            metrics['delta_hits_at_scaled_budget'] = metrics['hits_at_scaled_budget'] - baseline[algorithm]['hits_at_scaled_budget']
            methods.append(metrics)
        active = extra.loc[test.index].ne(0).any(axis=1)
        n = int(active.sum())
        hit = int(test.loc[active].label.sum())
        results.append({'name': name, 'why': WHY[name], 'decision': 'excluded', 'methods': methods,
                        'nonzero_coverage_2025': {'n': n, 'positives': hit,
                                                 'rate': hit / n if n else 0.}})
        print(name, [(m['name'], m['hits_at_500'], m['delta_hits_at_500']) for m in methods], flush=True)
    result = {'split': '2024 mature training; labels by 2024-12-31; 2025 test labels by 2025-12-31',
              'pool': len(test), 'positives': int(test.label.sum()), 'baseline': baseline,
              'features_excluded': results,
              'interpretation': 'Signed deltas measure observed inflation or degradation, not causality. No positive gain does not establish temporal safety.',
              'checks': {'strict_allowlist': True, 'no_post_2025_labels': True,
                         'all_metadata_local': True, 'production_suspect_columns': []}}
    write_json(CACHE / 'leak_audit.json', result)
    return result


if __name__ == '__main__':
    run()
