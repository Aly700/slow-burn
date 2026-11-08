"""Product-based review queue with dated, reconciled catalog evidence."""
from pathlib import Path
import hashlib
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd

from pipeline.data import ARTIFACTS, CACHE, END, kev, assign_outcomes, write_json
from pipeline.evaluate import prepared
from pipeline.features import clean_description, normalized, product_aliases
from pipeline.capability_text import display_description
from pipeline.watch import frozen_artifacts, no_signal

PATH = ARTIFACTS / 'product_watch_2026.csv'
COLUMNS = ['cve_id', 'published', 'snapshot_month', 'vendor', 'product', 'match_confidence',
           'prior_kev_count', 'latest_prior_kev_cve', 'latest_prior_kev_date', 'epss', 'cvss3_score', 'description']
CONFIDENCE = {'vendor_psirt': 'psirt_supported', 'description_vendor': 'vendor_text_supported',
              'description_product': 'product_alias_only'}
CONFIDENCE_DEFINITIONS = {
    'psirt_supported': 'Vendor PSIRT domain supports the vendor and a unique compatible product alias matches sanitized text.',
    'vendor_text_supported': 'Vendor wording and a compatible unique product alias match sanitized text; these may overlap and are not independent evidence.',
    'product_alias_only': 'A unique product alias supplies both product and vendor identity without vendor-domain or separate vendor-name support.',
}


def product_evidence(rows, identities, catalog):
    records = []
    for month, indices in rows.groupby('snapshot_month', sort=True).groups.items():
        cutoff = min(END, (pd.Timestamp(month + '-01') + pd.offsets.MonthEnd()).strftime('%Y-%m-%d'))
        past = catalog.loc[catalog.date_added.le(cutoff)]
        aliases = {}
        for item in past.itertuples():
            for alias in product_aliases(item.product, item.vendor):
                key = (normalized(item.vendor), alias)
                aliases.setdefault(key, {})[item.cve_id] = item.date_added
        for idx in indices:
            identity = identities.loc[idx]
            key = (normalized(identity.text_vendor_identity), identity.text_product_identity)
            matches = aliases.get(key, {})
            count = len(matches)
            assert count == int(identity.text_product_prior_kev), 'Dated evidence must match the profile count'
            assert count > 0
            latest = sorted(matches.items(), key=lambda pair: (-pd.Timestamp(pair[1]).value, pair[0]))[0]
            assert latest[1] <= cutoff
            records.append({'index': idx, 'vendor': identity.text_vendor_identity,
                            'product': identity.text_product_identity,
                            'match_confidence': CONFIDENCE[identity.entity_source],
                            'prior_kev_count': count, 'latest_prior_kev_cve': latest[0],
                            'latest_prior_kev_date': latest[1]})
    return pd.DataFrame(records).set_index('index').reindex(rows.index)


def queue(rows, identities, catalog):
    eligible = no_signal(rows)
    eligible = eligible.loc[identities.loc[eligible.index, 'text_product_prior_kev'].gt(0)].copy()
    evidence = product_evidence(eligible, identities, catalog)
    out = pd.concat([eligible, evidence], axis=1)
    out['description'] = out.description.fillna('').map(clean_description).map(lambda value: display_description(value)[0])
    return out.sort_values(['prior_kev_count', 'epss', 'cve_id'], ascending=[False, False, True],
                           na_position='last', kind='stable')


def summarize(selected, pool, labels):
    out = {'rows': len(selected), 'no_signal_pool': len(pool), 'pool_share': len(selected)/len(pool),
           'vendors': int(selected.vendor.nunique()),
           'products': int(selected[['vendor', 'product']].drop_duplicates().shape[0]),
           'confidence_counts': selected.match_confidence.value_counts().to_dict(),
           'missing_snapshot_observations': int(selected.signal_observed.eq(0).sum())}
    if labels:
        positives = int(selected.label.sum())
        total = int(pool.label.sum())
        out.update(positives=positives, no_signal_positives=total, recall=positives/total,
                   rate=positives/len(selected), base_rate=total/len(pool),
                   lift=(positives/len(selected))/(total/len(pool)),
                   positive_ids=selected.loc[selected.label.eq(1), 'cve_id'].sort_values().tolist())
    return out


def run():
    frozen_artifacts()
    rows, identities, _ = prepared()
    catalog = kev()
    historical = assign_outcomes(rows.loc[rows.published.str.startswith('2025')], END)
    target = rows.loc[rows.published.str.startswith('2026')]
    past_queue = queue(historical, identities, catalog)
    target_queue = queue(target, identities, catalog)
    target_queue[COLUMNS].to_csv(PATH, index=False)
    past_queue[['cve_id', 'snapshot_month', 'label', 'vendor', 'product', 'prior_kev_count',
                'latest_prior_kev_cve', 'latest_prior_kev_date']].to_parquet(CACHE / 'product_watch_2025.parquet', index=False)
    result = {'artifact_path': str(PATH.relative_to(ARTIFACTS.parent)),
              'definition': 'Every no-signal row with a positive prior count for the profile matcher’s chosen product alias; dated history stops at snapshot end and 2025-12-31.',
              'purpose': 'A complete review queue for teams running the matched products; no top-k performance or ranking improvement is claimed.',
              'sort': 'prior_kev_count descending, EPSS descending with missing last, cve_id ascending',
              'historical_2025': summarize(past_queue, no_signal(historical), True),
              'target_2026': summarize(target_queue, no_signal(target), False),
              'confidence': {'kind': 'Categorical support for a heuristic match, not a calibrated correctness probability.',
                             'definitions': CONFIDENCE_DEFINITIONS},
              'limitations': ['Current descriptions may have changed after the snapshot; explicit incident wording is removed but revision risk remains.',
                             'Aliases can cover broad product families and do not verify affected versions or whether a team runs the product.',
                             'A zero-flag pool includes missing monthly observations, not proof that public code was absent.',
                             'The 2025 product-history contrast was identified descriptively in the previous round.',
                             'Current CVSS is display-only metadata; it does not select or order this queue.'],
              'artifact_sha256': hashlib.sha256(PATH.read_bytes()).hexdigest(), 'generator': 'pipeline/product_watch.py'}
    path = ARTIFACTS / 'findings.json'
    findings = json.loads(path.read_text())
    contrast = next(c for c in findings['blind_spot']['profile']['contrasts'] if c['name'] == 'product_prior_kev_any')
    assert len(past_queue) == contrast['no_signal_pool']
    assert int(past_queue.label.sum()) == contrast['no_signal_positives']
    findings['blind_spot']['product_watch'] = result
    write_json(path, findings)
    product_checks()
    print('Product watch:', len(target_queue), '2026 rows;', len(past_queue), '2025 rows holding', int(past_queue.label.sum()), 'of', int(no_signal(historical).label.sum()), flush=True)
    return result


def product_checks():
    frozen_artifacts()
    rows, identities, _ = prepared()
    expected = queue(rows.loc[rows.published.str.startswith('2026')], identities, kev())
    actual = pd.read_csv(PATH, keep_default_na=False)
    assert actual.columns.tolist() == COLUMNS and actual.cve_id.is_unique
    assert actual.cve_id.tolist() == expected.cve_id.tolist()
    for name in ['vendor', 'product', 'match_confidence', 'latest_prior_kev_cve', 'latest_prior_kev_date', 'description']:
        assert actual[name].tolist() == expected[name].tolist()
    assert actual.prior_kev_count.tolist() == expected.prior_kev_count.tolist()
    assert np.allclose(pd.to_numeric(actual.epss, errors='coerce'), expected.epss, equal_nan=True)
    assert actual.latest_prior_kev_date.le(END).all()
    assert set(actual.match_confidence) <= set(CONFIDENCE.values())
    findings = json.loads((ARTIFACTS / 'findings.json').read_text())['blind_spot']['product_watch']
    assert findings['target_2026']['rows'] == len(actual)
    assert findings['artifact_sha256'] == hashlib.sha256(PATH.read_bytes()).hexdigest()
    print('Product watch checks: exact membership, order, dated evidence, counts and confidence', flush=True)


if __name__ == '__main__':
    run()
