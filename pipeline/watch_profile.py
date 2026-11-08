"""Descriptive blind-spot contrasts; current enrichment never becomes a predictor."""
import re
import numpy as np
import pandas as pd

from pipeline.features import clean_description
from pipeline.findings import rate_interval

CWE_FAMILIES = {
    'memory safety': {'119', '120', '121', '122', '125', '190', '416', '787'},
    'access control or authentication': {'269', '276', '284', '285', '287', '288', '306', '862', '863'},
    'command or code injection': {'77', '78', '94', '95'},
    'path traversal': {'22', '23', '36'}, 'cross-site scripting': {'79'},
    'sql injection': {'89'}, 'deserialization': {'502'},
    'information exposure': {'200', '209', '532'}, 'file upload': {'434'},
}
CLASS_PATTERNS = {
    'browser wording': r'\b(?:chrome|chromium|firefox|safari|web browser|webkit)\b',
    'mobile wording': r'\b(?:android|ios|iphone|ipad)\b',
    'perimeter or remote-access wording': r'\b(?:vpn|firewall|gateway|router|netscaler|fortios|remote access|file transfer)\b',
    'operating-system or kernel wording': r'\b(?:windows|macos|operating system|linux kernel|kernel driver)\b',
    'web application or cms wording': r'\b(?:wordpress|joomla|drupal|xwiki|cms|content management|web application)\b',
    'library or runtime wording': r'\b(?:library|runtime|framework|sdk)\b',
}


def cwe_family(value):
    for code in re.findall(r'CWE-(\d+)', str(value)):
        for family, codes in CWE_FAMILIES.items():
            if code in codes:
                return family
    return 'other or unassigned'


def product_class(text):
    for name, pattern in CLASS_PATTERNS.items():
        if re.search(pattern, text, re.I):
            return name
    return 'unclassified wording'


def profile(rows, history):
    blind = rows.any_exploit.eq(0)
    positive = rows.label.eq(1)
    n_blind, p_blind = int(blind.sum()), int((blind & positive).sum())
    n_signal_positive = int((~blind & positive).sum())
    base = p_blind / n_blind
    h = history.loc[rows.index]
    categories = pd.DataFrame(index=rows.index)
    for kind in ['vendor', 'product']:
        categories[f'{kind}_prior_kev'] = pd.cut(h[f'text_{kind}_prior_kev'],
            [-1, 0, 4, 19, 49, np.inf], labels=['0', '1-4', '5-19', '20-49', '50+']).astype(str)
    categories['cwe_family_current'] = rows.cwe_ids.map(cwe_family)
    for name in ['attack_vector', 'privileges_required', 'user_interaction']:
        categories[name + '_current'] = rows[name].fillna('').replace('', 'unassigned')
    cvss = pd.to_numeric(rows.cvss3_score, errors='coerce')
    categories['cvss_band_current'] = pd.cut(cvss, [-.01, 0, 3.9, 6.9, 8.9, 10],
        labels=['none', 'low', 'medium', 'high', 'critical']).astype('object').fillna('unscored')
    categories['assigner_type_proxy'] = np.where(h.entity_source.eq('vendor_psirt'),
        'recognized vendor psirt or cna', 'other or unresolved assigning organization')
    categories['product_class_description'] = rows.description.fillna('').map(clean_description).map(product_class)
    risks = {key: ('high: current enrichment, descriptive only' if key.endswith('_current') else
                  'medium: current sanitized text and heuristic identity') for key in categories}
    tables = {}
    for feature in categories:
        entries = []
        for value in sorted(categories[feature].unique()):
            mask = categories[feature].eq(value)
            n = int((blind & mask).sum())
            hits = int((blind & positive & mask).sum())
            signal_hits = int((~blind & positive & mask).sum())
            entries.append({'value': value, 'no_signal_pool': n, 'no_signal_pool_share': n/n_blind,
                            'no_signal_positives': hits, 'share_of_no_signal_positives': hits/p_blind,
                            'with_signal_positives': signal_hits, 'share_of_with_signal_positives': signal_hits/n_signal_positive,
                            'no_signal_rate': hits/n if n else 0., 'pool_base_rate': base,
                            'lift_over_pool': hits/n/base if n else None,
                            'rate_95_wilson_interval': rate_interval(hits, n)})
        tables[feature] = {'risk': risks[feature], 'rows': entries}
    clients = categories.product_class_description.isin(['browser wording', 'mobile wording', 'operating-system or kernel wording'])
    definitions = [
        ('vendor_20_plus', h.text_vendor_prior_kev.ge(20), 'medium',
         'Large vendor-wide history did not enrich this no-signal pool; do not assume it is an effective fallback when exploit feeds are quiet.'),
        ('client_or_endpoint_wording', clients, 'medium',
         'Include browser, mobile and operating-system products in watch reviews even when public-tool feeds are quiet; confirm the affected asset from the advisory.'),
        ('local_attack_vector_current', rows.attack_vector.eq('LOCAL'), 'high',
         'Review endpoint and privilege-escalation exposure rather than treating local access requirements as proof of low exploitation interest; these current vector values are descriptive only.'),
        ('product_prior_kev_any', h.text_product_prior_kev.gt(0), 'medium',
         'Review prior KEV cases for the specific matched product and confirm affected versions and asset exposure; this descriptive association does not validate the watch model or justify replacing the patch queue.'),
    ]
    contrasts = []
    for name, mask, risk, action in definitions:
        n = int((blind & mask).sum())
        hits = int((blind & positive & mask).sum())
        contrasts.append({'name': name, 'no_signal_pool': n, 'pool_share': n/n_blind,
                          'no_signal_positives': hits, 'positive_share': hits/p_blind,
                          'with_signal_positives': int((~blind & positive & mask).sum()),
                          'rate': hits/n if n else 0., 'base_rate': base,
                          'lift': hits/n/base if n else None, 'leak_risk': risk,
                          'rate_95_wilson_interval': rate_interval(hits, n), 'action': action})
    product = next(c for c in contrasts if c['name'] == 'product_prior_kev_any')
    vendor = next(c for c in contrasts if c['name'] == 'vendor_20_plus')
    actionable = ([product] if product['no_signal_positives'] >= 5 and product['rate'] > base else [])
    if vendor['no_signal_positives'] >= 5 and abs(vendor['lift'] - 1) < .2:
        actionable.append(vendor)
    lag = {}
    for name, mask in [('no_signal_positives', blind & positive), ('with_signal_positives', ~blind & positive)]:
        part = rows.loc[mask]
        published = (pd.to_datetime(part.date_added) - pd.to_datetime(part.published)).dt.days
        snapshot = part.event_lag_days
        lag[name] = {'n': len(part), 'publication_to_kev': published.describe(percentiles=[.25, .5, .75]).to_dict(),
                     'snapshot_to_kev': snapshot.describe(percentiles=[.25, .5, .75]).to_dict()}
    return {'no_signal_pool': n_blind, 'no_signal_positives': p_blind,
            'with_signal_pool': int((~blind).sum()), 'with_signal_base_rate': n_signal_positive/int((~blind).sum()),
            'with_signal_positives': n_signal_positive, 'base_rate': base,
            'tables': tables, 'contrasts': contrasts, 'actionable_contrasts': actionable,
            'days_to_kev': lag,
            'definitions': {'cwe_families': {k: sorted(v) for k, v in CWE_FAMILIES.items()},
                            'product_classes': CLASS_PATTERNS,
                            'assigner_type': 'A match to a prior-KEV vendor PSIRT domain is only a proxy; unresolved domains and UUIDs are not asserted to be non-vendor CNAs.'},
            'limitations': ['Descriptive 2025 contrasts do not select or modify the watch model.',
                           'CWE and vector/score fields are current enrichment with high timing risk; they are excluded from watch features.',
                           'Product classes use the first matching wording category, not verified asset identity; descriptions may have changed.',
                           'The product-level enrichment and absence of vendor-level enrichment were selected after inspecting the complete profile; these are exploratory contrasts, not preregistered causal tests, and they never alter the model.',
                           'Lag measures catalog addition, not the first attack. Late-year non-events remain censored.']}
