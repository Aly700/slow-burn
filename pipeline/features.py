"""Explicit feature blocks; current enrichment is never implicitly admitted."""
import re
from functools import lru_cache

import ahocorasick
import numpy as np
import pandas as pd

from pipeline.data import FLAGS, month_end

KEYWORDS = {
    'remote_code': r'remote code execution|execute arbitrary (?:code|commands)|arbitrary command|command injection',
    'unauthenticated': r'unauthenticated|without authentication|authentication bypass|prior to authentication|pre.auth',
    'traversal': r'path traversal|directory traversal',
    'deserialization': r'deserializ',
    'edge_device': r'\bvpn\b|firewall|gateway|router|file transfer|remote access|fortios|netscaler',
    'privilege_escalation': r'privilege escalation|elevation of privilege|escalate privileges',
    'memory_corruption': r'buffer overflow|use.after.free|out.of.bounds write|memory corruption|type confusion',
    'sql_injection': r'sql injection',
    'xss': r'cross.site scripting|\bxss\b',
    'wordpress': r'wordpress',
    'denial_service': r'denial of service',
    'upload': r'arbitrary file upload|unrestricted upload|upload.*executable',
}
EXPLOIT_CLAIM = re.compile(
    r'in.the.wild|actively exploited|has been exploited|have been exploited|may have been exploited|'
    r'known exploitation|known exploited|exploitation (?:has|was|is|of)|ransomware|zero.day|'
    r'threat actor|attack campaign|cisa|\bkev\b|observed attack|exploited in', re.I)
DOMAIN_ALIASES = {'fb': 'meta', 'facebook': 'meta', 'paloaltonetworks': 'paloaltonetworks',
                  'redhat': 'redhat', 'msrc': 'microsoft', '3ds': 'dassaultsystemes'}
GENERIC_ASSIGNERS = {'mitre', 'github', 'vulncheck', 'vuldb', 'hackerone', 'cert', 'trendmicro',
                     'huntr', 'incibe', 'nvd', 'nist', 'cisa', 'certcc', 'jpcert', 'twcert'}


def normalized(value):
    return re.sub(r'[^a-z0-9]', '', str(value).lower())


def assigner_vendor(assigner):
    domain = str(assigner).lower().split('@')[-1]
    parts = domain.split('.')
    token = parts[-2] if len(parts) > 1 else domain
    token = DOMAIN_ALIASES.get(token, normalized(token))
    return '' if token in GENERIC_ASSIGNERS or '@' not in str(assigner) else token


def clean_description(text):
    # Incident claims are excluded even from exploratory semantic features.
    sentences = re.split(r'(?<=[.!?])\s+|\n+', str(text))
    text = ' '.join(s for s in sentences if not EXPLOIT_CLAIM.search(s))
    text = re.sub(r'https?://\S+|CVE-\d{4}-\d+|\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b', ' ', text, flags=re.I)
    return re.sub(r'\s+', ' ', text).strip()[:4000]


def history_features(rows, history):
    columns = ['assigner_prior_kev', 'assigner_recent_kev', 'vendor_prior_kev', 'vendor_recent_kev',
               'text_vendor_prior_kev', 'text_product_prior_kev', 'vendor_prior_ransomware_audit']
    out = pd.DataFrame(0., index=rows.index, columns=columns)
    labels = pd.DataFrame('', index=rows.index, columns=['vendor_identity', 'text_vendor_identity', 'text_product_identity'])
    history = history.copy()
    history['vendor_key'] = history.vendor.map(normalized)
    history['assigner_key'] = history.assigner.fillna('').str.lower()
    for month, indices in rows.groupby('snapshot_month', sort=True).groups.items():
        end = (pd.Timestamp(month + '-01') + pd.offsets.MonthEnd()).strftime('%Y-%m-%d')
        start = (pd.Timestamp(end) - pd.Timedelta(days=365)).strftime('%Y-%m-%d')
        past = history.loc[history.date_added.le(end)]
        recent = past.loc[past.date_added.gt(start)]
        part = rows.loc[indices]
        ak = part.assigner.fillna('').str.lower()
        vk = part.assigner.map(assigner_vendor)
        labels.loc[indices, 'vendor_identity'] = vk
        for name, series, key in [('assigner_prior_kev', past.assigner_key.value_counts(), ak),
                                  ('assigner_recent_kev', recent.assigner_key.value_counts(), ak),
                                  ('vendor_prior_kev', past.vendor_key.value_counts(), vk),
                                  ('vendor_recent_kev', recent.vendor_key.value_counts(), vk)]:
            out.loc[indices, name] = key.map(series).fillna(0).to_numpy()
        ransom = past.loc[past.known_ransomware_use.eq('Known'), 'vendor_key'].value_counts()
        out.loc[indices, 'vendor_prior_ransomware_audit'] = vk.map(ransom).fillna(0).to_numpy()
        # Match only names already present in the catalog at this snapshot.
        vendor_counts = past.vendor.value_counts()
        product_counts = past['product'].value_counts()
        text = part.description.fillna('').str.lower().map(lambda s: re.sub(r'[ _-]+', ' ', s))
        for kind, counts in [('vendor', vendor_counts), ('product', product_counts)]:
            feature = 'text_vendor_prior_kev' if kind == 'vendor' else 'text_product_prior_kev'
            label = 'text_vendor_identity' if kind == 'vendor' else 'text_product_identity'
            matcher = ahocorasick.Automaton()
            for term, count in counts.items():
                if len(term) < 3 or term.lower() in {'multiple', 'various', 'unknown', 'other'}:
                    continue
                key = re.sub(r'[ _-]+', ' ', term.lower())
                existing = matcher.get(key, None)
                if existing is None or count > existing[2]:
                    matcher.add_word(key, (key, term, int(count)))
            if not len(matcher):
                continue
            matcher.make_automaton()
            values, identities = [], []
            for content in text:
                best_count, best_term = 0, ''
                for end_pos, (key, term, count) in matcher.iter(content):
                    start_pos = end_pos - len(key) + 1
                    left_ok = start_pos == 0 or not content[start_pos - 1].isalnum()
                    right_ok = end_pos + 1 == len(content) or not content[end_pos + 1].isalnum()
                    if left_ok and right_ok and (count > best_count or (count == best_count and term < best_term)):
                        best_count, best_term = count, term
                values.append(best_count)
                identities.append(best_term)
            out.loc[indices, feature] = values
            labels.loc[indices, label] = identities
    return pd.concat([out, labels], axis=1)


def base_features(rows):
    f = pd.DataFrame(index=rows.index)
    p = pd.to_numeric(rows.epss, errors='coerce').fillna(0).clip(0, 1)
    f['epss_log'] = np.log10(p.clip(lower=1e-6))
    f['epss_percentile'] = p.groupby(rows.snapshot_month).rank(pct=True, method='average')
    for flag in FLAGS:
        f[flag] = rows[flag].astype(float)
    f['exploit_count'] = rows[FLAGS].sum(axis=1).astype(float)
    f['any_exploit'] = rows[FLAGS].max(axis=1).astype(float)
    f['id_year_gap'] = (pd.to_datetime(rows.published).dt.year - rows.cve_id.str.extract(r'CVE-(\d{4})-')[0].astype(int)).clip(0, 20)
    f['days_at_snapshot'] = (month_end(rows.snapshot_month) - pd.to_datetime(rows.published)).dt.days.clip(0, 62)
    return f


def make_features(rows, history, block='strict', precomputed_history=None):
    f = base_features(rows)
    if block == 'signals':
        return f
    h = history_features(rows, history) if precomputed_history is None else precomputed_history.loc[rows.index]
    for col in ['assigner_prior_kev', 'assigner_recent_kev', 'vendor_prior_kev', 'vendor_recent_kev']:
        f[col] = np.log1p(h[col])
    if block in {'text', 'full'}:
        text = rows.description.fillna('').map(clean_description).str.lower()
        for col, pattern in KEYWORDS.items():
            f[f'text_{col}'] = text.str.contains(pattern, regex=True).astype(float)
        for col in ['text_vendor_prior_kev', 'text_product_prior_kev']:
            f[col] = np.log1p(h[col])
    if block == 'full':
        source = rows.cvss3_source.fillna('').str.lower()
        trusted = source.ne('') & ~source.isin(['nvd@nist.gov', '134c704f-9b21-4f2e-91b3-4a467353bcc0'])
        # This is an audit block: vendor provenance alone does not establish timing.
        score = pd.to_numeric(rows.cvss3_score, errors='coerce')
        f['vendor_cvss_audit'] = score.where(trusted).fillna(5.)
        vec = rows.cvss3_vector.where(trusted, '').fillna('')
        for part, values in {'AV': ['N', 'A', 'L', 'P'], 'AC': ['L', 'H'], 'PR': ['N', 'L', 'H'],
                              'UI': ['N', 'R'], 'S': ['U', 'C'], 'C': ['N', 'L', 'H'],
                              'I': ['N', 'L', 'H'], 'A': ['N', 'L', 'H']}.items():
            for value in values:
                f[f'vendor_cvss_{part}_{value}_audit'] = vec.str.contains(f'/{part}:{value}', regex=False).astype(float)
        for cwe in ['22', '78', '79', '89', '94', '119', '125', '190', '200', '269', '287', '306', '352', '416', '434', '502', '787', '862']:
            f[f'cwe_{cwe}_audit'] = rows.cwe_ids.fillna('').str.contains(rf'(?:^|;)CWE-{cwe}(?:;|$)', regex=True).astype(float)
    return f.astype('float32')


def strict_allowlist(columns):
    allowed = {'epss_log', 'epss_percentile', *FLAGS, 'exploit_count', 'any_exploit', 'id_year_gap',
               'days_at_snapshot', 'assigner_prior_kev', 'assigner_recent_kev', 'vendor_prior_kev', 'vendor_recent_kev'}
    bad = [c for c in columns if c not in allowed and not c.startswith('identity_emb_')]
    if bad:
        raise AssertionError(f'Unapproved production feature(s): {bad}')
    return True
