"""Explicit feature blocks; current enrichment is never implicitly admitted."""
import re
import unicodedata
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
    r'in.the.wild|actively exploit(?:ed|ing)|has been exploited|have been exploited|may have been exploited|'
    r'known exploitation|known exploited|exploitation (?:has|was|is) (?:been|observed|detected)|ransomware|zero.day|'
    r'threat actor|attack campaign|cisa|\bkev\b|observed attack|exploited in|'
    r'aware of reports|aware of.*(?:exploitation|attacks)|reports of.*(?:exploitation|attacks)|'
    r'(?:was|were|being|already|previously) exploited|evidence of.*exploitation|exploitation evidence|'
    r'(?:has|have|had) (?:been )?(?:actively )?exploited|used in (?:targeted |active )?attacks|'
    r'\b(?:is|are|was|were|been|being) (?:actively )?exploiting\b', re.I)
INCIDENT_SUBJECT = re.compile(r'\b(?:exploit(?:ation|ed|s|ing)?|attack(?:s|ing)?)\b', re.I)
INCIDENT_OBSERVATION = re.compile(r'\b(?:observed|reported|confirmed|detected|evidence|reports|aware|campaign|activity)\b', re.I)
DOMAIN_ALIASES = {'fb': 'meta', 'facebook': 'meta', 'paloaltonetworks': 'paloaltonetworks',
                  'redhat': 'redhat', 'msrc': 'microsoft', '3ds': 'dassaultsystemes'}
GENERIC_ASSIGNERS = {'mitre', 'github', 'vulncheck', 'vuldb', 'hackerone', 'cert', 'trendmicro',
                     'huntr', 'incibe', 'nvd', 'nist', 'cisa', 'certcc', 'jpcert', 'twcert'}


def normalized(value):
    text = unicodedata.normalize('NFKD', str(value)).encode('ascii', 'ignore').decode().lower()
    return re.sub(r'[^a-z0-9]', '', text)


def assigner_vendor(assigner):
    domain = str(assigner).lower().split('@')[-1]
    parts = domain.split('.')
    token = parts[-2] if len(parts) > 1 else domain
    token = DOMAIN_ALIASES.get(token, normalized(token))
    return '' if token in GENERIC_ASSIGNERS or '@' not in str(assigner) else token


def clean_description(text):
    # Incident claims are excluded even from exploratory semantic features.
    sentences = re.split(r'(?<=[.!?])\s+', re.sub(r'\s+', ' ', str(text)))
    text = ' '.join(s for s in sentences if not (EXPLOIT_CLAIM.search(s) or
                   (INCIDENT_SUBJECT.search(s) and INCIDENT_OBSERVATION.search(s))))
    text = re.sub(r'https?://\S+|CVE-\d{4}-\d+|\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b', ' ', text, flags=re.I)
    return re.sub(r'\s+', ' ', text).strip()[:4000]


def canonical_text(text):
    text = unicodedata.normalize('NFKD', str(text)).encode('ascii', 'ignore').decode().lower()
    return re.sub(r'[ _-]+', ' ', text).strip()


def dictionary_matcher(entries):
    matcher = ahocorasick.Automaton()
    for term, value in entries.items():
        if len(term) >= 3:
            matcher.add_word(term, (term, value))
    if len(matcher):
        matcher.make_automaton()
    return matcher


def entity_matches(content, matcher):
    if not len(matcher):
        return []
    matches = []
    for end, (term, value) in matcher.iter(content):
        start = end - len(term) + 1
        if (start == 0 or not content[start-1].isalnum()) and (end+1 == len(content) or not content[end+1].isalnum()):
            if start and content[start-1] == '.':
                continue
            # Language names commonly describe an unrelated application's code.
            # Require an explicit versioned subject; a vendor PSIRT can still
            # establish identity independently of this conservative text rule.
            if term in {'php', 'perl'}:
                if content[:start].strip() not in {'', 'in', 'the', 'in the'}:
                    continue
                if not re.match(r'\s+(?:v?\d|versions?\b|before\b|prior to\b|through\b)', content[end+1:]):
                    continue
            matches.append((start, -len(term), term, value))
    return sorted(matches, key=lambda m: (m[0], m[1], m[2]))


def product_aliases(product, vendor):
    name = canonical_text(product)
    aliases = {name}
    aliases.update(canonical_text(p) for p in re.split(r',|\band\b|\(|\)| & ', name))
    vendor_name = canonical_text(vendor)
    for term in list(aliases):
        if term.startswith(vendor_name + ' '):
            aliases.add(term[len(vendor_name)+1:])
    generic = {'multiple', 'products', 'multiple products', 'other', 'unknown', 'data center',
               'server', 'servers', 'client', 'desktop', 'application', 'applications', 'device',
               'devices', 'routers', 'software', 'web', 'web server', 'core', 'kernel', 'none',
               'scripting engine', 'javascript engine', 'javascript', 'cms', 'editor', 'http', 'http/2',
               'tls', 'ssl', 'tcp/ip', 'vpn', 'smart', 'control', 'central', 'connect', 'online',
               'access', 'security', 'management', 'content management system', 'web interface'}
    # Do not shorten catalog names to their first word: "smart" and "scripting"
    # wrongly identify unrelated products. Keep full names and explicit compound parts.
    return {a for a in aliases if len(a) >= 3 and a not in generic}


def history_features(rows, history):
    columns = ['assigner_prior_kev', 'assigner_recent_kev', 'vendor_prior_kev', 'vendor_recent_kev',
               'text_vendor_prior_kev', 'text_product_prior_kev', 'text_vendor_recent_kev',
               'text_product_recent_kev', 'vendor_prior_ransomware_audit']
    out = pd.DataFrame(0., index=rows.index, columns=columns)
    labels = pd.DataFrame('', index=rows.index, columns=['vendor_identity', 'text_vendor_identity', 'text_product_identity', 'entity_source'])
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
        # Names and aliases exist only after a source KEV entry has been added.
        vendor_names = past.drop_duplicates('vendor_key').set_index('vendor_key').vendor.to_dict()
        vendor_counts = past.vendor_key.value_counts().to_dict()
        recent_counts = recent.vendor_key.value_counts().to_dict()
        vendor_terms = {canonical_text(v): key for key, v in vendor_names.items()}
        vm = dictionary_matcher(vendor_terms)
        product_terms = {}
        for record in past.itertuples():
            for alias in product_aliases(record.product, record.vendor):
                info = product_terms.setdefault(alias, {'vendors': set(), 'ids': set(), 'recent_ids': set()})
                info['vendors'].add(record.vendor_key)
                info['ids'].add(record.cve_id)
                if record.date_added > start:
                    info['recent_ids'].add(record.cve_id)
        # Ambiguous product aliases cannot assign a vendor.
        product_terms = {term: (next(iter(info['vendors'])), len(info['ids']), len(info['recent_ids']))
                         for term, info in product_terms.items() if len(info['vendors']) == 1}
        pm = dictionary_matcher(product_terms)
        text = part.description.fillna('').map(clean_description).map(canonical_text)
        for idx, content in text.items():
            vendors = entity_matches(content, vm)
            products = entity_matches(content, pm)
            psirt = vk.loc[idx]
            if psirt in vendor_names:
                chosen_vendor, source = psirt, 'vendor_psirt'
            elif vendors:
                chosen_vendor, source = vendors[0][3], 'description_vendor'
            elif products:
                chosen_vendor, source = products[0][3][0], 'description_product'
            else:
                chosen_vendor, source = '', 'unmapped'
            compatible = [m for m in products if m[3][0] == chosen_vendor]
            out.loc[idx, 'text_vendor_prior_kev'] = vendor_counts.get(chosen_vendor, 0)
            out.loc[idx, 'text_vendor_recent_kev'] = recent_counts.get(chosen_vendor, 0)
            labels.loc[idx, 'text_vendor_identity'] = vendor_names.get(chosen_vendor, '')
            labels.loc[idx, 'entity_source'] = source
            if compatible:
                match = compatible[0]
                labels.loc[idx, 'text_product_identity'] = match[2]
                out.loc[idx, 'text_product_prior_kev'] = match[3][1]
                out.loc[idx, 'text_product_recent_kev'] = match[3][2]
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
        for col in ['text_vendor_prior_kev', 'text_product_prior_kev', 'text_vendor_recent_kev', 'text_product_recent_kev']:
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


def production_allowlist(columns, allow_text=False):
    if not allow_text:
        return strict_allowlist(columns)
    text_allowed = {f'text_{k}' for k in KEYWORDS} | {
        'text_vendor_prior_kev', 'text_product_prior_kev', 'text_vendor_recent_kev', 'text_product_recent_kev'}
    return strict_allowlist([c for c in columns if c not in text_allowed and not c.startswith('description_emb_')])
