"""Extract source spans for factual prose and bounded, source-backed action choices."""
import re

from .safety import scan_text

CLASSES = [
    ('VPN', r'\b(?:VPN|virtual private network)\b'),
    ('firewall', r'\bfirewall\b'),
    ('gateway', r'\bgateway\b'),
    ('file-transfer service', r'\bfile[ -]transfer\b'),
    ('remote-management service', r'\bremote[ -]management\b'),
    ('remote-access service', r'\bremote[ -]access\b'),
    ('application delivery controller', r'\b(?:application delivery controller|ADC)\b'),
]
IMPACT = re.compile(r'unauthenticated|un-authenticated|without authentication|pre-auth|remote code execution|arbitrary (?:OS |operating system )?(?:code|commands)|root privileges|privileges of root|administrative (?:access|accounts)|privilege escalation|elevation of privilege|deny service|denial.of.service|expose private|impersonate a user', re.I)
PATCH = re.compile(r'\b(?:fixed|patched|resolved)\s+(?:in|by)\b|\bversion\s+[\w.]+.*\b(?:containing|contains|includes)\s+a\s+fix\b', re.I)
CONDITION = re.compile(r'\b(?:requires?|must|only|if|when|depends|dependent|prerequisite|access|privileges|authentication|authenticated|unauthenticated|interaction|enabled|configured|configuration)\b', re.I)
UNCONFIRMED_FIX = re.compile(r'\b(?:not|never|no|unfixed|unpatched|will|planned|expected|scheduled|related|different|another)\b|n[\x27’]t\b|\b(?:to be|being|may be|might be|could be|should be|would be)\s+(?:fixed|patched|resolved)\b', re.I)


def excerpt(text, start, end):
    return {'text': text[start:end].strip(), 'start': start, 'end': end}


def sentences(text):
    boundaries = [0] + [m.end() for m in re.finditer(r'(?<=[.!?])\s+(?=[A-Z])', text)] + [len(text)]
    return [excerpt(text, a, b) for a, b in zip(boundaries, boundaries[1:]) if text[a:b].strip()]


def describe(row):
    text = row.get('description') or ''
    result = {'product': None, 'service_class': None, 'impact': None, 'patch': None, 'endpoint': None, 'quarantined': bool(scan_text(text))}
    if result['quarantined']:
        return result
    patterns = [
        r'^In the (?P<product>Linux kernel),',
        r'^(?:In\s+)?(?P<product>[A-Z][A-Za-z0-9() /+_-]{1,65}?)\s+(?:is|are)\s+affected\b',
        r'^(?P<product>(?!An?\b)[A-Za-z][A-Za-z0-9() /+._-]{1,65}?)\s+(?:through|contains|allows|has addressed|was reported|is an?)\b',
        r'\bin (?P<product>[A-Z][A-Za-z0-9() /+_-]{1,65}?)\s+(?:before|versions?\b)',
        r'^(?:In\s+)?(?P<product>[A-Z][A-Za-z0-9() /+_-]{1,65}?)\s+(?:before|versions?\b|is a\b|is vulnerable\b|Docker image\b)',
        r'\bin (?P<product>[A-Z](?:(?!\bin\b)[A-Za-z0-9() /+_-]){1,65}?\s+(?:Products|Gateway|Server|Appliance))\s+allows\b',
        r'\bin (?P<product>[A-Z][A-Za-z0-9() /+_-]{1,65}?)\s+\d+(?:\.\d+)+\s+allows\b',
        r'\bin (?P<product>[A-Z][A-Za-z0-9./()+_-]+)\s+allows\b',
        r'device models[^:]*:\s*(?P<product>[^.]+)',
    ]
    for pattern in patterns:
        m = re.search(pattern, text)
        if m and len(m.group('product').split()) <= 9:
            a0, b0 = m.span('product')
            tail = re.search(r'(?:\s+(?:v?\d[\w.]*|before|through|and|earlier|version|versions|affecting|all))+$', text[a0:b0])
            if tail and tail.start() > 0:
                b0 = a0 + tail.start()
            inner = text[a0:b0].rfind(' in ')
            if inner > 0:
                a0 = a0 + inner + 4
            result['product'] = excerpt(text, a0, b0)
            break
    if not result['product']:
        for item in row.get('products', []):
            name = item['product'].replace('_', ' ')
            m = re.search(r'\b' + re.escape(name) + r'\b', text, re.I)
            if m:
                result['product'] = excerpt(text, *m.span())
                break
    parts = sentences(text)
    for label, pattern in CLASSES:
        m = re.search(pattern, text, re.I)
        if m and not re.search(r'\b(?:not|no|without)\s+(?:an?\s+)?$', text[max(0,m.start()-25):m.start()], re.I):
            result['service_class'] = {**excerpt(text, *m.span()), 'label': label}
            break
    scored = [(len(IMPACT.findall(s['text'])), i, s) for i, s in enumerate(parts) if IMPACT.search(s['text'])]
    if scored:
        _, index, best = max(scored, key=lambda v: (v[0], -v[1]))
        conditions = [s for s in parts if CONDITION.search(s['text'])]
        start = min([best['start']] + [s['start'] for s in conditions])
        end = max([best['end']] + [s['end'] for s in conditions])
        # Keep gates before and after the capability; omit rather than truncate them.
        if end-start <= 900:
            result['impact'] = excerpt(text, start, end)
    result['patch'] = next((s for s in parts if PATCH.search(s['text']) and not UNCONFIRMED_FIX.search(s['text']) and len(s['text']) <= 500), None)
    endpoint = re.search(r'(?<![\w:])/(?:[\w.-]+/)*[\w.-]+(?:\.php|\.get|\.cgi)\b', text)
    if endpoint:
        result['endpoint'] = excerpt(text, *endpoint.span())
    return result


def description_ref(call, span):
    return {'tool': 'get_cve', 'field': 'description', 'value': call['output']['description'], 'call_id': call['call_id'], 'quote': span['text']}


def briefing_options(call, decision):
    row = call['output']
    profile = describe(row)
    product = profile['product']['text'] if profile['product'] else row['cve_id']
    anchor = [description_ref(call, profile['product'])] if profile['product'] else [{'tool':'get_cve','field':'cve_id','value':row['cve_id'],'call_id':call['call_id']}]
    prefix = decision['headline_prefix']
    headings = [{'id':'product', 'text':f'{prefix} remediation for {product}.', 'evidence': anchor}]
    if profile['service_class']:
        headings.append({'id':'exposure', 'text':f"{prefix} {profile['service_class']['label']} exposure review for {product}.", 'evidence':anchor+[description_ref(call,profile['service_class'])]})
    if profile['impact']:
        headings.append({'id':'impact', 'text':f'{prefix} the reported impact in {product}.', 'evidence':anchor+[description_ref(call,profile['impact'])]})
    timing = f"Use the {decision['review_window']}."
    target = f"the affected {product} endpoint" if profile['product'] else f"the service affected by {product}"
    actions = []
    if profile['patch']:
        patch = profile['patch']['text']
        refs = anchor + [description_ref(call, profile['patch'])]
        actions.append({'id':'apply_fix', 'text':f'Confirm the installed {product} version and apply the appropriate vendor fix described in the supplied record: “{patch}” {timing}', 'evidence':refs})
        actions.append({'id':'restrict_then_fix', 'text':f'If internet-exposed, restrict access to {target} while validating the applicable fix: “{patch}” {timing}', 'evidence':refs})
    else:
        refs = list(anchor)
        endpoint = profile['endpoint']
        endpoint_text = f" ({endpoint['text']})" if endpoint else ''
        if endpoint:
            refs.append(description_ref(call, endpoint))
        actions.append({'id':'isolate_service', 'text':f'Locate {target}{endpoint_text} in inventory; if exposed, isolate it from untrusted networks until vendor-supported remediation is validated. {timing}', 'evidence':refs})
        actions.append({'id':'restrict_access', 'text':f'Restrict access to {target}{endpoint_text} to trusted operators and test the access control; confirm the vendor mitigation before restoring exposure. {timing}', 'evidence':refs})
    return {'headlines': headings, 'actions': actions, 'profile': profile}
