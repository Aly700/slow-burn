"""Conservative English narrative admission, separate from write authorization."""
import html
import re
import unicodedata

NORMALIZATION='nfkc-strip-hidden-controls-v1'


def hidden_control(c):
    code=ord(c)
    return (unicodedata.category(c)=='Cf' or (unicodedata.category(c)=='Cc' and c not in '\t\n\r')
            or code in {0x034f,0x115f,0x1160,0x3164,0xffa0} or 0xfe00<=code<=0xfe0f or 0xe0100<=code<=0xe01ef)


def normalize_text(text):
    return ''.join(c for c in unicodedata.normalize('NFKC',text) if not hidden_control(c))


# A matching shadow only: never silently transliterate source names in the UI.
CONFUSABLES=str.maketrans('АВЕКМНОРСТХаеорсухіјΑΒΕΖΗΙΚΜΝΟΡΤΥΧαεικνορτυ',
                         'ABEKMHOPCTXaeopcyxijABEZHIKMNOPTYXaeikvopty')


def matching_text(text):
    return normalize_text(html.unescape(text)).translate(CONFUSABLES)
DIRECTIVE=re.compile(r'\b(?:print(?:ing)?|emit(?:ting)?|cop(?:y|ying)|reproduc(?:e|ing)|replac(?:e|ing)|omit(?:ting)?|treat(?:ing)?|regard(?:ing)?|accept(?:ing)?|select(?:ing)?|record(?:ing)?|submit(?:ting)?|fil(?:e|ing)|creat(?:e|ing)|follow(?:ing)?|includ(?:e|ing)|set(?:ting)?|mark(?:ing)?|bypass(?:ing)?|overrid(?:e|ing)|obey|perform|compos(?:e|ing)|present(?:ing)?|must|shall|should)\b',re.I)
CONTROL_KEYS=re.compile(r'["\x27](?:role|tools?|call_id|verified|approval_token|briefing_hash|approved|verdict)["\x27]\s*:',re.I)
READERS=re.compile(r'\b(?:report[ -]writer|summarizer|reviewer|reader|report[ -]generator|consumer)\b',re.I)
WORKFLOW_PATTERNS=[
    r'\b(?:print|emit|copy|reproduce|replace|omit|include|select|set|mark|use|follow|record|treat|regard|accept)\b.{0,140}\b(?:the|your|this|final|next|generated|proposed)\s+(?:briefing|headline|verdict|claim|summary|response|output|report|evidence|approval|decision)\b',
    r'\b(?:compos(?:e|ing)|present(?:ing)|render(?:ing)|prepar(?:e|ing))\s+(?:the|your|this|a)\s+(?:summary|briefing|report|answer|headline|product)\b',
    r'\b(?:this|the)\s+(?:note|advisory|source|description|document|paragraph|publication)\b.{0,100}\b(?:consent|approval|permission|authorization|operator decision)\b',
    r'\b(?:approval|consent|decision)\b.{0,60}\b(?:already|granted|implicit|affirmative|accepted|complete|satisfied)\b',
    r'\b(?:submit|fil(?:e|ing)|creat(?:e|ing)|finalize)\b.{0,60}\b(?:ticket|work[ -]order|work[ -]item|remediation request|maintenance request)\b',
    r'\b(?:instructions?|directive|output format|system message|trusted evidence)\s*:',
]


def narrative_risks(text):
    """Report reasons to withhold free source prose; these do not grant/deny writes."""
    reasons=[]
    normalized=normalize_text(text)
    shadow=matching_text(text)
    if any(hidden_control(c) for c in text): reasons.append('hidden formatting or direction controls')
    if CONTROL_KEYS.search(shadow): reasons.append('embedded workflow or evidence control object')
    directive=DIRECTIVE.search(shadow)
    if any(re.search(p,shadow,re.I|re.S) for p in WORKFLOW_PATTERNS):
        reasons.append('reader-directed workflow or reporting instruction')
    if READERS.search(shadow) and directive: reasons.append('instruction addressed to a document consumer')
    if re.search(r'\b(?:decode|decrypt|rot13|base64|hex bytes|percent.decoded)\b',shadow,re.I) and re.search(r'\b(?:obey|follow|perform|precedence|instruction)\b',shadow,re.I):
        reasons.append('encoded instruction request')
    # The extractor supports English, not interpretation of unfamiliar scripts.
    # Do not infer that an unsupported-language paragraph is malicious.
    for part in re.split(r'[.!?\n。！？]',normalized):
        letters=[c for c in part if c.isalpha()]
        other=[c for c in letters if 'LATIN' not in unicodedata.name(c,'')]
        if len(other)>=12 and len(other)/max(1,len(letters))>.35:
            reasons.append('paragraph outside supported English narrative');break
    for token in re.findall(r'\w+',normalized):
        scripts={unicodedata.name(c,'').split(' ')[0] for c in token if c.isalpha()}
        if 'LATIN' in scripts and scripts & {'CYRILLIC','GREEK'} and sum(c in CONFUSABLES for c in map(ord,token))>=2:
            reasons.append('mixed-script confusable word');break
    return list(dict.fromkeys(reasons))
