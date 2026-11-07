"""The only operational verdict and urgency policy. Description text cannot change it."""
import math

VERSION = 'ranking-and-public-signals-v1'
THRESHOLDS = {
    'fix_now': {'rank_at_most': 500, 'score_at_least': .10, 'epss_at_least': .10, 'any_public_signal': True},
    'watch': {'rank_at_most': 2000, 'score_at_least': .01, 'epss_at_least': .01},
}
URGENCY = {
    'fix_now': {'urgency': 'urgent', 'review_window': 'emergency change process', 'headline_prefix': 'Prioritize'},
    'watch': {'urgency': 'scheduled', 'review_window': 'next maintenance window', 'headline_prefix': 'Plan'},
    'defer': {'urgency': 'routine', 'review_window': 'normal patch cycle', 'headline_prefix': 'Review'},
}
PUBLIC_SOURCES = ('exploitdb', 'metasploit', 'nuclei', 'poc_github')


def numeric(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return value


def decide(score, signals=None):
    reasons = {r.get('feature'): r.get('value') for r in score.get('reasons', []) if isinstance(r, dict)}
    rank = numeric(score.get('rank'))
    if rank is not None and (rank < 1 or int(rank) != rank):
        rank = None
    probability = numeric(score.get('score')) if score.get('score_is_probability') else None
    if probability is not None and not 0 <= probability <= 1:
        probability = None
    epss = numeric((signals if signals is not None else reasons).get('epss'))
    if epss is not None and not 0 <= epss <= 1:
        epss = None
    public = any(signals.get(k) == 1 for k in PUBLIC_SOURCES) if signals is not None else reasons.get('any_exploit') == 1
    triggers = []
    verdict = 'defer'
    for tier, limits in THRESHOLDS.items():
        tier_triggers = []
        if rank is not None and rank <= limits['rank_at_most']:
            tier_triggers.append('rank_tier')
        if probability is not None and probability >= limits['score_at_least']:
            tier_triggers.append('score_tier')
        if epss is not None and epss >= limits['epss_at_least']:
            tier_triggers.append('epss_tier')
        if limits.get('any_public_signal') and public:
            tier_triggers.append('public_material_tier')
        if tier_triggers:
            verdict, triggers = tier, tier_triggers
            break
    return {'version': VERSION, 'verdict': verdict, **URGENCY[verdict], 'triggers': triggers,
            'inputs': {'rank': rank, 'score': probability, 'epss': epss, 'any_public_signal': public},
            'thresholds': THRESHOLDS,
            'public_signal_note': 'Nuclei denotes a scanner template, not proof of exploitation.'}
