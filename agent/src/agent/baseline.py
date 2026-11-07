"""Deterministic comparison restricted to the ranking reasons column."""
from .cards import ACTIONS, HEADLINES
from .evidence import verify


def template(cve_id, score_output, call_id='baseline-score'):
    reasons = score_output.get('reasons', [])
    values = {r['feature']: r.get('value') for r in reasons}
    epss = values.get('epss') or 0
    flag = values.get('any_exploit') or 0
    verdict = 'fix_now' if epss >= .1 or flag else 'watch' if epss >= .01 else 'defer'
    claims = [{'id': f'b{i+1}', 'text': f"The ranking's {r['feature']} feature has value {r.get('value')}.",
               'evidence': [{'tool': 'explain_score', 'field': f'reasons.{i}.feature', 'value': r['feature'], 'call_id': call_id},
                            {'tool': 'explain_score', 'field': f'reasons.{i}.value', 'value': r.get('value'), 'call_id': call_id}]} for i, r in enumerate(reasons)]
    calls = [{'call_id': call_id, 'tool': 'explain_score', 'output': score_output}]
    verified, report = verify(claims, calls)
    action = {'fix_now': 'remediate', 'watch': 'investigate', 'defer': 'monitor'}[verdict]
    return {'verdict': verdict, 'headline': f'{HEADLINES[verdict]} {cve_id}.', 'claims': verified,
            'action': ACTIONS[action], 'confidence': .5}, report
