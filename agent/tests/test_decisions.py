import pytest


def test_policy_tiers_and_public_material_are_deterministic():
    from agent.priority import decide
    base = {'rank': None, 'score': None, 'score_is_probability': False, 'reasons': []}
    quiet = {'epss': .001, 'exploitdb': 0, 'metasploit': 0, 'nuclei': 0, 'poc_github': 0}
    assert decide(base, quiet)['verdict'] == 'defer'
    assert decide({**base, 'rank': 500}, quiet)['verdict'] == 'fix_now'
    assert decide({**base, 'rank': 501}, quiet)['verdict'] == 'watch'
    assert decide({**base, 'rank': 2001}, quiet)['verdict'] == 'defer'
    assert decide({**base, 'score': 1.8}, quiet)['verdict'] == 'defer'
    assert decide({**base, 'score': .1, 'score_is_probability': True}, quiet)['urgency'] == 'urgent'
    assert decide(base, {**quiet, 'nuclei': 1})['verdict'] == 'fix_now'
    assert decide(base, {**quiet, 'epss': .01})['verdict'] == 'watch'


def test_policy_preserves_template_thresholds_for_historical_reasons():
    from agent.priority import decide
    for epss, flag, expected in [(.635, 0, 'fix_now'), (.005, 1, 'fix_now'), (.01, 0, 'watch'), (.0099, 0, 'defer')]:
        score = {'rank': None, 'score': None, 'reasons': [{'feature': 'epss', 'value': epss}, {'feature': 'any_exploit', 'value': flag}]}
        assert decide(score)['verdict'] == expected
    assert decide({'reasons': [{'feature': 'future_feature', 'value': {'a': 10}}]})['verdict'] == 'defer'


def test_watch_list_rank_is_not_global_urgency_and_public_signals_are_checked():
    from agent.priority import decide
    quiet = dict.fromkeys(['exploitdb','metasploit','nuclei','poc_github'],0) | {'epss':.001}
    assert decide({'rank':1},quiet,list_name='watch')['verdict'] == 'defer'
    assert decide({'rank':1,'score':.9,'score_is_probability':True},quiet,list_name='watch')['verdict'] == 'watch'
    assert decide({'rank':1},dict(quiet,epss=.9),list_name='watch')['urgency'] == 'scheduled'
    with pytest.raises(ValueError,match='public'):
        decide({'rank':1},dict(quiet,nuclei=1),list_name='watch')
    with pytest.raises(ValueError,match='public'):
        decide({'rank':1},dict(quiet,nuclei=None),list_name='watch')
