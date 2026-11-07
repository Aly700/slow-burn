import csv
import json

import pytest


def write_csv(path, rows):
    with path.open('w') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)


@pytest.fixture
def corpus(tmp_path):
    from agent.config import Settings
    d = tmp_path / 'data'; d.mkdir()
    a = tmp_path / 'artifacts'; a.mkdir()
    vuln = {'cve_id': 'CVE-2025-1000', 'published': '2025-01-01', 'description': 'Acme server command injection.', 'assigner': 'security@acme.test', 'cwe_ids': 'CWE-78', 'cvss3_score': '9.8', 'attack_vector': 'NETWORK', 'nvd_status': 'Modified'}
    write_csv(d / 'vulnerabilities.csv', [vuln, {**vuln, 'cve_id': 'CVE-2024-2000'}])
    write_csv(d / 'weakness_types.csv', [{'cwe_id': 'CWE-78', 'name': 'OS Command Injection'}])
    kev = {'cve_id': 'CVE-2024-2000', 'vendor': 'Acme', 'product': 'Server', 'date_added': '2025-02-20', 'known_ransomware_use': 'Known', 'cwe_ids': 'CWE-78', 'short_description': 'Acme server injection.'}
    write_csv(d / 'known_exploited.csv', [kev, {**kev, 'cve_id': 'CVE-2025-9999', 'date_added': '2025-12-01'}])
    write_csv(d / 'affected_products.csv', [{'cve_id': 'CVE-2025-1000', 'vendor': 'acme', 'product': 'server', 'vulnerable': 'Y'}])
    signal = {'cve_id': 'CVE-2025-1000', 'month': '2025-01', 'epss': '0.01', 'in_kev': '0', 'exploitdb': '0', 'metasploit': '0', 'nuclei': '0', 'poc_github': '0'}
    write_csv(d / 'exploit_signals_2024.csv', [{**signal, 'cve_id': 'CVE-2024-2000', 'month': '2024-12'}])
    write_csv(d / 'exploit_signals_2025.csv', [signal, {**signal, 'month': '2025-03', 'epss': '0.1'}, {**signal, 'month': '2025-12', 'epss': '0.99', 'in_kev': '1'}])
    write_csv(d / 'scoreboard_2026.csv', [{'cve_id': 'CVE-2026-1000', 'published': '2026-01-01', 'snapshot_month': '2026-01', 'epss': '.2', 'exploitdb': '0', 'metasploit': '0', 'nuclei': '0', 'poc_github': '0'}])
    score = {'rank': '1', **vuln, 'snapshot_month': '2025-03', 'score': '1.1', 'reasons': json.dumps([{'feature': 'epss', 'value': .1}])}
    write_csv(a / 'scores_2026_top5000.csv', [score])
    return Settings(root=tmp_path, snapshot_month='2025-03')


def test_month_cutoff_and_missing_are_preserved(corpus):
    from agent.data import DataTools
    tools = DataTools(corpus)
    row = tools.get_cve('CVE-2025-1000')
    assert row['signals']['epss'] == .1
    assert 'nvd_status' not in row
    assert row['snapshot_month'] == '2025-03'
    assert row['cwes'][0]['name'] == 'OS Command Injection'
    timeline = tools.signal_timeline('CVE-2025-1000')
    assert [r['month'] for r in timeline['months']] == ['2025-01', '2025-03']
    assert '2025-02' in timeline['missing_months']
    assert timeline['months'][-1]['in_kev'] == 0


def test_vendor_history_excludes_future_and_labels_ransomware_vintage(corpus):
    from agent.data import DataTools
    tools = DataTools(corpus)
    tools.get_cve('CVE-2025-1000')
    result = tools.vendor_history('Acme')
    assert result['prior_kev'] == 1
    assert result['last_added'] == '2025-02-20'
    assert result['ransomware_known_as_of'] == '2025-12-31'
    assert result['ransomware_known'] is None
    assert result['top_cwes'][0]['cwe_id'] == 'CWE-78'


def test_bad_seed_score_is_flagged_without_clamping(corpus):
    from agent.data import DataTools
    row = DataTools(corpus).explain_score('CVE-2025-1000')
    assert row['score'] == 1.1
    assert row['score_is_probability'] is False
    assert row['warnings']


def test_id_and_month_validation(corpus):
    from agent.data import DataTools
    tools = DataTools(corpus)
    with pytest.raises(ValueError):
        tools.get_cve('../../etc/passwd')
    with pytest.raises(ValueError):
        tools.vendor_history('Acme')
    with pytest.raises(ValueError):
        tools.queue(500)


def test_nearest_neighbors_are_cutoff_filtered(corpus):
    import numpy as np
    from agent.data import DataTools
    from agent.embeddings import EmbeddingIndex
    tools = DataTools(corpus)
    tools.get_cve('CVE-2025-1000')
    idx = EmbeddingIndex.__new__(EmbeddingIndex)
    idx.metadata = {'model': 'ibm-granite/granite-embedding-30m-english', 'max_length': 256}
    idx.kev = tools.rows('SELECT * FROM known_exploited ORDER BY date_added')
    idx.vectors = np.array([[1., 0.], [0.99, 0.01]])
    idx.queries = {'CVE-2025-1000': np.array([1., 0.])}
    matches = idx.search('CVE-2025-1000', 'irrelevant', '2025-03-31', 3)
    assert [m['cve_id'] for m in matches['matches']] == ['CVE-2024-2000']


def test_late_quoted_product_is_not_split_into_columns(corpus):
    path = corpus.data / 'affected_products.csv'
    rows = [{'cve_id': f'CVE-2025-{i+1000}', 'vendor': 'acme', 'product': 'server', 'vulnerable': 'Y'} for i in range(25000)]
    rows.append({'cve_id': 'CVE-2025-1000', 'vendor': 'acme', 'product': 'pages, products and orders', 'vulnerable': 'Y'})
    write_csv(path, rows)
    from agent.data import DataTools
    tools = DataTools(corpus)
    assert len(tools.rows('SELECT * FROM affected_products WHERE cve_id=?', ['CVE-2025-1000'])) == 2


def test_evaluation_fixture_does_not_claim_a_model_rank_or_probability(corpus):
    import csv
    path = corpus.scores
    with path.open() as f:
        rows = list(csv.DictReader(f))
    rows[0]['ranking_kind'] = 'evaluation_reasons_only'
    write_csv(path, rows)
    from agent.data import DataTools
    result = DataTools(corpus).explain_score('CVE-2025-1000')
    assert result['rank'] is None
    assert result['score'] is None
    assert result['reasons']
    assert result['ranking_kind'] == 'evaluation_reasons_only'


def test_ranking_cannot_disagree_with_scoreboard_snapshot(corpus):
    import csv
    corpus.snapshot_month = None
    with (corpus.data / 'vulnerabilities.csv').open() as f:
        rows = list(csv.DictReader(f))
    rows.append({**rows[0], 'cve_id': 'CVE-2026-1000', 'published': '2026-01-01'})
    write_csv(corpus.data / 'vulnerabilities.csv', rows)
    with corpus.scores.open() as f:
        score = next(csv.DictReader(f))
    score.update(cve_id='CVE-2026-1000', snapshot_month='2026-10')
    write_csv(corpus.scores, [score])
    from agent.data import DataTools
    tools = DataTools(corpus)
    assert tools.get_cve('CVE-2026-1000')['snapshot_month'] == '2026-01'
    with pytest.raises(ValueError, match='snapshot'):
        tools.explain_score('CVE-2026-1000')


def test_queue_respects_investigation_cutoff(corpus):
    import csv
    with corpus.scores.open() as f:
        base = next(csv.DictReader(f))
    rows = [{**base, 'cve_id': f'CVE-2025-{i+1000}', 'rank': i+1, 'snapshot_month': m} for i, m in enumerate(['2025-02', '2025-03', '2025-12'])]
    write_csv(corpus.scores, rows)
    from agent.data import DataTools
    tools = DataTools(corpus)
    assert len(tools.queue(10)['items']) == 2
    with pytest.raises(ValueError, match='snapshot'):
        tools.queue(10, {'snapshot_month':'2025-12'})
    corpus.snapshot_month = None
    assert len(tools.queue(10)['items']) == 3
