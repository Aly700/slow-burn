"""Temporal invariants and artifact contracts. Run with Python's isolated mode."""
from pathlib import Path
import sys
import unittest
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd


class TemporalChecks(unittest.TestCase):
    def test_snapshot_and_label_boundaries(self):
        from pipeline.data import assign_outcomes, snapshot_month
        self.assertEqual(snapshot_month(pd.Series(['2026-06-03']), june_shift=True).iloc[0], '2026-07')
        f = pd.DataFrame({'snapshot_month': ['2025-01'] * 4,
                          'date_added': ['2025-01-31', '2025-02-01', '2026-01-01', None]})
        out = assign_outcomes(f, '2025-12-31')
        self.assertEqual(out.eligible.tolist(), [False, True, True, True])
        self.assertEqual(out.label.tolist(), [0, 1, 0, 0])
        self.assertEqual(out.followup_days.tolist(), [334] * 4)

    def test_future_history_does_not_change_past_features(self):
        from pipeline.features import history_features
        rows = pd.DataFrame({'cve_id': ['CVE-2024-1'], 'snapshot_month': ['2024-01'],
                             'assigner': ['security@example.com'], 'description': ['Example widget flaw']})
        history = pd.DataFrame({'cve_id': ['CVE-2020-1', 'CVE-2024-1'],
                                'date_added': ['2023-12-31', '2024-03-01'],
                                'assigner': ['security@example.com'] * 2,
                                'vendor': ['Example'] * 2, 'product': ['widget'] * 2,
                                'known_ransomware_use': ['Unknown', 'Known']})
        before = history_features(rows, history.iloc[:1])
        after = history_features(rows, history)
        pd.testing.assert_frame_equal(before, after)
        self.assertEqual(before.assigner_prior_kev.iloc[0], 1)

    def test_strict_features_ignore_current_enrichment_and_description(self):
        from pipeline.features import make_features
        row = {'cve_id': 'CVE-2024-1', 'published': '2024-01-15', 'snapshot_month': '2024-01',
               'epss': .02, 'epss_first': .02, 'exploitdb': 0, 'metasploit': 0, 'nuclei': 1,
               'poc_github': 0, 'assigner': 'security@example.com', 'description': 'A flaw.',
               'cvss3_score': '9.8', 'cvss3_source': 'nvd@nist.gov', 'cvss3_vector': '',
               'cwe_ids': 'CWE-22', 'nvd_status': 'Analyzed', 'n_references': '50',
               'n_affected_cpes': '100'}
        a = pd.DataFrame([row])
        b = a.copy()
        b['description'] = 'Exploited in the wild. Different vendor.'
        b['cvss3_score'] = ''
        b['cwe_ids'] = ''
        b['nvd_status'] = 'Received'
        b['n_references'] = '0'
        b['n_affected_cpes'] = '0'
        history = pd.DataFrame(columns=['cve_id', 'date_added', 'assigner', 'vendor', 'product', 'known_ransomware_use'])
        pd.testing.assert_frame_equal(make_features(a, history, 'strict'), make_features(b, history, 'strict'))

    def test_censoring_excludes_immature_training_rows(self):
        from pipeline.data import training_rows
        f = pd.DataFrame({'snapshot_month': ['2024-08', '2024-12'], 'date_added': [None, None]})
        out = training_rows(f, '2024-12-31')
        self.assertEqual(out.snapshot_month.tolist(), ['2024-08'])

    def test_cache_invalidates_after_same_size_source_change(self):
        from pipeline import data
        original = data.ROOT, data.DATA, data.CACHE
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'pipeline').mkdir()
                (root / 'inputs').mkdir()
                for name in ['data.py', 'features.py']:
                    (root / 'pipeline' / name).write_text('version one')
                source = root / 'inputs' / 'source.csv'
                source.write_text('id\n1\n')
                data.ROOT, data.DATA, data.CACHE = root, root / 'inputs', root / 'cache'
                data.ensure_cache.cache_clear()
                first = data.ensure_cache()
                derived = data.CACHE / 'cohort_2025_natural.parquet'
                derived.write_text('stale')
                source.write_text('id\n2\n')
                data.ensure_cache.cache_clear()
                second = data.ensure_cache()
                self.assertNotEqual(first, second)
                self.assertFalse(derived.exists())
        finally:
            data.ROOT, data.DATA, data.CACHE = original
            data.ensure_cache.cache_clear()


def artifact_checks():
    import json
    from pipeline.data import ARTIFACTS, DATA
    expected = ['rank', 'cve_id', 'published', 'snapshot_month', 'score', 'epss', 'any_exploit',
                'exploitdb', 'metasploit', 'nuclei', 'poc_github', 'cvss3_score', 'attack_vector',
                'cwe_ids', 'assigner', 'description', 'reasons']
    top = pd.read_csv(ARTIFACTS / 'top500.csv')
    scores = pd.read_csv(ARTIFACTS / 'scores_2026_top5000.csv', keep_default_na=False)
    board = pd.read_csv(DATA / 'scoreboard_2026.csv', keep_default_na=False)
    assert list(top.columns) == ['cve_id'] and len(top) == 500 and top.cve_id.is_unique
    assert list(scores.columns[:len(expected)]) == expected and len(scores) == 5000
    assert scores.cve_id.is_unique and top.cve_id.tolist() == scores.cve_id.head(500).tolist()
    assert set(scores.cve_id) <= set(board.cve_id)
    assert scores['rank'].tolist() == list(range(1, 5001))
    assert scores.score.between(0, 1).all() and scores.score.is_monotonic_decreasing
    source = board.set_index('cve_id').loc[scores.cve_id]
    assert source.snapshot_month.tolist() == scores.snapshot_month.tolist()
    for flag in ['exploitdb', 'metasploit', 'nuclei', 'poc_github']:
        assert source[flag].astype(int).tolist() == scores[flag].astype(int).tolist()
    for text in scores.reasons:
        reasons = json.loads(text)
        assert 1 <= len(reasons) <= 5
        for r in reasons:
            assert {'feature', 'label', 'value', 'contribution'} <= r.keys()
            assert np.isfinite(r['contribution']) and isinstance(r['label'], str)
    from scipy.special import expit
    reconstructed = expit(scores.explanation_base_log_odds.to_numpy() +
                         scores.explanation_omitted_log_odds.to_numpy() +
                         np.array([sum(r['contribution'] for r in json.loads(t)) for t in scores.reasons]))
    assert np.allclose(reconstructed, scores.score, atol=1e-10)
    card = json.loads((ARTIFACTS / 'model_card.json').read_text())
    assert all(k in card for k in ['model', 'trained_on', 'features_used', 'features_excluded', 'ibm_technology'])
    assert card['leak_checks']['passed']
    for name in ['backtest', 'findings']:
        json.loads((ARTIFACTS / f'{name}.json').read_text())
    print('Artifact contracts: passed (500 / 5000 rows, probabilities, reasons, membership, column order)')


def historical_checks():
    from pipeline.data import cohort, historical_signals, FLAGS
    signals = historical_signals().rename(columns={'month': 'snapshot_month'})
    for year in [2024, 2025]:
        rows = cohort(year)
        actual = rows[['cve_id', 'snapshot_month', 'epss', *FLAGS, 'epss_first_month']]
        joined = actual.merge(signals, on=['cve_id', 'snapshot_month'], how='left', suffixes=('', '_source'), validate='one_to_one')
        assert np.allclose(joined.epss, joined.epss_source, equal_nan=True)
        for flag in FLAGS:
            assert joined[flag].eq(joined[flag + '_source'].fillna(0)).all()
        first = joined.epss_first_month.fillna('')
        assert first.le(joined.snapshot_month).all()
    print('Historical checks: exact monthly signals; no future first EPSS observation')


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(TemporalChecks))
    if not result.wasSuccessful():
        raise SystemExit(1)
    if '--artifacts' in sys.argv:
        historical_checks()
        artifact_checks()
