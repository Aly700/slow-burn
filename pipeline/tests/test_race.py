"""Small calendar examples, independent of the supplied outcomes."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import numpy as np
import pandas as pd
from pipeline import race


def pool(rows):
    return pd.DataFrame(rows, columns=['cve_id', 'snapshot_month', 'score', 'kev_date'])


class RaceChecks(unittest.TestCase):
    def test_capacity_backlog_and_new_arrivals(self):
        p = pool([('a', '2025-01', 3, None), ('b', '2025-01', 1, None),
                  ('c', '2025-02', 4, None), ('d', '2025-12', 9, None)])
        result = race.simulate(p, 'score', 1)
        self.assertEqual(result, [(0, 1, 1), (2, 2, 1), (1, 3, 1)])
        self.assertTrue(all(sum(n for _, month, n in result if month == m) <= 1 for m in range(12)))
        self.assertEqual(race.simulate(p, 'score', 2), [(0, 1, 1), (1, 1, 1), (2, 2, 1)])

    def test_ties_use_cve_id_and_do_not_depend_on_input_order(self):
        p = pool([('b', '2025-01', 5, None), ('a', '2025-01', 5, None)])
        fixed = race.simulate(p, 'score', 1)
        self.assertEqual([p.iloc[i].cve_id for i, _, _ in fixed], ['a', 'b'])

    def test_timing_is_strict_and_arrivals_wait_until_next_month(self):
        p = pool([('a', '2025-01', 5, '2025-02-15'),
                  ('b', '2025-01', 4, '2025-02-28'),
                  ('c', '2025-01', 3, '2025-02-01'),
                  ('d', '2025-12', 2, None)])
        fixed = race.simulate(p, 'score', 3)
        end = race.summarize(p, fixed, 'end')
        start = race.summarize(p, fixed, 'start')
        self.assertEqual((end['before'], end['after'], end['never']), (0, 3, 0))
        self.assertEqual((start['before'], start['after'], start['never']), (2, 1, 0))
        self.assertEqual(start['median_days_ahead'], 20.5)
        self.assertEqual(start['monthly'][0]['fixed_total'], 0)
        self.assertEqual(start['monthly'][1]['confirmed'], 3)
        self.assertEqual(start['monthly'][1]['before'], 2)

    def test_never_and_empty_success_median(self):
        p = pool([('a', '2025-01', 3, '2025-02-02'),
                  ('b', '2025-11', 2, '2025-12-01'),
                  ('c', '2025-11', 1, '2025-12-15')])
        result = race.summarize(p, race.simulate(p, 'score', 1), 'end')
        self.assertEqual((result['before'], result['after'], result['never']), (0, 2, 1))
        self.assertIsNone(result['median_days_ahead'])

    def test_repeated_months_consume_repeated_capacity(self):
        p = pool([('a', '2025-01', 3, '2025-03-15'), ('b', '2025-01', 1, None)])
        weights = np.zeros(12, dtype=int)
        weights[0] = 2
        self.assertEqual(race.simulate(p, 'score', 1, weights),
                         [(0, 1, 1), (0, 2, 1), (1, 3, 1), (1, 4, 1)])

    def test_bootstrap_uses_best_baseline_each_draw_and_fixed_seed(self):
        counts = np.array([[4, 3, 2, 4], [3, 5, 1, 4], [2, 1, 3, 4]])
        out = race.bootstrap_summary(counts)
        self.assertEqual([out[k] for k in ['ahead', 'tied', 'behind']], [1/3, 1/3, 1/3])
        np.testing.assert_array_equal(race.month_draws(1000), race.month_draws(1000))
        self.assertTrue((race.month_draws(1000).sum(axis=1) == 12).all())

    def test_heap_matches_explicit_repeated_backlog(self):
        p = pool([(f'cve-{i:02}', f'2025-{i % 12 + 1:02}', i % 4, None) for i in range(48)])
        weights = race.month_draws(1)[0]
        jobs = [(i, copy) for i, r in p.iterrows()
                for copy in range(weights[race.MONTHS.index(r.snapshot_month)])]
        expected = []
        for month in range(12):
            available = [job for job in jobs if p.iloc[job[0]].snapshot_month < race.MONTHS[month]]
            selected = sorted(available, key=lambda job: (-p.iloc[job[0]].score, p.iloc[job[0]].cve_id, job[1]))[:3]
            for row, copy in selected:
                expected.append((row, month))
                jobs.remove((row, copy))
        actual = [(row, month) for row, month, n in race.simulate(p, 'score', 3, weights) for _ in range(n)]
        self.assertEqual(actual, expected)

    def test_invalid_capacity_and_month_are_rejected(self):
        p = pool([('a', '2025-01', 1, None)])
        with self.assertRaises(ValueError):
            race.simulate(p, 'score', 0)
        with self.assertRaises(ValueError):
            race.simulate(p.assign(snapshot_month='2026-01'), 'score', 1)


if __name__ == '__main__':
    unittest.main()
