"""Matched comparison and ranking-budget invariants."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import unittest
import numpy as np
import pandas as pd
from pipeline.granite_ablation import hit_counts, paired_recipes, DESIGN


class AblationTests(unittest.TestCase):
    def test_only_embedding_is_removed(self):
        on, off = paired_recipes()
        a, b = vars(on).copy(), vars(off).copy()
        self.assertEqual(a.pop('embedding'), 'description')
        self.assertEqual(b.pop('embedding'), '')
        a.pop('name'); b.pop('name')
        self.assertEqual(a, b)
        self.assertEqual(DESIGN['seeds'], [2026, 2027, 2028, 2029, 2030])

    def test_hits_use_rank_and_cve_ties_without_changing_rows(self):
        rows = pd.DataFrame({'cve_id': ['CVE-3', 'CVE-2', 'CVE-1'], 'label': [1, 0, 1]})
        self.assertEqual(hit_counts(rows, np.array([1, 2, 2]), [1, 2, 3]), [1, 1, 2])
        self.assertEqual(rows.cve_id.tolist(), ['CVE-3', 'CVE-2', 'CVE-1'])

if __name__ == "__main__":
    unittest.main()
