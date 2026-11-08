"""Temporal evidence and compact map contract checks."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pandas as pd


class ProductChecks(unittest.TestCase):
    def test_product_evidence_excludes_future_entries_and_reconciles_alias(self):
        from pipeline.product_watch import product_evidence
        rows = pd.DataFrame({'cve_id': ['query'], 'snapshot_month': ['2025-01']})
        identities = pd.DataFrame({'text_vendor_identity': ['Example'], 'text_product_identity': ['widget'],
                                   'text_product_prior_kev': [1], 'entity_source': ['vendor_psirt']})
        catalog = pd.DataFrame({'cve_id': ['old', 'future'], 'vendor': ['Example'] * 2,
                                'product': ['Example Widget'] * 2, 'date_added': ['2024-12-01', '2025-02-01']})
        result = product_evidence(rows, identities, catalog)
        self.assertEqual(result.prior_kev_count.tolist(), [1])
        self.assertEqual(result.latest_prior_kev_cve.tolist(), ['old'])
        self.assertEqual(result.match_confidence.tolist(), ['psirt_supported'])
        identities['text_product_prior_kev'] = 2
        with self.assertRaisesRegex(AssertionError, 'profile count'):
            product_evidence(rows, identities, catalog)

    def test_product_evidence_caps_history_at_2025_and_breaks_date_ties(self):
        from pipeline.product_watch import product_evidence
        rows = pd.DataFrame({'cve_id': ['query'], 'snapshot_month': ['2026-09']})
        identities = pd.DataFrame({'text_vendor_identity': ['Example'], 'text_product_identity': ['widget'],
                                   'text_product_prior_kev': [2], 'entity_source': ['description_product']})
        catalog = pd.DataFrame({'cve_id': ['b', 'a', 'future'], 'vendor': ['Example'] * 3,
                                'product': ['Widget'] * 3, 'date_added': ['2025-12-31', '2025-12-31', '2026-01-01']})
        result = product_evidence(rows, identities, catalog)
        self.assertEqual(result.prior_kev_count.tolist(), [2])
        self.assertEqual(result.latest_prior_kev_cve.tolist(), ['a'])
        self.assertEqual(result.match_confidence.tolist(), ['product_alias_only'])


if __name__ == '__main__':
    unittest.main()
