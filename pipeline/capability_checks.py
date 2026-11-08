"""Temporal evidence and compact map contract checks."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pandas as pd
import numpy as np


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


class MapChecks(unittest.TestCase):
    def test_semantic_comparison_requires_remaining_description_text(self):
        from pipeline.map_neighbors import semantic_text_mask
        rows = pd.DataFrame({'description': [
            'This vulnerability has been exploited in the wild.',
            'A buffer overflow permits code execution. This vulnerability has been exploited in the wild.',
            '', '   ']})
        self.assertEqual(semantic_text_mask(rows).tolist(), [False, True, False, False])

    def test_region_terms_do_not_invent_display_summary_words(self):
        import hashlib
        from unittest.mock import patch
        from pipeline.capability_text import label_text
        blocked = {hashlib.sha256(b'privateproduct').hexdigest()}
        with patch('pipeline.capability_text.PUBLIC_DIGESTS', blocked):
            text = label_text('PrivateProduct has a buffer overflow.')
        self.assertNotIn('privateproduct', text)
        self.assertIn('buffer overflow', text)
        self.assertNotIn('summary', text)

    def test_coordinate_quantization_round_trips_with_half_step_error(self):
        from pipeline.map_format import pack_coordinates, unpack_coordinates
        points = np.array([[-15., 3.], [20., -4.], [1.234, .567]])
        encoded = pack_coordinates(points)
        restored = unpack_coordinates(encoded)
        self.assertLessEqual(float(np.max(np.abs(points-restored))), encoded['scale']/2 + 1e-12)
        self.assertEqual(restored.shape, (3, 2))

    def test_typed_array_endianness_and_flags(self):
        from pipeline.map_format import pack_array, unpack_array, make_flags
        values = np.array([1, 256, 65535], dtype=np.uint16)
        np.testing.assert_array_equal(unpack_array(pack_array(values, '<u2')), values)
        flags = make_flags([True, False], [True, False], [False, True], [False, False], [True, False])
        self.assertEqual(flags.tolist(), [19, 4])

    def test_original_space_check_counts_ties_and_has_permutation_null(self):
        from pipeline.map_neighbors import neighbour_test
        rows = pd.DataFrame({'label': [1, 0, 1, 0], 'snapshot_month': ['2025-01'] * 4})
        result = neighbour_test(rows, np.array([0., 0., .1, .9]), iterations=99)
        self.assertAlmostEqual(result['probability_positive_is_closer'], .625)
        self.assertGreaterEqual(result['permutation']['one_sided_p'], .01)
        self.assertEqual(result['permutation']['iterations'], 99)

    def test_comparison_anchors_exclude_later_catalog_additions(self):
        from pipeline.map_embeddings import comparison_anchors
        anchors = pd.DataFrame({'published': ['2024-01-01', '2024-12-01', '2025-01-01'],
                                'date_added': ['2024-12-31', '2025-01-01', '2025-02-01']})
        self.assertEqual(comparison_anchors(anchors).index.tolist(), [0])

    def test_cosine_neighbours_use_normalized_original_vectors(self):
        from pipeline.map_neighbors import closest_past
        distances, indices = closest_past(np.array([[2., 0.], [0., 3.], [1., 1.]]), np.array([[5., 0.]]))
        np.testing.assert_allclose(distances, [0., 1., 1-np.sqrt(.5)])
        self.assertEqual(indices.tolist(), [0, 0, 0])

    def test_month_permutation_does_not_treat_seasonal_separation_as_evidence(self):
        from pipeline.map_neighbors import neighbour_test
        rows = pd.DataFrame({'label': [1, 1, 0, 0], 'snapshot_month': ['2025-01'] * 2 + ['2025-02'] * 2})
        result = neighbour_test(rows, np.array([0., .1, .8, 1.]), iterations=99)
        self.assertEqual(result['probability_positive_is_closer'], 1.)
        self.assertEqual(result['permutation']['one_sided_p'], 1.)


if __name__ == '__main__':
    unittest.main()
