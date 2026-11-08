"""Frozen watch-list experiment, declared before any dedicated 2025 scoring."""
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.models import Recipe

CANDIDATES = (
    Recipe('watch_logistic_text', block='text'),
    Recipe('watch_logistic_granite', block='text', embedding='description'),
    Recipe('watch_lightgbm_text', 'lightgbm', 'text', variant='sparse'),
    Recipe('watch_lightgbm_granite', 'lightgbm', 'text', 'description', variant='sparse'),
)
BUDGETS = (100, 250, 500)
SEEDS = (2026, 2027, 2028, 2029, 2030)
POLICY = {
    'version': 'watch-1',
    'pool': 'All four snapshot flags and any_exploit equal zero; missing monthly observations follow the existing zero-flag tier rule.',
    'inner_train': '2024 publication cohorts with at least 90 days follow-up at 2024-06-30 (January–March).',
    'inner_validation': 'July–September 2024 publication cohorts; labels through 2024-12-31.',
    'selection': 'Largest sum of validation hits at 100, 250 and 500; then validation average precision; then no embedding, logistic, name.',
    'fixed_parameters': 'Existing logistic C=0.2 or sparse LightGBM: 160 trees, 7 leaves, depth 3, min leaf 40, Hessian 0.05; no tuning.',
    'features': 'Exact-month EPSS and percentile, publication timing, prior vendor/product/assigner KEV counts, sanitized keywords; optional pinned Granite description embeddings with train-only PCA.',
    'excluded': 'Constant tool flags/counts; all current CWE/CVSS fields, enrichment/status/counts/references, undated ransomware annotations and raw incident claims.',
    'encoder_timing': 'The frozen encoder was released by 2024 year-end, before 2025 evaluation; 2024 validation is retrospective recipe development, not a simulated live 2024 deployment.',
    'test_primary': 'Fit mature no-signal 2024 rows with labels through 2024-12-31; score all 2025 publication cohorts once, outcomes through 2025-12-31.',
    'test_secondary': 'Same chosen recipe, refit mature no-signal 2024+early-2025 rows with labels through 2025-06-30; score July–September 2025.',
    'test_use': '2025 cannot change recipes, hyperparameters, selection, or production seed; all selected-model seeds are diagnostics only.',
    'censoring': 'Training requires 90 days observation; primary includes immature late-2025 cohorts and reports their counts. Secondary has at least 90 days. Non-membership is unobserved exploitation, not safety.',
    'bootstrap': '1000 paired month resamples, fixed fitted scores, literal budgets 100/250/500, seed 2026; also show workload-fraction sensitivity.',
    'mixed_allocation': 'Report pure frozen top500, 450 exploit-tier plus 50 watch, and 400 plus 100; do not change submission.',
    'final_fit': 'Mature no-signal 2024+2025 rows; labels through 2025-12-31; seed 2026 regardless of test results.',
    'unavailable_2023': 'No 2023 monthly signals were supplied; no backfill from 2024.',
    'negative_result': 'Publish the same watch artifact and an explicit negative result if the chosen recipe catches no held-out positives.',
}
PROTECTED = {
    'top500.csv': 'd113581f44cde75e92dc6a041e37bdf8eb5a3b9a431a9e172b8db7aab55b8a4b',
    'scores_2026_top5000.csv': '0ef96f42ad1f54ff6ce04838751562483c4aba1682a440b337f46cade517901e',
    'model_card.json': 'c5e352f8664f8eb71633828f01d36808e72a3c43f8eadef6fced567ecdfad06c',
    'backtest.json': '86134332b395e7613da1f73c9d677da33a02f2122637b807990d84f1eb33340d',
}

if __name__ == '__main__':
    print(json.dumps({'policy': POLICY, 'candidates': [r.__dict__ for r in CANDIDATES],
                      'budgets': BUDGETS, 'seeds': SEEDS, 'protected_artifacts': PROTECTED}, indent=2))
