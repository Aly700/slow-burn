"""Optional isolated outputs and accounting for the existing HTTP benchmarks."""
import os
from pathlib import Path

from agent.record import save_record

BASE_URL = os.getenv('SLOWBURN_EVAL_URL', 'http://127.0.0.1:8765')
OUTPUT = Path(os.environ['SLOWBURN_EVAL_OUTPUT']) if os.getenv('SLOWBURN_EVAL_OUTPUT') else None


def destination(default):
    if OUTPUT:
        OUTPUT.mkdir(parents=True, exist_ok=True)
        return OUTPUT / default.name
    return default


def accounting(run):
    if OUTPUT:
        save_record(OUTPUT / 'runs' / (run['run_id']+'.json'), run)
    metrics = run.get('metrics', {})
    verifier = run.get('verifier', {})
    return {'metrics': metrics, 'claims_retained': verifier.get('claims_verified', 0),
            'claims_dropped': len(verifier.get('dropped', [])),
            'structured_rejections': sum('validation_error' in t for t in run.get('trace', []))}
