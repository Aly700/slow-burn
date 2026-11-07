"""Reproducible IBM Granite embeddings on Apple MPS, cached by input content."""
from pathlib import Path
import hashlib
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd
from pipeline.data import CACHE, cohort, write_json
from pipeline.features import clean_description

MODEL_ID = 'ibm-granite/granite-embedding-30m-english'
REVISION = 'ae3da2ae1b16814b84c52deccd9aeee77727d044'


def embedding_text(rows, kind):
    if kind == 'identity':
        return rows.assigner.fillna('').str.lower().map(lambda x: 'Vulnerability assigning organization: ' + x)
    if kind == 'description':
        return rows.description.fillna('').map(clean_description)
    raise ValueError(kind)


def embeddings(rows, kind, build=False):
    texts = embedding_text(rows, kind).tolist()
    fingerprint = hashlib.sha256((REVISION + kind + '\n'.join(texts)).encode()).hexdigest()
    path = CACHE / f'granite_{kind}_{fingerprint[:20]}.npy'
    if path.exists():
        return np.load(path, mmap_mode='r')
    if not build:
        raise FileNotFoundError(f'Run uv run python -I pipeline/embed.py to build {kind} embeddings')
    import torch
    from sentence_transformers import SentenceTransformer
    device = 'mps' if torch.backends.mps.is_available() else 'cpu'
    model = SentenceTransformer(MODEL_ID, revision=REVISION, device=device,
                                cache_folder=str(CACHE / 'weights'), trust_remote_code=False)
    model.max_seq_length = 256
    unique = list(dict.fromkeys(texts))
    print(f'Encoding {len(unique):,} unique {kind} texts on {device}; revision {REVISION}', flush=True)
    vec = model.encode(unique, batch_size=128, normalize_embeddings=True, show_progress_bar=True,
                       convert_to_numpy=True).astype('float32')
    lookup = {text: i for i, text in enumerate(unique)}
    values = vec[[lookup[t] for t in texts]]
    CACHE.mkdir(parents=True, exist_ok=True)
    np.save(path, values)
    write_json(path.with_suffix('.json'), {'model': MODEL_ID, 'revision': REVISION, 'device': device,
                                          'kind': kind, 'input_sha256': fingerprint, 'rows': len(rows),
                                          'dimensions': values.shape[1], 'max_tokens': 256})
    return values


def all_rows():
    return pd.concat([cohort(y) for y in [2024, 2025, 2026]], ignore_index=True)


if __name__ == '__main__':
    rows = all_rows()
    kinds = ['identity'] if '--identity-only' in sys.argv else ['identity', 'description']
    for kind in kinds:
        embeddings(rows, kind, build=True)
