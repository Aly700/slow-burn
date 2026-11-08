"""Prepare an explicit runtime bundle from the supplied local corpus and weights."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

import numpy as np

from .config import Settings, EMBED_MODEL, EMBED_REVISION
from .data import DataTools, build_cache
from .embeddings import EmbeddingIndex


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    settings = Settings()
    data = DataTools(settings)
    index = EmbeddingIndex(settings, data)
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(build_cache(settings), output / 'corpus.duckdb')
    shutil.copyfile(settings.scores, output / settings.scores.name)
    for path in (index.path, index.meta_path):
        shutil.copyfile(path, output / path.name)
    rows = data.rows('SELECT s.cve_id,v.description FROM scoreboard_2026 s JOIN vulnerabilities v USING(cve_id) ORDER BY s.cve_id')
    missing = [r for r in rows if r['cve_id'] not in index.queries]
    fingerprint = hashlib.sha256(json.dumps([EMBED_MODEL, EMBED_REVISION, missing], sort_keys=True).encode()).hexdigest()
    cache = settings.cache / f'scoreboard-queries-{fingerprint[:20]}.npz'
    if not cache.exists():
        model = EmbeddingIndex.encoder()
        import torch
        if torch.backends.mps.is_available():
            model.to('mps')
        texts = sorted({r.get('description') or '' for r in missing})
        vectors = model.encode(texts, batch_size=128, normalize_embeddings=True, show_progress_bar=True).astype(np.float32)
        by_text = dict(zip(texts, vectors))
        np.savez_compressed(cache, ids=np.array([r['cve_id'] for r in missing]),
                            vectors=np.stack([by_text[r.get('description') or ''] for r in missing]))
    shutil.copyfile(cache, output / 'scoreboard-queries.npz')
    manifest = {'embedding_model': EMBED_MODEL, 'embedding_revision': EMBED_REVISION,
                'scoreboard_rows': len(rows), 'additional_query_vectors': len(missing), 'query_content_sha256': fingerprint,
                'files': {p.name: {'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                          for p in sorted(output.iterdir()) if p.is_file() and p.name != 'manifest.json'}}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    data.close()
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
