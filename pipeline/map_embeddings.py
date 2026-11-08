"""Reuse Granite vectors and encode the historical anchors missing from ranking pools."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
from pipeline.data import END, kev, vulnerabilities
from pipeline.embed import all_rows, embeddings


def anchor_rows():
    records = vulnerabilities()
    records = records.loc[records.published.str[:4].isin(['2024', '2025'])]
    records = records.merge(kev()[['cve_id', 'date_added']], on='cve_id', how='inner', validate='one_to_one')
    assert records.date_added.le(END).all()
    return records.sort_values(['published', 'cve_id'], kind='stable').reset_index(drop=True)


def comparison_anchors(anchors):
    return anchors.loc[anchors.published.str.startswith('2024') & anchors.date_added.le('2024-12-31')]


def anchor_vectors(build=False):
    base = all_rows()
    vectors = embeddings(base, 'description', build=build)
    anchors = anchor_rows()
    positions = base.set_index('cve_id').index.get_indexer(anchors.cve_id)
    missing = positions < 0
    result = np.empty((len(anchors), vectors.shape[1]), dtype=np.float32)
    result[~missing] = vectors[positions[~missing]]
    if missing.any():
        result[missing] = embeddings(anchors.loc[missing], 'description', build=build)
    return anchors, result, {'reused_anchor_vectors': int((~missing).sum()), 'additional_anchor_vectors': int(missing.sum())}


if __name__ == '__main__':
    anchors, _, counts = anchor_vectors(build=True)
    print('Granite map anchors:', len(anchors), counts, flush=True)
