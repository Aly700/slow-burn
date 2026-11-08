"""Granite vulnerability map, compact rendering artifact and independent distance check."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd

from pipeline.data import ARTIFACTS, CACHE, ROOT, write_json
from pipeline.embed import MODEL_ID, REVISION, all_rows, embeddings
from pipeline.features import clean_description
from pipeline.map_embeddings import anchor_vectors
from pipeline.map_format import FLAG_BITS, make_flags, pack_array, pack_coordinates, unpack_array, unpack_coordinates
from pipeline.map_layout import layout, term_labels
from pipeline.watch import frozen_artifacts

PATH = ARTIFACTS / 'map_2026.json'
STORY_TITLE = 'The blind spot has familiar neighbours'


def map_inputs():
    base = all_rows()
    target = base.loc[base.published.str.startswith('2026')]
    anchors, anchor_embedding, reuse = anchor_vectors()
    points = pd.concat([target, anchors], ignore_index=True)
    vectors = np.concatenate([embeddings(base, 'description')[target.index], anchor_embedding])
    assert points.cve_id.is_unique and len(points) == len(vectors)
    top = set(pd.read_csv(ARTIFACTS / 'top500.csv').cve_id)
    product = set(pd.read_csv(ARTIFACTS / 'product_watch_2026.csv').cve_id)
    text = points.description.fillna('').map(clean_description)
    flags = make_flags(points.published.str.startswith('2026'), points.cve_id.isin(top),
                       points.cve_id.isin(anchors.cve_id), points.cve_id.isin(product),
                       text.str.contains('wordpress', case=False, regex=False))
    return points, text, vectors, flags, reuse


def region_records(labels, coordinates, flags, terms):
    regions = []
    for cluster in sorted(set(labels)):
        mask = labels == cluster
        part = coordinates[mask].astype(np.float64)
        counts = {name: int(((flags[mask] & bit) != 0).sum()) for name, bit in FLAG_BITS.items()}
        regions.append({'id': int(cluster), **terms[int(cluster)], 'rows': int(mask.sum()),
                        'centroid': np.round(part.mean(axis=0), 3).tolist(),
                        'bounds': [part.min(axis=0).tolist(), part.max(axis=0).tolist()], 'counts': counts})
    return regions


def preview(artifact):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    xy = unpack_array(artifact['coordinates']) / 65535.
    flags = unpack_array(artifact['flags'])
    fig, axes = plt.subplots(1, 2, figsize=(18, 8), dpi=160)
    for axis in axes:
        axis.scatter(xy[:, 0], xy[:, 1], s=.5, color='#adbac7', alpha=.35, rasterized=True)
        axis.set_aspect('equal')
        axis.set_axis_off()
    for name, color, size, marker in [('in_top500', '#008080', 9, 'o'), ('is_past_exploited', '#d25231', 14, '^')]:
        mask = flags & FLAG_BITS[name] != 0
        axes[0].scatter(xy[mask, 0], xy[mask, 1], s=size, color=color, marker=marker, alpha=.8, label=name)
    mask = flags & FLAG_BITS['in_product_watch'] != 0
    axes[1].scatter(xy[mask, 0], xy[mask, 1], s=1.5, color='#6652a3', alpha=.45)
    for region in sorted(artifact['clusters'], key=lambda r: -r['rows'])[:12]:
        if region['id'] < 0:
            continue
        x, y = np.asarray(region['centroid'])/65535
        axes[1].text(x, y, region['label'], fontsize=6, ha='center', bbox={'facecolor': 'white', 'alpha': .75, 'edgecolor': 'none'})
    axes[0].set_title('Frozen top 500 and historical KEV anchors')
    axes[0].legend(loc='lower left', markerscale=1.5)
    axes[1].set_title('Complete product watch queue and largest regions')
    fig.suptitle('IBM Granite description space — layout distance is not risk', fontsize=15)
    fig.tight_layout()
    fig.savefig(CACHE / 'map_preview.png')
    plt.close(fig)


def run(refit=False):
    frozen_artifacts()
    subprocess.run([sys.executable, '-I', str(Path(__file__).with_name('map_embeddings.py'))], check=True)
    points, texts, vectors, flags, reuse = map_inputs()
    coordinates, labels, metadata = layout(vectors, refit=refit)
    encoded = pack_coordinates(coordinates)
    quantized = unpack_array(encoded)
    named = (flags & (FLAG_BITS['in_top500'] | FLAG_BITS['is_past_exploited'] | FLAG_BITS['in_product_watch'])) != 0
    regions = region_records(labels, quantized, flags, term_labels(texts.tolist(), labels))
    from pipeline.map_neighbors import run as neighbour_check
    comparison = neighbour_check()
    artifact = {'schema_version': 1, 'point_count': len(points),
                'point_order': '2026 scoreboard source order, then historical anchors sorted by published and cve_id',
                'coordinates': encoded, 'flags': pack_array(flags, '|u1'), 'flag_bits': FLAG_BITS,
                'cluster_ids': pack_array(labels, '<i2'),
                'ids': {'indices': pack_array(np.flatnonzero(named), '<u4'), 'values': points.loc[named, 'cve_id'].tolist()},
                'clusters': regions, 'embedding': {'model': MODEL_ID, 'revision': REVISION, 'dimensions': vectors.shape[1],
                                                  'max_tokens': 256, 'sanitized': True,
                                                  'empty_sanitized_descriptions': int(texts.eq('').sum())},
                'layout': metadata, 'coordinate_note': 'Decode interleaved coordinates as origin + uint16 * scale; region centroids and bounds use the same uint16 coordinate units. Both axes share one scale.',
                'limitations': ['A transductive description map, not a forecast or a risk score; 2026 outcomes are unknown.',
                               'Layout gaps, density and region size can be projection artifacts. HDBSCAN regions are visual groupings, not ground-truth families.',
                               'Historical anchors include first-month KEV additions omitted from the ranking pool.',
                               'Descriptions are current revisions after incident-claim stripping; residual wording risk remains.',
                               'Region terms are automatic TF-IDF contrasts on display-safe text; names need human interpretation.']}
    text = json.dumps(artifact, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    assert len(text.encode()) < 3_000_000
    PATH.write_text(text)
    counts = {name: int(((flags & bit) != 0).sum()) for name, bit in FLAG_BITS.items()}
    result = {'artifact_path': str(PATH.relative_to(ROOT)), 'bytes': PATH.stat().st_size, 'rows': len(points),
              'counts': counts, 'clusters': len([r for r in regions if r['id'] >= 0]),
              'unassigned_rows': int((labels < 0).sum()), 'named_rows': int(named.sum()),
              'anchor_publication_years': points.loc[flags & FLAG_BITS['is_past_exploited'] != 0, 'published'].str[:4].value_counts().sort_index().to_dict(),
              'embedding': artifact['embedding'], 'embedding_reuse': reuse, 'layout': metadata,
              'neighbour_check': comparison, 'cluster_summaries': regions,
              'limitations': artifact['limitations'], 'artifact_sha256': hashlib.sha256(PATH.read_bytes()).hexdigest(),
              'generator': 'pipeline/space_map.py'}
    path = ARTIFACTS / 'findings.json'
    findings = json.loads(path.read_text())
    findings['map'] = result
    findings['story'] = [s for s in findings.get('story', []) if s['title'] != STORY_TITLE]
    if comparison['story_qualifies']:
        valid = comparison['empty_text_audit']
        primary = valid['primary_2025']
        blind = valid['no_signal_sensitivity']
        findings['story'].append({'title': STORY_TITLE,
            'sentence': (f"Among descriptions with technical text remaining after sanitization, a later-listed 2025 CVE had a closer Granite-text neighbour among already-listed 2024 CVEs than a non-listed CVE in {primary['probability_positive_is_closer']:.1%} of pairs "
                         f"({blind['probability_positive_is_closer']:.1%} within the no-signal pool); this is descriptive similarity, not a proven ranking improvement."),
            'numbers': {'primary_probability': primary['probability_positive_is_closer'], 'no_signal_probability': blind['probability_positive_is_closer'],
                        'primary_permutation_p': primary['permutation']['one_sided_p'], 'no_signal_permutation_p': blind['permutation']['one_sided_p'],
                        'past_anchors': valid['anchor_count'], 'later_positives': primary['positives'],
                        'no_signal_positives': blind['positives'], 'primary_rows': primary['rows'], 'no_signal_rows': blind['rows'],
                        'post_hoc_empty_text_exclusion': True},
            'source_script': 'pipeline/map_neighbors.py'})
    write_json(path, findings)
    preview(artifact)
    map_checks()
    print('Map:', len(points), 'points;', len(regions), 'regions including noise;', PATH.stat().st_size, 'bytes', flush=True)
    print('Neighbour check:', comparison['primary_2025']['probability_positive_is_closer'], comparison['primary_2025']['permutation'], flush=True)
    return result


def map_checks():
    frozen_artifacts()
    artifact = json.loads(PATH.read_text())
    assert PATH.stat().st_size < 3_000_000
    assert artifact['schema_version'] == 1 and artifact['flag_bits'] == FLAG_BITS
    assert artifact['coordinates']['dtype'] == '<u2'
    assert artifact['flags']['dtype'] == '|u1' and artifact['cluster_ids']['dtype'] == '<i2'
    assert artifact['ids']['indices']['dtype'] == '<u4'
    points, texts, vectors, expected_flags, _ = map_inputs()
    flags = unpack_array(artifact['flags'])
    labels = unpack_array(artifact['cluster_ids'])
    coordinates = unpack_coordinates(artifact['coordinates'])
    assert artifact['point_count'] == len(points) == len(flags) == len(labels) == len(coordinates)
    assert np.isfinite(coordinates).all()
    np.testing.assert_array_equal(flags, expected_flags)
    _, first, inverse = np.unique(vectors, axis=0, return_index=True, return_inverse=True)
    np.testing.assert_array_equal(coordinates, coordinates[first][inverse],
                                  err_msg='Identical description vectors must share a map coordinate')
    indices = unpack_array(artifact['ids']['indices'])
    expected_named = np.flatnonzero(flags & 14 != 0)
    np.testing.assert_array_equal(indices, expected_named)
    assert artifact['ids']['values'] == points.iloc[indices].cve_id.tolist()
    assert set(labels) == {r['id'] for r in artifact['clusters']}
    for region in artifact['clusters']:
        mask = labels == region['id']
        assert region['rows'] == int(mask.sum())
        for name, bit in FLAG_BITS.items():
            assert region['counts'][name] == int((flags[mask] & bit != 0).sum())
    findings = json.loads((ARTIFACTS / 'findings.json').read_text())
    assert findings['map']['artifact_sha256'] == hashlib.sha256(PATH.read_bytes()).hexdigest()
    assert findings['map']['counts']['in_top500'] == 500
    assert findings['map']['counts']['in_product_watch'] == findings['blind_spot']['product_watch']['target_2026']['rows']
    assert sum(s['title'] == STORY_TITLE for s in findings['story']) == int(findings['map']['neighbour_check']['story_qualifies'])
    print('Map checks: exact points, flags, sparse IDs, cluster counts, byte budget and frozen submission', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--refit', action='store_true', help='Recompute layout without using its cache')
    run(refit=parser.parse_args().refit)
