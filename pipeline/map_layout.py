"""Fixed descriptive UMAP layout and term-labelled visual regions."""
from pathlib import Path
import hashlib
import importlib.metadata
import json
import os

os.environ.setdefault('NUMBA_NUM_THREADS', '1')
import numpy as np
from sklearn.cluster import HDBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer, ENGLISH_STOP_WORDS
from pipeline.data import CACHE
from pipeline.capability_text import label_text

PARAMETERS = {'n_components': 2, 'n_neighbors': 30, 'min_dist': .1, 'spread': 1., 'metric': 'cosine',
              'n_epochs': 500, 'init': 'spectral', 'random_state': 2026, 'n_jobs': 1,
              'low_memory': True, 'verbose': False, 'unique': True}
CLUSTER_PARAMETERS = {'min_cluster_size': 150, 'min_samples': 15, 'metric': 'euclidean',
                      'cluster_selection_method': 'eom', 'n_jobs': 1, 'copy': True}
PACKAGES = ['umap-learn', 'pynndescent', 'numba', 'llvmlite', 'numpy', 'scipy', 'scikit-learn']


def layout(vectors, refit=False):
    versions = {name: importlib.metadata.version(name) for name in PACKAGES}
    unique_rows = len(np.unique(vectors, axis=0))
    metadata = {'parameters': PARAMETERS, 'clustering': CLUSTER_PARAMETERS, 'versions': versions,
                'unique_vector_rows': unique_rows, 'duplicate_vector_rows': len(vectors)-unique_rows,
                'duplicate_policy': 'Fit one location per distinct vector, then expand back to every CVE; identical vectors share coordinates.',
                'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    digest = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode())
    digest.update(np.asarray(vectors, dtype='<f4').tobytes())
    fingerprint = digest.hexdigest()
    path = CACHE / f'map_layout_{fingerprint[:20]}.npz'
    if path.exists() and not refit:
        cached = np.load(path)
        coordinates, labels = cached['coordinates'], cached['labels']
        print('Map layout: using verified input/parameter cache', flush=True)
    else:
        from umap import UMAP
        print('Map layout: fitting UMAP on', len(vectors), 'vectors', flush=True)
        coordinates = UMAP(**PARAMETERS).fit_transform(vectors)
        assert np.isfinite(coordinates).all()
        print('Map layout: clustering visual regions', flush=True)
        labels = HDBSCAN(**CLUSTER_PARAMETERS).fit_predict(coordinates)
        np.savez_compressed(path, coordinates=coordinates, labels=labels)
    return coordinates, labels, {**metadata, 'input_parameters_sha256': fingerprint}


def term_labels(texts, labels):
    # These exclusions affect labels only, not Granite vectors or the geometry.
    visible = [label_text(text) for text in texts]
    generic = {'vulnerability', 'vulnerabilities', 'vulnerable', 'allows', 'allow', 'allowing', 'attacker',
               'attackers', 'affected', 'affects', 'versions', 'version', 'issue', 'could', 'using', 'via',
               'prior', 'remote', 'arbitrary', 'successful', 'exploitation', 'exploit', 'exploited', 'cve',
               'cwe', 'technical', 'summary', 'unspecified', 'following', 'fixed', 'discovered', 'exists',
               'resolved', 'classified', 'problematic', 'identified', 'manipulation', 'unknown'}
    vectorizer = TfidfVectorizer(stop_words=sorted(set(ENGLISH_STOP_WORDS) | generic),
        token_pattern=r'(?u)\b[a-z][a-z]{2,}\b', lowercase=True, min_df=10, max_df=.35,
        max_features=15000, ngram_range=(1, 2), sublinear_tf=True, dtype=np.float32)
    matrix = vectorizer.fit_transform(visible)
    terms = vectorizer.get_feature_names_out()
    global_mean = np.asarray(matrix.mean(axis=0)).ravel()
    result = {}
    for cluster in sorted(set(labels)):
        if cluster < 0:
            result[int(cluster)] = {'label': 'Unassigned', 'terms': []}
            continue
        part = matrix[labels == cluster]
        scores = np.asarray(part.mean(axis=0)).ravel() - global_mean
        counts = np.asarray((part > 0).sum(axis=0)).ravel()
        scores[counts < max(5, .02*part.shape[0])] = 0
        selected = []
        for idx in np.argsort(-scores, kind='stable'):
            if scores[idx] <= 0 or len(selected) == 6:
                break
            term = terms[idx]
            if any(term in value['term'] or value['term'] in term for value in selected):
                continue
            selected.append({'term': term, 'distinguishing_tfidf': round(float(scores[idx]), 6),
                             'documents': int(counts[idx])})
        result[int(cluster)] = {'label': ' · '.join(value['term'] for value in selected[:3]) or 'Mixed technical wording',
                                'terms': selected}
    return result
