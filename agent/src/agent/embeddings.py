import hashlib
import json
import os
from pathlib import Path
import time

import numpy as np

from .config import EMBED_MODEL, EMBED_REVISION, Settings


class EmbeddingIndex:
    def __init__(self, settings, data):
        self.settings = settings
        self.kev = data.rows("SELECT * FROM known_exploited WHERE date_added<='2025-12-31' ORDER BY cve_id")
        candidate_ids = sorted(data.load_scores())
        candidate_rows = data.rows("SELECT cve_id,description FROM vulnerabilities WHERE cve_id IN (SELECT unnest(?)) ORDER BY cve_id", [candidate_ids])
        self.texts = [r.get("short_description") or "" for r in self.kev] + [r.get("description") or "" for r in candidate_rows]
        payload = json.dumps({"model": EMBED_MODEL, "revision": EMBED_REVISION, "ids": [r["cve_id"] for r in self.kev] + candidate_ids, "texts": self.texts}, sort_keys=True)
        key = hashlib.sha256(payload.encode()).hexdigest()[:20]
        self.path = settings.cache / f"granite-embeddings-v1-{key}.npz"
        self.meta_path = self.path.with_suffix(".json")
        if not self.path.exists() or not self.meta_path.exists():
            raise FileNotFoundError("Granite embedding cache is missing or stale. Run python -m agent.prepare --embeddings.")
        cached = np.load(self.path, allow_pickle=False)
        self.vectors = cached["kev"]
        self.queries = dict(zip(cached["ids"].tolist(), cached["candidates"]))
        self.metadata = json.loads(self.meta_path.read_text())
        self._model = None

    @staticmethod
    def encoder():
        import torch
        from sentence_transformers import SentenceTransformer
        torch.set_num_threads(4)
        model = SentenceTransformer(EMBED_MODEL, revision=EMBED_REVISION, device="cpu", trust_remote_code=False, local_files_only=True)
        model.max_seq_length = 256
        return model

    @classmethod
    def build(cls, settings, data):
        shell = cls.__new__(cls)
        # Resolve the same content-addressed path without loading model weights on reads.
        kev = data.rows("SELECT * FROM known_exploited WHERE date_added<='2025-12-31' ORDER BY cve_id")
        ids = sorted(data.load_scores())
        candidates = data.rows("SELECT cve_id,description FROM vulnerabilities WHERE cve_id IN (SELECT unnest(?)) ORDER BY cve_id", [ids])
        texts = [r.get("short_description") or "" for r in kev] + [r.get("description") or "" for r in candidates]
        payload = json.dumps({"model": EMBED_MODEL, "revision": EMBED_REVISION, "ids": [r["cve_id"] for r in kev] + ids, "texts": texts}, sort_keys=True)
        key = hashlib.sha256(payload.encode()).hexdigest()[:20]
        path = settings.cache / f"granite-embeddings-v1-{key}.npz"
        if path.exists() and path.with_suffix(".json").exists():
            return json.loads(path.with_suffix(".json").read_text())
        start = time.monotonic()
        model = cls.encoder()
        vectors = model.encode(texts, batch_size=64, normalize_embeddings=True, show_progress_bar=True).astype(np.float32)
        tmp = path.with_suffix(".building.npz")
        np.savez_compressed(tmp, kev=vectors[:len(kev)], candidates=vectors[len(kev):], ids=np.array([r["cve_id"] for r in candidates]))
        tmp.replace(path)
        meta = {"model": EMBED_MODEL, "revision": EMBED_REVISION, "max_length": 256, "normalization": "L2; cosine similarity", "kev_count": len(kev), "candidate_count": len(candidates), "seconds": round(time.monotonic() - start, 3), "content_sha256": hashlib.sha256(payload.encode()).hexdigest()}
        path.with_suffix(".json").write_text(json.dumps(meta, indent=2))
        return meta

    def search(self, cve_id, description, cutoff, k):
        query = self.queries.get(cve_id)
        if query is None:
            key = hashlib.sha256(json.dumps([EMBED_MODEL,EMBED_REVISION,description]).encode()).hexdigest()
            cache = self.settings.cache/'query_vectors'
            cache.mkdir(exist_ok=True)
            path = cache/f'{key}.npy'
            if path.exists():
                query = np.load(path,allow_pickle=False)
            else:
                if self._model is None:
                    self._model = self.encoder()
                query = self._model.encode([description], normalize_embeddings=True)[0]
                tmp=path.with_suffix('.pending.npy')
                np.save(tmp,query,allow_pickle=False)
                tmp.replace(path)
            self.queries[cve_id] = query
        scores = self.vectors @ query
        allowed = [i for i, row in enumerate(self.kev) if row["date_added"] <= cutoff and row["cve_id"] != cve_id]
        top = sorted(allowed, key=lambda i: (-float(scores[i]), self.kev[i]["cve_id"]))[:k]
        matches = [{"cve_id": self.kev[i]["cve_id"], "similarity": round(float(scores[i]), 6), "date_added": self.kev[i]["date_added"], "vendor": self.kev[i].get("vendor"), "product": self.kev[i].get("product"), "description": self.kev[i].get("short_description"), "cwe_ids": self.kev[i].get("cwe_ids")} for i in top]
        return {"cve_id": cve_id, "matches": matches, "catalog_cutoff": cutoff, "embedding_model": self.metadata["model"], "embedding_revision": self.metadata.get("revision"),
                "warnings": ["Similarity is a description analogy, not proof of exploitation or affected product identity.", "KEV descriptions are from the supplied 2025-12-31 extract; only admission dates can be filtered historically."]}
