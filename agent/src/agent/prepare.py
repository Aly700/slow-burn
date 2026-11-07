import argparse
import json

from .config import Settings
from .data import DataTools


def main():
    parser = argparse.ArgumentParser(description="Build local read-only data and Granite retrieval caches")
    parser.add_argument("--embeddings", action="store_true")
    args = parser.parse_args()
    settings = Settings()
    data = DataTools(settings)
    print(json.dumps({"data_cache": "ready", "scores": len(data.load_scores())}), flush=True)
    if args.embeddings:
        from .embeddings import EmbeddingIndex
        print(json.dumps(EmbeddingIndex.build(settings, data), indent=2), flush=True)


if __name__ == "__main__":
    main()
