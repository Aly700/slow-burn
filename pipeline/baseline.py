"""Print the three reference rankings on the historical eligible cohort."""
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.data import cohort
from pipeline.evaluate import baseline_scores, ranking_metrics

if __name__ == '__main__':
    rows = cohort(2025)
    print(json.dumps([ranking_metrics(rows, score, name) for name, score in baseline_scores(rows).items()], indent=2))
