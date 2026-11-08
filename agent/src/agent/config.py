from dataclasses import dataclass, field
import os
from pathlib import Path

# Live inference uses preloaded local weights and never consults remote metadata.
os.environ.setdefault('HF_HUB_OFFLINE','1')
os.environ.setdefault('TRANSFORMERS_OFFLINE','1')

ROOT = Path(__file__).resolve().parents[3]
MODEL = "mlx-community/granite-4.0-h-small-4bit"
MODEL_REVISION = "db4baaa911c39582ab9fdcfc9f43a6bbc343d54a"
IBM_MODEL = "ibm-granite/granite-4.0-h-small"
EMBED_MODEL = "ibm-granite/granite-embedding-30m-english"
EMBED_REVISION = "9b5b096411652ec1189c68fcfb90d0a82c5b45af"


@dataclass
class Settings:
    root: Path = field(default_factory=lambda: Path(os.getenv("TRIAGE_ROOT", ROOT)).resolve())
    model: str = field(default_factory=lambda: os.getenv("TRIAGE_MODEL", MODEL))
    max_seconds: float = 55.0
    max_turns: int = 4
    max_tool_calls: int = 10
    snapshot_month: str | None = field(default_factory=lambda: os.getenv("TRIAGE_SNAPSHOT_MONTH"))
    score_path: Path | None = field(default_factory=lambda: Path(os.environ["TRIAGE_SCORES"]) if os.getenv("TRIAGE_SCORES") else None)

    @property
    def data(self):
        return self.root / "data"

    @property
    def artifacts(self):
        return self.root / "artifacts"

    @property
    def cache(self):
        return self.artifacts / "cache"

    @property
    def scores(self):
        return self.score_path or self.artifacts / "scores_2026_top5000.csv"

    @property
    def state(self):
        return Path(os.getenv("TRIAGE_STATE_DB", self.cache / "triage.sqlite"))

    @property
    def tickets(self):
        return Path(os.getenv("TRIAGE_TICKETS", self.artifacts / "tickets.jsonl"))
