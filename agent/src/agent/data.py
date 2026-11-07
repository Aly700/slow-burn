import calendar
import csv
import fcntl
import hashlib
import json
import math
import re
from collections import Counter

import duckdb

from .config import Settings

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")
SIGNAL_FLAGS = ("in_kev", "exploitdb", "metasploit", "nuclei", "poc_github")
CVSS_PARTS = ("cvss3_version", "cvss3_score", "cvss3_severity", "cvss3_vector", "attack_vector", "attack_complexity",
              "privileges_required", "user_interaction", "scope", "confidentiality_impact", "integrity_impact",
              "availability_impact", "cvss3_exploitability_score", "cvss3_impact_score", "cvss3_source")
NVD_VINTAGE = "Provided NVD extract dated 2026-11-06; narrative, CVSS, CWE and product metadata are not historical snapshots."


def validate_cve(cve_id):
    if not CVE_RE.fullmatch(cve_id):
        raise ValueError("invalid CVE ID")
    return cve_id


def month_end(month):
    if not re.fullmatch(r"\d{4}-\d{2}", month):
        raise ValueError("invalid snapshot month")
    year, m = map(int, month.split("-"))
    if year < 2024 or year > 2026 or not 1 <= m <= 12:
        raise ValueError("snapshot outside the supplied historical data")
    return f"{month}-{calendar.monthrange(year, m)[1]:02d}"


def number(value):
    if value is None or value == "":
        return None
    val = float(value)
    return val if math.isfinite(val) else None


def signals(row):
    return {"epss": number(row.get("epss")), **{f: int(row[f]) if row.get(f) not in (None, "") else None for f in SIGNAL_FLAGS}}


def build_cache(settings):
    settings.cache.mkdir(parents=True, exist_ok=True)
    names = ["vulnerabilities", "known_exploited", "weakness_types", "scoreboard_2026", "affected_products", "exploit_signals_2024", "exploit_signals_2025"]
    manifest = [(name, (settings.data / f"{name}.csv").stat().st_size, (settings.data / f"{name}.csv").stat().st_mtime_ns) for name in names]
    key = hashlib.sha256(json.dumps(manifest).encode()).hexdigest()[:16]
    path = settings.cache / f"corpus-v1-{key}.duckdb"
    with (settings.cache / "corpus.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if path.exists():
            return path
        tmp = path.with_suffix(".building")
        if tmp.exists():
            tmp.unlink()
        db = duckdb.connect(str(tmp))
        db.execute("SET threads=4")
        for name in names:
            source = str(settings.data / f"{name}.csv")
            if name == "affected_products":
                db.execute(f"CREATE TABLE {name} AS SELECT DISTINCT cve_id,vendor,product FROM read_csv(?, all_varchar=true, quote='\"', escape='\"') WHERE vulnerable='Y'", [source])
            else:
                db.execute(f"CREATE TABLE {name} AS SELECT * FROM read_csv(?, all_varchar=true, quote='\"', escape='\"')", [source])
            key_col = "cwe_id" if name == "weakness_types" else "cve_id"
            db.execute(f"CREATE INDEX {name}_id ON {name}({key_col})")
        db.close()
        tmp.replace(path)
    return path


class DataTools:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        self.db = duckdb.connect(str(build_cache(self.settings)), read_only=True)
        self.db.execute("SET threads=2")
        self._scores_stamp = None
        self._scores = {}
        self.active_cve = None
        self.active_month = None
        self.index = None

    def close(self):
        self.db.close()

    def rows(self, sql, params=None):
        cursor = self.db.execute(sql, params or [])
        cols = [c[0] for c in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def load_scores(self):
        stamp = (self.settings.scores.stat().st_mtime_ns, self.settings.scores.stat().st_size)
        if stamp != self._scores_stamp:
            raw = self.settings.scores.read_bytes()
            self.score_hash = hashlib.sha256(raw).hexdigest()
            self._scores = {r["cve_id"]: r for r in csv.DictReader(raw.decode().splitlines())}
            self._scores_stamp = stamp
        return self._scores

    def snapshot(self, cve_id):
        if self.settings.snapshot_month:
            month_end(self.settings.snapshot_month)
            return self.settings.snapshot_month
        self.load_scores()
        rows = self.rows("SELECT snapshot_month FROM scoreboard_2026 WHERE cve_id=?", [cve_id])
        month = rows[0]["snapshot_month"] if rows else self._scores.get(cve_id, {}).get("snapshot_month")
        if not month:
            raise ValueError("CVE has no ranking snapshot; historical evaluation must specify a month")
        month_end(month)
        return month

    def get_cve(self, cve_id):
        validate_cve(cve_id)
        month = self.snapshot(cve_id)
        rows = self.rows("SELECT * FROM vulnerabilities WHERE cve_id=?", [cve_id])
        if not rows:
            raise ValueError("CVE is absent from the provided NVD extract")
        row = rows[0]
        if (row.get("published") or "9999")[:10] > month_end(month):
            raise ValueError("CVE was published after the requested snapshot")
        self.active_cve, self.active_month = cve_id, month
        if month.startswith("2026"):
            ss = self.rows("SELECT * FROM scoreboard_2026 WHERE cve_id=? AND snapshot_month=?", [cve_id, month])
            signal = {**ss[0], "in_kev": "0"} if ss else {}
        else:
            ss = self.rows("SELECT * FROM exploit_signals_2025 WHERE cve_id=? AND month=? UNION ALL SELECT * FROM exploit_signals_2024 WHERE cve_id=? AND month=?", [cve_id, month, cve_id, month])
            signal = ss[0] if ss else {}
        cwes = []
        for cwe in (row.get("cwe_ids") or "").split(";"):
            if not cwe:
                continue
            name = self.rows("SELECT name FROM weakness_types WHERE cwe_id=?", [cwe])
            cwes.append({"id": cwe, "name": name[0]["name"] if name else "Name unavailable in supplied CWE dictionary"})
        products = self.rows("SELECT vendor,product FROM affected_products WHERE cve_id=? ORDER BY vendor,product LIMIT 12", [cve_id])
        cvss = {key: (number(row.get(key)) if key.endswith("_score") else row.get(key)) for key in CVSS_PARTS}
        vendor = products[0]["vendor"] if products else None
        # An assigner domain is only a candidate name, never proof of product ownership.
        if not vendor and "@" in (row.get("assigner") or ""):
            domain = row["assigner"].split("@")[-1].split(".")[0]
            if domain not in {"cve", "mitre", "github", "nist"}:
                vendor = domain
        return {"cve_id": cve_id, "description": row.get("description"), "published": row.get("published"),
                "assigner": row.get("assigner"), "cvss": cvss, "cwes": cwes, "products": products,
                "vendor_candidate": vendor, "snapshot_month": month, "snapshot_end": month_end(month),
                "signals": signals(signal), "signals_available": bool(ss),
                "provenance": {"signals": "month-end scoreboard or historical monthly file", "metadata": NVD_VINTAGE},
                "warnings": [] if ss else ["No signal row for this month; missing is not zero."]}

    def explain_score(self, cve_id):
        validate_cve(cve_id)
        rows = self.load_scores()
        row = rows.get(cve_id)
        if not row:
            return {"cve_id": cve_id, "rank": None, "score": None, "reasons": [], "score_is_probability": False,
                    "score_file_sha256": self.score_hash, "warnings": ["No model ranking for this historical snapshot."]}
        expected_month = self.active_month if self.active_cve == cve_id else self.snapshot(cve_id)
        if row["snapshot_month"] != expected_month:
            raise ValueError("ranking snapshot does not match the CVE's scoreboard or investigation snapshot")
        score = number(row["score"])
        reasons = json.loads(row["reasons"])
        if not isinstance(reasons, list) or len(reasons) > 5:
            raise ValueError("scores reasons must be a JSON list with at most five entries")
        if row.get("ranking_kind") == "evaluation_reasons_only":
            return {"cve_id": cve_id, "rank": None, "score": None, "snapshot_month": row["snapshot_month"],
                    "reasons": reasons, "score_is_probability": False, "score_file_sha256": self.score_hash,
                    "ranking_kind": "evaluation_reasons_only",
                    "warnings": ["Historical fixture supplies snapshot reasons only; no model rank or KEV probability is available."]}
        warnings = []
        valid_score = score is not None and 0 <= score <= 1
        if not valid_score:
            warnings.append("Seed ranking score is outside [0,1]; it is not a calibrated probability.")
        if any(not all(key in reason for key in ("feature", "label", "value", "contribution")) for reason in reasons):
            warnings.append("Seed reasons omit label or contribution; raw feature values are preserved.")
        return {"cve_id": cve_id, "rank": int(row["rank"]), "score": score, "snapshot_month": row["snapshot_month"],
                "reasons": reasons, "score_is_probability": valid_score, "warnings": warnings,
                "score_file_sha256": self.score_hash}

    def vendor_history(self, vendor):
        if not self.active_month:
            raise ValueError("call get_cve first to establish the snapshot for this session")
        if len(vendor) > 100:
            raise ValueError("vendor is too long")
        cutoff = min(month_end(self.active_month), "2025-12-31")
        norm = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
        candidates = self.rows("SELECT * FROM known_exploited WHERE date_added<=? AND cve_id<>?", [cutoff, self.active_cve])
        matches = [r for r in candidates if norm(r["vendor"]) == norm(vendor)]
        counts = Counter(c for r in matches for c in (r.get("cwe_ids") or "").split(";") if c)
        vintage_ok = cutoff >= "2025-12-31"
        return {"vendor": vendor, "prior_kev": len(matches), "last_added": max((r["date_added"] for r in matches), default=None),
                "ransomware_known": sum(r.get("known_ransomware_use") == "Known" for r in matches) if vintage_ok else None,
                "ransomware_known_as_of": "2025-12-31", "snapshot_end": month_end(self.active_month), "catalog_cutoff": cutoff,
                "top_cwes": [{"cwe_id": c, "count": n} for c, n in counts.most_common(5)],
                "match_method": "case and punctuation normalized exact vendor name; no corporate alias expansion",
                "warnings": ["Ransomware status and CWE fields have no historical change dates."] if not vintage_ok else []}

    def signal_timeline(self, cve_id):
        validate_cve(cve_id)
        month = self.snapshot(cve_id)
        history = self.rows("SELECT * FROM exploit_signals_2024 WHERE cve_id=? AND month<=? UNION ALL SELECT * FROM exploit_signals_2025 WHERE cve_id=? AND month<=? ORDER BY month", [cve_id, month, cve_id, month])
        board = self.rows("SELECT * FROM scoreboard_2026 WHERE cve_id=? AND snapshot_month<=?", [cve_id, month])
        history += [{**r, "month": r["snapshot_month"], "in_kev": "0"} for r in board]
        published = self.rows("SELECT published FROM vulnerabilities WHERE cve_id=?", [cve_id])
        start = max("2024-01", published[0]["published"][:7]) if published else "2024-01"
        available = {r["month"] for r in history}
        expected = [f"{y}-{m:02}" for y in range(2024, 2027) for m in range(1, 13) if start <= f"{y}-{m:02}" <= month]
        return {"cve_id": cve_id, "snapshot_month": month, "months": [{"month": r["month"], **signals(r)} for r in history],
                "missing_months": [m for m in expected if m not in available],
                "warnings": ["No continuous 2026 history was provided; only each candidate's scoreboard snapshot is available.",
                             "EPSS model changed in March 2025; values across that boundary are not directly comparable.",
                             "February 2025 has incomplete coverage; absent rows are unknown."]}

    def similar_exploited(self, cve_id, k=3):
        validate_cve(cve_id)
        if not 1 <= k <= 10:
            raise ValueError("k must be between 1 and 10")
        from .embeddings import EmbeddingIndex
        if self.index is None:
            self.index = EmbeddingIndex(self.settings, self)
        row = self.rows("SELECT description FROM vulnerabilities WHERE cve_id=?", [cve_id])
        if not row:
            raise ValueError("unknown CVE")
        return self.index.search(cve_id, row[0]["description"], min(month_end(self.snapshot(cve_id)), "2025-12-31"), k)

    def queue(self, n=15, filters=None):
        if not 1 <= n <= 100:
            raise ValueError("n must be between 1 and 100")
        filters = filters or {}
        if set(filters) - {"snapshot_month", "any_exploit", "min_epss"}:
            raise ValueError("unsupported queue filter")
        cutoff_month = self.active_month or self.settings.snapshot_month
        if "snapshot_month" in filters:
            month_end(filters["snapshot_month"])
            if cutoff_month and filters["snapshot_month"] > cutoff_month:
                raise ValueError("queue filter is after the investigation snapshot")
        rows = sorted(self.load_scores().values(), key=lambda r: int(r["rank"]))
        result = []
        for r in rows:
            if cutoff_month and r["snapshot_month"] > cutoff_month:
                continue
            if "snapshot_month" in filters and r["snapshot_month"] != filters["snapshot_month"]:
                continue
            if "any_exploit" in filters and int(r.get("any_exploit", 0)) != int(filters["any_exploit"]):
                continue
            if "min_epss" in filters and (number(r.get("epss")) or 0) < float(filters["min_epss"]):
                continue
            result.append({"cve_id": r["cve_id"], "rank": int(r["rank"]), "snapshot_month": r["snapshot_month"], "score": number(r["score"])})
            if len(result) == n:
                break
        return {"items": result, "score_file_sha256": self.score_hash, "snapshot_cutoff": cutoff_month,
                "rank_scope": "supplied benchmark-wide ranking, not a historical observation"}
