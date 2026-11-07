"""Baseline ranking: public exploit code first, then EPSS. Writes the artifact contract the other parts read."""
import json, pandas as pd, numpy as np
D, A = "data/", "artifacts/"
s = pd.read_csv(D + "scoreboard_2026.csv", dtype={"cve_id": str, "snapshot_month": str})
v = pd.read_csv(D + "vulnerabilities.csv", usecols=["cve_id", "assigner", "description", "cvss3_score", "attack_vector", "cwe_ids"], dtype=str)
s = s.merge(v, on="cve_id", how="left")
flags = ["exploitdb", "metasploit", "nuclei", "poc_github"]
s["any_exploit"] = s[flags].max(axis=1)
s["score"] = s["any_exploit"] + s["epss"].fillna(0)
s = s.sort_values("score", ascending=False).reset_index(drop=True)
s["rank"] = np.arange(1, len(s) + 1)
s["reasons"] = [json.dumps([{"feature": "any_exploit", "value": int(a)}, {"feature": "epss", "value": e}]) for a, e in zip(s.any_exploit, s.epss)]
cols = ["rank", "cve_id", "published", "snapshot_month", "score", "epss", "any_exploit", *flags, "cvss3_score", "attack_vector", "cwe_ids", "assigner", "description", "reasons"]
s[cols].head(5000).to_csv(A + "scores_2026_top5000.csv", index=False)
s[["cve_id"]].head(500).to_csv(A + "top500.csv", index=False)
json.dump({"model": "baseline: exploit flag then EPSS", "note": "placeholder until the model lands"}, open(A + "model_card.json", "w"), indent=2)
print("wrote", len(s), "ranked; top500 + top5000")
