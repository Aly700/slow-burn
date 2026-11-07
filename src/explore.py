import pandas as pd, numpy as np
D = "data/"
v = pd.read_csv(D+"vulnerabilities.csv", usecols=["cve_id","published","assigner","cvss3_score","attack_vector","cwe_ids","nvd_status"], dtype=str)
v["published"] = pd.to_datetime(v["published"], errors="coerce")
v["cvss3_score"] = pd.to_numeric(v["cvss3_score"], errors="coerce")
k = pd.read_csv(D+"known_exploited.csv", dtype=str)
k["date_added"] = pd.to_datetime(k["date_added"])
v = v.merge(k[["cve_id","date_added","vendor"]], on="cve_id", how="left")

# 2025 backtest: published 2025, not in KEV by end of publish month, label = added later by 2025-12-31
t = v[(v.published >= "2025-01-01") & (v.published < "2026-01-01")].copy()
t["pm"] = t.published.dt.to_period("M")
eom = t.pm.dt.to_timestamp(how="end")
t = t[~(t.date_added.notna() & (t.date_added <= eom))]
t["y"] = t.date_added.notna().astype(int)
print("2025 pool", len(t), "later-KEV", t.y.sum())

s = pd.read_csv(D+"exploit_signals_2025.csv", dtype={"month":str,"cve_id":str})
t["month"] = t.pm.astype(str)
t = t.merge(s[["month","cve_id","epss","exploitdb","metasploit","nuclei","poc_github"]], on=["month","cve_id"], how="left")
for c in ["epss","exploitdb","metasploit","nuclei","poc_github"]: t[c] = pd.to_numeric(t[c], errors="coerce")
t[["exploitdb","metasploit","nuclei","poc_github"]] = t[["exploitdb","metasploit","nuclei","poc_github"]].fillna(0)
t["anyexp"] = t[["exploitdb","metasploit","nuclei","poc_github"]].max(axis=1)

# prior-KEV history of the assigner: KEV entries whose CVE (any year) was added before 2025 and shares the assigner
hist = v[v.date_added.notna() & (v.date_added < "2025-01-01")]
ak = hist.groupby("assigner").size().rename("assigner_prior_kev")
an = v[v.published < "2025-01-01"].groupby("assigner").size().rename("assigner_prior_n")
t = t.join(ak, on="assigner").join(an, on="assigner")
t["assigner_prior_kev"] = t.assigner_prior_kev.fillna(0); t["assigner_prior_n"] = t.assigner_prior_n.fillna(0)
t["assigner_rate"] = (t.assigner_prior_kev + 0.01) / (t.assigner_prior_n + 10)

def top(col, n=500, asc=False, tie=None):
    o = t.sort_values([col] + ([tie] if tie else []), ascending=[asc] + ([False] if tie else []))
    return int(o.head(n).y.sum())
print("top500 hits | CVSS:", top("cvss3_score"), "| EPSS:", top("epss"), "| exploit then EPSS:", top("anyexp", tie="epss"),
      "| assigner KEV rate:", top("assigner_rate", tie="epss"))
t["combo"] = np.log(t.assigner_rate) + 0.5*np.log(t.epss.fillna(1e-5)+1e-5) + 1.0*t.anyexp + 0.3*(t.attack_vector=="NETWORK")
print("simple combo:", top("combo"))
print("\nlater-KEV by assigner (2025 pool):")
g = t.groupby("assigner").agg(n=("y","size"), kev=("y","sum")).sort_values("kev", ascending=False).head(15)
g["rate%"] = (100*g.kev/g.n).round(2); print(g.to_string())
print("\nbase rate %:", round(100*t.y.mean(),3))
print("share of later-KEV whose assigner had ANY prior KEV:", round(t[t.y==1].assigner_prior_kev.gt(0).mean(),3),
      "| share of all pool:", round(t.assigner_prior_kev.gt(0).mean(),3))
