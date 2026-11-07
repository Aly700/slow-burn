import pandas as pd, numpy as np, re
D="data/"
v = pd.read_csv(D+"vulnerabilities.csv", usecols=["cve_id","published","description","assigner"], dtype=str)
v["published"]=pd.to_datetime(v.published, errors="coerce")
k = pd.read_csv(D+"known_exploited.csv", dtype=str); k["date_added"]=pd.to_datetime(k.date_added)
v=v.merge(k[["cve_id","date_added"]],on="cve_id",how="left")
t=v[(v.published>="2025-01-01")&(v.published<"2026-01-01")].copy()
eom=t.published.dt.to_period("M").dt.to_timestamp(how="end")
inpm = t.date_added.notna() & (t.date_added<=eom)
print("2025 published:",len(t),"| KEV by end of publish month (zero-day-ish, excluded from benchmark):",int(inpm.sum()),
      "| KEV later:",int((t.date_added.notna() & ~inpm).sum()))
t=t[~inpm].copy(); t["y"]=t.date_added.notna().astype(int)
d=t.description.fillna("").str.lower()
pats={"in-the-wild wording":r"exploited in the wild|may have been exploited|actively exploited|aware of (a )?reports?|limited, targeted",
 "edge device words":r"\b(vpn|firewall|gateway|router|load balancer|ssl ?vpn|remote access|file transfer|mft)\b",
 "unauth RCE wording":r"unauthenticated.{0,60}(remote code|execute arbitrary|command injection)|remote code execution",
 "deserialization":r"deserializ",
 "path traversal":r"path traversal|directory traversal",
 "wordpress plugin":r"wordpress|plugin for wordpress"}
for n,p in pats.items():
    m=d.str.contains(p,regex=True)
    print(f"{n:22s} n={int(m.sum()):6d}  laterKEV={int(t.y[m].sum()):3d}  rate={100*t.y[m].mean():.2f}%  (base {100*t.y.mean():.3f}%)")
# how old are the CVE ids that got KEV later
t["idyear"]=t.cve_id.str.slice(4,8)
print("\nlater-KEV by CVE-id year:",t[t.y==1].idyear.value_counts().to_dict())
print("\nlag publish->KEV (days) for later-KEV:",(t[t.y==1].date_added-t[t.y==1].published).dt.days.describe()[["min","50%","max"]].to_dict())
