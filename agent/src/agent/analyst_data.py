"""Bounded ranking queries with explicit missing values and row-specific cutoffs."""
from collections import Counter, defaultdict
import json
import re

from pydantic import BaseModel, ConfigDict, Field

from .data import month_end, number, validate_cve, NVD_VINTAGE


class RankingFilters(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    vendor: str | None = Field(default=None, max_length=100)
    product: str | None = Field(default=None, max_length=150)
    cwe: str | None = Field(default=None, pattern=r'^CWE-\d+$')
    text: str | None = Field(default=None, max_length=150)
    top_n: int = Field(default=5000, ge=1, le=5000, description='Overall rank cutoff ONLY when the question says within/of the top N. First K matching results uses limit, not top_n.')
    min_epss: float | None = Field(default=None, ge=0, le=1)
    public_signal: bool | None = None
    has_vendor_history: bool | None = None


def normalize(value):
    return re.sub(r'[^a-z0-9]', '', value.lower())


class RankedData:
    def __init__(self, data):
        self.data=data
        self.stamp=None

    def prepare(self):
        scores=self.data.load_scores()
        if self.stamp==self.data.score_hash: return
        ids=list(scores)
        products=defaultdict(list)
        for row in self.data.rows('SELECT cve_id,vendor,product FROM affected_products WHERE cve_id IN (SELECT unnest(?)) ORDER BY vendor,product',[ids]):
            products[row['cve_id']].append(row)
        histories=defaultdict(list)
        for row in self.data.rows("SELECT cve_id,vendor,date_added FROM known_exploited WHERE date_added<='2025-12-31'"):
            histories[normalize(row['vendor'])].append(row)
        result=[]
        for raw in sorted(scores.values(),key=lambda r:int(r['rank']))[:5000]:
            if self.data.settings.snapshot_month and raw['snapshot_month']>self.data.settings.snapshot_month: continue
            p=products[raw['cve_id']]
            vendor=p[0]['vendor'] if p else None
            if not vendor and '@' in (raw.get('assigner') or ''):
                candidate=raw['assigner'].split('@')[-1].split('.')[0]
                if candidate not in {'cve','mitre','github','nist'}: vendor=candidate
            cutoff=min(month_end(raw['snapshot_month']),'2025-12-31')
            history=None if not vendor else sum(r['date_added']<=cutoff and r['cve_id']!=raw['cve_id'] for r in histories[normalize(vendor)])
            flags=[number(raw.get(k)) for k in ('exploitdb','metasploit','nuclei','poc_github')]
            public=True if 1 in flags else False if all(f==0 for f in flags) else None
            result.append({'cve_id':raw['cve_id'],'rank':int(raw['rank']),'score':number(raw['score']),
                           'snapshot_month':raw['snapshot_month'],'vendor':vendor,
                           'products':sorted({r['product'] for r in p}), 'description':raw.get('description') or '',
                           'cwes':[c for c in (raw.get('cwe_ids') or '').split(';') if c],
                           'epss':number(raw.get('epss')),'public_signal':public,
                           'public_sources':[k for k in ('exploitdb','metasploit','nuclei','poc_github') if number(raw.get(k))==1],
                           'vendor_prior_kev':history,'catalog_cutoff':cutoff,'reasons':json.loads(raw['reasons'])})
        self.items=result
        self.stamp=self.data.score_hash

    def filtered(self, filters):
        f=RankingFilters.model_validate(filters or {})
        self.prepare()
        items=[]
        for r in self.items:
            if r['rank']>f.top_n: continue
            if f.vendor and normalize(r['vendor'] or '')!=normalize(f.vendor): continue
            if f.product and not any(f.product.casefold() in p.casefold() for p in r['products']) and f.product.casefold() not in r['description'].casefold(): continue
            if f.cwe and f.cwe not in r['cwes']: continue
            if f.text and f.text.casefold() not in r['description'].casefold(): continue
            if f.min_epss is not None and (r['epss'] is None or r['epss']<f.min_epss): continue
            if f.public_signal is not None and r['public_signal'] is not f.public_signal: continue
            if f.has_vendor_history is not None and (r['vendor_prior_kev'] is None or (r['vendor_prior_kev']>0) is not f.has_vendor_history): continue
            items.append(r)
        return f,items

    def header(self,f,items):
        return {'filters':f.model_dump(exclude_none=True),'matched_count':len(items),'scope':'supplied top 5000 ranking only',
                'score_file_sha256':self.stamp,'metadata_note':NVD_VINTAGE,
                'history_note':'Exact normalized candidate vendor; no alias expansion. Unknown vendor is not zero history.'}

    def search(self,filters=None,limit=5):
        if type(limit) is not int or not 1<=limit<=10: raise ValueError('limit must be between 1 and 10')
        f,items=self.filtered(filters)
        return {**self.header(f,items),'returned_count':min(limit,len(items)),
                'items':[{k:v for k,v in r.items() if k!='description'} for r in items[:limit]]}

    def summary(self,filters=None):
        f,items=self.filtered(filters)
        cwes=Counter(c for r in items for c in set(r['cwes']))
        return {**self.header(f,items),
                'public_material_count':sum(r['public_signal'] is True for r in items),
                'no_public_material_count':sum(r['public_signal'] is False for r in items),
                'unknown_public_material_count':sum(r['public_signal'] is None for r in items),
                'vendor_history_count':sum(r['vendor_prior_kev'] is not None and r['vendor_prior_kev']>0 for r in items),
                'no_vendor_history_count':sum(r['vendor_prior_kev']==0 for r in items),
                'unknown_vendor_count':sum(r['vendor_prior_kev'] is None for r in items),
                'top_cwes':[{'cwe':k,'count':v} for k,v in cwes.most_common(5)]}

    def compare(self,cve_a,cve_b):
        validate_cve(cve_a);validate_cve(cve_b)
        return {'left':self.data.explain_score(cve_a),'right':self.data.explain_score(cve_b),
                'scope':'supplied ranking; reasons describe model contributions, not proof of causation'}
