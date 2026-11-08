import type { Score } from './types';
export interface Component {
  name: string; version: string; ecosystem: string; purl: string;
  vendor: string; product?: string;
}
export interface Inventory { format: string; components: Component[]; warnings: string[] }
export interface AffectedRange {
  version: string; update: string; startIncluding: string; startExcluding: string;
  endIncluding: string; endExcluding: string;
}
export type Confidence = 'version_range' | 'product' | 'name_only';
export interface SoftwareEvidence {
  component: string; version: string; ecosystem: string; purl: string;
  vendor: string; product: string; confidence: Confidence; evidence: string;
}
export interface SoftwareIndex {
  schema_version: number;
  coverage: { benchmark_cves: number; cpe_cves: number; identity_cves: number };
  cves: [string, number, number, string][];
  products: {vendor: string; product: string; source: 'cpe' | 'identity'; affected: [number, string, string, string, string, string, string][]}[];
}
export function decodeSoftwareIndex(value: SoftwareIndex & {ranges?: string[][]}): SoftwareIndex {
  if (value.schema_version !== 1 || !Array.isArray(value.cves) || !Array.isArray(value.products)) throw new Error('Unsupported software index.');
  if (!value.ranges) return value;
  const ranges = value.ranges;
  return {...value, products:value.products.map(product=>({...product, affected:product.affected.map(item=>
    [item[0], ...ranges[Number(item[1])]] as [number,string,string,string,string,string,string])}))};
}
export interface SoftwareMatch extends Score { software_matches: SoftwareEvidence[] }
export const confidenceLabel: Record<Confidence, string> = {
  version_range: 'Product + affected version', product: 'Product match', name_only: 'Name only',
};
const text = (value: unknown): string => typeof value === 'string' ? value.trim() : '';
const object = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
const array = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const unknownVersion = (value: string) => /^(NOASSERTION|NONE|\*|-)$/i.test(value) ? '' : value;

function purlParts(value: string) {
  const match = /^pkg:([^/]+)\/(.+?)(?:\?[^#]*)?(?:#.*)?$/.exec(value);
  if (!match) return null;
  try {
    const split = match[2].lastIndexOf('@');
    const hasVersion = split > 0;
    return {ecosystem: match[1].toLowerCase(), name: decodeURIComponent(hasVersion ? match[2].slice(0, split) : match[2]), version: hasVersion ? decodeURIComponent(match[2].slice(split + 1)) : ''};
  } catch { return null; }
}
function cpeParts(value: string) {
  // Escaped or extended identities need a full CPE binding parser; do not guess.
  if (value.includes('\\')) return null;
  const parts = value.split(':');
  if (parts.length !== 13 || parts[0] !== 'cpe' || parts[1] !== '2.3' || !['a','o','h'].includes(parts[2])) return null;
  if (['*','-',''].includes(parts[3]) || ['*','-',''].includes(parts[4])) return null;
  return {vendor: parts[3], product: parts[4]};
}
function component(raw: Record<string, unknown>, ecosystem = ''): Component | null {
  const purl = text(raw.purl), parsed = purlParts(purl), cpe = cpeParts(text(raw.cpe));
  const name = parsed?.name || text(raw.name);
  if (!name) return null;
  const suppliedVersion = unknownVersion(text(raw.version)), purlVersion = unknownVersion(parsed?.version ?? '');
  return {name, version: suppliedVersion && purlVersion && suppliedVersion !== purlVersion ? '' : suppliedVersion || purlVersion,
    ecosystem: parsed?.ecosystem || ecosystem, purl,
    vendor: cpe?.vendor || text(raw.vendor).replace(/^Organization:\s*/i, '').replace(/^(NOASSERTION|NONE)$/i, ''),
    ...(cpe ? {product:cpe.product} : {})};
}
export function parseInventory(source: string): Inventory {
  if (source.length > 5_000_000) throw new Error('Use a file smaller than 5 MB.');
  source = source.replace(/^\uFEFF/, '').trim();
  const components: Component[] = [], warnings: string[] = [];
  let format = '';
  function add(raw: Record<string, unknown>, ecosystem = '') {
    if (components.length >= 20000) throw new Error('Use an inventory with fewer than 20,000 components.');
    const value = component(raw, ecosystem);
    if (value) components.push(value);
    else warnings.push('Skipped a component without a name.');
  }
  if (/^[{[]/.test(source)) {
    let root: Record<string, unknown>;
    try { root = object(JSON.parse(source)); } catch { throw new Error('This JSON could not be read. Check the file and try again.'); }
    if (root.bomFormat === 'CycloneDX') {
      format = 'CycloneDX';
      const pending = [...array(root.components)];
      while (pending.length) {
        const raw = object(pending.shift());
        const supplier = object(raw.supplier);
        add({...raw, vendor: text(supplier.name) || text(raw.publisher)});
        pending.push(...array(raw.components));
      }
    } else if (text(root.spdxVersion).startsWith('SPDX-')) {
      format = 'SPDX';
      for (const item of array(root.packages)) {
        const raw = object(item), refs = array(raw.externalRefs).map(object);
        add({name:raw.name, version:raw.versionInfo, vendor:raw.supplier,
          purl:refs.find(ref=>ref.referenceType === 'purl')?.referenceLocator,
          cpe:refs.find(ref=>ref.referenceType === 'cpe23Type')?.referenceLocator});
      }
    } else if ([1,2,3].includes(Number(root.lockfileVersion))) {
      format = 'npm lockfile';
      if (root.packages && typeof root.packages === 'object') {
        for (const [path, item] of Object.entries(object(root.packages))) {
          const raw = object(item);
          if (!path || raw.link) continue;
          const name = text(raw.name) || path.split('node_modules/').at(-1) || '';
          add({name,version:raw.version}, 'npm');
        }
      } else {
        const pending = Object.entries(object(root.dependencies));
        while (pending.length) {
          const [name, item] = pending.shift()!, raw = object(item);
          add({name, version:raw.version}, 'npm');
          pending.push(...Object.entries(object(raw.dependencies)));
        }
      }
    } else throw new Error('Use CycloneDX JSON, SPDX JSON, an npm lockfile, or requirements.txt.');
  } else {
    format = 'Python requirements';
    for (const line of source.replace(/\\\r?\n/g, ' ').split(/\r?\n/)) {
      const value = line.replace(/\s+#.*$/, '').trim();
      if (!value || value.startsWith('#')) continue;
      if (value.startsWith('-')) { warnings.push('Skipped a requirements option or external file.'); continue; }
      const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$/.exec(value);
      if (!match) { warnings.push('Skipped an unreadable requirement.'); continue; }
      const spec = match[2].split(';')[0].replace(/\s+--hash=\S+/g, '').trim();
      const pin = /^==\s*([0-9]+(?:\.[0-9]+)*(?:[a-zA-Z0-9.+-]*))$/.exec(spec);
      if (spec && !/^(===|==|~=|!=|<=|>=|<|>|@)/.test(spec)) { warnings.push('Skipped an unreadable requirement.'); continue; }
      add({name:match[1],version:pin?.[1] ?? ''}, 'pypi');
    }
  }
  const unique = [...new Map(components.map(c=>[JSON.stringify(c),c])).values()];
  if (!unique.length) throw new Error('No components found. Check the inventory format.');
  return {format,components:unique,warnings};
}
const canonical = (value: string) => value.normalize('NFKC').toLowerCase().replace(/[._\s-]+/g,'-');
function numeric(value: string): number[] | null {
  if (!/^\d+(?:\.\d+)*$/.test(value)) return null;
  const values = value.split('.').map(Number);
  return values.every(Number.isSafeInteger) ? values : null;
}
function compare(a: number[], b: number[]) {
  for (let i=0;i<Math.max(a.length,b.length);i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return Math.sign((a[i] ?? 0) - (b[i] ?? 0));
  }
  return 0;
}
export function versionStatus(version: string, range: AffectedRange): 'inside' | 'outside' | 'unknown' {
  const value = numeric(version);
  if (!value || (range.update && !['*','-'].includes(range.update))) return 'unknown';
  const bounds: [string, (delta: number)=>boolean][] = [
    [range.version, (d: number)=>d === 0], [range.startIncluding, (d: number)=>d >= 0], [range.startExcluding, (d: number)=>d > 0],
    [range.endIncluding, (d: number)=>d <= 0], [range.endExcluding, (d: number)=>d < 0],
  ].filter(([v])=>v && v !== '*' && v !== '-') as [string, (delta:number)=>boolean][];
  if (!bounds.length || bounds.some(([bound])=>!numeric(bound))) return 'unknown';
  return bounds.every(([bound, test])=>test(compare(value,numeric(bound)!))) ? 'inside' : 'outside';
}
function rangeText(range: AffectedRange) {
  return [[range.version,'='],[range.startIncluding,'>='],[range.startExcluding,'>'],[range.endIncluding,'<='],[range.endExcluding,'<']]
    .filter(([v])=>v && v !== '*' && v !== '-').map(([v,op])=>`${op} ${v}`).join(', ');
}
export function matchInventory(components: Component[], index: SoftwareIndex): SoftwareMatch[] {
  const lookup = new Map<string, SoftwareIndex['products']>();
  for (const product of index.products) {
    const key = canonical(product.product);
    lookup.set(key,[...(lookup.get(key) ?? []),product]);
  }
  const results = new Map<string,SoftwareMatch>();
  for (const comp of components) {
    for (const product of lookup.get(canonical(comp.product || comp.name)) ?? []) {
      if (comp.vendor && canonical(comp.vendor) !== canonical(product.vendor)) continue;
      const name = comp.product || comp.name;
      const exactName = comp.ecosystem === 'pypi' && !comp.product
        ? canonical(name) === canonical(product.product)
        : name.toLowerCase() === product.product.toLowerCase();
      const supported = !!comp.vendor && exactName;
      for (const [idx,version,update,startIncluding,startExcluding,endIncluding,endExcluding] of product.affected) {
        const range = {version,update,startIncluding,startExcluding,endIncluding,endExcluding};
        const status = product.source === 'cpe' ? versionStatus(comp.version,range) : 'unknown';
        if (supported && status === 'outside') continue;
        const confidence: Confidence = !supported ? 'name_only' : status === 'inside' ? 'version_range' : 'product';
        const evidence = confidence === 'version_range'
          ? `Supplied CPE: ${product.vendor} / ${product.product}; affected ${rangeText(range)}. Confirm deployment conditions.`
          : `${product.source === 'cpe' ? 'Supplied CPE' : 'Heuristic identity'}: ${product.vendor} / ${product.product}. ${!supported ? 'Product name or ecosystem unverified. ' : ''}Confirm affected versions.`;
        const [cve_id,rank,score,snapshot_month] = index.cves[idx];
        const row = results.get(cve_id) ?? {cve_id,rank,score,snapshot_month,vendor_identity:product.vendor,product_identity:product.product,software_matches:[]};
        const match = {component:comp.name, version:comp.version, ecosystem:comp.ecosystem, purl:comp.purl,
          vendor:product.vendor, product:product.product, confidence, evidence};
        const same = row.software_matches.findIndex(m=>m.component === comp.name && m.version === comp.version && m.vendor === product.vendor && m.product === product.product);
        const weight = {version_range:3,product:2,name_only:1};
        if (same < 0) row.software_matches.push(match);
        else if (weight[confidence] > weight[row.software_matches[same].confidence]) row.software_matches[same] = match;
        results.set(cve_id,row);
      }
    }
  }
  return [...results.values()].sort((a,b)=>a.rank-b.rank || a.cve_id.localeCompare(b.cve_id));
}
