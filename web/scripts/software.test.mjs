import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseInventory, matchInventory, versionStatus } from '../src/software.ts';

const parse = value => parseInventory(typeof value === 'string' ? value : JSON.stringify(value));
test('CycloneDX reads nested components, purl namespace, CPE and versions', () => {
  const result = parse({bomFormat:'CycloneDX',specVersion:'1.5',components:[{name:'server',components:[{name:'widget',version:'1.2.3',purl:'pkg:npm/%40example/widget@1.2.3',cpe:'cpe:2.3:a:example:widget:1.2.3:*:*:*:*:*:*:*'}]}]});
  assert.equal(result.components.length,2);
  assert.equal(result.components[1].name,'@example/widget');
  assert.equal(result.components[1].ecosystem,'npm');
  assert.equal(result.components[1].vendor,'example');
  assert.equal(result.components[1].product,'widget');
});
test('SPDX reads package purls and supplier without using document version', () => {
  const result=parse({spdxVersion:'SPDX-2.3',packages:[{name:'Django',versionInfo:'5.0.1',supplier:'Organization: djangoproject',externalRefs:[{referenceType:'purl',referenceLocator:'pkg:pypi/django@5.0.1'}]}]});
  assert.equal(result.components[0].version,'5.0.1');
  assert.equal(result.components[0].vendor,'djangoproject');
  assert.equal(result.components[0].ecosystem,'pypi');
});
test('npm lock v2/v3 skips root and links but preserves nested and scoped installs', () => {
  const result=parse({lockfileVersion:3,packages:{'':{name:'app',version:'1.0.0'},'node_modules/vite':{version:'6.0.0'},'node_modules/a/node_modules/vite':{version:'5.0.0'},'node_modules/@example/widget':{version:'1.2.0'},'node_modules/local':{link:true}}});
  assert.deepEqual(result.components.map(c=>[c.name,c.version]),[['vite','6.0.0'],['vite','5.0.0'],['@example/widget','1.2.0']]);
});
test('npm lock v1 walks transitive dependencies',()=>{
  const result=parse({lockfileVersion:1,dependencies:{vite:{version:'5.0.0',dependencies:{widget:{version:'2.0.0'}}}}});
  assert.deepEqual(result.components.map(c=>c.name),['vite','widget']);
});
test('requirements only treats a plain == pin as an installed version',()=>{
  const result=parse('# demo\nDjango[extra]==5.0.1 ; python_version>="3"\nrequests>=2.0\nFlask==3.*\n-r other.txt\n-e git+https://example.invalid/repo\nwidget @ https://example.invalid/a.whl\npillow==10.0.0 \\\n --hash=sha256:abc\n');
  assert.deepEqual(result.components.map(c=>[c.name,c.version]),[['Django','5.0.1'],['requests',''],['Flask',''],['widget',''],['pillow','10.0.0']]);
  assert.equal(result.warnings.length,2);
});
test('invalid JSON, unknown JSON and empty inventories fail clearly',()=>{
  for (const input of ['{broken','{}','[]','# nothing']) assert.throws(()=>parse(input));
});
test('range comparison respects boundaries and declines nonnumeric versions and updates',()=>{
  const range={version:'',update:'',startIncluding:'1.2',startExcluding:'',endIncluding:'',endExcluding:'2.0'};
  assert.equal(versionStatus('1.2.0',range),'inside');
  assert.equal(versionStatus('2.0',range),'outside');
  assert.equal(versionStatus('1.1.9',range),'outside');
  assert.equal(versionStatus('1.5rc1',range),'unknown');
  assert.equal(versionStatus('1.5',{...range,endExcluding:'2.0-beta'}),'unknown');
  assert.equal(versionStatus('1.5',{...range,update:'sp1'}),'unknown');
  assert.equal(versionStatus('1.5',{...range,startIncluding:'',endExcluding:''}),'unknown');
});
const index={schema_version:1,coverage:{},cves:[['CVE-A',90,0.1,'2026-01'],['CVE-B',5,0.2,'2026-02']],products:[
  {vendor:'example',product:'widget',source:'cpe',affected:[[0,'','','1.0','','','2.0'],[1,'','','1.0','','','2.0']]},
  {vendor:'other',product:'widget',source:'cpe',affected:[[0,'','','','','','']]},
]};
test('matcher preserves rank, deduplicates CVEs and confirms ranges only with vendor support',()=>{
  const components=[{name:'widget',product:'widget',vendor:'example',version:'1.5',ecosystem:'',purl:''}];
  const result=matchInventory(components,index);
  assert.deepEqual(result.map(r=>r.cve_id),['CVE-B','CVE-A']);
  assert.equal(result[0].software_matches[0].confidence,'version_range');
  assert.match(result[0].software_matches[0].evidence,/>= 1.0.*< 2.0/);
  assert.equal(matchInventory([{...components[0],version:'2.0'}],index).length,0);
  assert.equal(matchInventory([{...components[0],version:''}],index)[0].software_matches[0].confidence,'product');
  assert.equal(matchInventory([{...components[0],vendor:''}],index)[0].software_matches[0].confidence,'name_only');
  assert.equal(matchInventory([{...components[0],vendor:'missing'}],index).length,0);
});
test('heuristic identities never claim an affected version and scoped names never collapse to a leaf',()=>{
  const heuristic={...index,products:[{...index.products[0],source:'identity'}]};
  assert.equal(matchInventory([{name:'widget',vendor:'example',version:'1.5',ecosystem:'',purl:''}],heuristic)[0].software_matches[0].confidence,'product');
  assert.equal(matchInventory([{name:'@different/widget',vendor:'',version:'1.5',ecosystem:'npm',purl:''}],index).length,0);
});

test('exports carry inventory confidence and evidence without approving tickets',async()=>{
  const {queueCsv,ticketDrafts}=await import('../src/exports.ts');
  const result=matchInventory([{name:'widget',vendor:'example',version:'1.5',ecosystem:'npm',purl:''}],index);
  const ticket=ticketDrafts(result,[])[0];
  assert.equal(ticket.software_matches[0].confidence,'version_range');
  assert.equal(ticket.verdict,'pending');
  assert.match(queueCsv(result,[]),/version_range/);
  assert.match(queueCsv(result,[]),/Confirm deployment conditions/);
});

test('committed samples match supplied identities and preserve confidence through packed index decoding',async()=>{
  const fs=await import('node:fs/promises');
  const {decodeSoftwareIndex}=await import('../src/software.ts');
  const index=decodeSoftwareIndex(JSON.parse(await fs.readFile(new URL('../../artifacts/software_index_2026.json',import.meta.url),'utf8')));
  for(const [file,count] of [['python-sbom.json',3],['package-lock.json',2]]) {
    const input=parse(await fs.readFile(new URL(`../public/samples/${file}`,import.meta.url),'utf8'));
    const rows=matchInventory(input.components,index);
    assert.equal(new Set(rows.flatMap(r=>r.software_matches.map(m=>m.component))).size,count);
    assert.ok(rows.every((r,i)=>!i || r.rank>rows[i-1].rank));
    if(file==='python-sbom.json') assert.deepEqual(new Set(rows.flatMap(r=>r.software_matches.map(m=>m.confidence))),new Set(['version_range','product','name_only']));
    else assert.deepEqual(new Set(rows.flatMap(r=>r.software_matches.map(m=>m.confidence))),new Set(['name_only']));
  }
});

test('punctuation-only product aliases cannot upgrade an npm identity to a confirmed affected version',()=>{
  const cpes={...index,products:[{...index.products[0],product:'widget_name'}]};
  const matches=matchInventory([{name:'widget-name',vendor:'example',version:'1.5',ecosystem:'npm',purl:''}],cpes);
  assert.equal(matches[0].software_matches[0].confidence,'name_only');
});
test('explicit operating-system CPE identities are preserved',()=>{
  const parsed=parse({bomFormat:'CycloneDX',components:[{name:'Example OS',version:'1.0',cpe:'cpe:2.3:o:example:example_os:1.0:*:*:*:*:*:*:*'}]});
  assert.equal(parsed.components[0].product,'example_os');
});
