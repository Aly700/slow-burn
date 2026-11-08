import { readFile, writeFile, mkdir, rm, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { decodeMap } from '../src/graniteMap.ts';
import { renderField } from '../src/heroField.ts';

const root = new URL('../', import.meta.url);
const out = new URL('public/hero/', root);
const inputs = await Promise.all(['../../artifacts/map_2026.json', '../src/heroField.ts', '../src/styles.css', './render-hero.mjs'].map(p => readFile(new URL(p, import.meta.url))));
const hash = createHash('sha256').update(Buffer.concat(inputs)).digest('hex');
const variants = [['desktop', 1440, 824], ['phone', 390, 784]];
const names = variants.flatMap(([name]) => [1, 2].flatMap(d => ['avif', 'webp'].map(ext => `${name}-${d}x.${ext}`)));
try {
  const manifest = JSON.parse(await readFile(new URL('manifest.json', out)));
  if (!process.argv.includes('--force') && manifest.inputHash === hash && await Promise.all(names.map(async name => {
    const bytes = await readFile(new URL(name, out));
    return manifest.files[name]?.sha256 === createHash('sha256').update(bytes).digest('hex');
  })).then(v => v.every(Boolean))) {
    console.log('Hero posters verified against map, renderer and tokens.');
    process.exit(0);
  }
} catch { /* A missing or stale poster is rebuilt below. */ }
if (process.argv.includes('--check')) throw new Error('Hero posters need regeneration');

function rgb(name) {
  const css = inputs[2].toString();
  const match = css.match(new RegExp(`--${name}:\\s*oklch\\(([\\d.]+)\\s+([\\d.]+)\\s+([\\d.]+)\\)`));
  if (!match) throw new Error(`Expected an absolute OKLCH token: ${name}`);
  const [l, c, h] = match.slice(1).map(Number), a = c * Math.cos(h * Math.PI / 180), b = c * Math.sin(h * Math.PI / 180);
  const L = (l + .3963377774 * a + .2158037573 * b) ** 3;
  const M = (l - .1055613458 * a - .0638541728 * b) ** 3;
  const S = (l - .0894841775 * a - 1.291485548 * b) ** 3;
  return [4.0767416621 * L - 3.3077115913 * M + .2309699292 * S, -1.2684380046 * L + 2.6097574011 * M - .3413193965 * S, -.0041960863 * L - .7034186147 * M + 1.707614701 * S].map(v => Math.round(255 * Math.max(0, Math.min(1, v <= .0031308 ? 12.92 * v : 1.055 * v ** (1 / 2.4) - .055))));
}
function crc(bytes) {
  let c = 0xffffffff;
  for (const b of bytes) { c ^= b; for (let j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ c >>> 1 : c >>> 1; }
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, bytes) {
  const name = Buffer.from(type), size = Buffer.alloc(4), check = Buffer.alloc(4);
  size.writeUInt32BE(bytes.length); check.writeUInt32BE(crc(Buffer.concat([name, bytes])));
  return Buffer.concat([size, name, bytes, check]);
}
function png(pixels, w, h) {
  const header = Buffer.alloc(13); header.writeUInt32BE(w); header.writeUInt32BE(h, 4); header[8] = 8; header[9] = 6;
  const scan = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; y++) scan.set(pixels.subarray(y * w * 4, (y + 1) * w * 4), y * (w * 4 + 1) + 1);
  return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk('IHDR', header), chunk('IDAT', deflateSync(scan)), chunk('IEND', Buffer.alloc(0))]);
}
await mkdir(out, { recursive: true });
const map = decodeMap(JSON.parse(inputs[0]));
const palette = { bg: rgb('bg'), ash: rgb('field-ash'), ember: rgb('accent') };
const manifest = { inputHash: hash, rows: map.n, benchmark: map.groups.dust.length, picks: map.groups.top.length, anchors: map.groups.anchors.length, files: {} };
const temporary = new URL('.field.png', out);
try {
  for (const [name, w, h] of variants) for (const d of [1, 2]) {
    await writeFile(temporary, png(renderField(map, w * d, h * d, palette, d), w * d, h * d));
    for (const ext of ['avif', 'webp']) {
      const filename = `${name}-${d}x.${ext}`, target = fileURLToPath(new URL(filename, out));
      execFileSync(ext === 'avif' ? 'avifenc' : 'cwebp', ext === 'avif'
        ? ['-q', '62', '-s', '6', '-j', '2', '--yuv', '444', fileURLToPath(temporary), target]
        : ['-quiet', '-q', '83', fileURLToPath(temporary), '-o', target], { stdio: 'ignore' });
      const bytes = await readFile(target);
      if ((await stat(target)).size > 450000) throw new Error(`${filename} exceeds 450 KB`);
      manifest.files[filename] = { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), width: w * d, height: h * d };
      console.log(`${filename}: ${bytes.length} bytes`);
    }
  }
  await writeFile(new URL('manifest.json', out), JSON.stringify(manifest, null, 2) + '\n');
} finally { await rm(temporary, { force: true }); }
