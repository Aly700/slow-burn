export function parseCsv(source) {
  const text = source.replace(/^\uFEFF/, '');
  const rows = [];
  let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      if (quoted && text[i + 1] === '"') { field += '"'; i++; }
      else quoted = !quoted;
    } else if (c === ',' && !quoted) { row.push(field); field = ''; }
    else if ((c === '\n' || c === '\r') && !quoted) {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field);
      if (row.some(Boolean)) rows.push(row);
      row = []; field = '';
    } else field += c;
  }
  if (quoted) throw new Error('Unclosed CSV quote');
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

const numeric = new Set(['rank', 'score', 'epss', 'any_exploit', 'exploitdb', 'metasploit', 'nuclei', 'poc_github', 'cvss3_score']);
export function convertScores(source, limit = 1000) {
  const [headers, ...rows] = parseCsv(source);
  if (!headers) return [];
  return rows.slice(0, limit).map(row => Object.fromEntries(headers.map((key, i) => {
    const raw = row[i] ?? '';
    if (key === 'reasons') {
      try { const parsed = JSON.parse(raw); return [key, Array.isArray(parsed) ? parsed : []]; }
      catch { return [key, []]; }
    }
    if (numeric.has(key)) return [key, raw.trim() !== '' && Number.isFinite(Number(raw)) ? Number(raw) : null];
    return [key, raw];
  })));
}
