import type { Data } from './types';

export function workflowExample(data: Data) {
  if (data.meta?.runs_source !== 'recorded') return undefined;
  for (const cve of ['CVE-2026-39808', 'CVE-2026-42533']) {
    const run = data.runs?.find(item => item.cve_id === cve && !item.fixture && item.state === 'WAITING_APPROVAL');
    const score = data.scores?.find(item => item.cve_id === cve);
    if (!run || !score) continue;
    const product = score.product_identity || run.briefing?.claims
      ?.filter(claim => claim.verified)
      .flatMap(claim => claim.evidence ?? [])
      .find(evidence => evidence.tool === 'get_cve' && evidence.field === 'description' && evidence.quote &&
        typeof evidence.value === 'string' && evidence.value.includes(evidence.quote))?.quote;
    return { score, run, product };
  }
  return undefined;
}
