import type { AnalystEvaluation, AnalystSession, Run } from './types';
import { newQuestion, questionKey, recordedAnswer } from './analyst.ts';

export const HOSTED_API = (import.meta.env?.VITE_SLOWBURN_API_URL ?? '').trim();
// Override only for isolated local testing; the offline default stays on 8765.
const LOCAL_API = import.meta.env?.VITE_SLOWBURN_LOCAL_API_URL ?? 'http://127.0.0.1:8765';
const local = (host: string) => ['localhost', '127.0.0.1', '[::1]'].includes(host);
export type ApiConnection = { base: string | null; backend?: string; public?: boolean; message?: string };

export function apiCandidates(host: string, configured = HOSTED_API): string[] {
  const candidates = local(host) ? [LOCAL_API.replace(/\/+$/, '')] : [];
  if (configured) {
    try {
      const url = new URL(configured);
      if ((url.protocol === 'https:' || (url.protocol === 'http:' && local(url.hostname))) && !url.username && !url.password && !url.search && !url.hash)
        candidates.push(configured.replace(/\/+$/, ''));
    } catch { /* An invalid build setting leaves recorded answers available. */ }
  }
  return [...new Set(candidates)];
}

export async function findApi(host: string, configured = HOSTED_API, request: typeof fetch = fetch, signal?: AbortSignal): Promise<ApiConnection> {
  let message: string | undefined;
  for (const base of apiCandidates(host, configured)) {
    if (signal?.aborted) break;
    try {
      const timeout = AbortSignal.timeout(base === 'http://127.0.0.1:8765' ? 1800 : 8000);
      const response = await request(`${base}/live/health`, { signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
      const health = await response.json();
      if (response.ok && health.ready === true && !health.budget?.exhausted)
        return { base, backend: health.backend ?? 'mlx', public: health.public === true };
      if (health.budget?.exhausted) message = 'Daily limit reached, showing recorded answers.';
    } catch { /* Network and cold-start failures use the recorded experience. */ }
  }
  return { base: null, message };
}

export const liveLabel = (api: ApiConnection) => api.backend === 'watsonx'
  ? 'Live · IBM Granite on watsonx' : 'Local Granite ready';

export function fallbackQuestion(q: string, evaluation?: AnalystEvaluation | null, message?: string): AnalystSession {
  const record = evaluation?.results?.find(r => questionKey(r.question) === questionKey(q));
  return record ? { ...recordedAnswer(record), message }
    : { ...newQuestion(q, 'recorded'), status: 'complete', message: `${message ? message+' ' : ''}No recorded answer for this question. Choose a suggestion below.` };
}

export const previewOnly = (run?: Pick<Run, 'public'>, host = location.hostname, configured = HOSTED_API) =>
  run?.public === true || (!!configured && !local(host));
