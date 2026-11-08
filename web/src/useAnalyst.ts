import { useEffect, useRef, useState } from 'react';
import type { AnalystEvaluation, AnalystSession } from './types';
import { applyAskEvent, connectAnalyst, newQuestion } from './analyst';
import { fallbackQuestion } from './api';
import { useApi } from './useApi';

export function useAnalyst(evaluation?: AnalystEvaluation | null) {
  const [input, setInput] = useState('');
  const { api, health, checkHealth, label } = useApi();
  const [session, setSession] = useState<AnalystSession>({...newQuestion('', 'recorded'), status:'idle'});
  const active = useRef(session), generation = useRef(0), stop = useRef<(() => void) | null>(null);
  useEffect(() => () => { generation.current++; stop.current?.(); }, []);
  const launch = (question = input) => {
    const q = question.trim();
    if (!q || q.length > 1000) return;
    setInput(q); stop.current?.();
    const id = ++generation.current;
    if (!api.base || health !== 'ready') {
      setSession(fallbackQuestion(q, evaluation, api.message));
      return;
    }
    active.current = newQuestion(q, 'live'); setSession(active.current);
    const fail = (message: string) => {
      if (id !== generation.current) return;
      stop.current?.();
      setSession(fallbackQuestion(q, evaluation, message.includes('Daily limit reached') ? message : 'Live answer unavailable, showing recorded answers.'));
    };
    try {
      stop.current = connectAnalyst(q, event => {
        if (id !== generation.current) return;
        active.current = applyAskEvent(active.current, event); setSession(active.current);
      }, fail, undefined, api.base);
    } catch { fail('Live connection unavailable.'); }
  };
  const cancel = () => {
    generation.current++; stop.current?.();
    setSession(p => ({...p, status:'cancelled', message:'Question stopped. No completed answer is available.'}));
  };
  return { input, setInput, health, session, launch, cancel, checkHealth, label, hosted: api.backend === 'watsonx' };
}
