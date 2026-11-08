import { useCallback, useEffect, useRef, useState } from 'react';
import { findApi, HOSTED_API, liveLabel } from './api';
import type { ApiConnection } from './api';

export function useApi() {
  const [api, setApi] = useState<ApiConnection>({base:null});
  const [health, setHealth] = useState<'checking'|'ready'|'offline'>('checking');
  const request = useRef<AbortController | null>(null);
  const checkHealth = useCallback(async () => {
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    const next = await findApi(location.hostname, HOSTED_API, fetch, controller.signal);
    if (!controller.signal.aborted) { setApi(next); setHealth(next.base ? 'ready' : 'offline'); }
    return next;
  }, []);
  useEffect(() => {
    void checkHealth();
    // A hosted page must allow the service to scale to zero while idle.
    const timer = !HOSTED_API ? setInterval(() => void checkHealth(), 15000) : undefined;
    return () => { clearInterval(timer); request.current?.abort(); };
  }, [checkHealth]);
  return { api, health, checkHealth, label: liveLabel(api) };
}
