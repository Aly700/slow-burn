import { useCallback, useEffect, useState } from 'react';
import type { Data, Score } from './types';
import { list } from './lib';
import { Hero, Methods, Signals, Timing } from './components/Story';
import { Queue } from './components/Queue';
import { Briefing } from './components/Briefing';
import { Icon } from './components/Icon';

export default function App() {
  const [data, setData] = useState<Data>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [selected, setSelected] = useState<Score | null>(null);
  const [active, setActive] = useState('overview');
  useEffect(() => {
    let active = true;
    fetch(`${import.meta.env.BASE_URL}data/bundle.json`).then(response => {if (!response.ok) throw new Error('Missing data');return response.json();}).then(value => {if (active) setData(value ?? {});}).catch(() => {if (active) setError(true);}).finally(() => {if (active) setLoading(false);});
    return () => {active = false;};
  }, []);
  useEffect(() => {
    const observer = new IntersectionObserver(entries => {for (const entry of entries) if (entry.isIntersecting) setActive(entry.target.id);}, {rootMargin: '-10% 0px -65% 0px'});
    document.querySelectorAll('main section[id]').forEach(section => observer.observe(section));
    return () => observer.disconnect();
  }, [loading]);
  const close = useCallback(() => setSelected(null), []);
  return <>
    <a className="skip-link" href="#queue">Skip to fix-first queue</a>
    <header className="site-header"><a className="brand" href="#overview" aria-label="Before the Breach overview"><span className="brand-mark"><span/><span/><span/></span><strong>Before the Breach<span> / </span></strong></a><nav aria-label="Main navigation">{[['overview','Overview'],['timing','Discovery'],['queue','Fix-first queue'],['methods','Methods']].map(([id, label]) => <a key={id} className={(active === id || (id === 'timing' && active === 'signals')) ? 'active' : ''} href={`#${id}`}>{label}</a>)}</nav><div className="header-end"><span>SHERIDAN DATATHON 2026</span><span className="track-label">IBM TRACK</span></div></header>
    {error && <div className="data-banner" role="status">Data bundle unavailable. Findings remain pending; run the data sync before the demo.</div>}
    <main aria-busy={loading}><Hero data={data}/><Timing findings={data.findings}/><Signals findings={data.findings}/><Queue data={data} onOpen={setSelected}/><Methods data={data}/></main>
    <footer className="site-footer"><a href="#overview">Before the Breach <Icon name="arrow" size={16}/></a><span>Know what to fix. Know why.</span><span>Sheridan Datathon · 07–08 Nov 2026</span></footer>
    {selected && <Briefing key={selected.cve_id} score={selected} run={list(data.runs).find(run => run.cve_id === selected.cve_id)} fixture={data.meta?.runs_source === 'fixtures'} onClose={close}/>}
  </>;
}
