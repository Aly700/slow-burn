import { useEffect, useRef } from 'react';
import { decodeMap } from '../graniteMap';
import { renderField } from '../heroField';
import type { RGB } from '../heroField';
import { readCanvasTheme } from '../theme';
import '../ashHero.css';

export function AshHero() {
  const canvas = useRef<HTMLCanvasElement>(null);
  const field = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const node = canvas.current, host = field.current;
    if (!node || !host) return;
    const reduced = matchMedia('(prefers-reduced-motion: reduce)');
    if (reduced.matches) return;
    const controller = new AbortController();
    let observer: ResizeObserver | undefined;
    const timer = window.setTimeout(async () => {
      try {
        const response = await fetch(`${import.meta.env.BASE_URL}data/map_2026.json`, { signal: controller.signal });
        if (!response.ok) return;
        const map = decodeMap(await response.json());
        if (controller.signal.aborted) return;
        const theme = readCanvasTheme(), sample = document.createElement('canvas').getContext('2d')!;
        const color = (value: string): RGB => { sample.clearRect(0, 0, 1, 1); sample.fillStyle = value; sample.fillRect(0, 0, 1, 1); return Array.from(sample.getImageData(0, 0, 1, 1).data).slice(0, 3) as RGB; };
        const draw = () => {
          const d = Math.min(devicePixelRatio, 2), rect = host.getBoundingClientRect();
          node.width = Math.round(rect.width * d); node.height = Math.round(rect.height * d);
          const pixels = renderField(map, node.width, node.height, { bg: color(theme.bg), ash: color(theme.fieldAsh), ember: color(theme.accent) }, d);
          node.getContext('2d')?.putImageData(new ImageData(pixels, node.width, node.height), 0, 0);
          node.dataset.points = String(map.n); node.classList.add('is-ready');
        };
        observer = new ResizeObserver(draw); observer.observe(host); draw();
      } catch { /* The complete static field remains available if enhancement fails. */ }
    }, 1800);
    return () => { clearTimeout(timer); controller.abort(); observer?.disconnect(); };
  }, []);
  const base = `${import.meta.env.BASE_URL}hero/`;
  return <section id="overview" className="ash-hero" aria-labelledby="ash-title">
    <div className="ash-field" ref={field} aria-hidden="true">
      <picture className="ash-poster">
        <source media="(max-width: 700px)" type="image/avif" srcSet={`${base}phone-1x.avif 1x, ${base}phone-2x.avif 2x`} />
        <source media="(max-width: 700px)" type="image/webp" srcSet={`${base}phone-1x.webp 1x, ${base}phone-2x.webp 2x`} />
        <source type="image/avif" srcSet={`${base}desktop-1x.avif 1x, ${base}desktop-2x.avif 2x`} />
        <img src={`${base}desktop-1x.webp`} srcSet={`${base}desktop-1x.webp 1x, ${base}desktop-2x.webp 2x`} alt="" width="1440" height="824" fetchPriority="high" />
      </picture>
      <canvas ref={canvas} />
    </div>
    <div className="ash-top"><span>IBM Granite / description map</span><span>72,987 descriptions</span></div>
    <div className="ash-copy">
      <h1 id="ash-title">Ranking vulnerabilities by likelihood of exploitation</h1>
      <p>In 2025, our top 500 held <strong>22 of the 55</strong> later-exploited CVEs, against 5 for CVSS and 10 for EPSS.</p>
      <a className="ash-explore" href="#granite-map">Explore the description map <span aria-hidden="true">↗</span></a>
    </div>
    <div className="ash-bottom">
      <div className="ash-legend"><span><i />72,670 benchmark CVEs</span><span><i />500 picks</span><span><i />317 past exploited</span></div>
      <a href="#backtest">View the 2025 backtest <span aria-hidden="true">↓</span></a>
    </div>
  </section>;
}
