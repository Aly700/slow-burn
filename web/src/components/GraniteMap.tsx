import { useEffect, useRef, useState } from "react";
import type { Data } from "../types";
import { decodeMap, overlaps, zoomAt } from "../graniteMap";
import type { DecodedMap, LabelBox, MapView } from "../graniteMap";
import { number, percent } from "../lib";
import "../graniteMap.css";

type Layer = "dust" | "wordpress" | "watch" | "top" | "anchors";
const layerNames: Record<Layer, string> = {
  dust: "2026 field",
  wordpress: "WordPress",
  watch: "Product review",
  top: "Top 500",
  anchors: "Past exploited",
};
const colors: Record<Layer, string> = {
  dust: "#55859a",
  wordpress: "#7b8298",
  watch: "#92b7a7",
  top: "#ed9569",
  anchors: "#ffe3b1",
};
const mapCache = new Map<string, Promise<DecodedMap>>();
function loadMap(file: string) {
  const url = `${import.meta.env.BASE_URL}data/${file}`;
  if (!mapCache.has(url))
    mapCache.set(
      url,
      fetch(url)
        .then((response) => {
          if (!response.ok) throw new Error("Missing map");
          return response.json();
        })
        .then(decodeMap)
        .catch((error) => {
          mapCache.delete(url);
          throw error;
        }),
    );
  return mapCache.get(url)!;
}
export function MapEvidence({ data }: { data: Data }) {
  const check = data.findings?.map?.neighbour_check;
  return (
    <div className="map-evidence">
      <p>
        In the pre-registered check, later-exploited 2025 bugs sat closer to
        already-exploited 2024 ones{" "}
        <strong>
          {percent(check?.primary_2025?.probability_positive_is_closer, 0)}
        </strong>{" "}
        of the time, against{" "}
        <strong>
          {percent(check?.primary_2025?.permutation?.null_mean, 0)}
        </strong>{" "}
        by chance; within the no-public-signal blind spot, it was{" "}
        <strong>
          {percent(
            check?.no_signal_sensitivity?.probability_positive_is_closer,
            0,
          )}
        </strong>
        .
      </p>
      <span>
        Measured in the original Granite vectors, independently of this layout.
        Similarity is not a risk score.
      </span>
    </div>
  );
}
export function GraniteMap({
  data,
  appendix = false,
}: {
  data: Data;
  appendix?: boolean;
}) {
  const root = useRef<HTMLDivElement>(null),
    canvas = useRef<HTMLCanvasElement>(null);
  const [ready, setReady] = useState(appendix),
    [map, setMap] = useState<DecodedMap | null>(null),
    [error, setError] = useState(false),
    [attempt, setAttempt] = useState(0);
  const [layers, setLayers] = useState<Record<Layer, boolean>>({
    dust: true,
    wordpress: true,
    watch: false,
    top: true,
    anchors: true,
  });
  const [labels, setLabels] = useState(true);
  const [hover, setHover] = useState<{
    cve?: string;
    region: string;
    tags: string;
    index: number;
  } | null>(null);
  const [zoom, setZoom] = useState(1);
  const [selectedRegion, setSelectedRegion] = useState("");
  const controls = useRef<{
    zoom: (factor: number) => void;
    reset: () => void;
    region: (id: number) => void;
  } | null>(null);
  const file = data.lazy?.map?.file;
  useEffect(() => {
    if (ready) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setReady(true);
          observer.disconnect();
        }
      },
      { rootMargin: "250px" },
    );
    if (root.current) observer.observe(root.current);
    return () => observer.disconnect();
  }, [ready]);
  useEffect(() => {
    if (!ready || !file) return;
    let active = true;
    setError(false);
    loadMap(file)
      .then((value) => {
        if (active) setMap(value);
      })
      .catch(() => {
        if (active) setError(true);
      });
    return () => {
      active = false;
    };
  }, [ready, file, attempt]);
  const drawOptions = useRef({ layers, labels });
  const redraw = useRef<() => void>(() => {});
  useEffect(() => {
    drawOptions.current = { layers, labels };
    redraw.current();
  }, [layers, labels]);
  useEffect(() => {
    const element = canvas.current;
    if (!map || !element) return;
    const ctx = element.getContext("2d", { alpha: false });
    if (!ctx) return;
    let width = 0,
      height = 0,
      unit = 1,
      frame = 0,
      disposed = false;
    let view: MapView = { x: 0, y: 0, zoom: 1 };
    let pointer: { x: number; y: number; moved: boolean } | null = null;
    let selected: number | null = null;
    const sorted = [...map.regions.values()]
      .filter((region) => region.id >= 0)
      .sort((a, b) => b.rows - a.rows);
    const sprites = new Map<string, HTMLCanvasElement>();
    for (const key of ["top", "anchors"] as const) {
      const sprite = document.createElement("canvas");
      sprite.width = sprite.height = 64;
      const c = sprite.getContext("2d")!;
      const glow = c.createRadialGradient(32, 32, 0, 32, 32, 32);
      glow.addColorStop(0, key === "anchors" ? "#ffe3b16a" : "#e2824540");
      glow.addColorStop(0.23, key === "anchors" ? "#e7a97130" : "#dc704118");
      glow.addColorStop(1, "#dc704100");
      c.fillStyle = glow;
      c.fillRect(0, 0, 64, 64);
      sprites.set(key, sprite);
    }
    const project = (x: number, y: number): [number, number] => [
      view.x + x * unit * view.zoom,
      view.y + y * unit * view.zoom,
    ];
    const constrain = () => {
      const extent = 65535 * unit * view.zoom;
      view.x = Math.min(width * 0.8, Math.max(width * 0.2 - extent, view.x));
      view.y = Math.min(height * 0.8, Math.max(height * 0.2 - extent, view.y));
    };
    function draw() {
      frame = 0;
      if (disposed || !ctx) return;
      const start = performance.now();
      ctx.fillStyle = "#090f12";
      ctx.fillRect(0, 0, width, height);
      const visible = drawOptions.current.layers;
      // Shared scale preserves geometry; every source row remains in its layer.
      for (const layer of [
        "dust",
        "wordpress",
        "watch",
        "top",
        "anchors",
      ] as Layer[]) {
        if (!visible[layer]) continue;
        const lit = layer === "top" || layer === "anchors";
        const size = lit
          ? layer === "anchors"
            ? 2.2
            : 1.8
          : layer === "watch"
            ? 1.25
            : 1.05;
        const radius = size * Math.min(1.8, Math.sqrt(view.zoom));
        ctx.globalAlpha = lit
          ? 1
          : layer === "watch"
            ? 0.65
            : layer === "wordpress"
              ? 0.65
              : 0.58;
        ctx.fillStyle = colors[layer];
        if (!lit) ctx.beginPath();
        for (const index of map!.groups[layer]) {
          const [x, y] = project(
            map!.coordinates[index * 2],
            map!.coordinates[index * 2 + 1],
          );
          if (x < -12 || x > width + 12 || y < -12 || y > height + 12) continue;
          if (lit) {
            const glowSize = layer === "anchors" ? 12 : 9;
            ctx.drawImage(
              sprites.get(layer)!,
              x - glowSize / 2,
              y - glowSize / 2,
              glowSize,
              glowSize,
            );
            ctx.beginPath();
            ctx.arc(x, y, radius * 0.5, 0, Math.PI * 2);
            ctx.fill();
          } else ctx.rect(x - radius / 2, y - radius / 2, radius, radius);
        }
        if (!lit) ctx.fill();
      }
      ctx.globalAlpha = 1;
      if (drawOptions.current.labels) {
        const reserved: LabelBox[] = [
          { x: 10, y: 8, width: 280, height: 55 },
          { x: width - 210, y: height - 62, width: 200, height: 54 },
        ];
        const occupied: LabelBox[] = [];
        ctx.font = '11px "IBM Plex Sans", sans-serif';
        ctx.textBaseline = "middle";
        const limit = width < 500 ? 4 : view.zoom < 2 ? 8 : 12;
        const usedLabels = new Set<string>();
        for (const region of sorted) {
          if (occupied.length >= limit) break;
          const [x, y] = project(...region.centroid);
          if (x < 15 || x > width - 15 || y < 30 || y > height - 30) continue;
          const text = region.label.split(" · ").slice(0, 2).join(" / ");
          if (usedLabels.has(text)) continue;
          const boxWidth = ctx.measureText(text).width + 16;
          const candidates = [
            [x + 36, y - 34],
            [x - boxWidth - 36, y - 34],
            [x + 36, y + 16],
            [x - boxWidth - 36, y + 16],
            [x - boxWidth / 2, y - 62],
            [x - boxWidth / 2, y + 45],
          ];
          const box = candidates
            .map(([x, y]) => ({ x, y, width: boxWidth, height: 23 }))
            .find(
              (box) =>
                box.x > 8 &&
                box.x + box.width < width - 8 &&
                box.y > 8 &&
                box.y + box.height < height - 8 &&
                ![...occupied, ...reserved].some((other) =>
                  overlaps(box, other, 9),
                ),
            );
          if (!box) continue;
          occupied.push(box);
          usedLabels.add(text);
          ctx.strokeStyle = "#5f727860";
          ctx.lineWidth = 0.6;
          ctx.beginPath();
          ctx.moveTo(x, y);
          ctx.lineTo(box.x + box.width / 2, box.y + box.height / 2);
          ctx.stroke();
          ctx.fillStyle = "#0c1419e8";
          ctx.fillRect(box.x, box.y, box.width, box.height);
          ctx.fillStyle = "#b1c3c9";
          ctx.fillText(text, box.x + 8, box.y + box.height / 2);
        }
      }
      if (selected != null) {
        const [x, y] = project(
          map!.coordinates[selected * 2],
          map!.coordinates[selected * 2 + 1],
        );
        ctx.strokeStyle = "#f8e3c1";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(x, y, 7, 0, Math.PI * 2);
        ctx.stroke();
      }
      element!.dataset.renderMs = (performance.now() - start).toFixed(2);
      element!.dataset.zoom = view.zoom.toFixed(2);
    }
    const request = () => {
      if (!frame) frame = requestAnimationFrame(draw);
    };
    redraw.current = request;
    const reset = () => {
      view = {
        x: (width - 65535 * unit) / 2,
        y: (height - 65535 * unit) / 2,
        zoom: 1,
      };
      setZoom(1);
      setSelectedRegion("");
      request();
    };
    const resize = () => {
      const bounds = element.getBoundingClientRect();
      width = bounds.width;
      height = bounds.height;
      const dpr = Math.min(3, window.devicePixelRatio || 1);
      element.width = Math.round(width * dpr);
      element.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      unit = Math.max(1, Math.min(width - 60, height - 50)) / 65535;
      reset();
    };
    const changeZoom = (factor: number, x = width / 2, y = height / 2) => {
      view = zoomAt(view, factor, x, y);
      constrain();
      setZoom(view.zoom);
      request();
    };
    controls.current = {
      zoom: changeZoom,
      reset,
      region: (id: number) => {
        const region = map.regions.get(id);
        if (!region) return;
        view = {
          zoom: 4,
          x: width / 2 - region.centroid[0] * unit * 4,
          y: height / 2 - region.centroid[1] * unit * 4,
        };
        setZoom(4);
        request();
      },
    };
    const position = (event: PointerEvent | WheelEvent) => {
      const box = element.getBoundingClientRect();
      return { x: event.clientX - box.left, y: event.clientY - box.top };
    };
    const inspect = (x: number, y: number) => {
      let closest = -1,
        distance = 100,
        priority = -1;
      for (const layer of [
        "dust",
        "wordpress",
        "watch",
        "top",
        "anchors",
      ] as Layer[]) {
        if (!drawOptions.current.layers[layer]) continue;
        for (const index of map!.groups[layer]) {
          const [px, py] = project(
            map!.coordinates[index * 2],
            map!.coordinates[index * 2 + 1],
          );
          const d = (px - x) ** 2 + (py - y) ** 2,
            named = map!.ids.has(index) ? 1 : 0;
          if (
            d < 100 &&
            ((d < distance && named >= priority) || named > priority)
          ) {
            closest = index;
            distance = d;
            priority = named;
          }
        }
      }
      selected = closest < 0 ? null : closest;
      if (closest < 0) setHover(null);
      else {
        const flag = map!.flags[closest],
          bits = map!.artifact.flag_bits;
        setHover({
          index: closest,
          cve: map!.ids.get(closest),
          region:
            map!.regions.get(map!.clusters[closest])?.label ??
            "No named region",
          tags:
            [
              flag & bits.in_top500 ? "Top 500" : null,
              flag & bits.is_past_exploited
                ? "Past exploited · 2024–2025"
                : null,
              flag & bits.in_product_watch
                ? "Product review · all match types"
                : null,
              flag & bits.is_wordpress ? "WordPress wording" : null,
            ]
              .filter(Boolean)
              .join(" · ") || "2026 field",
        });
      }
      request();
    };
    const down = (event: PointerEvent) => {
      if (event.button !== 0) return;
      pointer = { ...position(event), moved: false };
      element.setPointerCapture(event.pointerId);
      element.focus({ preventScroll: true });
    };
    const move = (event: PointerEvent) => {
      const p = position(event);
      if (pointer) {
        const dx = p.x - pointer.x,
          dy = p.y - pointer.y;
        view.x += dx;
        view.y += dy;
        pointer = {
          ...p,
          moved: pointer.moved || Math.abs(dx) + Math.abs(dy) > 2,
        };
        constrain();
        request();
      } else inspect(p.x, p.y);
    };
    const up = (event: PointerEvent) => {
      if (pointer && !pointer.moved) {
        const p = position(event);
        inspect(p.x, p.y);
      }
      pointer = null;
      if (element.hasPointerCapture(event.pointerId))
        element.releasePointerCapture(event.pointerId);
    };
    const leave = () => {
      if (!pointer) {
        selected = null;
        setHover(null);
        request();
      }
    };
    const wheel = (event: WheelEvent) => {
      event.preventDefault();
      const p = position(event);
      changeZoom(
        Math.exp(-Math.max(-120, Math.min(120, event.deltaY)) * 0.003),
        p.x,
        p.y,
      );
    };
    const key = (event: KeyboardEvent) => {
      if (
        [
          "ArrowLeft",
          "ArrowRight",
          "ArrowUp",
          "ArrowDown",
          "+",
          "=",
          "-",
          "0",
        ].includes(event.key)
      ) {
        event.preventDefault();
        event.stopPropagation();
      }
      if (event.key === "+" || event.key === "=") changeZoom(1.4);
      else if (event.key === "-") changeZoom(1 / 1.4);
      else if (event.key === "0") reset();
      else if (event.key.startsWith("Arrow")) {
        view.x +=
          event.key === "ArrowLeft" ? 50 : event.key === "ArrowRight" ? -50 : 0;
        view.y +=
          event.key === "ArrowUp" ? 50 : event.key === "ArrowDown" ? -50 : 0;
        constrain();
        request();
      }
    };
    const observer = new ResizeObserver(resize);
    observer.observe(element);
    resize();
    element.addEventListener("pointerdown", down);
    element.addEventListener("pointermove", move);
    element.addEventListener("pointerup", up);
    element.addEventListener("pointercancel", up);
    element.addEventListener("pointerleave", leave);
    element.addEventListener("wheel", wheel, { passive: false });
    element.addEventListener("keydown", key);
    return () => {
      disposed = true;
      cancelAnimationFrame(frame);
      observer.disconnect();
      redraw.current = () => {};
      controls.current = null;
      element.removeEventListener("pointerdown", down);
      element.removeEventListener("pointermove", move);
      element.removeEventListener("pointerup", up);
      element.removeEventListener("pointercancel", up);
      element.removeEventListener("pointerleave", leave);
      element.removeEventListener("wheel", wheel);
      element.removeEventListener("keydown", key);
    };
  }, [map]);
  const largest = map
    ? [...map.regions.values()]
        .filter((region) => region.id >= 0)
        .sort((a, b) => b.rows - a.rows)
        .slice(0, 20)
    : [];
  return (
    <div className={`granite-map ${appendix ? "map-appendix" : ""}`} ref={root}>
      <div className="map-heading">
        <div>
          <span className="eyebrow">IBM GRANITE / DESCRIPTION SPACE</span>
          <h2>What Granite reads</h2>
          <p>
            Similar descriptions gather. Earlier attacks leave reference points.
          </p>
        </div>
        <div className="map-total">
          <strong>{number(map?.n ?? data.findings?.map?.rows)}</strong>
          <span>vulnerabilities · one field of language</span>
        </div>
      </div>
      <div className="map-toolbar" aria-label="Map overlays">
        {(["dust", "top", "anchors", "wordpress", "watch"] as Layer[]).map(
          (layer) => (
            <label
              key={layer}
              className={`map-layer layer-${layer}`}
              style={{ "--layer-color": colors[layer] } as React.CSSProperties}
            >
              <input
                type="checkbox"
                checked={layers[layer]}
                onChange={(event) =>
                  setLayers((previous) => ({
                    ...previous,
                    [layer]: event.target.checked,
                  }))
                }
              />
              <i aria-hidden="true" />
              <span>{layerNames[layer]}</span>
              <small>
                {map ? number(map.groups[layer].length) : "pending"}
              </small>
            </label>
          ),
        )}
        <label className="map-label-toggle">
          <input
            type="checkbox"
            checked={labels}
            onChange={(event) => setLabels(event.target.checked)}
          />{" "}
          Region labels
        </label>
      </div>
      <div className="map-field">
        <canvas
          ref={canvas}
          tabIndex={0}
          aria-label="Granite description similarity map. Drag to pan, scroll to zoom; arrow keys pan, plus and minus zoom, zero resets. Use the region picker to explore named regions."
          data-points={map?.n}
        />
        {!map && (
          <div className="map-loading" role="status">
            {error ? (
              <>
                <p>The map could not load.</p>
                <button onClick={() => setAttempt((value) => value + 1)}>
                  Try again
                </button>
              </>
            ) : file ? (
              "Loading the Granite description map…"
            ) : (
              "Map data pending"
            )}
          </div>
        )}
        <div className="map-corner">
          <span>DESCRIPTION SIMILARITY</span>
          <small>Nearness ≠ risk · no 2026 outcome labels</small>
        </div>
        <div className="map-controls">
          <button
            disabled={!map}
            aria-label="Zoom in on map"
            onClick={() => controls.current?.zoom(1.5)}
          >
            +
          </button>
          <button
            disabled={!map}
            aria-label="Zoom out on map"
            onClick={() => controls.current?.zoom(1 / 1.5)}
          >
            −
          </button>
          <button
            disabled={!map}
            aria-label="Reset map view"
            onClick={() => controls.current?.reset()}
          >
            Reset
          </button>
          <span>{zoom.toFixed(1)}×</span>
        </div>
        {hover && (
          <div className="map-tooltip" role="status">
            <strong>{hover.cve ?? "Identifier not bundled"}</strong>
            <span>{hover.region}</span>
            <small>{hover.tags}</small>
            {!hover.cve && (
              <small>
                All points are shown; identifiers are included for highlighted
                cohorts.
              </small>
            )}
          </div>
        )}
      </div>
      <div className="map-under">
        <label>
          Explore a region{" "}
          <select
            aria-label="Explore a map region"
            value={selectedRegion}
            onChange={(event) => {
              setSelectedRegion(event.target.value);
              if (event.target.value)
                controls.current?.region(Number(event.target.value));
              else controls.current?.reset();
            }}
          >
            <option value="">Whole field</option>
            {largest.map((region) => (
              <option key={region.id} value={region.id}>
                {region.label} · {number(region.rows)}
              </option>
            ))}
          </select>
        </label>
        <span>
          Drag to pan · scroll or + / − to zoom · hover or tap a point
        </span>
      </div>
      {layers.watch && (
        <p className="map-overlay-note">
          Product review overlay includes looser name matches. Use the stack
          review list to filter for vendor-supported matches.
        </p>
      )}
      <MapEvidence data={data} />
      <details className="map-methods">
        <summary>How to read this map</summary>
        <p>
          Granite turns descriptions into{" "}
          {number(map?.artifact.embedding?.dimensions)}-dimensional vectors;
          UMAP arranges them here. Region names are automatic text summaries.
          Shared product names, templates and later description revisions can
          explain similarity. Gaps, density and region sizes are not calibrated
          evidence of risk.
        </p>
        <p>
          Past exploited anchors were published in 2024–2025 and listed by the
          end of 2025. The quantitative check uses only 2024 anchors known by
          the end of 2024, and the primary pre-registered cohort.{" "}
          {number(map?.artifact.layout?.duplicate_vector_rows)} duplicate
          vectors overlap; all source rows remain.{" "}
          {number(map?.artifact.embedding?.empty_sanitized_descriptions)} empty
          descriptions have no interpretable position.
        </p>
        <a
          href="https://github.com/Aly700/slow-burn/blob/main/pipeline/MAP_PLAN.md"
          target="_blank"
          rel="noreferrer"
        >
          Read the pre-registered check ↗
        </a>
      </details>
    </div>
  );
}
