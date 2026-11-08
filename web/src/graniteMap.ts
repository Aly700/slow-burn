export interface PackedArray {
  dtype: string;
  shape: number[];
  data: string;
}
export interface MapRegion {
  id: number;
  label: string;
  rows: number;
  centroid: [number, number];
  counts: Record<string, number>;
}
export interface MapArtifact {
  schema_version: number;
  point_count: number;
  coordinates: PackedArray & { origin: [number, number]; scale: number };
  flags: PackedArray;
  flag_bits: Record<string, number>;
  cluster_ids: PackedArray;
  ids: { indices: PackedArray; values: string[] };
  clusters: MapRegion[];
  embedding?: {
    model?: string;
    dimensions?: number;
    empty_sanitized_descriptions?: number;
  };
  layout?: { duplicate_vector_rows?: number };
}
export interface NeighbourCheck {
  primary_2025?: {
    probability_positive_is_closer?: number | null;
    permutation?: { null_mean?: number | null };
  };
  no_signal_sensitivity?: { probability_positive_is_closer?: number | null };
}
function unpack(array: PackedArray, dtype: string, length: number) {
  if (
    array?.dtype !== dtype ||
    array.shape.reduce((a, b) => a * b, 1) !== length
  )
    throw new Error("Map array shape mismatch");
  const bytes = Uint8Array.from(atob(array.data), (char) => char.charCodeAt(0));
  const width = dtype === "|u1" ? 1 : dtype === "<u4" ? 4 : 2;
  if (bytes.byteLength !== length * width)
    throw new Error("Incomplete map array");
  const view = new DataView(bytes.buffer);
  if (width === 1) return bytes;
  const result =
    dtype === "<i2"
      ? new Int16Array(length)
      : dtype === "<u4"
        ? new Uint32Array(length)
        : new Uint16Array(length);
  for (let i = 0; i < length; i++)
    result[i] =
      dtype === "<i2"
        ? view.getInt16(i * width, true)
        : width === 4
          ? view.getUint32(i * width, true)
          : view.getUint16(i * width, true);
  return result;
}
export function decodeMap(value: MapArtifact) {
  if (
    value?.schema_version !== 1 ||
    !Number.isInteger(value.point_count) ||
    value.point_count < 1
  )
    throw new Error("Unsupported map");
  const n = value.point_count;
  const coordinates = unpack(value.coordinates, "<u2", n * 2),
    flags = unpack(value.flags, "|u1", n),
    clusters = unpack(value.cluster_ids, "<i2", n);
  const ids = new Map<number, string>();
  unpack(value.ids.indices, "<u4", value.ids.values.length).forEach(
    (index, i) => {
      if (index >= n) throw new Error("Map identity outside field");
      ids.set(index, value.ids.values[i]);
    },
  );
  const groups: Record<string, number[]> = {
    dust: [],
    wordpress: [],
    watch: [],
    top: [],
    anchors: [],
  };
  const bits = value.flag_bits;
  for (let i = 0; i < n; i++) {
    const flag = flags[i];
    if (flag & bits.is_2026) groups.dust.push(i);
    if (flag & bits.is_wordpress) groups.wordpress.push(i);
    if (flag & bits.in_product_watch) groups.watch.push(i);
    if (flag & bits.in_top500) groups.top.push(i);
    if (flag & bits.is_past_exploited) groups.anchors.push(i);
  }
  return {
    artifact: value,
    n,
    coordinates,
    flags,
    clusters,
    ids,
    groups,
    regions: new Map(value.clusters.map((region) => [region.id, region])),
  };
}
export type DecodedMap = ReturnType<typeof decodeMap>;
export interface MapView {
  x: number;
  y: number;
  zoom: number;
}
export function zoomAt(
  view: MapView,
  factor: number,
  px: number,
  py: number,
): MapView {
  const zoom = Math.min(24, Math.max(0.25, view.zoom * factor)),
    ratio = zoom / view.zoom;
  return { x: px - (px - view.x) * ratio, y: py - (py - view.y) * ratio, zoom };
}
export interface LabelBox {
  x: number;
  y: number;
  width: number;
  height: number;
}
export function overlaps(a: LabelBox, b: LabelBox, gap = 5) {
  return (
    a.x < b.x + b.width + gap &&
    a.x + a.width + gap > b.x &&
    a.y < b.y + b.height + gap &&
    a.y + a.height + gap > b.y
  );
}

export type MapBounds = [number, number, number, number];
export function robustBounds(
  coordinates: ArrayLike<number>,
  indices?: number[],
  tail = 0.01,
): MapBounds {
  const count = indices?.length ?? coordinates.length / 2;
  if (!count) return [0, 0, 65535, 65535];
  const x = new Float64Array(count),
    y = new Float64Array(count);
  for (let i = 0; i < count; i++) {
    const index = indices ? indices[i] : i;
    x[i] = coordinates[index * 2];
    y[i] = coordinates[index * 2 + 1];
  }
  x.sort();
  y.sort();
  const lo = Math.floor((count - 1) * tail),
    hi = Math.ceil((count - 1) * (1 - tail));
  return [x[lo], y[lo], Math.max(x[lo] + 1, x[hi]), Math.max(y[lo] + 1, y[hi])];
}
export function fitBounds(
  bounds: MapBounds,
  viewport: LabelBox,
  unit: number,
  padding = 0.045,
): MapView {
  const [x0, y0, x1, y1] = bounds;
  const scale =
    Math.min(
      viewport.width / Math.max(1, x1 - x0),
      viewport.height / Math.max(1, y1 - y0),
    ) /
    (1 + padding * 2);
  const zoom = Math.max(0.25, Math.min(24, scale / unit));
  return {
    x: viewport.x + viewport.width / 2 - ((x0 + x1) / 2) * unit * zoom,
    y: viewport.y + viewport.height / 2 - ((y0 + y1) / 2) * unit * zoom,
    zoom,
  };
}
export function easeCamera(
  from: MapView,
  to: MapView,
  progress: number,
): MapView {
  const t = Math.min(1, Math.max(0, progress));
  const eased = t * t * (3 - 2 * t);
  return {
    x: from.x + (to.x - from.x) * eased,
    y: from.y + (to.y - from.y) * eased,
    zoom: from.zoom + (to.zoom - from.zoom) * eased,
  };
}
export function entranceOpacity(elapsed: number, reducedMotion = false) {
  const fade = (start: number, duration: number) =>
    reducedMotion ? 1 : Math.max(0, Math.min(1, (elapsed - start) / duration));
  return {
    dust: fade(0, 700),
    wordpress: fade(0, 700),
    watch: fade(0, 700),
    anchors: fade(600, 700),
    top: fade(1250, 750),
  };
}
export interface MapStory {
  id: "whole" | "wordpress" | "dense" | "island";
  title: string;
  region?: MapRegion;
  bounds: MapBounds;
  caption: string;
}
export function mapStories(map: DecodedMap): MapStory[] {
  const regions = [...map.regions.values()].filter((region) => region.id >= 0);
  const wordpress = regions
    .filter((region) => /wordpress/i.test(region.label))
    .sort((a, b) => b.counts.is_wordpress - a.counts.is_wordpress)[0];
  const island = regions
    .filter((region) => /chrome|chromium/i.test(region.label))
    .sort((a, b) => b.rows - a.rows)[0];
  const dense = regions
    .filter((region) => region.id !== wordpress?.id && region.id !== island?.id)
    .sort(
      (a, b) =>
        b.counts.in_top500 * b.counts.is_past_exploited -
        a.counts.in_top500 * a.counts.is_past_exploited,
    )[0];
  const count = (n: number | undefined) =>
    typeof n === "number" ? n.toLocaleString("en-CA") : "pending";
  const overview = robustBounds(map.coordinates, undefined, 0.1);
  if (wordpress) {
    overview[0] = Math.min(overview[0], wordpress.centroid[0] - 1800);
    overview[1] = Math.min(overview[1], wordpress.centroid[1] - 1800);
    overview[2] = Math.max(overview[2], wordpress.centroid[0] + 1800);
    overview[3] = Math.max(overview[3], wordpress.centroid[1] + 1800);
  }
  const result: MapStory[] = [
    {
      id: "whole",
      title: "Whole field",
      bounds: overview,
      caption: `${count(map.n)} vulnerabilities in one description map. The overview focuses on the dense centre; zoom out to reach the tails and islands.`,
    },
  ];
  for (const [id, region] of [
    ["wordpress", wordpress],
    ["dense", dense],
    ["island", island],
  ] as const) {
    if (!region) continue;
    const indices: number[] = [];
    for (let i = 0; i < map.n; i++)
      if (map.clusters[i] === region.id) indices.push(i);
    const raw = robustBounds(map.coordinates, indices, 0.1);
    // Keep neighbouring descriptions visible rather than magnifying one cluster to the frame edges.
    const cx = (raw[0] + raw[2]) / 2,
      cy = (raw[1] + raw[3]) / 2;
    const spanX = Math.max(6500, (raw[2] - raw[0]) * 1.7),
      spanY = Math.max(6500, (raw[3] - raw[1]) * 1.7);
    const title =
      id === "wordpress"
        ? "WordPress"
        : region.label.split(" · ").slice(0, 2).join(" / ");
    result.push({
      id,
      title,
      region,
      bounds: [cx - spanX / 2, cy - spanY / 2, cx + spanX / 2, cy + spanY / 2],
      caption: `${count(region.counts.is_2026)} 2026 rows, ${count(region.counts.is_past_exploited)} past-exploited anchors and ${count(region.counts.in_top500)} top-500 picks in the ${region.label.split(" · ").slice(0, 2).join(" / ")} region.${id === "wordpress" && region.counts.is_past_exploited === 0 && region.counts.in_top500 === 0 ? " This region stays dark." : id === "dense" ? " Past attacks and current picks gather around similar descriptions." : " Shared browser language forms a distinct island."}`,
    });
  }
  return result;
}
