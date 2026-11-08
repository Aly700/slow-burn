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
  const zoom = Math.min(18, Math.max(1, view.zoom * factor)),
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
