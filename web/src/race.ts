export interface RaceOutcome {
  before: number;
  after: number;
  never: number;
  median_days_ahead: number | null;
  fixed_total: number;
  monthly: { month: string; confirmed: number; before: number; fixed_total: number }[];
}
export interface RaceMethod {
  key: string;
  name: string;
  end: RaceOutcome;
  start: RaceOutcome;
}
export interface RaceBootstrap {
  observed_delta: number;
  ahead: number;
  tied: number;
  behind: number;
  delta_95_percentile_interval: number[];
}
export interface RaceCapacity {
  capacity: number;
  annual_budget: number;
  methods: RaceMethod[];
  bootstrap: { end: RaceBootstrap; start: RaceBootstrap };
}
export interface RaceData {
  schema_version: number;
  pool: number;
  positives: number;
  excluded_first_month: number;
  uncertainty: { iterations: number; seed: number };
  capacities: RaceCapacity[];
}
export const capacityResult = (data: RaceData, capacity: number) =>
  data.capacities.find(c => c.capacity === capacity);

export function comparisonText(capacity: RaceCapacity, timing: 'end' | 'start' = 'end') {
  const ours = capacity.methods.find(m => m.key === 'ours')![timing].before;
  const baselines = capacity.methods.filter(m => m.key !== 'ours');
  const best = Math.max(...baselines.map(m => m[timing].before));
  return `Slow Burn ${ours === best ? 'ties' : ours > best ? 'leads' : 'trails'} the best baseline, ${ours} to ${best}.`;
}

export function stepPath(values: number[], x: number, bottom: number, width: number, height: number, max: number) {
  if (!values.length) return '';
  return values.map((value, i) => {
    const px = x + i * width / Math.max(1, values.length - 1);
    const py = bottom - value / max * height;
    return i ? `H${px} V${py}` : `M${px},${py}`;
  }).join(' ');
}
