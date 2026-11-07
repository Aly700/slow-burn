export type Nullable = number | null;
export interface Reason {
  feature?: string;
  label?: string;
  value?: unknown;
  contribution?: number;
}
export interface Score {
  rank: number;
  cve_id: string;
  published?: string;
  snapshot_month?: string;
  score?: Nullable;
  epss?: Nullable;
  any_exploit?: Nullable;
  cvss3_score?: Nullable;
  attack_vector?: string;
  cwe_ids?: string;
  assigner?: string;
  description?: string;
  reasons?: Reason[];
}
export interface Signal {
  name?: string;
  n?: Nullable;
  hits?: Nullable;
  rate?: Nullable;
  lift?: Nullable;
  leak_risk?: string;
}
export interface Findings {
  _status?: string;
  headline?: {
    ours_hits_top500_2025_backtest?: Nullable;
    baselines_2025_backtest?: Record<string, Nullable>;
    benchmark_2026_reference?: Record<string, Nullable>;
    later_kev_without_public_signal?: Nullable;
    later_kev_with_public_signal?: Nullable;
    pool_2025?: Nullable;
    positives_2025?: Nullable;
  };
  two_clocks?: {
    kev_2025_total?: Nullable;
    first_month?: Nullable;
    later?: Nullable;
    later_lag_days?: { min?: Nullable; median?: Nullable; max?: Nullable };
    lag_hist?: { bucket: string; n: number }[];
  };
  signals?: Signal[];
  deprioritize?: {
    name?: string;
    n?: Nullable;
    hits?: Nullable;
    share_of_pool?: Nullable;
  }[];
  base_rate_2025?: Nullable;
  vendor_history_within_poc?: {
    pool?: Nullable;
    positives?: Nullable;
    base_rate?: Nullable;
    buckets?: {
      identity?: string;
      earlier_kev_bucket?: string;
      n?: Nullable;
      hits?: Nullable;
      rate?: Nullable;
      lift_within_poc?: Nullable;
    }[];
  };
  story?: {
    title?: string;
    sentence?: string;
    numbers?: Record<string, unknown>;
  }[];
}
export interface Backtest {
  _status?: string;
  pool?: string;
  label?: string;
  methods?: {
    name: string;
    hits_at_500?: Nullable;
    recall_at_500?: Nullable;
  }[];
  monthly?: {
    month: string;
    pool?: number;
    positives?: number;
    ours_hits?: Nullable;
    baseline_hits?: Nullable;
  }[];
  ablations?: { name: string; hits_at_500?: Nullable }[];
}
export interface ModelCard {
  model?: string;
  trained_on?: string;
  features_used?: string[];
  features_excluded?: { name: string; why: string }[];
  ibm_technology?: string[];
  note?: string;
}
export interface Run {
  run_id: string;
  briefing_hash?: string;
  snapshot_month?: string;
  cve_id: string;
  state: string;
  states_seen?: string[];
  model?: string;
  started_at?: string;
  duration_ms?: number;
  briefing?: {
    verdict?: string;
    headline?: string;
    claims?: {
      id: string;
      text?: string;
      evidence?: { tool: string; field: string; value: unknown }[];
      verified?: boolean;
    }[];
    action?: string;
    confidence?: Nullable;
  };
  verifier?: {
    claims_total?: number;
    claims_verified?: number;
    dropped?: { id: string; text?: string; why: string }[];
  };
  policy?: {
    write_requested?: boolean;
    write_allowed?: boolean;
    reason?: string;
  };
  injection?: { detected?: boolean; spans?: unknown[] };
  trace?: {
    t_ms?: number;
    kind?: string;
    name?: string;
    input?: unknown;
    output_summary?: string;
    duration_ms?: number;
  }[];
}
export interface Data {
  findings?: Findings | null;
  backtest?: Backtest | null;
  model_card?: ModelCard | null;
  scores?: Score[];
  runs?: Run[];
  agent_eval?: AgentEval | null;
  verifier_example?: Run | null;
  meta?: {
    synced_at?: string;
    runs_source?: string;
    score_mode?: string;
    warnings?: string[];
  };
}

export interface EvalArm {
  id?: string;
  name?: string;
  cases?: Nullable;
  observed_outcome_accuracy?: Nullable;
  history_or_analogy_coverage?: Nullable;
  evidence_fidelity?: Nullable;
}
export interface AgentEval {
  cases?: Nullable;
  model?: string;
  active_arm?: string;
  arms?: EvalArm[];
  baseline?: EvalArm;
  granite_decides?: EvalArm;
  policy_granite?: EvalArm;
  snapshot_end?: string;
  outcome_end?: string;
  limitations?: string[];
}
