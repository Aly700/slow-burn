import type { BlindSpotStudyData } from "./types";

const finite = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value);

export function blindSpotSummary(study?: BlindSpotStudyData | null) {
  const primary = study?.splits?.find(
    (split) => split?.name === "2024_to_2025",
  );
  const allocations = study?.mixed_allocations?.find(
    (item) => item?.split === primary?.name,
  );
  const frozen = allocations?.allocations?.find(
    (item) => item?.name === "frozen submitted model",
  );
  const mixed = allocations?.allocations
    ?.filter(
      (item) =>
        item?.feasible && finite(item.watch_rows) && item.watch_rows > 0,
    )
    .sort((a, b) => a.watch_rows! - b.watch_rows!)[0];
  const model = study?.selected_recipe
    ? primary?.methods?.find((method) => method?.name === study.selected_recipe)
    : undefined;
  const budget = frozen?.budget;
  const result = finite(budget)
    ? model?.budgets?.find((item) => item?.budget === budget)
    : undefined;
  const epss = finite(budget)
    ? primary?.methods
        ?.find((method) => method?.name === "EPSS first")
        ?.budgets?.find((item) => item?.budget === budget)
    : undefined;
  const contrasts =
    study?.profile?.actionable_contrasts ?? study?.profile?.contrasts;
  const product = contrasts?.find(
    (item) => item?.name === "product_prior_kev_any",
  );
  const vendor = contrasts?.find((item) => item?.name === "vendor_20_plus");
  const vendorThreshold = vendor?.name?.match(/^vendor_(\d+)_plus$/)?.[1];
  const year = primary?.test_label_cutoff?.match(/^(\d{4})-/)?.[1];
  const unseen = study?.profile?.no_signal_positives;
  const seen = study?.profile?.with_signal_positives;
  return {
    year,
    selectionYear: study?.selection?.selection_year,
    registered: Boolean(study?.policy?.version && study.policy.negative_result),
    selectionFrozen: study?.selection?.test_used_for_selection === false,
    unseen,
    seen,
    total: finite(unseen) && finite(seen) ? unseen + seen : undefined,
    positives: primary?.test?.positives,
    budget,
    result,
    epss,
    product,
    vendor,
    vendorThreshold,
    frozen,
    mixed,
    mixedAdopted: allocations?.adopted,
    exploitShare:
      finite(frozen?.exploit_tier_rows) && finite(budget) && budget > 0
        ? frozen.exploit_tier_rows / budget
        : undefined,
  };
}
