import type { Score } from "../types";
import { list, number, percent, reasonLabel, compactReasonLabel } from "../lib";
import { Icon } from "./Icon";

export function QueueRow({ row, ranking, selected = false, hasRun = false, product = row.product_identity, onOpen }: {
  row: Score;
  ranking: boolean;
  selected?: boolean;
  hasRun?: boolean;
  product?: string;
  onOpen: () => void;
}) {
  return (
    <tr
      className={selected ? "selected" : ""}
      onClick={onOpen}
    >
      <td className="rank mono" data-label="Rank">
        {String(row.rank).padStart(3, "0")}
      </td>
      <td>
        <button
          className="cve-button"
          onClick={(event) => {
            event.stopPropagation();
            onOpen();
          }}
        >
          {row.cve_id}
        </button>
        <span className="assigner" title={row.assigner}>
          {row.vendor_identity && row.vendor_identity !== "unmapped"
            ? row.vendor_identity
            : row.assigner || "Assigner unavailable"}
          {product && (
            <span className="product-name">
              {" "}
              · {product}
            </span>
          )}
        </span>
      </td>
      <td className="mono snapshot" data-label="Snapshot">{row.snapshot_month || "-"}</td>
      <td className="score-cell mono" data-label={ranking ? "Rank score" : "Model score"}>
        {ranking ? number(row.score, 4) : percent(row.score, 2)}
      </td>
      <td>
        <div className="reason-chips">
          {list(row.reasons)
            .slice(0, 2)
            .map((reason, i) => (
              <span
                className="chip"
                title={reasonLabel(reason)}
                key={i}
              >
                {compactReasonLabel(reason)}
              </span>
            ))}
          {!list(row.reasons).length && (
            <span className="muted">Reasons pending</span>
          )}
          {list(row.reasons).length > 2 && (
            <span className="more-reasons">
              +{list(row.reasons).length - 2}
            </span>
          )}
        </div>
      </td>
      <td className="row-action">
        {hasRun && (
          <span className="run-dot" title="Briefing available" />
        )}
        <Icon name="arrow" size={17} />
      </td>
    </tr>
  );
}
