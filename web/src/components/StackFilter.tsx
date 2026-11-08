import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { Score } from "../types";
import {
  choiceKey,
  choiceLabel,
  matchesStack,
  normalizeIdentity,
  stackSuggestions,
} from "../stack";
import type { StackChoice } from "../stack";
import { number } from "../lib";
import { Icon } from "./Icon";
import "../stack.css";

export function StackFilter({
  scores,
  choices,
  persisted,
  onChange,
  secondaryList,
  reviewIdentities = [],
}: {
  scores: Score[];
  choices: StackChoice[];
  persisted: boolean;
  onChange: (choices: StackChoice[]) => void;
  // Supply an inventory-matched secondary list only when its artifact is present.
  secondaryList?: ReactNode;
  reviewIdentities?: { vendor: string; product: string }[];
}) {
  const [query, setQuery] = useState("");
  const suggestions = useMemo(() => {
    const ranked = stackSuggestions(scores), keys = new Set(ranked.map(choiceKey));
    const review = stackSuggestions(reviewIdentities.map((item, index) => ({ rank: 501 + index, cve_id: "", vendor_identity: item.vendor, product_identity: item.product })));
    return [...ranked, ...review.filter(item => !keys.has(choiceKey(item)))];
  }, [scores, reviewIdentities]);
  const keys = new Set(choices.map(choiceKey));
  const matching = suggestions
    .filter(
      (choice) =>
        !keys.has(choiceKey(choice)) &&
        (query
          ? normalizeIdentity(choiceLabel(choice)).includes(
              normalizeIdentity(query),
            )
          : choice.kind === "vendor"),
    )
    .slice(0, choices.length && !query ? 3 : 6);
  const top = scores.filter((row) => row.rank <= 500);
  const count = top.filter((row) => matchesStack(row, choices)).length;
  function add(choice: StackChoice) {
    if (!keys.has(choiceKey(choice)))
      onChange([
        ...choices,
        {
          kind: choice.kind,
          value: choice.value,
          ...(choice.vendor ? { vendor: choice.vendor } : {}),
        },
      ]);
    setQuery("");
  }
  function typed() {
    const value = query.trim();
    if (!value) return;
    const sameValue = suggestions.filter(
      (choice) => normalizeIdentity(choice.value) === normalizeIdentity(value),
    );
    const exact =
      suggestions.find(
        (choice) =>
          normalizeIdentity(choiceLabel(choice)) === normalizeIdentity(value),
      ) ?? (sameValue.length === 1 ? sameValue[0] : undefined);
    add(exact ?? { kind: "text", value });
  }
  return (
    <div className="stack-filter">
      <div className="stack-heading">
        <div>
          <span className="eyebrow">YOUR ENVIRONMENT</span>
          <h3>What do you run?</h3>
          <p>Choose vendors and products to make this queue yours.</p>
        </div>
        <div className="stack-impact" aria-live="polite">
          <strong>
            {scores.length ? number(count) : "pending"}
            <span> / {scores.length ? number(top.length) : "pending"}</span>
          </strong>
          <span>
            {choices.length
              ? "of the top 500 match your stack"
              : "top-ranked CVEs · choose your stack"}
          </span>
        </div>
      </div>
      <div className="stack-input-row">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            typed();
          }}
        >
          <Icon name="search" size={17} />
          <input
            aria-label="Add vendor or product"
            aria-describedby="stack-help"
            placeholder="Type a vendor or product…"
            value={query}
            maxLength={100}
            onChange={(event) => setQuery(event.target.value)}
          />
          <button type="submit" disabled={!query.trim()}>
            Add to stack <span aria-hidden="true">+</span>
          </button>
        </form>
        <span className="stack-save">
          {persisted ? "Saved in this browser" : "Kept for this visit"}
        </span>
      </div>
      {choices.length > 0 && (
        <div className="stack-selected" aria-label="Your selected stack">
          {choices.map((choice) => (
            <button
              key={choiceKey(choice)}
              onClick={() =>
                onChange(
                  choices.filter(
                    (item) => choiceKey(item) !== choiceKey(choice),
                  ),
                )
              }
              aria-label={`Remove ${choiceLabel(choice)} from stack`}
            >
              <span>
                {choiceLabel(choice)}
                {choice.kind === "text" && <small>text match</small>}
              </span>
              <Icon name="close" size={13} />
            </button>
          ))}
          <button className="clear-stack" onClick={() => onChange([])}>
            Clear stack
          </button>
        </div>
      )}
      <div className="stack-suggestions" aria-label="Stack suggestions">
        <span>{query ? "Matches" : "From the data"}</span>
        {matching.map((choice) => (
          <button key={choiceKey(choice)} onClick={() => add(choice)}>
            <span>{choiceLabel(choice)}</span>
            <small>{choice.kind === "product" ? "product" : "vendor"}</small>
            <b>+</b>
          </button>
        ))}
        {query && !matching.length && (
          <span>No identity match. Add “{query}” as a text match.</span>
        )}
      </div>
      <p id="stack-help" className="stack-help">
        Matches any selected identity; custom text searches descriptions too.
        Confirm affected versions before patching.
      </p>
      {secondaryList}
    </div>
  );
}
