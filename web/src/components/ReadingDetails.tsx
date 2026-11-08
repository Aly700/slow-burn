import type { ReactNode } from "react";

export function ReadingDetails({ label, children, collapsed = true }: {
  label: string;
  children: ReactNode;
  collapsed?: boolean;
}) {
  return collapsed ? (
    <details className="reading-details">
      <summary>{label}</summary>
      <div className="reading-evidence">{children}</div>
    </details>
  ) : <>{children}</>;
}
