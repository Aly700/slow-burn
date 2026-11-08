import type { ReactNode } from "react";

export function SectionHeading({ index, label, title, detail, dek, meta }: {
  index: string;
  label: string;
  title: string;
  detail?: string;
  dek?: string;
  meta?: ReactNode;
}) {
  return (
    <div className="section-heading">
      <div className="section-title">
        <span className="section-index">{index} / {label}</span>
        <h2>{title}</h2>
        {dek && <p className="section-dek">{dek}</p>}
      </div>
      {meta ?? (detail && <p className="section-meta">{detail}</p>)}
    </div>
  );
}
