import type { Data, Score } from '../types';
import { workflowExample } from '../workflow';
import { SectionHeading } from './SectionHeading';
import { QueueRow } from './QueueRow';
import { ApprovalFooter, ProposedAction, VerifiedClaims } from './BriefingCards';
import { Icon } from './Icon';
import '../workflow.css';

export function Workflow({ data, onOpen }: { data: Data; onOpen: (score: Score) => void }) {
  const example = workflowExample(data);
  if (!example) return null;
  const { score, run, product } = example;
  const open = () => onOpen(score);
  return (
    <section id="workflow" className="story-section workflow-section" aria-label="Ranking, briefing and approval">
      <SectionHeading index="01" label="Workflow" title="From a ranked CVE to a ticket" detail={score.cve_id} />
      <div className="workflow-steps">
        <div className="workflow-step">
          <div className="workflow-copy">
            <span className="eyebrow">Step 1 / Ranked queue</span>
            <h3>Rank the month’s new CVEs</h3>
            <p>The queue uses evidence available at each snapshot.</p>
            <a className="text-link" href="#queue">Explore the queue <Icon name="arrow" size={16} /></a>
          </div>
          <div className="workflow-card workflow-queue">
            <table aria-label="Recorded fix-first queue row">
              <thead><tr><th>Rank</th><th>Vulnerability / vendor or assigner</th><th>Snapshot</th><th>Model score</th><th>Why it ranks</th><th>Briefing</th></tr></thead>
              <tbody><QueueRow row={score} ranking={data.meta?.score_mode === 'ranking'} product={product} hasRun onOpen={open} /></tbody>
            </table>
          </div>
        </div>
        <div className="workflow-step">
          <div className="workflow-copy">
            <span className="eyebrow">Step 2 / Granite briefing</span>
            <h3>Check every claim against tool results</h3>
            <p>Every delivered claim links to a tool result.</p>
            <button className="text-link" onClick={open}>Inspect the briefing <Icon name="arrow" size={16} /></button>
          </div>
          <div className="workflow-card workflow-claims">
            <span className="eyebrow">IBM Granite · {run.cve_id}</span>
            <h3 className="briefing-headline">{run.briefing?.headline}</h3>
            <VerifiedClaims briefing={run.briefing} />
          </div>
        </div>
        <div className="workflow-step">
          <div className="workflow-copy">
            <span className="eyebrow">Step 3 / Ticket approval</span>
            <h3>A person approves the ticket</h3>
            <p>The final action waits for your approval.</p>
            <button className="text-link" onClick={open}>Review the proposed action <Icon name="arrow" size={16} /></button>
          </div>
          <div className="workflow-card workflow-approval">
            <div className="workflow-proposal">
              <span className="eyebrow">{run.cve_id} · Awaiting approval</span>
              <ProposedAction briefing={run.briefing} />
            </div>
            <ApprovalFooter run={run} onDecide={open} noteId="workflow-approval-note" notice="Preview only. Either button opens the full briefing for review." />
          </div>
        </div>
      </div>
    </section>
  );
}
