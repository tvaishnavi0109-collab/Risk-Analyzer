import type { Reason, RiskLevel } from "../utils/scoring";
import { Card } from "./ui/Card";
import { Badge } from "./ui/Badge";

interface ResultPanelProps {
  level: RiskLevel;
  score: number;
  reasons: Reason[];
  extra?: React.ReactNode; // domain row, warnings, highlights, etc.
}

const FILL_STYLES: Record<RiskLevel, string> = {
  Low: "bg-gradient-to-r from-emerald-500 to-emerald-400",
  Medium: "bg-gradient-to-r from-amber-500 to-orange-400",
  High: "bg-gradient-to-r from-rose-500 to-red-500",
};

const REASON_STYLES = {
  good: "border-l-emerald-500 text-emerald-200/90",
  warn: "border-l-amber-500 text-amber-100/90",
  bad: "border-l-rose-500 text-rose-100/90",
};

export function ResultPanel({ level, score, reasons, extra }: ResultPanelProps) {
  return (
    <Card className="fade-in">
      {/* Risk level header */}
      <div className="flex items-center justify-between gap-3 flex-wrap mb-5">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Risk Level
        </span>
        <Badge level={level} />
      </div>

      {/* Optional extra info (domain, warnings, etc.) */}
      {extra}

      {/* Risk score with bar */}
      <div className="mb-6">
        <div className="flex items-baseline justify-between mb-2">
          <span className="text-sm text-slate-400 font-medium">Risk Score</span>
          <span className="text-3xl font-extrabold text-slate-50">
            {score}%
          </span>
        </div>
        <div className="w-full h-2.5 bg-slate-950/80 rounded-full overflow-hidden border border-slate-800">
          <div
            className={`h-full rounded-full transition-all duration-500 ${FILL_STYLES[level]}`}
            style={{ width: `${score}%` }}
          />
        </div>
      </div>

      {/* Reasons */}
      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
        Reasons
      </h3>
      <ul className="flex flex-col gap-2">
        {reasons.map((reason, idx) => (
          <li
            key={idx}
            className={`px-4 py-3 bg-slate-950/60 border-l-[3px] rounded-lg text-sm ${REASON_STYLES[reason.type]}`}
          >
            {reason.text}
          </li>
        ))}
      </ul>
    </Card>
  );
}
