import type { RiskLevel } from "../../utils/scoring";

interface BadgeProps {
  level: RiskLevel;
}

const STYLES: Record<RiskLevel, string> = {
  Low: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  Medium: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  High: "bg-rose-500/15 text-rose-300 border-rose-500/40",
};

export function Badge({ level }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center px-3.5 py-1.5 rounded-full text-sm font-bold border ${STYLES[level]}`}
    >
      {level} Risk
    </span>
  );
}
