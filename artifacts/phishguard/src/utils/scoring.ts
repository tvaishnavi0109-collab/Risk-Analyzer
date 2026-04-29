// Shared scoring utilities used by all three scanners.
// Each scanner produces a numeric score (0-100) plus a list of reasons.
// We keep the level math in one place so all scanners feel consistent.

export type ReasonType = "good" | "warn" | "bad";

export interface Reason {
  type: ReasonType;
  text: string;
}

export type RiskLevel = "Low" | "Medium" | "High";

export interface ScanResult {
  score: number;
  level: RiskLevel;
  reasons: Reason[];
}

// Keep a number inside a min/max range
export function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

// Convert a 0-100 score to a Low / Medium / High risk level.
// Same thresholds across all three scanners so the badges feel consistent.
export function levelFromScore(score: number): RiskLevel {
  if (score <= 40) return "Low";
  if (score <= 70) return "Medium";
  return "High";
}

// CSS color helpers used by the Badge / score bar components
export function levelClass(level: RiskLevel): string {
  if (level === "Low") return "safe";
  if (level === "Medium") return "warn";
  return "danger";
}
