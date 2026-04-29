// Email scanner detection logic.
// Looks for fake authority tone, spoofed domains, suspicious links/attachments,
// job scam patterns, and basic grammar anomalies.

import {
  clamp,
  levelFromScore,
  type Reason,
  type ScanResult,
} from "./scoring";

const AUTHORITY_PHRASES = [
  "your bank",
  "irs",
  "tax refund",
  "government",
  "security alert",
  "account suspended",
  "unauthorized access",
  "verify your identity",
  "compliance",
  "legal action",
  "suspended",
  "locked",
];

const URGENCY_PHRASES = [
  "urgent",
  "immediately",
  "act now",
  "within 24 hours",
  "final notice",
  "expires today",
  "last warning",
];

const ATTACHMENT_HINTS = [
  ".exe",
  ".scr",
  ".zip",
  ".rar",
  ".js",
  ".vbs",
  "invoice.pdf",
  "statement.pdf",
  "attached file",
];

const URL_PATTERN = /https?:\/\/[^\s]+/gi;
const EMAIL_PATTERN =
  /\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g;

// Domains commonly spoofed
const SPOOF_TARGETS = [
  "paypal.com",
  "apple.com",
  "google.com",
  "microsoft.com",
  "amazon.com",
  "netflix.com",
  "facebook.com",
];

const JOB_SCAM_PATTERNS = [
  "internship",
  "induction",
  "selection process",
  "submit your resume",
  "upload resume",
  "hiring process",
];

const WEIGHTS = {
  authority: 12,
  urgency: 10,
  attachment: 25,
  suspiciousLink: 30, // increased
  spoofedDomain: 35,
  grammar: 8,
};

export interface EmailScanResult extends ScanResult {
  warnings: string[];
}

function findMatches(text: string, list: string[]): string[] {
  const lower = text.toLowerCase();
  return list.filter((p) => lower.includes(p));
}

function grammarScore(text: string): number {
  let issues = 0;
  if (/\s{2,}/.test(text)) issues++;
  if (/[!?]{2,}/.test(text)) issues++;
  const capsWords = text.match(/\b[A-Z]{5,}\b/g) || [];
  if (capsWords.length >= 2) issues++;
  if (/[.,!?][a-zA-Z]/.test(text)) issues++;
  return issues;
}

function detectSpoofedDomain(text: string): string | null {
  const lower = text.toLowerCase();
  const mentioned = SPOOF_TARGETS.find((d) =>
    lower.includes(d.replace(".com", ""))
  );
  if (!mentioned) return null;

  const senderDomains: string[] = [];
  let m: RegExpExecArray | null;
  EMAIL_PATTERN.lastIndex = 0;

  while ((m = EMAIL_PATTERN.exec(text)) !== null) {
    if (m[1]) senderDomains.push(m[1].toLowerCase());
  }

  if (senderDomains.length === 0) return null;

  const matchesReal = senderDomains.some((d) => d === mentioned);
  if (matchesReal) return null;

  return mentioned;
}

export function analyzeEmail(text: string): EmailScanResult {
  const reasons: Reason[] = [];
  const warnings: string[] = [];
  let score = 0;

  // Rule 1: Authority tone
  const authority = findMatches(text, AUTHORITY_PHRASES);
  if (authority.length > 0) {
    score += Math.min(authority.length, 3) * WEIGHTS.authority;
    reasons.push({
      type: "warn",
      text: `Authoritative / threatening phrases: ${authority.slice(0, 3).join(", ")}`,
    });
  }

  // Rule 2: Urgency
  const urgent = findMatches(text, URGENCY_PHRASES);
  if (urgent.length > 0) {
    score += Math.min(urgent.length, 2) * WEIGHTS.urgency;
    reasons.push({
      type: "warn",
      text: `Urgency language: ${urgent.join(", ")}`,
    });
    warnings.push("This email pressures you to act quickly — slow down.");
  }

  // Rule 3: Attachments
  const attachments = findMatches(text, ATTACHMENT_HINTS);
  if (attachments.length > 0) {
    score += WEIGHTS.attachment;
    reasons.push({
      type: "bad",
      text: `Mentions risky attachment(s): ${attachments.join(", ")}`,
    });
    warnings.push("Do not open attachments unless you trust the sender.");
  }

  // Rule 4: Links
  const links = text.match(URL_PATTERN) || [];
  if (links.length > 0) {
    const shortener = links.find((l) =>
      /(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|rb\.gy)/i.test(l)
    );

    const googleForm = links.find((l) =>
      /(forms\.gle|docs\.google\.com\/forms)/i.test(l)
    );

    if (shortener) {
      score += WEIGHTS.suspiciousLink;
      reasons.push({
        type: "bad",
        text: `Contains shortened link: ${shortener}`,
      });
    }

    if (googleForm) {
      score += 25;
      reasons.push({
        type: "bad",
        text: "Uses external Google Form for application (common scam tactic)",
      });
    }

    if (!shortener && !googleForm) {
      reasons.push({
        type: "warn",
        text: `Contains ${links.length} link(s) — verify before clicking`,
      });
    }
  }

  // Rule 5: Spoofing
  const spoof = detectSpoofedDomain(text);
  if (spoof) {
    score += WEIGHTS.spoofedDomain;
    reasons.push({
      type: "bad",
      text: `Mentions ${spoof} but sender domain does not match — possible spoof`,
    });
    warnings.push("Verify sender email carefully.");
  }

  // Rule 6: Grammar
  const issues = grammarScore(text);
  if (issues >= 2) {
    score += issues * WEIGHTS.grammar;
    reasons.push({
      type: "warn",
      text: `Grammar / formatting anomalies detected (${issues} issues)`,
    });
  }

  // Rule 7: Job scam patterns
  const job = findMatches(text, JOB_SCAM_PATTERNS);
  if (job.length > 0) {
    score += 15;
    reasons.push({
      type: "warn",
      text: "Generic hiring / internship language detected",
    });
  }

  // Rule 8: Combo logic (🔥 important)
  const hasJobLanguage = /(internship|hiring|selection|induction)/i.test(text);
  const hasExternalForm = /(forms\.gle|docs\.google\.com)/i.test(text);
  const hasUrgency = /(today|urgent|immediately|mandatory)/i.test(text);

  if (hasJobLanguage && hasExternalForm) {
    score += 25;
    reasons.push({
      type: "warn",
      text: "Hiring process uses external form (common scam pattern)",
    });
  }

  if (hasJobLanguage && hasUrgency) {
    score += 20;
    reasons.push({
      type: "warn",
      text: "Job-related message with urgency pressure",
    });
  }

  // Rule 9: Unrealistic hiring
  if (/no interview|direct selection|guaranteed/i.test(text)) {
    score += 25;
    reasons.push({
      type: "bad",
      text: "Unrealistic hiring promise (no interview / direct selection)",
    });
  }

  // Extra warning (context awareness)
  if (hasJobLanguage && links.length > 0 && !spoof) {
    warnings.push(
      "Job-related email with external links — verify legitimacy independently."
    );
  }

  if (reasons.length === 0) {
    reasons.push({
      type: "good",
      text: "No common phishing patterns detected in this email",
    });
  }

  score = clamp(Math.round(score), 0, 100);

  return {
    score,
    level: levelFromScore(score),
    reasons,
    warnings,
  };
}
