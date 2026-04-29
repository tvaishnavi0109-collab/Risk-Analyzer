// Message / SMS scanner detection logic.
// Looks for urgency, financial bait, suspicious links and OTP requests.

import {
  clamp,
  levelFromScore,
  type Reason,
  type ScanResult,
} from "./scoring";

const URGENCY_WORDS = [
  "urgent",
  "immediately",
  "right now",
  "asap",
  "act now",
  "expires",
  "expiring",
  "last chance",
  "final notice",
  "limited time",
];

const FINANCIAL_BAIT = [
  "win",
  "winner",
  "prize",
  "free money",
  "cash",
  "lottery",
  "jackpot",
  "reward",
  "claim",
  "gift card",
  "bonus",
];

const CREDENTIAL_REQUESTS = [
  "otp",
  "one time password",
  "password",
  "pin",
  "cvv",
  "bank account",
  "credit card",
  "card number",
  "social security",
  "ssn",
];

const URL_PATTERN = /https?:\/\/[^\s]+/gi;
const SUSPICIOUS_LINK_HOSTS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "rb.gy",
  "shorturl.at",
];

const MONEY_PATTERNS = [
  "rupees",
  "₹",
  "rs",
  "cash",
  "earn",
  "income",
];

const WEIGHTS = {
  urgency: 12, // per matched word, capped
  financialBait: 14, // per matched word, capped
  credentialRequest: 25, // per matched phrase, capped
  suspiciousLink: 40,
  anyLink: 8,
};

export interface MessageScanResult extends ScanResult {
  matches: string[]; // suspicious phrases to highlight in the message
}

function findMatches(text: string, list: string[]): string[] {
  const lower = text.toLowerCase();
  return list.filter((word) => lower.includes(word));
}

export function analyzeMessage(text: string): MessageScanResult {
  const reasons: Reason[] = [];
  const matches: string[] = [];
  let score = 0;

  // Rule 1: Urgency words
  const urgent = findMatches(text, URGENCY_WORDS);
  if (urgent.length > 0) {
    matches.push(...urgent);
    const points = Math.min(urgent.length, 2) * WEIGHTS.urgency;
    score += points;
    reasons.push({
      type: "warn",
      text: `Urgency language detected: ${urgent.join(", ")}`,
    });
  }

  // Rule 2: Financial bait
  const bait = findMatches(text, FINANCIAL_BAIT);
  if (bait.length > 0) {
    matches.push(...bait);
    const points = Math.min(bait.length, 2) * WEIGHTS.financialBait;
    score += points;
    reasons.push({
      type: "warn",
      text: `Financial bait words: ${bait.join(", ")}`,
    });
  }

  // Rule 3: Money bait (NEW 🔥)
const money = findMatches(text, MONEY_PATTERNS);
if (money.length > 0) {
  matches.push(...money);
  score += 20;
  reasons.push({
    type: "bad",
    text: `Money-related bait detected: ${money.join(", ")}`,
  });
}

  // Rule 4: Credential / OTP requests
  const creds = findMatches(text, CREDENTIAL_REQUESTS);
  if (creds.length > 0) {
    matches.push(...creds);
    const points = Math.min(creds.length, 2) * WEIGHTS.credentialRequest;
    score += points;
    reasons.push({
      type: "bad",
      text: `Requests sensitive info: ${creds.join(", ")}`,
    });
  }

  // Rule 5: Links inside the message
  const links: string[] = text.match(URL_PATTERN) ?? [];
  if (links.length > 0) {
    score += WEIGHTS.anyLink;
    const suspicious = links.filter((link) => {
      const lower = link.toLowerCase();
      return SUSPICIOUS_LINK_HOSTS.some((h) => lower.includes(h));
    });

    if (suspicious.length > 0) {
      matches.push(...suspicious);
      score += WEIGHTS.suspiciousLink;
      reasons.push({
        type: "bad",
        text: `Contains suspicious shortened link(s): ${suspicious.join(", ")}`,
      });
    } else {
      matches.push(...links);
      reasons.push({
        type: "warn",
        text: `Contains link(s) — verify before clicking`,
      });
    }
  }

  if (reasons.length === 0) {
    reasons.push({
      type: "good",
      text: "No common phishing patterns detected in this message",
    });
  }
  if (
    /(rupees|₹|rs|cash)/i.test(text) &&
    /(bit\.ly|tinyurl|shorturl|t\.co)/i.test(text)
  ) {
    score += 35;
    reasons.push({
      type: "bad",
      text: "Money + shortened link combination (very high risk)",
    });
  }
  score = clamp(Math.round(score), 0, 100);
  return {
    score,
    level: levelFromScore(score),
    reasons,
    matches,
  };
}
