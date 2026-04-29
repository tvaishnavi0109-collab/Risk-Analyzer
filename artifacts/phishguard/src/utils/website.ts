// Website / URL scanner detection logic.
// Pure functions only — no React, no DOM. Easy to read and test.

import {
  clamp,
  levelFromScore,
  type Reason,
  type ScanResult,
} from "./scoring";

const SUSPICIOUS_KEYWORDS = [
  "login",
  "verify",
  "secure",
  "update",
  "signin",
  "account",
];

const URL_SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "rb.gy",
  "shorturl.at",
];

const LONG_URL_LIMIT = 75;
const MAX_SUBDOMAINS = 3;

const WEIGHTS = {
  noHttps: 20,
  keyword: 10, // per keyword, capped
  shortener: 30,
  ipAddress: 45,
  manySubdomains: 20,
  atSymbol: 30,
  longUrl: 10,
};

// ---- Helpers ----

function getHost(url: string): string {
  const withoutProtocol = url.replace(/^https?:\/\//i, "");
  const afterAt = withoutProtocol.includes("@")
    ? (withoutProtocol.split("@").pop() ?? "")
    : withoutProtocol;
  return afterAt.split(/[/:?#]/)[0] ?? "";
}

export function extractDomain(url: string): string {
  const host = getHost(url).toLowerCase();
  if (!host) return "unknown";
  return host.replace(/^www\./, "");
}

function isIpAddress(host: string): boolean {
  const ipv4 =
    /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  return ipv4.test(host);
}

function countSubdomains(host: string): number {
  // Strip "www." then count dots — a normal "example.com" has 1 dot = 0 subdomains
  // "mail.example.com" has 2 dots = 1 subdomain, etc.
  const cleaned = host.replace(/^www\./, "");
  const dotCount = (cleaned.match(/\./g) || []).length;
  return Math.max(0, dotCount - 1);
}

function findKeywords(url: string): string[] {
  const lower = url.toLowerCase();
  return SUSPICIOUS_KEYWORDS.filter((word) => lower.includes(word));
}

function matchedShortener(host: string): string | null {
  return URL_SHORTENERS.find((s) => host === s || host.endsWith("." + s)) ?? null;
}

// ---- Main analyzer ----

export interface WebsiteScanResult extends ScanResult {
  domain: string;
}

export function analyzeUrl(url: string): WebsiteScanResult {
  const reasons: Reason[] = [];
  let score = 0;

  const host = getHost(url);

  // Rule 1: HTTPS
  if (url.toLowerCase().startsWith("https://")) {
    reasons.push({ type: "good", text: "Uses HTTPS (secure connection)" });
  } else {
    score += WEIGHTS.noHttps;
    reasons.push({
      type: "bad",
      text: "Does not use HTTPS (connection is not secure)",
    });
  }

  // Rule 2: IP address instead of a domain
  if (isIpAddress(host)) {
    score += WEIGHTS.ipAddress;
    reasons.push({ type: "bad", text: "Uses IP address instead of domain" });
  }

  // Rule 3: URL shorteners
  const shortener = matchedShortener(host.toLowerCase());
  if (shortener) {
    score += WEIGHTS.shortener;
    reasons.push({
      type: "bad",
      text: `Uses URL shortener (${shortener}) — real destination is hidden`,
    });
  }

  // Rule 4: "@" symbol
  if (url.includes("@")) {
    score += WEIGHTS.atSymbol;
    reasons.push({
      type: "bad",
      text: "URL contains @ symbol which can hide real destination",
    });
  }

  // Rule 5: Suspicious keywords
  const keywords = findKeywords(url);
  if (keywords.length > 0) {
    const points = Math.min(keywords.length, 3) * WEIGHTS.keyword;
    score += points;
    reasons.push({
      type: "warn",
      text: `Contains suspicious keyword(s): ${keywords.join(", ")}`,
    });
  } else {
    reasons.push({ type: "good", text: "No common phishing keywords found" });
  }

  // Rule 6: Too many subdomains
  const subs = countSubdomains(host);
  if (subs > MAX_SUBDOMAINS) {
    score += WEIGHTS.manySubdomains;
    reasons.push({
      type: "warn",
      text: `Too many subdomains (${subs}) — often used to mimic real sites`,
    });
  }

  // Rule 7: URL length
  if (url.length > LONG_URL_LIMIT) {
    score += WEIGHTS.longUrl;
    reasons.push({
      type: "warn",
      text: `URL is very long (${url.length} characters)`,
    });
  }

  score = clamp(Math.round(score), 0, 100);
  return {
    score,
    level: levelFromScore(score),
    reasons,
    domain: extractDomain(url),
  };
}
