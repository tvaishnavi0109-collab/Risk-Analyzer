// PhishGuard - URL Risk Analyzer
// Beginner-friendly URL risk analysis using simple weighted rules.

// ---- Configuration ----

// Words commonly found in phishing URLs trying to impersonate trusted services
const SUSPICIOUS_KEYWORDS = [
  'login',
  'verify',
  'secure',
  'account',
  'update',
  'signin',
];

// If the URL is longer than this, we consider it suspicious
const LONG_URL_LIMIT = 75;

// More than this many hyphens looks suspicious
const MAX_HYPHENS = 3;

// Each rule contributes some points to the total risk score (out of 100).
// We tune these weights so a single big issue (like an IP address) is enough
// to push the URL into the high-risk zone.
const WEIGHTS = {
  noHttps: 25,       // URL does not use HTTPS
  keyword: 12,       // Each suspicious keyword found (capped below)
  longUrl: 15,       // URL is too long
  manyHyphens: 10,   // URL has too many hyphens
  ipAddress: 45,     // URL uses an IP address instead of a domain
  atSymbol: 30,      // URL contains "@" which can hide the real destination
};

// ---- Helpers ----

// Find all suspicious keywords inside the URL (case-insensitive)
function findSuspiciousKeywords(url) {
  const lower = url.toLowerCase();
  return SUSPICIOUS_KEYWORDS.filter((word) => lower.includes(word));
}

// Count how many "-" characters are in the URL
function countHyphens(url) {
  return (url.match(/-/g) || []).length;
}

// Get the host portion of a URL (the part after the protocol, before the path).
// Example: "https://example.com/login?x=1" -> "example.com"
function getHost(url) {
  const withoutProtocol = url.replace(/^https?:\/\//i, '');
  // If the URL has an "@" (like user@host), take the part AFTER it as the host
  const afterAt = withoutProtocol.includes('@')
    ? withoutProtocol.split('@').pop()
    : withoutProtocol;
  // Host is everything before the first "/", "?", "#", or ":"
  return afterAt.split(/[/:?#]/)[0];
}

// Extract the main domain (e.g., "https://www.example.com/foo" -> "example.com")
// We drop a leading "www." but otherwise return the host as-is so the user
// can see the exact domain being analyzed.
function extractDomain(url) {
  const host = getHost(url).toLowerCase();
  if (!host) return 'unknown';
  return host.replace(/^www\./, '');
}

// Check if the URL contains an IPv4 address (e.g., 192.168.1.1)
function containsIpAddress(url) {
  const host = getHost(url);
  // Match four numbers (0-255) separated by dots
  const ipPattern = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  return ipPattern.test(host);
}

// Check if the URL contains an "@" symbol (often used to hide the real host)
function containsAtSymbol(url) {
  return url.includes('@');
}

// Keep a number inside a min/max range
function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

// ---- Main analyzer ----

// Returns: { score, level, reasons, domain }
function analyzeUrl(url) {
  const reasons = [];
  let score = 0;

  // Rule 1: HTTPS check
  if (url.toLowerCase().startsWith('https://')) {
    reasons.push({ type: 'good', text: 'Uses HTTPS (secure connection)' });
  } else {
    score += WEIGHTS.noHttps;
    reasons.push({
      type: 'bad',
      text: 'Does not use HTTPS (connection is not secure)',
    });
  }

  // Rule 2: IP address check (big risk increase)
  if (containsIpAddress(url)) {
    score += WEIGHTS.ipAddress;
    reasons.push({
      type: 'bad',
      text: 'Uses IP address instead of domain',
    });
  }

  // Rule 3: "@" symbol check
  // Attackers use "@" to make a URL look legitimate while sending you elsewhere.
  // Example: https://google.com@evil.com actually goes to evil.com
  if (containsAtSymbol(url)) {
    score += WEIGHTS.atSymbol;
    reasons.push({
      type: 'bad',
      text: 'URL contains @ symbol which can hide real destination',
    });
  }

  // Rule 4: Suspicious keywords
  const foundKeywords = findSuspiciousKeywords(url);
  if (foundKeywords.length > 0) {
    // Cap the keyword penalty so dozens of matches don't blow up the score
    const keywordPoints = Math.min(foundKeywords.length, 3) * WEIGHTS.keyword;
    score += keywordPoints;
    reasons.push({
      type: 'warn',
      text: `Contains suspicious keyword(s): ${foundKeywords.join(', ')}`,
    });
  } else {
    reasons.push({
      type: 'good',
      text: 'No common phishing keywords found',
    });
  }

  // Rule 5: URL length
  if (url.length > LONG_URL_LIMIT) {
    score += WEIGHTS.longUrl;
    reasons.push({
      type: 'warn',
      text: `URL is very long (${url.length} characters)`,
    });
  } else {
    reasons.push({
      type: 'good',
      text: `URL length looks normal (${url.length} characters)`,
    });
  }

  // Rule 6: Hyphen count
  const hyphens = countHyphens(url);
  if (hyphens > MAX_HYPHENS) {
    score += WEIGHTS.manyHyphens;
    reasons.push({
      type: 'warn',
      text: `Contains many hyphens (${hyphens} found)`,
    });
  } else {
    reasons.push({
      type: 'good',
      text: `Hyphen count is normal (${hyphens} found)`,
    });
  }

  // Keep the score between 0 and 100
  score = clamp(Math.round(score), 0, 100);

  // Convert score to a level
  let level;
  if (score <= 40) {
    level = 'Likely Safe';
  } else if (score <= 70) {
    level = 'Suspicious';
  } else {
    level = 'High Risk';
  }

  // Pull out the main domain so we can show it in the UI
  const domain = extractDomain(url);

  return { score, level, reasons, domain };
}

// Map a level to a CSS class used for badge + score bar colors
function levelClass(level) {
  if (level === 'Likely Safe') return 'safe';
  if (level === 'Suspicious') return 'suspicious';
  return 'high-risk';
}

// ---- DOM wiring ----

const urlInput = document.getElementById('url-input');
const analyzeBtn = document.getElementById('analyze-btn');
const errorMessage = document.getElementById('error-message');
const resultSection = document.getElementById('result');
const riskBadge = document.getElementById('risk-badge');
const riskScore = document.getElementById('risk-score');
const scoreBarFill = document.getElementById('score-bar-fill');
const reasonsList = document.getElementById('reasons-list');
const detectedDomain = document.getElementById('detected-domain');

// Show an error message under the input
function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
  resultSection.hidden = true;
}

// Hide the error message
function clearError() {
  errorMessage.hidden = true;
  errorMessage.textContent = '';
}

// Render the analysis result on the page
function renderResult(result) {
  const cls = levelClass(result.level);

  // Detected domain
  detectedDomain.textContent = result.domain;

  // Risk badge
  riskBadge.textContent = result.level;
  riskBadge.className = 'badge ' + cls;

  // Risk score number
  riskScore.textContent = result.score + '%';

  // Risk score bar
  scoreBarFill.className = 'score-bar-fill ' + cls;
  scoreBarFill.style.width = result.score + '%';

  // Reasons list
  reasonsList.innerHTML = '';
  result.reasons.forEach((reason) => {
    const li = document.createElement('li');
    li.textContent = reason.text;
    li.classList.add(reason.type);
    reasonsList.appendChild(li);
  });

  resultSection.hidden = false;
}

// Run when the user clicks the Analyze button
function handleAnalyze() {
  const url = urlInput.value.trim();

  // Basic validation
  if (!url) {
    showError('Please enter a URL to analyze.');
    return;
  }

  if (!url.includes('.')) {
    showError('That does not look like a valid URL.');
    return;
  }

  clearError();
  const result = analyzeUrl(url);
  renderResult(result);
}

// Click button to analyze
analyzeBtn.addEventListener('click', handleAnalyze);

// Press Enter inside the input to analyze
urlInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    handleAnalyze();
  }
});
