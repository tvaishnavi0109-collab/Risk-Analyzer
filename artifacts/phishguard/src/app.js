// PhishGuard - URL Risk Analyzer
// Simple, beginner-friendly URL risk analysis using basic rules.

// ---- Configuration ----

// Words commonly found in phishing URLs trying to impersonate trusted services
const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'account'];

// If the URL is longer than this, we consider it suspicious
const LONG_URL_LIMIT = 75;

// More than this many hyphens looks suspicious
const MAX_HYPHENS = 3;

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

// ---- Main analyzer ----

// Returns an object: { level: 'Safe' | 'Suspicious' | 'High Risk', reasons: [...] }
function analyzeUrl(url) {
  const reasons = [];

  // Rule 1: Check if URL starts with https
  if (url.toLowerCase().startsWith('https://')) {
    reasons.push({ type: 'good', text: 'Uses HTTPS (secure connection)' });
  } else {
    reasons.push({
      type: 'bad',
      text: 'Does not use HTTPS (connection is not secure)',
    });
  }

  // Rule 2: Check for suspicious keywords (login, verify, secure, account)
  const foundKeywords = findSuspiciousKeywords(url);
  if (foundKeywords.length > 0) {
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

  // Rule 3: Check if URL is too long
  if (url.length > LONG_URL_LIMIT) {
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

  // Rule 4: Check for too many hyphens
  const hyphens = countHyphens(url);
  if (hyphens > MAX_HYPHENS) {
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

  // ---- Decide overall risk level ----
  // Count how many warnings/bad signals we found
  const badCount = reasons.filter((r) => r.type === 'bad').length;
  const warnCount = reasons.filter((r) => r.type === 'warn').length;
  const totalIssues = badCount + warnCount;

  let level;
  if (totalIssues === 0) {
    level = 'Safe';
  } else if (totalIssues <= 2) {
    level = 'Suspicious';
  } else {
    level = 'High Risk';
  }

  return { level, reasons };
}

// ---- DOM wiring ----

const urlInput = document.getElementById('url-input');
const analyzeBtn = document.getElementById('analyze-btn');
const errorMessage = document.getElementById('error-message');
const resultSection = document.getElementById('result');
const riskBadge = document.getElementById('risk-badge');
const reasonsList = document.getElementById('reasons-list');

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
  // Set the risk badge text and color
  riskBadge.textContent = result.level;
  riskBadge.className = 'badge';
  if (result.level === 'Safe') riskBadge.classList.add('safe');
  if (result.level === 'Suspicious') riskBadge.classList.add('suspicious');
  if (result.level === 'High Risk') riskBadge.classList.add('high-risk');

  // Build the list of reasons
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
