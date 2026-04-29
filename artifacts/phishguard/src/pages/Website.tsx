import { useState } from "react";
import { Navbar } from "../components/Navbar";
import { Disclaimer } from "../components/Disclaimer";
import { Card } from "../components/ui/Card";
import { Input } from "../components/ui/Input";
import { Button } from "../components/ui/Button";
import { ResultPanel } from "../components/ResultPanel";
import {
  analyzeUrl,
  type WebsiteScanResult,
} from "../utils/website";

export function Website() {
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<WebsiteScanResult | null>(null);

  function handleAnalyze() {
    const value = url.trim();
    if (!value) {
      setError("Please enter a URL to analyze.");
      setResult(null);
      return;
    }
    if (!value.includes(".")) {
      setError("That does not look like a valid URL.");
      setResult(null);
      return;
    }
    setError(null);
    setLoading(true);
    // Tiny artificial delay so the loading animation is visible — feels like a scan.
    setTimeout(() => {
      setResult(analyzeUrl(value));
      setLoading(false);
    }, 450);
  }

  return (
    <div className="max-w-3xl mx-auto px-5 py-8">
      <Navbar />

      <header className="mb-6 text-center">
        <div className="text-4xl mb-2">🌐</div>
        <h1 className="text-3xl font-extrabold text-slate-100">
          Website Scanner
        </h1>
        <p className="mt-1.5 text-sm text-slate-400">
          Paste a URL to check for common phishing signals.
        </p>
      </header>

      <Card className="mb-5">
        <label
          htmlFor="url-input"
          className="block text-sm font-semibold text-slate-300 mb-2.5"
        >
          Enter a URL
        </label>
        <div className="flex flex-col sm:flex-row gap-2.5">
          <Input
            id="url-input"
            type="text"
            placeholder="https://example.com/login"
            autoComplete="off"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleAnalyze();
            }}
          />
          <Button onClick={handleAnalyze} loading={loading} size="lg">
            {loading ? "Analyzing" : "Analyze"}
          </Button>
        </div>
        {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}
      </Card>

      {result && (
        <ResultPanel
          level={result.level}
          score={result.score}
          reasons={result.reasons}
          extra={
            <div className="mb-5 flex items-center gap-2 flex-wrap px-4 py-3 bg-slate-950/60 border border-slate-800 rounded-xl">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Detected Domain
              </span>
              <span className="text-base font-semibold text-slate-100 break-all">
                {result.domain}
              </span>
            </div>
          }
        />
      )}

      <Disclaimer />
    </div>
  );
}
