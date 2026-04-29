import { useState } from "react";
import { Navbar } from "../components/Navbar";
import { Disclaimer } from "../components/Disclaimer";
import { Card } from "../components/ui/Card";
import { Textarea } from "../components/ui/Input";
import { Button } from "../components/ui/Button";
import { ResultPanel } from "../components/ResultPanel";
import {
  analyzeEmail,
  type EmailScanResult,
} from "../utils/email";

export function Email() {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<EmailScanResult | null>(null);

  function handleAnalyze() {
    const value = text.trim();
    if (!value) {
      setError("Please paste an email to analyze.");
      setResult(null);
      return;
    }
    setError(null);
    setLoading(true);
    setTimeout(() => {
      setResult(analyzeEmail(value));
      setLoading(false);
    }, 500);
  }

  return (
    <div className="max-w-3xl mx-auto px-5 py-8">
      <Navbar />

      <header className="mb-6 text-center">
        <div className="text-4xl mb-2">📧</div>
        <h1 className="text-3xl font-extrabold text-slate-100">Email Scanner</h1>
        <p className="mt-1.5 text-sm text-slate-400">
          Paste an email's content to detect phishing techniques.
        </p>
      </header>

      <Card className="mb-5">
        <label
          htmlFor="email-input"
          className="block text-sm font-semibold text-slate-300 mb-2.5"
        >
          Email content
        </label>
        <Textarea
          id="email-input"
          placeholder={`From: support@paypa1.com\nSubject: URGENT - Verify your PayPal account\n\nDear customer, your account has been suspended...`}
          value={text}
          onChange={(e) => setText(e.target.value)}
          className="min-h-[200px]"
        />
        <div className="mt-3 flex justify-end">
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
            result.warnings.length > 0 ? (
              <div className="mb-5 px-4 py-3 bg-rose-950/30 border border-rose-900/50 rounded-xl">
                <span className="text-xs font-semibold uppercase tracking-wider text-rose-300 block mb-2">
                  Warnings
                </span>
                <ul className="list-disc pl-5 text-sm text-rose-200/90 space-y-1">
                  {result.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              </div>
            ) : undefined
          }
        />
      )}

      <Disclaimer />
    </div>
  );
}
