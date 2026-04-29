import { useMemo, useState } from "react";
import { Navbar } from "../components/Navbar";
import { Disclaimer } from "../components/Disclaimer";
import { Card } from "../components/ui/Card";
import { Textarea } from "../components/ui/Input";
import { Button } from "../components/ui/Button";
import { ResultPanel } from "../components/ResultPanel";
import {
  analyzeMessage,
  type MessageScanResult,
} from "../utils/message";

// Escape regex special characters so phrases can be safely placed in a regex.
function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

interface HighlightedProps {
  text: string;
  matches: string[];
}

// Highlights matched phrases inside the original message text.
function HighlightedMessage({ text, matches }: HighlightedProps) {
  const parts = useMemo(() => {
    if (matches.length === 0) return [{ value: text, hit: false }];
    // Build a single regex that matches any of the phrases (case-insensitive)
    const unique = Array.from(new Set(matches.filter(Boolean)));
    if (unique.length === 0) return [{ value: text, hit: false }];
    const regex = new RegExp(`(${unique.map(escapeRegex).join("|")})`, "gi");
    const split = text.split(regex);
    return split.map((segment) => ({
      value: segment,
      hit: regex.test(segment) && segment.length > 0,
    }));
  }, [text, matches]);

  return (
    <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-wrap break-words">
      {parts.map((p, i) =>
        p.hit ? (
          <mark
            key={i}
            className="bg-amber-500/30 text-amber-100 px-1 rounded"
          >
            {p.value}
          </mark>
        ) : (
          <span key={i}>{p.value}</span>
        ),
      )}
    </p>
  );
}

export function Message() {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<MessageScanResult | null>(null);
  const [analyzed, setAnalyzed] = useState("");

  function handleAnalyze() {
    const value = text.trim();
    if (!value) {
      setError("Please paste a message to analyze.");
      setResult(null);
      return;
    }
    setError(null);
    setLoading(true);
    setTimeout(() => {
      setResult(analyzeMessage(value));
      setAnalyzed(value);
      setLoading(false);
    }, 450);
  }

  return (
    <div className="max-w-3xl mx-auto px-5 py-8">
      <Navbar />

      <header className="mb-6 text-center">
        <div className="text-4xl mb-2">💬</div>
        <h1 className="text-3xl font-extrabold text-slate-100">
          Message Scanner
        </h1>
        <p className="mt-1.5 text-sm text-slate-400">
          Paste an SMS or chat message to spot phishing patterns.
        </p>
      </header>

      <Card className="mb-5">
        <label
          htmlFor="msg-input"
          className="block text-sm font-semibold text-slate-300 mb-2.5"
        >
          Message text
        </label>
        <Textarea
          id="msg-input"
          placeholder="URGENT: Your account is locked. Verify now at http://bit.ly/abc..."
          value={text}
          onChange={(e) => setText(e.target.value)}
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
            <div className="mb-5 px-4 py-3 bg-slate-950/60 border border-slate-800 rounded-xl">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-2">
                Message Preview
              </span>
              <HighlightedMessage text={analyzed} matches={result.matches} />
            </div>
          }
        />
      )}

      <Disclaimer />
    </div>
  );
}
