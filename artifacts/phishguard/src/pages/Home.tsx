import { Link } from "wouter";
import { Navbar } from "../components/Navbar";
import { Disclaimer } from "../components/Disclaimer";

interface ScannerCard {
  href: string;
  icon: string;
  title: string;
  description: string;
  accent: string;
}

const SCANNERS: ScannerCard[] = [
  {
    href: "/website",
    icon: "🌐",
    title: "Website Scanner",
    description:
      "Analyze a URL for phishing signs: HTTPS, suspicious keywords, IP hosts, shorteners and more.",
    accent: "from-blue-500/20 to-blue-500/0",
  },
  {
    href: "/message",
    icon: "💬",
    title: "Message Scanner",
    description:
      "Paste an SMS or chat message to detect urgency, financial bait and credential requests.",
    accent: "from-purple-500/20 to-purple-500/0",
  },
  {
    href: "/email",
    icon: "📧",
    title: "Email Scanner",
    description:
      "Inspect email content for fake authority tone, spoofed domains and risky attachments.",
    accent: "from-pink-500/20 to-pink-500/0",
  },
];

export function Home() {
  return (
    <div className="max-w-5xl mx-auto px-5 py-8">
      <Navbar />

      <header className="text-center mt-6 mb-12">
        <h1 className="text-5xl sm:text-6xl font-extrabold tracking-tight gradient-text">
          PhishGuard
        </h1>
        <p className="mt-3 text-base sm:text-lg text-slate-400">
          Multi-Vector Phishing Detection System
        </p>
      </header>

      <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
        {SCANNERS.map((scanner) => (
          <Link
            key={scanner.href}
            href={scanner.href}
            className={`scanner-card-hover block bg-slate-900/70 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm relative overflow-hidden`}
          >
            <div
              className={`absolute inset-0 bg-gradient-to-b ${scanner.accent} pointer-events-none`}
              aria-hidden="true"
            />
            <div className="relative">
              <div className="text-4xl mb-3">{scanner.icon}</div>
              <h2 className="text-xl font-bold text-slate-100 mb-2">
                {scanner.title}
              </h2>
              <p className="text-sm text-slate-400 leading-relaxed">
                {scanner.description}
              </p>
              <span className="inline-flex items-center gap-1 mt-4 text-sm text-blue-400 font-semibold">
                Open scanner <span aria-hidden="true">&rarr;</span>
              </span>
            </div>
          </Link>
        ))}
      </div>

      <Disclaimer />
    </div>
  );
}
