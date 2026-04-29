import { Link, useLocation } from "wouter";

export function Navbar() {
  const [location] = useLocation();
  const onHome = location === "/";

  return (
    <nav className="flex items-center justify-between mb-8">
      <Link
        href="/"
        className="flex items-center gap-2.5 group"
        aria-label="PhishGuard home"
      >
        <span className="inline-flex items-center justify-center w-10 h-10 rounded-xl gradient-border group-hover:scale-105 transition-transform">
          <span className="text-xl">&#128737;</span>
        </span>
        <span className="text-lg font-bold text-slate-100">PhishGuard</span>
      </Link>

      {!onHome && (
        <Link
          href="/"
          className="text-sm text-slate-400 hover:text-slate-100 transition-colors flex items-center gap-1.5"
        >
          <span aria-hidden="true">&larr;</span> Back to Home
        </Link>
      )}
    </nav>
  );
}
