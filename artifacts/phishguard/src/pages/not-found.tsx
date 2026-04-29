import { Link } from "wouter";
import { Card } from "../components/ui/Card";

export function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center px-5">
      <Card className="max-w-md w-full text-center">
        <div className="text-5xl mb-3">⚠️</div>
        <h1 className="text-2xl font-bold text-slate-100 mb-2">
          Page not found
        </h1>
        <p className="text-sm text-slate-400 mb-5">
          The page you're looking for doesn't exist.
        </p>
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-blue-400 hover:text-blue-300 text-sm font-semibold"
        >
          <span aria-hidden="true">&larr;</span> Back to Home
        </Link>
      </Card>
    </div>
  );
}
