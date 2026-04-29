import type { ReactNode } from "react";

interface CardProps {
  children: ReactNode;
  className?: string;
}

export function Card({ children, className = "" }: CardProps) {
  return (
    <div
      className={`bg-slate-900/70 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm shadow-xl shadow-black/20 ${className}`}
    >
      {children}
    </div>
  );
}
