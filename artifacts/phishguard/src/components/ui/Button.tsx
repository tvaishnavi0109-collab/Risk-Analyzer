import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "ghost";
type Size = "md" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  children: ReactNode;
}

export function Button({
  variant = "primary",
  size = "md",
  loading = false,
  children,
  disabled,
  className = "",
  ...rest
}: ButtonProps) {
  const base =
    "inline-flex items-center justify-center gap-2 font-semibold rounded-xl transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900 disabled:opacity-60 disabled:cursor-not-allowed";

  const sizes = {
    md: "px-5 py-2.5 text-sm",
    lg: "px-6 py-3 text-base",
  };

  const variants = {
    primary:
      "text-white bg-gradient-to-r from-blue-500 to-indigo-600 hover:brightness-110 active:scale-[0.98] shadow-lg shadow-blue-500/30 focus:ring-blue-400",
    ghost:
      "text-slate-300 bg-slate-800/60 hover:bg-slate-800 border border-slate-700 focus:ring-slate-500",
  };

  return (
    <button
      {...rest}
      disabled={disabled || loading}
      className={`${base} ${sizes[size]} ${variants[variant]} ${className}`}
    >
      {loading && <span className="spinner" aria-hidden="true" />}
      {children}
    </button>
  );
}
