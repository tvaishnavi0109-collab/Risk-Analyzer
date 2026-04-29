import type { InputHTMLAttributes, TextareaHTMLAttributes } from "react";

type InputProps = InputHTMLAttributes<HTMLInputElement>;

export function Input({ className = "", ...rest }: InputProps) {
  return (
    <input
      {...rest}
      className={`w-full px-4 py-3 text-[15px] bg-slate-950/60 text-slate-100 placeholder:text-slate-500 border-2 border-slate-700 rounded-xl outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/20 transition-colors ${className}`}
    />
  );
}

type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement>;

export function Textarea({ className = "", ...rest }: TextareaProps) {
  return (
    <textarea
      {...rest}
      className={`w-full px-4 py-3 text-[15px] bg-slate-950/60 text-slate-100 placeholder:text-slate-500 border-2 border-slate-700 rounded-xl outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/20 transition-colors resize-y min-h-[140px] font-sans ${className}`}
    />
  );
}
