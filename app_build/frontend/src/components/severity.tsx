"use client";

import type { Severity } from "@/types";

const cfg: Record<Severity | "pass", { bg: string; text: string; label: string }> = {
  critical: { bg: "bg-red-500 text-white border-black", text: "text-red-600", label: "CRIT" },
  high: { bg: "bg-orange-400 text-black border-black", text: "text-orange-600", label: "HIGH" },
  medium: { bg: "bg-yellow-300 text-black border-black", text: "text-yellow-700", label: "MED" },
  low: { bg: "bg-neutral-200 text-black border-black", text: "text-neutral-700", label: "LOW" },
  info: { bg: "bg-sky-200 text-black border-black", text: "text-sky-700", label: "INFO" },
  pass: { bg: "bg-emerald-400 text-black border-black", text: "text-emerald-700", label: "PASS" },
};

export function SeverityBadge({ severity }: { severity: Severity | "pass" }) {
  const c = cfg[severity];
  return (
    <span className={`inline-block px-1.5 py-0.5 text-[10px] font-mono font-bold border leading-none shadow-[1px_1px_0_#000] ${c.bg}`}>
      {c.label}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: Severity }) {
  const c = cfg[severity];
  return <span className={`inline-block w-2 h-2 border border-black ${c.bg}`} />;
}
