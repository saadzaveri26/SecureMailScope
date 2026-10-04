"use client";

import type { Severity } from "@/types";

const cfg: Record<Severity | "pass", { bg: string; text: string; label: string }> = {
  critical: { bg: "bg-sev-critical text-white", text: "text-sev-critical", label: "Critical" },
  high: { bg: "bg-sev-high text-white", text: "text-sev-high", label: "High" },
  medium: { bg: "bg-sev-medium-bg text-sev-medium border-sev-medium/30", text: "text-sev-medium", label: "Medium" },
  low: { bg: "bg-surface-2 text-text-secondary", text: "text-muted", label: "Low" },
  info: { bg: "bg-surface-1 text-muted", text: "text-muted", label: "Info" },
  pass: { bg: "bg-sev-pass text-white", text: "text-sev-pass", label: "Pass" },
};

export function SeverityBadge({ severity }: { severity: Severity | "pass" }) {
  const c = cfg[severity];
  return (
    <span
      className={`inline-block px-1.5 py-0.5 text-[11px] font-semibold rounded-[var(--radius-sm)] leading-none ${c.bg}`}
      aria-label={`${severity} severity`}
    >
      {c.label}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: Severity }) {
  const dotColors: Record<Severity, string> = {
    critical: "bg-sev-critical",
    high: "bg-sev-high",
    medium: "bg-sev-medium",
    low: "bg-muted",
    info: "bg-muted",
  };
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full ${dotColors[severity]}`}
      aria-hidden="true"
    />
  );
}
