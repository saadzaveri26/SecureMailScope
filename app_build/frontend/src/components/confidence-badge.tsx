"use client";

import type { Confidence } from "@/types";

const styles: Record<Confidence, string> = {
  high: "text-sev-pass bg-sev-pass-bg",
  medium: "text-sev-medium bg-sev-medium-bg",
  low: "text-muted bg-surface-2",
};

export function ConfidenceBadge({ level }: { level: Confidence }) {
  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 text-[var(--font-size-sm)] font-mono font-bold uppercase rounded-[var(--radius-sm)] ${styles[level]}`}
      aria-label={`${level} confidence`}
    >
      {level}
    </span>
  );
}
