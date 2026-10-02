"use client";

import type { Confidence } from "@/types";

const styles: Record<Confidence, string> = {
  high: "text-sev-pass bg-sev-pass-bg",
  medium: "text-sev-medium bg-sev-medium-bg",
  low: "text-not-observable bg-not-observable-bg",
};

export function ConfidenceBadge({ level }: { level: Confidence }) {
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-medium ${styles[level]}`}>
      {level}
    </span>
  );
}
