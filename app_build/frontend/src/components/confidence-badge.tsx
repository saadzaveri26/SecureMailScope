"use client";

import type { Confidence } from "@/types";

const styles: Record<Confidence, string> = {
  high: "text-emerald-900 bg-emerald-200 border-black",
  medium: "text-yellow-900 bg-yellow-200 border-black",
  low: "text-neutral-900 bg-neutral-200 border-black",
};

export function ConfidenceBadge({ level }: { level: Confidence }) {
  return (
    <span className={`inline-flex items-center px-1.5 py-0.2 border text-[10px] font-mono font-bold uppercase shadow-[1px_1px_0_#000] ${styles[level]}`}>
      {level}
    </span>
  );
}
