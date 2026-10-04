"use client";

import type { CustodyEvent } from "@/types";

const ICONS: Record<string, string> = {
  uploaded: "📤",
  analysis_started: "🔬",
  analysis_completed: "✅",
  report_exported: "📄",
  payload_deleted: "🗑️",
  keylog_attached: "🔑",
  artifact_attached: "📎",
};

export function CustodyTimeline({ events }: { events: CustodyEvent[] }) {
  if (!events.length) {
    return (
      <div className="text-[var(--font-size-md)] text-muted py-4 text-center">No custody events recorded.</div>
    );
  }

  return (
    <div className="space-y-0" role="list" aria-label="Chain of custody events">
      {events.map((ev, i) => (
        <div key={ev.id} className="flex gap-3 group" role="listitem">
          <div className="flex flex-col items-center w-5 shrink-0">
            <span className="text-[var(--font-size-md)] leading-none mt-0.5" aria-hidden="true">
              {ICONS[ev.action] ?? "•"}
            </span>
            {i < events.length - 1 && (
              <div className="flex-1 w-px bg-border mt-1 mb-0" />
            )}
          </div>
          <div className="flex-1 pb-4 min-w-0">
            <div className="flex items-baseline gap-2 flex-wrap">
              <span className="text-[var(--font-size-md)] font-medium text-foreground">
                {ev.action.replace(/_/g, " ")}
              </span>
              <span className="text-[11px] text-muted font-mono">
                {ev.actor}
              </span>
            </div>
            <p className="text-[11px] text-muted mt-0.5 truncate">{ev.detail}</p>
            <time className="text-[11px] text-muted/60 font-mono tabular-nums block mt-0.5">
              {new Date(ev.ts).toLocaleString("en-US", {
                year: "numeric",
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                timeZoneName: "short",
              })}
            </time>
          </div>
        </div>
      ))}
    </div>
  );
}
