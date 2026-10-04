"use client";

import { useState, useEffect } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import type { Capture } from "@/types";
import { getCaptures } from "@/data";
import { Copy, Check } from "@phosphor-icons/react";

export function CaptureStrip() {
  const path = usePathname();
  const router = useRouter();
  const params = useSearchParams();

  const [caps, setCaps] = useState<Capture[]>([]);
  const [copied, setCopied] = useState(false);
  const [copyAnnounce, setCopyAnnounce] = useState("");

  const show = [
    "/overview",
    "/sessions",
    "/findings",
    "/drift",
    "/reports",
  ].some((p) => path.startsWith(p));

  useEffect(() => {
    if (!show) return;
    let active = true;
    getCaptures().then((list) => {
      if (active) setCaps(list);
    });
    return () => {
      active = false;
    };
  }, [show]);

  if (!show || caps.length === 0) return null;

  const currentId = params.get("capture") ?? params.get("current") ?? caps[0].id;
  const current = caps.find((c) => c.id === currentId) ?? caps[0];

  function onSwitch(id: string) {
    const next = new URLSearchParams(params.toString());
    if (path.startsWith("/drift")) {
      next.set("current", id);
      next.set("capture", id);
    } else {
      next.set("capture", id);
    }
    router.push(`${path}?${next.toString()}`);
  }

  function onCopy() {
    navigator.clipboard.writeText(current.sha256);
    setCopied(true);
    setCopyAnnounce("SHA-256 hash copied to clipboard");
    setTimeout(() => {
      setCopied(false);
      setCopyAnnounce("");
    }, 2000);
  }

  const isCritical = current.posture_score !== null && current.posture_score < 60;
  const isHealthy = current.posture_score !== null && current.posture_score >= 80;

  return (
    <div className="bg-surface-1 border-b border-border text-[var(--font-size-sm)] select-none">
      <div className="max-w-[1600px] mx-auto px-4 h-7 flex items-center justify-between gap-3 font-mono">
        <div className="flex items-center gap-[var(--space-6)] min-w-0">
          <label htmlFor="capture-select" className="text-muted font-bold">capture:</label>
          <select
            id="capture-select"
            value={current.id}
            onChange={(e) => onSwitch(e.target.value)}
            className="bg-surface-0 border border-border rounded-[var(--radius-xs)] px-1 font-mono text-[var(--font-size-sm)] text-foreground focus-ring cursor-pointer font-bold"
          >
            {caps.map((c) => (
              <option key={c.id} value={c.id} className="bg-surface-0 text-foreground">
                {c.filename} [{c.id}]
              </option>
            ))}
          </select>

          <span className="text-border">│</span>

          <span className="text-muted">sha256:</span>
          <span className="text-foreground font-bold select-all">{current.sha256.slice(0, 12)}…</span>
          <button
            onClick={onCopy}
            className="p-0.5 text-muted hover:text-foreground transition-colors duration-[var(--motion-fast)] cursor-pointer focus-ring rounded-[var(--radius-xs)]"
            aria-label="Copy full SHA-256 to clipboard"
          >
            {copied ? <Check size={11} weight="bold" className="text-sev-pass" /> : <Copy size={11} weight="bold" />}
          </button>

          {/* Screen reader live region for copy announcement */}
          <span className="sr-only" aria-live="polite">{copyAnnounce}</span>

          <span className="text-border">│</span>

          <span className="text-foreground font-semibold">{current.packet_count.toLocaleString()} pkts</span>

          <span className="text-border">│</span>

          <span className="text-muted uppercase font-bold">{current.status}</span>
        </div>

        <div className="flex items-center gap-[var(--space-6)] shrink-0">
          {current.posture_score !== null ? (
            <div className={`px-2 py-0.5 rounded-[var(--radius-sm)] font-mono font-bold text-[var(--font-size-sm)] flex items-center gap-1.5 ${
              isCritical ? "bg-sev-critical text-white" : isHealthy ? "bg-sev-pass text-white" : "bg-accent text-white"
            }`}>
              <span className="tabular-nums">
                {current.posture_score}/100
              </span>
              <span className="text-[10px] opacity-80">
                [{current.grade}]
              </span>
            </div>
          ) : (
            <div className="px-2 py-0.5 rounded-[var(--radius-sm)] bg-surface-2 text-muted font-mono font-bold text-[var(--font-size-sm)]">
              <span>NO TRAFFIC [N/A]</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
