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
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="bg-surface-0 border-b border-border-subtle">
      <div className="max-w-[1400px] mx-auto px-4 py-2 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-3 min-w-0 flex-wrap">
          <div className="flex items-center gap-1.5">
            <span className="text-muted">Capture:</span>
            <select
              value={current.id}
              onChange={(e) => onSwitch(e.target.value)}
              className="bg-surface-1 border border-border rounded-md px-2 py-1 font-mono text-xs text-foreground focus:outline-none focus:border-brand"
            >
              {caps.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.filename} ({c.id})
                </option>
              ))}
            </select>
          </div>

          <span className="text-border">|</span>

          <span className="font-mono font-medium text-foreground truncate max-w-xs">{current.filename}</span>

          <span className="text-border">|</span>

          <div className="flex items-center gap-1 text-muted text-xs">
            <span>SHA-256:</span>
            <span className="font-mono text-foreground">{current.sha256.slice(0, 12)}</span>
            <button
              onClick={onCopy}
              className="p-1 hover:bg-surface-2 rounded text-muted hover:text-foreground transition-colors"
              title="Copy SHA-256"
            >
              {copied ? <Check size={12} className="text-brand" /> : <Copy size={12} />}
            </button>
          </div>

          <span className="text-border">|</span>

          <span className="tabular-nums text-muted text-xs">
            {current.packet_count.toLocaleString()} packets
          </span>

          <span className="text-border">|</span>

          <span className="text-muted capitalize text-xs">
            Status: <span className="font-medium text-foreground">{current.status}</span>
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0 text-xs">
          <span className="text-muted">Score:</span>
          {current.posture_score !== null ? (
            <span className="font-medium text-foreground">
              <strong className="tabular-nums font-semibold">{current.posture_score}</strong>
              <span className="text-muted ml-1">({current.grade})</span>
            </span>
          ) : (
            <span className="text-muted">—</span>
          )}
        </div>
      </div>
    </div>
  );
}
