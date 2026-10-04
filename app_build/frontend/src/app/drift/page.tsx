"use client";

import { useState, useEffect, useMemo, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import type { Capture, Drift, DriftDirection } from "@/types";
import { getCaptures, getDrift } from "@/data";
import { SeverityBadge } from "@/components/severity";
import { ArrowsLeftRight } from "@phosphor-icons/react";

export default function DriftPage() {
  return (
    <Suspense fallback={<Skeleton />}>
      <Content />
    </Suspense>
  );
}

function Skeleton() {
  return (
    <div className="w-full space-y-3 animate-pulse">
      <div className="h-4 w-44 bg-surface-2" />
      <div className="border border-border bg-surface-0 h-96 xcor-shadow" />
    </div>
  );
}

function Content() {
  const searchParams = useSearchParams();
  const [caps, setCaps] = useState<Capture[]>([]);
  const [baselineId, setBaselineId] = useState<string>(searchParams.get("baseline") ?? "cap-002");
  const [currentId, setCurrentId] = useState<string>(searchParams.get("current") ?? searchParams.get("capture") ?? "cap-001");
  const [drift, setDrift] = useState<Drift | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterDir, setFilterDir] = useState<string>("");
  const [diffMode, setDiffMode] = useState<"unified" | "split">("unified");

  function loadDrift(bId: string, cId: string) {
    setLoading(true);
    setError(null);
    getDrift(bId, cId)
      .then((d) => { setDrift(d); setLoading(false); })
      .catch((e: unknown) => { setError(e instanceof Error ? e.message : "Failed to load drift"); setLoading(false); });
  }

  useEffect(() => {
    let active = true;
    getCaptures()
      .then((cList) => {
        if (!active) return;
        setCaps(cList);
        const complete = cList.filter((c) => c.status === "complete");
        const b = searchParams.get("baseline") ?? (complete.find((c) => c.id === "cap-002")?.id ?? complete[1]?.id ?? "cap-002");
        const c = searchParams.get("current") ?? searchParams.get("capture") ?? (complete.find((c) => c.id === "cap-001")?.id ?? complete[0]?.id ?? "cap-001");
        setBaselineId(b);
        setCurrentId(c);
        return getDrift(b, c);
      })
      .then((d) => { if (active && d) { setDrift(d); setLoading(false); } })
      .catch((e: unknown) => { if (active) { setError(e instanceof Error ? e.message : "Failed to load drift"); setLoading(false); } });
    return () => { active = false; };
  }, [searchParams]);

  function handleCompare(b: string, c: string) {
    setBaselineId(b);
    setCurrentId(c);
    loadDrift(b, c);
  }

  const baselineCap = caps.find((c) => c.id === baselineId);
  const currentCap = caps.find((c) => c.id === currentId);
  const changes = drift?.changes ?? [];

  const filtered = useMemo(() => {
    return filterDir ? changes.filter((ch) => ch.direction === filterDir) : changes;
  }, [changes, filterDir]);

  const degradedCount = changes.filter((c) => c.direction === "degraded").length;
  const improvedCount = changes.filter((c) => c.direction === "improved").length;
  const otherCount = changes.filter((c) => !["degraded", "improved"].includes(c.direction)).length;

  return (
    <div className="w-full px-4 2xl:px-6 py-4 space-y-3 select-none text-[13px]">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h1 className="text-[20px] font-semibold text-foreground">Posture drift</h1>
          <span className="text-muted">·</span>
          <span className="text-muted text-[13px] font-medium">{filtered.length} changes detected</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex border border-border bg-surface-0 rounded-[var(--radius-xs)] overflow-hidden">
            <button
              onClick={() => setDiffMode("unified")}
              className={`px-2.5 py-1 text-[12px] font-medium cursor-pointer transition-colors ${diffMode === "unified" ? "bg-accent text-white" : "text-muted hover:text-foreground"}`}
            >
              Unified
            </button>
            <button
              onClick={() => setDiffMode("split")}
              className={`px-2.5 py-1 text-[12px] font-medium cursor-pointer transition-colors border-l border-border ${diffMode === "split" ? "bg-accent text-white" : "text-muted hover:text-foreground"}`}
            >
              Side-by-side
            </button>
          </div>
          <select
            value={filterDir}
            onChange={(e) => setFilterDir(e.target.value)}
            className="px-2.5 py-1 bg-surface-0 border border-border text-[12px] font-medium text-foreground rounded-[var(--radius-xs)] focus-ring cursor-pointer"
          >
            <option value="">All directions</option>
            <option value="degraded">Degraded</option>
            <option value="improved">Improved</option>
            <option value="changed">Changed</option>
          </select>
        </div>
      </div>

      {/* Capture comparison selectors */}
      <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_1fr] gap-3 items-center text-[13px]">
        <div className="border border-border bg-surface-0 p-3 rounded-[var(--radius-md)] space-y-1 xcor-shadow-subtle">
          <div className="text-[12px] text-sev-critical font-medium">Baseline capture</div>
          <select
            value={baselineId}
            onChange={(e) => handleCompare(e.target.value, currentId)}
            className="w-full bg-surface-1 border border-border p-1.5 rounded-[var(--radius-xs)] text-foreground font-medium text-[13px] focus-ring cursor-pointer"
          >
            {caps.map((c) => (
              <option key={c.id} value={c.id} className="bg-surface-0 font-sans">{c.filename} [{c.id}] score: {c.posture_score ?? "—"}</option>
            ))}
          </select>
        </div>
        <div className="flex items-center justify-center p-2 bg-accent rounded-[var(--radius-sm)] text-white">
          <ArrowsLeftRight size={16} weight="bold" />
        </div>
        <div className="border border-border bg-surface-0 p-3 rounded-[var(--radius-md)] space-y-1 xcor-shadow-subtle">
          <div className="text-[12px] text-sev-pass font-medium">Current capture</div>
          <select
            value={currentId}
            onChange={(e) => handleCompare(baselineId, e.target.value)}
            className="w-full bg-surface-1 border border-border p-1.5 rounded-[var(--radius-xs)] text-foreground font-medium text-[13px] focus-ring cursor-pointer"
          >
            {caps.map((c) => (
              <option key={c.id} value={c.id} className="bg-surface-0 font-sans">{c.filename} [{c.id}] score: {c.posture_score ?? "—"}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Stats strip */}
      <div className="flex items-center gap-3 text-[13px] border border-border bg-surface-0 px-3 py-2 rounded-[var(--radius-md)] xcor-shadow-subtle">
        <span className="text-sev-critical tabular-nums bg-sev-critical-bg px-2 py-0.5 rounded-[var(--radius-xs)] font-medium">{degradedCount} degraded</span>
        <span className="text-sev-pass tabular-nums bg-sev-pass-bg px-2 py-0.5 rounded-[var(--radius-xs)] font-medium">{improvedCount} improved</span>
        <span className="tabular-nums text-muted">{otherCount} other changes</span>
        {baselineCap && currentCap && baselineCap.posture_score !== null && currentCap.posture_score !== null && (
          <>
            <span className="text-border">│</span>
            <span className={`tabular-nums font-mono px-2 py-0.5 rounded-[var(--radius-xs)] font-medium ${
              (currentCap.posture_score - baselineCap.posture_score) < 0 ? "bg-sev-critical text-white" : "bg-sev-pass text-white"
            }`}>
              Δ {currentCap.posture_score - baselineCap.posture_score} pts posture change
            </span>
          </>
        )}
      </div>

      {/* Diff content */}
      {loading ? (
        <Skeleton />
      ) : error ? (
        <div className="text-[13px] text-sev-critical border border-border bg-sev-critical-bg p-3 rounded-[var(--radius-md)]">{error}</div>
      ) : baselineId === currentId ? (
        <div className="text-[13px] text-muted border border-border bg-surface-0 p-6 rounded-[var(--radius-md)] text-center xcor-shadow-subtle font-medium">Identical captures — select different targets</div>
      ) : filtered.length === 0 ? (
        <div className="text-[13px] text-muted border border-border bg-surface-0 p-6 rounded-[var(--radius-md)] text-center xcor-shadow-subtle font-medium">No drift detected</div>
      ) : diffMode === "unified" ? (
        <div className="border border-border bg-surface-0 rounded-[var(--radius-md)] text-[13px] divide-y divide-border overflow-hidden max-h-[700px] overflow-y-auto xcor-shadow-subtle">
          {filtered.map((ch, idx) => {
            const isDeg = ch.direction === "degraded";
            const isImp = ch.direction === "improved";
            return (
              <div key={idx}>
                <div className="bg-surface-1 px-3 py-1.5 flex items-center justify-between text-[12px] font-medium text-foreground border-b border-border">
                  <span>{ch.server} [{ch.kind}]</span>
                  <div className="flex items-center gap-2">
                    <DirLabel dir={ch.direction} />
                    <SeverityBadge severity={ch.severity} />
                  </div>
                </div>
                <div className="px-3 py-1.5 bg-sev-critical-bg text-red-950 flex items-start gap-2 text-[12px] font-mono leading-tight">
                  <span className="text-sev-critical font-bold select-none shrink-0">-</span>
                  <span className="break-all">{ch.before}</span>
                </div>
                <div className={`px-3 py-1.5 flex items-start gap-2 text-[12px] font-mono leading-tight ${
                  isDeg ? "bg-sev-high-bg text-orange-950" : isImp ? "bg-sev-pass-bg text-emerald-950" : "bg-neutral-100 text-neutral-900"
                }`}>
                  <span className={`select-none shrink-0 font-bold ${isDeg ? "text-sev-high" : isImp ? "text-emerald-600" : "text-neutral-600"}`}>+</span>
                  <span className="break-all">{ch.after}</span>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="border border-border bg-surface-0 rounded-[var(--radius-md)] overflow-hidden max-h-[700px] overflow-y-auto xcor-shadow-subtle">
          <table className="w-full text-[13px] text-left">
            <thead className="sticky top-0 bg-surface-1 border-b border-border text-[12px] font-medium text-muted z-10 h-8">
              <tr>
                <th className="px-3 py-1 w-36">Server</th>
                <th className="px-3 py-1 w-28">Kind</th>
                <th className="px-3 py-1 text-sev-critical border-r border-border">Baseline</th>
                <th className="px-3 py-1 text-sev-pass">Current</th>
                <th className="px-3 py-1 w-28 text-center">Direction</th>
                <th className="px-3 py-1 w-20 text-right">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((ch, idx) => (
                <tr key={idx} className="hover:bg-surface-1 transition-colors h-8">
                  <td className="px-3 py-1 text-foreground font-mono text-[12px]">{ch.server}</td>
                  <td className="px-3 py-1 text-muted text-[12px] capitalize">{ch.kind}</td>
                  <td className="px-3 py-1 font-mono text-[12px] text-red-950 bg-red-50/50 border-r border-border break-all">{ch.before}</td>
                  <td className={`px-3 py-1 font-mono text-[12px] break-all ${
                    ch.direction === "degraded" ? "text-orange-950 bg-orange-50/50" : ch.direction === "improved" ? "text-emerald-950 bg-emerald-50/50" : "text-foreground"
                  }`}>
                    {ch.after}
                  </td>
                  <td className="px-3 py-1 text-center"><DirLabel dir={ch.direction} /></td>
                  <td className="px-3 py-1 text-right"><SeverityBadge severity={ch.severity} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function DirLabel({ dir }: { dir: DriftDirection }) {
  if (dir === "degraded") return <span className="text-[11px] font-medium text-sev-critical bg-sev-critical-bg px-1.5 py-0.5 rounded-[var(--radius-xs)]">▼ degraded</span>;
  if (dir === "improved") return <span className="text-[11px] font-medium text-sev-pass bg-sev-pass-bg px-1.5 py-0.5 rounded-[var(--radius-xs)]">▲ improved</span>;
  return <span className="text-[11px] font-medium text-muted bg-surface-2 px-1.5 py-0.5 rounded-[var(--radius-xs)]">{dir}</span>;
}
