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
    <div className="max-w-[1600px] mx-auto px-4 py-4 space-y-4 animate-pulse">
      <div className="h-4 w-44 bg-surface-2" />
      <div className="border-2 border-black bg-surface-0 h-96 brutal-shadow" />
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
    <div className="max-w-[1600px] mx-auto px-4 py-4 space-y-3 font-mono text-xs select-none">
      {/* Header */}
      <div className="flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2 font-bold text-foreground">
          <span className="uppercase tracking-wider text-black">posture drift</span>
          <span className="text-black/40">·</span>
          <span className="text-muted font-semibold">{filtered.length} changes detected</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex border-2 border-black bg-surface-0 brutal-shadow-sm">
            <button
              onClick={() => setDiffMode("unified")}
              className={`px-3 py-1 text-xs font-mono font-bold cursor-pointer transition-colors ${diffMode === "unified" ? "bg-accent text-black" : "text-muted hover:text-black"}`}
            >
              unified
            </button>
            <button
              onClick={() => setDiffMode("split")}
              className={`px-3 py-1 text-xs font-mono font-bold cursor-pointer transition-colors border-l-2 border-black ${diffMode === "split" ? "bg-accent text-black" : "text-muted hover:text-black"}`}
            >
              side-by-side
            </button>
          </div>
          <select
            value={filterDir}
            onChange={(e) => setFilterDir(e.target.value)}
            className="px-2.5 py-1 bg-surface-0 border-2 border-black text-xs font-mono font-bold text-black focus:outline-none cursor-pointer brutal-shadow-sm"
          >
            <option value="">all directions</option>
            <option value="degraded">degraded</option>
            <option value="improved">improved</option>
            <option value="changed">changed</option>
          </select>
        </div>
      </div>

      {/* Capture comparison selectors */}
      <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_1fr] gap-3 items-center text-xs font-mono">
        <div className="border-2 border-black bg-surface-0 p-2.5 space-y-1 brutal-shadow-sm">
          <div className="text-[11px] text-red-600 font-bold uppercase">--- baseline capture</div>
          <select
            value={baselineId}
            onChange={(e) => handleCompare(e.target.value, currentId)}
            className="w-full bg-surface-1 border border-black p-1 text-foreground font-bold focus:outline-none cursor-pointer"
          >
            {caps.map((c) => (
              <option key={c.id} value={c.id} className="bg-surface-0">{c.filename} [{c.id}] score:{c.posture_score ?? "—"}</option>
            ))}
          </select>
        </div>
        <div className="flex items-center justify-center p-2 bg-accent border-2 border-black brutal-shadow-sm">
          <ArrowsLeftRight size={16} weight="bold" className="text-black" />
        </div>
        <div className="border-2 border-black bg-surface-0 p-2.5 space-y-1 brutal-shadow-sm">
          <div className="text-[11px] text-emerald-600 font-bold uppercase">+++ current capture</div>
          <select
            value={currentId}
            onChange={(e) => handleCompare(baselineId, e.target.value)}
            className="w-full bg-surface-1 border border-black p-1 text-foreground font-bold focus:outline-none cursor-pointer"
          >
            {caps.map((c) => (
              <option key={c.id} value={c.id} className="bg-surface-0">{c.filename} [{c.id}] score:{c.posture_score ?? "—"}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Stats strip */}
      <div className="flex items-center gap-4 text-xs font-mono border-2 border-black bg-surface-0 px-3 py-2 brutal-shadow-sm font-bold">
        <span className="text-red-600 tabular-nums bg-red-100 px-2 py-0.5 border border-black">{degradedCount} degraded</span>
        <span className="text-emerald-700 tabular-nums bg-emerald-100 px-2 py-0.5 border border-black">{improvedCount} improved</span>
        <span className="tabular-nums text-muted">{otherCount} other changes</span>
        {baselineCap && currentCap && baselineCap.posture_score !== null && currentCap.posture_score !== null && (
          <>
            <span className="text-black/40">│</span>
            <span className={`tabular-nums px-2 py-0.5 border border-black ${
              (currentCap.posture_score - baselineCap.posture_score) < 0 ? "bg-red-500 text-white" : "bg-emerald-400 text-black"
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
        <div className="text-xs font-mono font-bold text-sev-critical border-2 border-black bg-sev-critical-bg px-3 py-2 brutal-shadow-sm">{error}</div>
      ) : baselineId === currentId ? (
        <div className="text-xs font-mono text-muted border-2 border-black bg-surface-0 px-3 py-8 text-center brutal-shadow font-bold">identical captures — select different targets</div>
      ) : filtered.length === 0 ? (
        <div className="text-xs font-mono text-muted border-2 border-black bg-surface-0 px-3 py-8 text-center brutal-shadow font-bold">no drift detected</div>
      ) : diffMode === "unified" ? (
        <div className="border-2 border-black bg-surface-0 font-mono text-xs divide-y-2 divide-black/20 overflow-hidden max-h-[700px] overflow-y-auto brutal-shadow">
          {filtered.map((ch, idx) => {
            const isDeg = ch.direction === "degraded";
            const isImp = ch.direction === "improved";
            return (
              <div key={idx}>
                <div className="bg-surface-1 px-3 py-1.5 flex items-center justify-between text-[11px] font-bold text-black border-b border-black/20">
                  <span className="font-bold">@@ {ch.server} [{ch.kind}] @@</span>
                  <div className="flex items-center gap-2">
                    <DirLabel dir={ch.direction} />
                    <SeverityBadge severity={ch.severity} />
                  </div>
                </div>
                <div className="px-3 py-1.5 bg-red-100 text-red-950 flex items-start gap-2 text-[11px] font-medium leading-tight">
                  <span className="text-red-600 font-bold select-none shrink-0">-</span>
                  <span className="break-all">{ch.before}</span>
                </div>
                <div className={`px-3 py-1.5 flex items-start gap-2 text-[11px] font-medium leading-tight ${
                  isDeg ? "bg-orange-100 text-orange-950" : isImp ? "bg-emerald-100 text-emerald-950" : "bg-neutral-100 text-neutral-900"
                }`}>
                  <span className={`select-none shrink-0 font-bold ${isDeg ? "text-orange-600" : isImp ? "text-emerald-600" : "text-neutral-600"}`}>+</span>
                  <span className="break-all">{ch.after}</span>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="border-2 border-black bg-surface-0 overflow-hidden max-h-[700px] overflow-y-auto brutal-shadow">
          <table className="w-full text-xs font-mono text-left">
            <thead className="sticky top-0 bg-surface-1 border-b-2 border-black text-[11px] font-bold text-black uppercase z-10">
              <tr>
                <th className="py-2 px-3 w-36">server</th>
                <th className="py-2 px-3 w-28">kind</th>
                <th className="py-2 px-3 text-red-600 border-r-2 border-black">- baseline</th>
                <th className="py-2 px-3 text-emerald-700">+ current</th>
                <th className="py-2 px-3 w-28 text-center">shift</th>
                <th className="py-2 px-3 w-20 text-right">sev</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-black/20">
              {filtered.map((ch, idx) => (
                <tr key={idx} className="hover:bg-accent/10 transition-colors">
                  <td className="py-2 px-3 text-black font-bold">{ch.server}</td>
                  <td className="py-2 px-3 text-muted text-[10px] uppercase font-bold">{ch.kind}</td>
                  <td className="py-2 px-3 text-red-950 bg-red-50 border-r-2 border-black break-all font-medium">{ch.before}</td>
                  <td className={`py-2 px-3 break-all font-medium ${
                    ch.direction === "degraded" ? "text-orange-950 bg-orange-50" : ch.direction === "improved" ? "text-emerald-950 bg-emerald-50" : "text-black"
                  }`}>
                    {ch.after}
                  </td>
                  <td className="py-2 px-3 text-center"><DirLabel dir={ch.direction} /></td>
                  <td className="py-2 px-3 text-right"><SeverityBadge severity={ch.severity} /></td>
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
  if (dir === "degraded") return <span className="text-[10px] font-mono font-bold bg-red-500 text-white border border-black px-1.5 py-0.5 shadow-[1px_1px_0_#000]">▼ degraded</span>;
  if (dir === "improved") return <span className="text-[10px] font-mono font-bold bg-emerald-400 text-black border border-black px-1.5 py-0.5 shadow-[1px_1px_0_#000]">▲ improved</span>;
  return <span className="text-[10px] font-mono font-bold bg-neutral-200 text-black border border-black px-1.5 py-0.5">{dir}</span>;
}
