"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import type { Capture, Drift, DriftDirection } from "@/types";
import { getCaptures, getDrift } from "@/data";
import { SeverityBadge } from "@/components/severity";
import {
  TrendDown,
  TrendUp,
  ArrowsLeftRight,
  ArrowRight,
} from "@phosphor-icons/react";

export default function DriftPage() {
  return (
    <Suspense fallback={<DriftSkeleton />}>
      <DriftContent />
    </Suspense>
  );
}

function DriftSkeleton() {
  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8 space-y-6 animate-pulse">
      <div className="space-y-1">
        <div className="h-6 w-44 bg-surface-2 rounded" />
        <div className="h-4 w-72 bg-surface-2 rounded" />
      </div>
      <div className="bg-surface-0 rounded-sm border border-border p-5 space-y-4">
        <div className="h-10 bg-surface-2 rounded" />
        <div className="grid grid-cols-3 gap-3 pt-4 border-t border-border">
          <div className="h-16 bg-surface-2 rounded" />
          <div className="h-16 bg-surface-2 rounded" />
          <div className="h-16 bg-surface-2 rounded" />
        </div>
      </div>
      <div className="bg-surface-0 rounded-sm border border-border overflow-hidden">
        <div className="h-10 bg-surface-1 border-b border-border" />
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-10 border-b border-border flex items-center px-4 gap-4">
            <div className="h-4 w-28 bg-surface-2 rounded" />
            <div className="h-4 w-16 bg-surface-2 rounded" />
            <div className="h-4 w-20 bg-surface-2 rounded" />
            <div className="h-4 w-32 bg-surface-2 rounded" />
            <div className="h-4 w-32 bg-surface-2 rounded" />
          </div>
        ))}
      </div>
    </div>
  );
}

function DriftContent() {
  const searchParams = useSearchParams();
  const [caps, setCaps] = useState<Capture[]>([]);
  const [baselineId, setBaselineId] = useState<string>(searchParams.get("baseline") ?? "cap-002");
  const [currentId, setCurrentId] = useState<string>(searchParams.get("current") ?? searchParams.get("capture") ?? "cap-001");
  const [drift, setDrift] = useState<Drift | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterDirection, setFilterDirection] = useState<string>("");

  function loadDriftData(bId: string, cId: string) {
    setLoading(true);
    setError(null);
    getDrift(bId, cId)
      .then((d) => {
        setDrift(d);
        setLoading(false);
      })
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : "Failed to load drift");
        setLoading(false);
      });
  }

  useEffect(() => {
    let active = true;
    getCaptures()
      .then((cList) => {
        if (!active) return;
        setCaps(cList);
        const complete = cList.filter((c) => c.status === "complete");
        const b = searchParams.get("baseline") ?? (complete.length > 1 ? complete[1].id : complete[0]?.id ?? "cap-002");
        const c = searchParams.get("current") ?? searchParams.get("capture") ?? complete[0]?.id ?? "cap-001";
        setBaselineId(b);
        setCurrentId(c);
        return getDrift(b, c);
      })
      .then((d) => {
        if (active && d) {
          setDrift(d);
          setLoading(false);
        }
      })
      .catch((e: unknown) => {
        if (active) {
          setError(e instanceof Error ? e.message : "Failed to load drift");
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [searchParams]);

  function handleCompare(b: string, c: string) {
    setBaselineId(b);
    setCurrentId(c);
    loadDriftData(b, c);
  }

  const completeCaps = caps.filter((c) => c.status === "complete");
  const changes = drift?.changes ?? [];

  const filtered = filterDirection
    ? changes.filter((ch) => ch.direction === filterDirection)
    : changes;

  const degradedCount = changes.filter((c) => c.direction === "degraded").length;
  const improvedCount = changes.filter((c) => c.direction === "improved").length;
  const otherCount = changes.filter((c) => !["degraded", "improved"].includes(c.direction)).length;

  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8">
      <div className="mb-6">
        <h1 className="text-xl font-semibold">Posture drift analysis</h1>
        <p className="text-sm text-muted">
          Compare security posture, TLS parameters, and certificate changes across PCAP captures
        </p>
      </div>

      <div className="bg-surface-0 rounded-sm border border-border p-5 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 items-end">
          <div className="md:col-span-2">
            <label className="text-xs font-medium text-muted block mb-1.5">
              Baseline capture
            </label>
            <select
              value={baselineId}
              onChange={(e) => handleCompare(e.target.value, currentId)}
              className="w-full text-xs bg-surface-1 border border-border rounded-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-ink font-mono"
            >
              {completeCaps.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.filename} ({c.id}) — Score: {c.posture_score ?? "—"}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center justify-center text-muted py-2">
            <ArrowsLeftRight size={18} className="hidden md:block" />
          </div>

          <div className="md:col-span-2">
            <label className="text-xs font-medium text-muted block mb-1.5">
              Current / target capture
            </label>
            <select
              value={currentId}
              onChange={(e) => handleCompare(baselineId, e.target.value)}
              className="w-full text-xs bg-surface-1 border border-border rounded-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-ink font-mono"
            >
              {completeCaps.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.filename} ({c.id}) — Score: {c.posture_score ?? "—"}
                </option>
              ))}
            </select>
          </div>
        </div>

        {changes.length > 0 && (
          <div className="grid grid-cols-3 gap-3 mt-6 pt-4 border-t border-border">
            <div className="bg-sev-critical-bg border border-sev-critical/20 rounded-sm p-3 text-center">
              <span className="text-xs text-sev-critical block font-medium">Regressions</span>
              <span className="text-xl font-bold font-mono text-sev-critical tabular-nums">{degradedCount}</span>
            </div>
            <div className="bg-surface-1 border border-border rounded-sm p-3 text-center">
              <span className="text-xs text-foreground block font-medium">Improvements</span>
              <span className="text-xl font-bold font-mono text-foreground tabular-nums">{improvedCount}</span>
            </div>
            <div className="bg-surface-2 border border-border rounded-sm p-3 text-center">
              <span className="text-xs text-muted block font-medium">Neutral shifts</span>
              <span className="text-xl font-bold font-mono text-foreground tabular-nums">{otherCount}</span>
            </div>
          </div>
        )}
      </div>

      <div className="flex items-center justify-between gap-4 mb-4">
        <h2 className="text-sm font-semibold text-foreground">
          Observed differences <span className="tabular-nums font-normal text-muted">({filtered.length})</span>
        </h2>
        <select
          value={filterDirection}
          onChange={(e) => setFilterDirection(e.target.value)}
          className="text-xs bg-surface-0 border border-border rounded-sm px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-ink"
        >
          <option value="">All directions</option>
          <option value="degraded">Regressed only</option>
          <option value="improved">Improved only</option>
          <option value="changed">Neutral changed only</option>
          <option value="appeared">Appeared only</option>
          <option value="disappeared">Disappeared only</option>
        </select>
      </div>

      {loading ? (
        <DriftSkeleton />
      ) : error ? (
        <div className="bg-sev-critical-bg border border-sev-critical/20 rounded-sm p-4 space-y-2">
          <p className="text-xs font-semibold text-sev-critical">Failed to evaluate posture drift</p>
          <p className="text-xs text-sev-critical/90">{error}</p>
          <button
            onClick={() => loadDriftData(baselineId, currentId)}
            className="text-xs font-medium text-sev-critical underline"
          >
            Retry analysis
          </button>
        </div>
      ) : baselineId === currentId ? (
        <div className="text-center py-16 bg-surface-0 rounded-sm border border-border text-muted">
          <p className="text-xs font-medium text-foreground">Identical captures selected</p>
          <p className="text-xs text-muted mt-1">Select distinct baseline and current captures to evaluate posture drift.</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16 bg-surface-0 rounded-sm border border-border text-muted">
          <p className="text-xs font-medium text-foreground">No posture drift detected</p>
          <p className="text-xs text-muted mt-1">The evaluated parameters match the baseline capture exactly.</p>
        </div>
      ) : (
        <div className="bg-surface-0 rounded-sm border border-border overflow-hidden">
          <div className="overflow-x-auto max-h-[750px] overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-surface-1 z-10 border-b border-border shadow-none">
                <tr className="text-left font-medium text-muted h-9">
                  <th className="px-4 py-2">Server target</th>
                  <th className="px-4 py-2">Category / kind</th>
                  <th className="px-4 py-2">Direction</th>
                  <th className="px-4 py-2">Baseline configuration</th>
                  <th className="px-4 py-2">Current configuration</th>
                  <th className="px-4 py-2 text-right">Severity</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((ch, idx) => (
                  <tr key={idx} className="border-b border-border last:border-0 hover:bg-surface-1 transition-colors h-10">
                    <td className="px-4 py-2 font-mono text-xs font-medium text-foreground">
                      {ch.server}
                    </td>
                    <td className="px-4 py-2">
                      <span className="text-xs px-2 py-0.5 bg-surface-2 rounded-[3px] font-mono text-muted border border-border">
                        {ch.kind}
                      </span>
                    </td>
                    <td className="px-4 py-2">
                      <DirectionBadge direction={ch.direction} />
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-muted">
                      <span className="bg-surface-1 px-2 py-1 rounded-[3px] border border-border block max-w-xs truncate">
                        {ch.before}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-foreground">
                      <div className="flex items-center gap-2">
                        <ArrowRight size={12} className="text-muted shrink-0" />
                        <span className="bg-surface-1 px-2 py-1 rounded-[3px] border border-border block max-w-xs truncate font-medium">
                          {ch.after}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-2 text-right">
                      <SeverityBadge severity={ch.severity} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function DirectionBadge({ direction }: { direction: DriftDirection }) {
  if (direction === "degraded") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-[3px] text-xs font-medium bg-sev-critical-bg text-sev-critical border border-sev-critical/20">
        <TrendDown size={14} weight="bold" /> Degraded
      </span>
    );
  }
  if (direction === "improved") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-[3px] text-xs font-medium bg-surface-2 text-foreground border border-border">
        <TrendUp size={14} weight="bold" /> Improved
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-[3px] text-xs font-medium bg-surface-1 text-muted border border-border">
      <ArrowsLeftRight size={14} /> {direction}
    </span>
  );
}
