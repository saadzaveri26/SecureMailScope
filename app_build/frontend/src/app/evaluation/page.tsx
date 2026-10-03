"use client";

import { useState, useEffect } from "react";
import { getEvaluation } from "@/data";
import type { Evaluation } from "@/types";

export default function EvaluationPage() {
  const [ev, setEv] = useState<Evaluation | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getEvaluation()
      .then(setEv)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="max-w-[1400px] mx-auto px-4 py-8 space-y-4 animate-pulse">
        <div className="h-6 w-32 bg-surface-2 rounded" />
        <div className="h-64 bg-surface-0 rounded-lg border border-border-subtle" />
      </div>
    );
  }

  if (!ev) {
    return (
      <div className="max-w-[1400px] mx-auto px-4 py-8">
        <p className="text-xs text-muted">No evaluation data available.</p>
      </div>
    );
  }

  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Evaluation</h1>
        <span className="text-xs text-muted font-mono">Corpus {ev.corpus_version}</span>
      </div>

      <div className="bg-not-observable-bg border border-border-subtle rounded-md px-4 py-3">
        <p className="text-xs text-muted">{ev.label}</p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-surface-0 rounded-lg border border-border-subtle p-4">
          <span className="text-[11px] text-muted block">Overall precision</span>
          <span className="text-2xl font-bold font-mono tabular-nums text-foreground">
            {(ev.overall.precision * 100).toFixed(1)}%
          </span>
        </div>
        <div className="bg-surface-0 rounded-lg border border-border-subtle p-4">
          <span className="text-[11px] text-muted block">Overall recall</span>
          <span className="text-2xl font-bold font-mono tabular-nums text-foreground">
            {(ev.overall.recall * 100).toFixed(1)}%
          </span>
        </div>
        <div className="bg-surface-0 rounded-lg border border-border-subtle p-4">
          <span className="text-[11px] text-muted block">Captures evaluated</span>
          <span className="text-2xl font-bold font-mono tabular-nums text-foreground">{ev.captures}</span>
        </div>
        <div className="bg-surface-0 rounded-lg border border-border-subtle p-4">
          <span className="text-[11px] text-muted block">Clean capture false alarms</span>
          <span className={`text-2xl font-bold font-mono tabular-nums ${ev.clean_capture_false_alarms > 0 ? "text-sev-medium" : "text-foreground"}`}>
            {ev.clean_capture_false_alarms}
          </span>
        </div>
      </div>

      <div className="bg-surface-0 rounded-lg border border-border-subtle overflow-hidden">
        <div className="px-4 py-3 border-b border-border-subtle bg-surface-1">
          <h3 className="text-xs font-medium text-foreground">Per-rule results</h3>
          <p className="text-[11px] text-muted mt-0.5">
            Ruleset {ev.ruleset_version} — evaluated {new Date(ev.run_at).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" })}
          </p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border-subtle bg-surface-1 text-left text-muted">
                <th className="px-3 py-2 font-medium">Rule</th>
                <th className="px-3 py-2 font-medium text-right">Expected</th>
                <th className="px-3 py-2 font-medium text-right">Detected</th>
                <th className="px-3 py-2 font-medium text-right">TP</th>
                <th className="px-3 py-2 font-medium text-right">FP</th>
                <th className="px-3 py-2 font-medium text-right">FN</th>
                <th className="px-3 py-2 font-medium text-right">Precision</th>
                <th className="px-3 py-2 font-medium text-right">Recall</th>
              </tr>
            </thead>
            <tbody>
              {ev.per_rule.map((r) => (
                <tr key={r.rule_id} className="border-b border-border-subtle last:border-0 hover:bg-surface-1 transition-colors">
                  <td className="px-3 py-2.5 font-mono text-foreground">{r.rule_id}</td>
                  <td className="px-3 py-2.5 font-mono text-muted text-right tabular-nums">{r.expected}</td>
                  <td className="px-3 py-2.5 font-mono text-muted text-right tabular-nums">{r.detected}</td>
                  <td className="px-3 py-2.5 font-mono text-sev-pass text-right tabular-nums">{r.tp}</td>
                  <td className={`px-3 py-2.5 font-mono text-right tabular-nums ${r.fp > 0 ? "text-sev-medium font-semibold" : "text-muted"}`}>{r.fp}</td>
                  <td className={`px-3 py-2.5 font-mono text-right tabular-nums ${r.fn > 0 ? "text-sev-critical font-semibold" : "text-muted"}`}>{r.fn}</td>
                  <td className="px-3 py-2.5 font-mono text-right tabular-nums text-foreground">
                    {r.precision !== null ? `${(r.precision * 100).toFixed(1)}%` : "—"}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-right tabular-nums text-foreground">
                    {r.recall !== null ? `${(r.recall * 100).toFixed(1)}%` : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="flex items-center justify-between text-xs text-muted font-mono pt-1">
        <span>Run at: {new Date(ev.run_at).toUTCString()}</span>
        <span>Corpus version: {ev.corpus_version}</span>
      </div>
    </div>
  );
}
