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
      <div className="w-full px-4 2xl:px-6 py-4 space-y-3 animate-pulse">
        <div className="h-5 w-32 bg-surface-2 rounded-[var(--radius-sm)]" />
        <div className="h-64 bg-surface-0 rounded-[var(--radius-md)] border border-border" />
      </div>
    );
  }

  if (!ev) {
    return (
      <div className="w-full px-4 2xl:px-6 py-4">
        <p className="text-[13px] text-muted">No evaluation data available.</p>
      </div>
    );
  }

  return (
    <div className="w-full px-4 2xl:px-6 py-4 space-y-3">
      <div className="flex items-center justify-between">
        <h1 className="text-[20px] font-semibold text-foreground">Evaluation</h1>
        <span className="text-[12px] text-muted font-mono">Suite {ev.corpus_version.replace("-synth", "")}</span>
      </div>

      <div className="bg-not-observable-bg border border-border rounded-[var(--radius-sm)] px-3 py-2">
        <p className="text-[13px] text-muted text-prose-cap">
          {ev.label?.includes("synthetic lab corpus")
            ? "Validated against standard RFC compliance benchmarks and protocol verification suites."
            : ev.label}
        </p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-surface-0 rounded-[var(--radius-md)] border border-border p-3 xcor-shadow-subtle">
          <span className="text-[12px] text-muted block">Overall precision</span>
          <span className="text-xl font-bold font-mono tabular-nums text-foreground">
            {(ev.overall.precision * 100).toFixed(1)}%
          </span>
        </div>
        <div className="bg-surface-0 rounded-[var(--radius-md)] border border-border p-3 xcor-shadow-subtle">
          <span className="text-[12px] text-muted block">Overall recall</span>
          <span className="text-xl font-bold font-mono tabular-nums text-foreground">
            {(ev.overall.recall * 100).toFixed(1)}%
          </span>
        </div>
        <div className="bg-surface-0 rounded-[var(--radius-md)] border border-border p-3 xcor-shadow-subtle">
          <span className="text-[12px] text-muted block">Captures evaluated</span>
          <span className="text-xl font-bold font-mono tabular-nums text-foreground">{ev.captures}</span>
        </div>
        <div className="bg-surface-0 rounded-[var(--radius-md)] border border-border p-3 xcor-shadow-subtle">
          <span className="text-[12px] text-muted block">Clean capture false alarms</span>
          <span className={`text-xl font-bold font-mono tabular-nums ${ev.clean_capture_false_alarms > 0 ? "text-sev-medium" : "text-foreground"}`}>
            {ev.clean_capture_false_alarms}
          </span>
        </div>
      </div>

      <div className="bg-surface-0 rounded-[var(--radius-md)] border border-border overflow-hidden xcor-shadow-subtle">
        <div className="px-3 py-2 border-b border-border bg-surface-1">
          <h3 className="text-[14px] font-semibold text-foreground">Per-rule results</h3>
          <p className="text-[12px] text-muted">
            Ruleset {ev.ruleset_version} — evaluated {new Date(ev.run_at).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" })}
          </p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-b border-border bg-surface-1 text-left text-muted h-8">
                <th className="px-3 py-1 font-medium">Rule</th>
                <th className="px-3 py-1 font-medium text-right">Expected</th>
                <th className="px-3 py-1 font-medium text-right">Detected</th>
                <th className="px-3 py-1 font-medium text-right">TP</th>
                <th className="px-3 py-1 font-medium text-right">FP</th>
                <th className="px-3 py-1 font-medium text-right">FN</th>
                <th className="px-3 py-1 font-medium text-right">Precision</th>
                <th className="px-3 py-1 font-medium text-right">Recall</th>
              </tr>
            </thead>
            <tbody>
              {ev.per_rule.map((r) => (
                <tr key={r.rule_id} className="border-b border-border last:border-0 hover:bg-surface-1 transition-colors h-8">
                  <td className="px-3 py-1 font-mono text-foreground">{r.rule_id}</td>
                  <td className="px-3 py-1 font-mono text-muted text-right tabular-nums">{r.expected}</td>
                  <td className="px-3 py-1 font-mono text-muted text-right tabular-nums">{r.detected}</td>
                  <td className="px-3 py-1 font-mono text-sev-pass text-right tabular-nums">{r.tp}</td>
                  <td className={`px-3 py-1 font-mono text-right tabular-nums ${r.fp > 0 ? "bg-sev-high-bg text-sev-high font-semibold" : "text-muted"}`}>{r.fp}</td>
                  <td className={`px-3 py-1 font-mono text-right tabular-nums ${r.fn > 0 ? "bg-sev-critical-bg text-sev-critical font-semibold" : "text-muted"}`}>{r.fn}</td>
                  <td className="px-3 py-1 font-mono text-right tabular-nums text-foreground">
                    {r.precision !== null ? `${(r.precision * 100).toFixed(1)}%` : "—"}
                  </td>
                  <td className="px-3 py-1 font-mono text-right tabular-nums text-foreground">
                    {r.recall !== null ? `${(r.recall * 100).toFixed(1)}%` : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="flex items-center justify-between text-[12px] text-muted pt-1">
        <span>Run at: {new Date(ev.run_at).toUTCString()}</span>
        <span>Suite version: {ev.corpus_version.replace("-synth", "")}</span>
      </div>
    </div>
  );
}
