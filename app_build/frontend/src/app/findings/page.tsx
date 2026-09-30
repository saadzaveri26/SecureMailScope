"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import type { Finding, Severity, FindingCategory } from "@/types";
import { getFindings } from "@/data";
import { SeverityBadge } from "@/components/severity";
import {
  X,
  Copy,
  Check,
  ArrowSquareOut,
} from "@phosphor-icons/react";

export default function FindingsPage() {
  return (
    <Suspense fallback={<FindingsSkeleton />}>
      <FindingsContent />
    </Suspense>
  );
}

function FindingsSkeleton() {
  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8 space-y-6 animate-pulse">
      <div className="flex justify-between items-center">
        <div className="space-y-1">
          <div className="h-6 w-36 bg-surface-2 rounded" />
          <div className="h-4 w-64 bg-surface-2 rounded" />
        </div>
        <div className="h-8 w-48 bg-surface-2 rounded" />
      </div>
      <div className="bg-surface-0 rounded-lg border border-border-subtle overflow-hidden">
        <div className="h-10 bg-surface-1 border-b border-border-subtle" />
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-10 border-b border-border-subtle flex items-center px-4 gap-4">
            <div className="h-4 w-12 bg-surface-2 rounded" />
            <div className="h-4 w-20 bg-surface-2 rounded" />
            <div className="h-4 w-48 bg-surface-2 rounded" />
            <div className="h-4 w-24 bg-surface-2 rounded" />
            <div className="h-4 w-16 bg-surface-2 rounded" />
          </div>
        ))}
      </div>
    </div>
  );
}

function FindingsContent() {
  const params = useSearchParams();
  const captureId = params.get("capture") ?? "cap-001";
  const initialFindingId = params.get("finding");

  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState<string>("");
  const [category, setCategory] = useState<string>("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [copied, setCopied] = useState(false);

  function loadFindings() {
    setLoading(true);
    setError(null);
    getFindings(captureId, {
      severity: severity ? (severity as Severity) : undefined,
      category: category ? (category as FindingCategory) : undefined,
    })
      .then((data) => {
        setFindings(data);
        if (initialFindingId) {
          const match = data.find((f) => f.id === initialFindingId);
          if (match) setSelected(match);
        }
        setLoading(false);
      })
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : "Failed to load findings");
        setLoading(false);
      });
  }

  useEffect(() => {
    let active = true;
    getFindings(captureId, {
      severity: severity ? (severity as Severity) : undefined,
      category: category ? (category as FindingCategory) : undefined,
    })
      .then((data) => {
        if (active) {
          setFindings(data);
          if (initialFindingId) {
            const match = data.find((f) => f.id === initialFindingId);
            if (match) setSelected(match);
          }
          setLoading(false);
        }
      })
      .catch((e: unknown) => {
        if (active) {
          setError(e instanceof Error ? e.message : "Failed to load findings");
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [captureId, severity, category, initialFindingId]);

  function copyText(txt: string) {
    navigator.clipboard.writeText(txt);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div>
          <h1 className="text-xl font-semibold">Findings</h1>
          <p className="text-sm text-muted">
            Security vulnerabilities, posture violations, and anomalies for <span className="font-mono text-foreground font-medium">{captureId}</span>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="text-xs bg-surface-0 border border-border rounded-md px-3 py-1.5 focus:outline-none focus:border-brand"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="text-xs bg-surface-0 border border-border rounded-md px-3 py-1.5 focus:outline-none focus:border-brand"
          >
            <option value="">All categories</option>
            <option value="cleartext_exposure">Cleartext exposure</option>
            <option value="tls_configuration">TLS configuration</option>
            <option value="certificate_validation">Certificate validation</option>
            <option value="protocol_security">Protocol security</option>
            <option value="drift_regression">Drift regression</option>
            <option value="anomaly">Baseline anomaly</option>
          </select>
        </div>
      </div>

      {loading ? (
        <FindingsSkeleton />
      ) : error ? (
        <div className="bg-sev-critical-bg border border-sev-critical/20 rounded-md p-4 space-y-2">
          <p className="text-xs font-semibold text-sev-critical">Failed to load findings</p>
          <p className="text-xs text-sev-critical/90">{error}</p>
          <button
            onClick={loadFindings}
            className="text-xs font-medium text-sev-critical underline"
          >
            Retry
          </button>
        </div>
      ) : findings.length === 0 ? (
        <div className="text-center py-16 bg-surface-0 rounded-lg border border-border-subtle text-muted">
          <p className="text-xs font-medium text-foreground">No findings match the selected filters</p>
          <p className="text-xs text-muted mt-1">Try adjusting the severity or category filter</p>
        </div>
      ) : (
        <div className="bg-surface-0 rounded-lg border border-border-subtle overflow-hidden">
          <div className="overflow-x-auto max-h-[750px] overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-surface-1 z-10 border-b border-border shadow-none">
                <tr className="text-left font-medium text-muted h-9">
                  <th className="px-4 py-2">Rank</th>
                  <th className="px-4 py-2">Severity</th>
                  <th className="px-4 py-2">Finding</th>
                  <th className="px-4 py-2">Category</th>
                  <th className="px-4 py-2">Target</th>
                  <th className="px-4 py-2 text-right">Score impact</th>
                  <th className="px-4 py-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelected(f)}
                    className="border-b border-border-subtle last:border-0 hover:bg-surface-1 cursor-pointer transition-colors h-10"
                  >
                    <td className="px-4 py-2 font-mono text-muted tabular-nums">
                      #{f.priority_rank}
                    </td>
                    <td className="px-4 py-2">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-4 py-2 max-w-md">
                      <div className="font-medium text-foreground">{f.title}</div>
                      <div className="text-[11px] text-muted truncate mt-0.5">{f.description}</div>
                      <div className="text-[10px] font-mono text-muted/70">{f.rule_id}</div>
                    </td>
                    <td className="px-4 py-2">
                      <span className="text-xs px-2 py-0.5 bg-surface-2 rounded-[3px] text-muted border border-border-subtle">
                        {f.category}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono text-muted">
                      {f.evidence.server ? (
                        <span>{f.evidence.server}:{f.evidence.server_port}</span>
                      ) : (
                        <span className="italic font-sans">Capture-level</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <span className="font-mono text-xs font-semibold text-sev-critical tabular-nums">
                        {f.score_impact}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-right">
                      <button
                        onClick={(e) => { e.stopPropagation(); setSelected(f); }}
                        className="text-xs font-medium text-brand hover:underline"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selected && (
        <div className="fixed inset-0 z-50 bg-black/40 flex justify-end animate-in fade-in duration-150">
          <div className="w-full max-w-2xl bg-surface-0 h-full shadow-2xl flex flex-col border-l border-border overflow-hidden">
            <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-surface-1">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={selected.severity} />
                  <span className="text-xs font-mono text-muted">Rank #{selected.priority_rank}</span>
                  <span className="text-xs font-mono font-medium text-sev-critical">
                    Impact: {selected.score_impact}
                  </span>
                </div>
                <h2 className="text-base font-semibold text-foreground">{selected.title}</h2>
                <p className="text-xs font-mono text-muted">{selected.rule_id}</p>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="p-1.5 rounded-md hover:bg-surface-2 text-muted hover:text-foreground shrink-0"
              >
                <X size={18} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              <div>
                <h3 className="text-xs font-medium text-muted mb-2">
                  Description
                </h3>
                <p className="text-sm leading-relaxed text-foreground bg-surface-1 p-3.5 rounded-md border border-border-subtle">
                  {selected.description}
                </p>
              </div>

              <div className="bg-surface-1 rounded-md p-4 border border-border-subtle">
                <h3 className="text-xs font-medium text-muted mb-3">
                  Wireshark display filter
                </h3>
                <div className="flex items-center justify-between gap-2 bg-surface-0 border border-border rounded px-3 py-2">
                  <code className="text-xs font-mono text-brand truncate">{selected.wireshark_filter}</code>
                  <button
                    onClick={() => copyText(selected.wireshark_filter)}
                    className="p-1 rounded hover:bg-surface-2 text-muted hover:text-foreground shrink-0 transition-colors"
                    title="Copy filter"
                  >
                    {copied ? <Check size={14} className="text-brand" /> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              <div className="bg-surface-1 rounded-md p-4 border border-border-subtle">
                <h3 className="text-xs font-medium text-muted mb-3">
                  Technical evidence
                </h3>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-muted block">Target server</span>
                    <span className="font-mono font-medium">
                      {selected.evidence.server ? `${selected.evidence.server}:${selected.evidence.server_port}` : "—"}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted block">Client IP</span>
                    <span className="font-mono font-medium">{selected.evidence.client || "—"}</span>
                  </div>
                  <div>
                    <span className="text-muted block">Associated frames</span>
                    <span className="font-mono font-medium tabular-nums">
                      {selected.evidence.frames.length > 0
                        ? selected.evidence.frames.map((n) => `#${n}`).join(", ")
                        : "—"}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted block">Session ID</span>
                    <span className="font-mono font-medium">{selected.session_id || "None (Capture-wide)"}</span>
                  </div>
                  {selected.evidence.certificate_sha256 && (
                    <div className="col-span-2">
                      <span className="text-muted block">Certificate SHA-256</span>
                      <span className="font-mono text-xs break-all text-foreground">
                        {selected.evidence.certificate_sha256}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              <div className="bg-surface-1 rounded-md p-4 border border-border-subtle">
                <h3 className="text-xs font-medium text-muted mb-3">
                  Operational context
                </h3>
                <div className="grid grid-cols-3 gap-3 text-xs">
                  <div>
                    <span className="text-muted block">Server role</span>
                    <span className="font-mono font-medium uppercase">{selected.context.server_role}</span>
                  </div>
                  <div>
                    <span className="text-muted block">Sessions affected</span>
                    <span className="font-mono font-medium tabular-nums">{selected.context.sessions_affected}</span>
                  </div>
                  <div>
                    <span className="text-muted block">Clients affected</span>
                    <span className="font-mono font-medium tabular-nums">{selected.context.clients_affected}</span>
                  </div>
                </div>
              </div>

              {selected.anomaly && selected.anomaly.deviating_features.length > 0 && (
                <div className="bg-surface-1 rounded-md p-4 border border-border-subtle">
                  <h3 className="text-xs font-medium text-sev-high mb-3">
                    Baseline anomaly deviations
                  </h3>
                  <div className="space-y-2 text-xs">
                    {selected.anomaly.deviating_features.map((dev, idx) => (
                      <div key={idx} className="bg-surface-0 border border-border rounded p-2.5">
                        <div className="font-medium text-foreground">{dev.feature}</div>
                        <div className="grid grid-cols-2 gap-2 mt-1.5 text-muted">
                          <div>
                            <span className="text-muted/70 block">Observed:</span>
                            <span className="font-mono text-sev-critical font-medium">{dev.observed}</span>
                          </div>
                          <div>
                            <span className="text-muted/70 block">Baseline expected:</span>
                            <span className="font-mono text-foreground font-medium">{dev.baseline}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="bg-surface-1 rounded-md p-4 border border-border-subtle">
                <h3 className="text-xs font-medium text-muted mb-2">
                  Remediation recommendations
                </h3>
                <p className="text-xs font-medium text-foreground mb-3">{selected.remediation.summary}</p>
                <ol className="list-decimal list-inside space-y-1.5 text-xs text-muted mb-4">
                  {selected.remediation.steps.map((step, idx) => (
                    <li key={idx} className="leading-relaxed">
                      <span className="text-foreground">{step}</span>
                    </li>
                  ))}
                </ol>
                {selected.remediation.references.length > 0 && (
                  <div>
                    <span className="text-xs text-muted block mb-1">References:</span>
                    <div className="space-y-1">
                      {selected.remediation.references.map((ref, idx) => (
                        <div key={idx} className="flex items-center gap-1 text-xs text-brand">
                          <ArrowSquareOut size={12} />
                          <span className="font-mono">{ref}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
