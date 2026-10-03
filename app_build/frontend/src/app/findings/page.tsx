"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import type { Finding, Severity, FindingCategory, Incident, Evidence } from "@/types";
import { getFindings, getIncidents, getEvidence } from "@/data";
import { SeverityBadge } from "@/components/severity";
import { ConfidenceBadge } from "@/components/confidence-badge";
import { EvidenceTag } from "@/components/evidence-tag";
import { X, Copy, Check, CaretDown, CaretRight, ArrowSquareOut } from "@phosphor-icons/react";

const sevBorder: Record<Severity, string> = {
  critical: "border-l-sev-critical",
  high: "border-l-sev-high",
  medium: "border-l-sev-medium",
  low: "border-l-sev-low",
  info: "border-l-sev-info",
};

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
      <div className="bg-surface-0 rounded-sm border border-border overflow-hidden">
        <div className="h-10 bg-surface-1 border-b border-border" />
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-10 border-b border-border flex items-center px-4 gap-4">
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
  const capId = params.get("capture") ?? "cap-001";
  const initFindingId = params.get("finding");

  const [view, setView] = useState<"findings" | "incident">("findings");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sev, setSev] = useState<string>("");
  const [cat, setCat] = useState<string>("");
  const [selFinding, setSelFinding] = useState<Finding | null>(null);
  const [expandedIncs, setExpandedIncs] = useState<Record<string, boolean>>({});
  const [expandedEvs, setExpandedEvs] = useState<Record<string, boolean>>({});
  const [copied, setCopied] = useState(false);

  function loadData() {
    setLoading(true);
    setError(null);
    Promise.all([
      getFindings(capId, {
        severity: sev ? (sev as Severity) : undefined,
        category: cat ? (cat as FindingCategory) : undefined,
      }),
      getIncidents(capId),
      getEvidence(capId),
    ])
      .then(([f, incs, evs]) => {
        setFindings(f);
        setIncidents(incs);
        setEvidenceList(evs);
        if (initFindingId) {
          const match = f.find((x) => x.id === initFindingId);
          if (match) setSelFinding(match);
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
    Promise.all([
      getFindings(capId, {
        severity: sev ? (sev as Severity) : undefined,
        category: cat ? (cat as FindingCategory) : undefined,
      }),
      getIncidents(capId),
      getEvidence(capId),
    ])
      .then(([f, incs, evs]) => {
        if (active) {
          setFindings(f);
          setIncidents(incs);
          setEvidenceList(evs);
          if (initFindingId) {
            const match = f.find((x) => x.id === initFindingId);
            if (match) setSelFinding(match);
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
  }, [capId, sev, cat, initFindingId]);

  function copyText(txt: string) {
    navigator.clipboard.writeText(txt);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function toggleInc(id: string) {
    setExpandedIncs((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  function toggleEv(id: string) {
    setExpandedEvs((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  const relatedEvidence = selFinding
    ? evidenceList.filter((e) => selFinding.evidence_ids.includes(e.id))
    : [];

  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div>
          <h1 className="text-xl font-semibold">Findings</h1>
          <p className="text-sm text-muted">
            Security vulnerabilities, posture violations, and anomalies for <span className="font-mono text-foreground font-medium">{capId}</span>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex rounded-sm border border-border p-0.5 bg-surface-1">
            <button
              onClick={() => setView("findings")}
              className={[
                "px-3 py-1.5 text-xs font-medium rounded transition-colors",
                view === "findings"
                  ? "bg-surface-0 text-foreground"
                  : "text-muted hover:text-foreground",
              ].join(" ")}
            >
              Findings
            </button>
            <button
              onClick={() => setView("incident")}
              className={[
                "px-3 py-1.5 text-xs font-medium rounded transition-colors",
                view === "incident"
                  ? "bg-surface-0 text-foreground"
                  : "text-muted hover:text-foreground",
              ].join(" ")}
            >
              By incident
            </button>
          </div>

          {view === "findings" && (
            <>
              <select
                value={sev}
                onChange={(e) => setSev(e.target.value)}
                className="text-xs bg-surface-0 border border-border rounded-sm px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-ink"
              >
                <option value="">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
              <select
                value={cat}
                onChange={(e) => setCat(e.target.value)}
                className="text-xs bg-surface-0 border border-border rounded-sm px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-ink"
              >
                <option value="">All categories</option>
                <option value="transport">Transport</option>
                <option value="certificate">Certificate</option>
                <option value="protocol">Protocol</option>
                <option value="message">Message</option>
                <option value="drift">Drift</option>
                <option value="anomaly">Baseline anomaly</option>
              </select>
            </>
          )}
        </div>
      </div>

      {loading ? (
        <FindingsSkeleton />
      ) : error ? (
        <div className="bg-sev-critical-bg border border-sev-critical/20 rounded-sm p-4 space-y-2">
          <p className="text-xs font-semibold text-sev-critical">Failed to load findings</p>
          <p className="text-xs text-sev-critical/90">{error}</p>
          <button
            onClick={loadData}
            className="text-xs font-medium text-sev-critical underline"
          >
            Retry
          </button>
        </div>
      ) : view === "findings" ? (
        findings.length === 0 ? (
          <div className="text-center py-16 bg-surface-0 rounded-sm border border-border text-muted">
            <p className="text-xs font-medium text-foreground">No findings match the selected filters</p>
            <p className="text-xs text-muted mt-1">Try adjusting the severity or category filter</p>
          </div>
        ) : (
          <div className="bg-surface-0 rounded-sm border border-border overflow-hidden">
            <div className="overflow-x-auto max-h-[750px] overflow-y-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-surface-1 z-10 border-b border-border shadow-none">
                  <tr className="text-left font-medium text-muted h-9">
                    <th className="px-4 py-2">Rank</th>
                    <th className="px-4 py-2">Severity</th>
                    <th className="px-4 py-2">Confidence</th>
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
                      onClick={() => setSelFinding(f)}
                      className="border-b border-border last:border-0 hover:bg-surface-1 cursor-pointer transition-colors h-10"
                    >
                      <td className={`px-4 py-2 font-mono text-muted tabular-nums border-l-[3px] ${sevBorder[f.severity]}`}>
                        #{f.priority_rank}
                      </td>
                      <td className="px-4 py-2">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="px-4 py-2">
                        <ConfidenceBadge level={f.confidence} />
                      </td>
                      <td className="px-4 py-2 max-w-md">
                        <div className="font-medium text-foreground">{f.title}</div>
                        <div className="text-[11px] text-muted truncate mt-0.5">{f.description}</div>
                        <div className="text-[10px] font-mono text-muted/70">{f.rule_id}</div>
                      </td>
                      <td className="px-4 py-2">
                        <span className="text-xs px-2 py-0.5 bg-surface-2 rounded-[3px] text-muted border border-border">
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
                          onClick={(e) => { e.stopPropagation(); setSelFinding(f); }}
                          className="text-xs font-medium text-foreground underline hover:text-ink"
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
        )
      ) : (
        incidents.length === 0 ? (
          <div className="text-center py-16 bg-surface-0 rounded-sm border border-border text-muted">
            <p className="text-xs font-medium text-foreground">No incidents found</p>
          </div>
        ) : (
          <div className="space-y-3">
            {incidents.map((inc) => {
              const isExp = expandedIncs[inc.id] ?? false;
              const incFindings = findings.filter(
                (f) => inc.finding_ids.includes(f.id) || f.incident_id === inc.id
              );
              return (
                <div key={inc.id} className="bg-surface-0 rounded-sm border border-border overflow-hidden">
                  <div
                    onClick={() => toggleInc(inc.id)}
                    className="p-4 flex items-center justify-between gap-4 cursor-pointer hover:bg-surface-1 transition-colors"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span className="text-muted">
                        {isExp ? <CaretDown size={14} /> : <CaretRight size={14} />}
                      </span>
                      <div>
                        <div className="flex items-center gap-2">
                          <EvidenceTag>{inc.id}</EvidenceTag>
                          <span className="font-mono text-xs text-muted">({inc.rule_id})</span>
                          <SeverityBadge severity={inc.severity} />
                          <ConfidenceBadge level={inc.confidence} />
                        </div>
                        <h3 className="text-sm font-medium text-foreground mt-1 truncate">{inc.title}</h3>
                      </div>
                    </div>

                    <div className="flex items-center gap-6 shrink-0 text-right text-xs">
                      <div>
                        <span className="font-mono text-foreground font-medium block">{inc.server}</span>
                        <span className="text-[10px] text-muted uppercase font-mono">{inc.server_role}</span>
                      </div>
                      <div>
                        <span className="font-mono text-foreground tabular-nums block">
                          {inc.sessions_affected} sess · {inc.clients_affected} cli
                        </span>
                        <span className="text-[10px] text-muted block tabular-nums">
                          {new Date(inc.first_seen).toLocaleTimeString()} – {new Date(inc.last_seen).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  </div>

                  {isExp && (
                    <div className="border-t border-border bg-surface-1 px-4 py-3 space-y-2">
                      <div className="text-[11px] font-semibold text-muted uppercase tracking-wider mb-2">
                        Grouped findings ({incFindings.length})
                      </div>
                      {incFindings.map((f) => (
                        <div
                          key={f.id}
                          onClick={() => setSelFinding(f)}
                          className="bg-surface-0 border border-border rounded-sm p-3 flex items-center justify-between gap-3 cursor-pointer hover:border-ink transition-colors"
                        >
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <SeverityBadge severity={f.severity} />
                              <ConfidenceBadge level={f.confidence} />
                              <span className="font-medium text-xs text-foreground truncate">{f.title}</span>
                            </div>
                            <p className="text-[11px] text-muted truncate mt-0.5">{f.description}</p>
                          </div>
                          <div className="flex items-center gap-4 shrink-0 text-right">
                            <span className="font-mono text-xs font-semibold text-sev-critical tabular-nums">
                              {f.score_impact}
                            </span>
                            <button
                              onClick={(e) => { e.stopPropagation(); setSelFinding(f); }}
                              className="text-xs font-medium text-foreground underline hover:text-ink"
                            >
                              Inspect evidence
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )
      )}

      {selFinding && (
        <div className="fixed inset-0 z-50 bg-black/40 flex justify-end animate-in fade-in duration-150">
          <div className="w-full max-w-2xl bg-surface-0 h-full shadow-2xl flex flex-col border-l border-border overflow-hidden">
            <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-surface-1">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={selFinding.severity} />
                  <ConfidenceBadge level={selFinding.confidence} />
                  <span className="text-xs font-mono text-muted">Rank #{selFinding.priority_rank}</span>
                  <span className="text-xs font-mono font-medium text-sev-critical">
                    Impact: {selFinding.score_impact}
                  </span>
                </div>
                <h2 className="text-base font-semibold text-foreground">{selFinding.title}</h2>
                <p className="text-xs font-mono text-muted">{selFinding.rule_id}</p>
              </div>
              <button
                onClick={() => setSelFinding(null)}
                className="p-1.5 rounded-sm hover:bg-surface-2 text-muted hover:text-foreground shrink-0"
              >
                <X size={18} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              <div>
                <h3 className="text-xs font-medium text-muted mb-2">
                  Description
                </h3>
                <p className="text-sm leading-relaxed text-foreground bg-surface-1 p-3.5 rounded-sm border border-border">
                  {selFinding.description}
                </p>
              </div>

              {selFinding.confidence_basis && selFinding.confidence_basis.length > 0 && (
                <div className="bg-surface-1 rounded-sm p-4 border border-border">
                  <h3 className="text-xs font-medium text-muted mb-2">
                    Confidence basis
                  </h3>
                  <ul className="space-y-1 text-xs text-foreground list-disc list-inside">
                    {selFinding.confidence_basis.map((b, i) => (
                      <li key={i}>{b}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="bg-surface-1 rounded-sm p-4 border border-border">
                <h3 className="text-xs font-medium text-muted mb-3">
                  Wireshark display filter
                </h3>
                <div className="flex items-center justify-between gap-2 bg-surface-0 border border-border rounded px-3 py-2">
                  <code className="text-xs font-mono text-foreground truncate">{selFinding.wireshark_filter}</code>
                  <button
                    onClick={() => copyText(selFinding.wireshark_filter)}
                    className="p-1 rounded hover:bg-surface-2 text-muted hover:text-foreground shrink-0 transition-colors"
                  >
                    {copied ? <Check size={14} className="text-sev-pass" /> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              <div className="bg-surface-1 rounded-sm p-4 border border-border">
                <h3 className="text-xs font-medium text-muted mb-3">
                  Technical evidence
                </h3>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-muted block">Target server</span>
                    <span className="font-mono font-medium">
                      {selFinding.evidence.server ? `${selFinding.evidence.server}:${selFinding.evidence.server_port}` : "—"}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted block">Client IP</span>
                    <span className="font-mono font-medium">{selFinding.evidence.client || "—"}</span>
                  </div>
                  <div className="col-span-2">
                    <span className="text-muted block mb-1">Associated frames</span>
                    <div className="flex flex-wrap gap-1">
                      {selFinding.evidence.frames.length > 0 ? (
                        selFinding.evidence.frames.map((n) => (
                          <EvidenceTag key={n}>#{n}</EvidenceTag>
                        ))
                      ) : (
                        <span className="text-muted font-mono">—</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <span className="text-muted block">Session ID</span>
                    <span className="font-mono font-medium">{selFinding.session_id || "None (Capture-wide)"}</span>
                  </div>
                  {selFinding.evidence.certificate_sha256 && (
                    <div className="col-span-2">
                      <span className="text-muted block">Certificate SHA-256</span>
                      <span className="font-mono text-xs break-all text-foreground">
                        {selFinding.evidence.certificate_sha256}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {relatedEvidence.length > 0 && (
                <div className="bg-surface-1 rounded-sm p-4 border border-border space-y-3">
                  <h3 className="text-xs font-medium text-muted">
                    Evidence items ({relatedEvidence.length})
                  </h3>
                  <div className="space-y-2">
                    {relatedEvidence.map((ev) => {
                      const isEvExp = expandedEvs[ev.id] ?? false;
                      return (
                        <div key={ev.id} className="bg-surface-0 border border-border rounded p-3 text-xs space-y-2">
                          <div
                            onClick={() => toggleEv(ev.id)}
                            className="flex items-center justify-between cursor-pointer"
                          >
                            <div className="flex items-center gap-2">
                              <span className="text-muted">
                                {isEvExp ? <CaretDown size={12} /> : <CaretRight size={12} />}
                              </span>
                              <EvidenceTag>{ev.id}</EvidenceTag>
                              <span className="text-muted font-mono">[{ev.type}]</span>
                            </div>
                            <span className="text-muted font-mono tabular-nums">
                              {ev.frames.length} frames
                            </span>
                          </div>

                          <p className="text-muted text-[11px]">{ev.summary}</p>

                          {isEvExp && (
                            <div className="pt-2 border-t border-border space-y-2">
                              <div>
                                <span className="text-muted block text-[10px] mb-1">Frames:</span>
                                <div className="flex flex-wrap gap-1">
                                  {ev.frames.map((n) => (
                                    <EvidenceTag key={n}>#{n}</EvidenceTag>
                                  ))}
                                </div>
                              </div>
                              <div>
                                <span className="text-muted block text-[10px]">Filter:</span>
                                <code className="font-mono text-[11px] text-foreground block break-all">{ev.wireshark_filter}</code>
                              </div>
                              {ev.certificate_sha256 && (
                                <div>
                                  <span className="text-muted block text-[10px]">Certificate SHA-256:</span>
                                  <span className="font-mono text-[10px] break-all">{ev.certificate_sha256}</span>
                                </div>
                              )}
                              {ev.session_id && (
                                <div>
                                  <span className="text-muted block text-[10px]">Session ID:</span>
                                  <span className="font-mono">{ev.session_id}</span>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              <div className="bg-surface-1 rounded-sm p-4 border border-border">
                <h3 className="text-xs font-medium text-muted mb-3">
                  Operational context
                </h3>
                <div className="grid grid-cols-3 gap-3 text-xs">
                  <div>
                    <span className="text-muted block">Server role</span>
                    <span className="font-mono font-medium uppercase">{selFinding.context.server_role}</span>
                  </div>
                  <div>
                    <span className="text-muted block">Sessions affected</span>
                    <span className="font-mono font-medium tabular-nums">{selFinding.context.sessions_affected}</span>
                  </div>
                  <div>
                    <span className="text-muted block">Clients affected</span>
                    <span className="font-mono font-medium tabular-nums">{selFinding.context.clients_affected}</span>
                  </div>
                </div>
              </div>

              {selFinding.anomaly && selFinding.anomaly.deviating_features.length > 0 && (
                <div className="bg-surface-1 rounded-sm p-4 border border-border">
                  <h3 className="text-xs font-medium text-sev-high mb-3">
                    Baseline anomaly deviations
                  </h3>
                  <div className="space-y-2 text-xs">
                    {selFinding.anomaly.deviating_features.map((dev, idx) => (
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

              <div className="bg-surface-1 rounded-sm p-4 border border-border">
                <h3 className="text-xs font-medium text-muted mb-2">
                  Remediation recommendations
                </h3>
                <p className="text-xs font-medium text-foreground mb-3">{selFinding.remediation.summary}</p>
                <ol className="list-decimal list-inside space-y-1.5 text-xs text-muted mb-4">
                  {selFinding.remediation.steps.map((step, idx) => (
                    <li key={idx} className="leading-relaxed">
                      <span className="text-foreground">{step}</span>
                    </li>
                  ))}
                </ol>
                {selFinding.remediation.references.length > 0 && (
                  <div>
                    <span className="text-xs text-muted block mb-1">References:</span>
                    <div className="space-y-1">
                      {selFinding.remediation.references.map((ref, idx) => (
                        <div key={idx} className="flex items-center gap-1.5 text-xs text-foreground font-mono">
                          <ArrowSquareOut size={12} className="text-muted shrink-0" />
                          <span className="underline hover:text-ink break-all">{ref}</span>
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
