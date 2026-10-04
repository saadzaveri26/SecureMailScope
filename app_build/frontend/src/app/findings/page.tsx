"use client";

import { useState, useEffect, useMemo, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import type { Finding, Severity, FindingCategory, Incident, Evidence } from "@/types";
import { getFindings, getIncidents, getEvidence } from "@/data";
import { SeverityBadge } from "@/components/severity";
import { ConfidenceBadge } from "@/components/confidence-badge";
import {
  X,
  Copy,
  Check,
  CaretDown,
  CaretRight,
  ArrowSquareOut,
} from "@phosphor-icons/react";

const sevWeight: Record<Severity, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};

export default function FindingsPage() {
  return (
    <Suspense fallback={<Skeleton />}>
      <Content />
    </Suspense>
  );
}

function Skeleton() {
  return (
    <div className="max-w-[1600px] mx-auto px-4 py-4 space-y-4 animate-pulse">
      <div className="h-4 w-32 bg-surface-2" />
      <div className="border-2 border-black bg-surface-0 brutal-shadow">
        <div className="h-8 bg-surface-1 border-b-2 border-black" />
        {[...Array(8)].map((_, i) => (
          <div key={i} className="h-9 border-b border-black/20 flex items-center px-3 gap-4">
            <div className="h-3 w-10 bg-surface-2" />
            <div className="h-3 w-16 bg-surface-2" />
            <div className="h-3 w-48 bg-surface-2" />
          </div>
        ))}
      </div>
    </div>
  );
}

function Content() {
  const params = useSearchParams();
  const capId = params.get("capture") ?? "cap-001";
  const initFindingId = params.get("finding");

  const [view, setView] = useState<"findings" | "incident">("findings");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [sev, setSev] = useState<string>("");
  const [cat, setCat] = useState<string>("");
  const [sortField, setSortField] = useState<"rank" | "severity" | "impact">("rank");
  const [sortAsc, setSortAsc] = useState(true);

  const [sel, setSel] = useState<Finding | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [openIncidentIds, setOpenIncidentIds] = useState<Set<string>>(new Set());

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    Promise.all([
      getFindings(capId),
      getIncidents(capId),
      getEvidence(capId),
    ])
      .then(([f, inc, ev]) => {
        if (!active) return;
        setFindings(f);
        setIncidents(inc);
        setEvidenceList(ev);
        setLoading(false);
        if (initFindingId) {
          const match = f.find((x) => x.id === initFindingId);
          if (match) {
            setSel(match);
            setDrawerOpen(true);
          }
        }
      })
      .catch((e: unknown) => {
        if (!active) return;
        setError(e instanceof Error ? e.message : "Failed to load findings");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [capId, initFindingId]);

  const filtered = useMemo(() => {
    return findings
      .filter((f) => {
        if (sev && f.severity !== sev) return false;
        if (cat && f.category !== cat) return false;
        if (query) {
          const q = query.toLowerCase();
          const match =
            f.title.toLowerCase().includes(q) ||
            f.rule_id.toLowerCase().includes(q) ||
            f.description.toLowerCase().includes(q) ||
            (f.evidence.server && f.evidence.server.toLowerCase().includes(q));
          if (!match) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortField === "rank") {
          return sortAsc ? a.priority_rank - b.priority_rank : b.priority_rank - a.priority_rank;
        }
        if (sortField === "severity") {
          const diff = sevWeight[b.severity] - sevWeight[a.severity];
          return sortAsc ? diff : -diff;
        }
        if (sortField === "impact") {
          return sortAsc ? a.score_impact - b.score_impact : b.score_impact - a.score_impact;
        }
        return 0;
      });
  }, [findings, sev, cat, query, sortField, sortAsc]);

  function toggleSort(field: "rank" | "severity" | "impact") {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(true);
    }
  }

  function openDrawer(f: Finding) {
    setSel(f);
    setDrawerOpen(true);
  }

  function toggleIncident(id: string) {
    setOpenIncidentIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function copyText(val: string, key: string) {
    navigator.clipboard.writeText(val);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  }

  return (
    <div className="max-w-[1600px] mx-auto px-4 py-4 space-y-3 font-mono text-xs select-none">
      {/* Header strip */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-foreground font-bold">
          <span className="uppercase tracking-wider text-black">findings</span>
          <span className="text-black/40">·</span>
          <span className="bg-surface-2 px-1.5 py-0.5 border border-black">{capId}</span>
          <span className="text-black/40">·</span>
          <span className="text-muted font-semibold">{filtered.length} results</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex border-2 border-black bg-surface-0 brutal-shadow-sm">
            <button
              onClick={() => setView("findings")}
              className={`px-3 py-1 text-xs font-mono font-bold cursor-pointer transition-colors ${view === "findings" ? "bg-accent text-black" : "text-muted hover:text-black"}`}
            >
              table
            </button>
            <button
              onClick={() => setView("incident")}
              className={`px-3 py-1 text-xs font-mono font-bold cursor-pointer transition-colors border-l-2 border-black ${view === "incident" ? "bg-accent text-black" : "text-muted hover:text-black"}`}
            >
              by incident
            </button>
          </div>
        </div>
      </div>

      {/* Filter row */}
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="filter…"
          className="w-52 px-2.5 py-1.5 bg-surface-0 border-2 border-black text-black placeholder:text-muted focus:outline-none focus:bg-accent/10 text-xs font-mono font-bold brutal-shadow-sm"
        />
        <select value={sev} onChange={(e) => setSev(e.target.value)} className="px-2.5 py-1.5 bg-surface-0 border-2 border-black text-xs font-mono font-bold text-black focus:outline-none cursor-pointer brutal-shadow-sm">
          <option value="">all severities</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
          <option value="info">info</option>
        </select>
        <select value={cat} onChange={(e) => setCat(e.target.value)} className="px-2.5 py-1.5 bg-surface-0 border-2 border-black text-xs font-mono font-bold text-black focus:outline-none cursor-pointer brutal-shadow-sm">
          <option value="">all categories</option>
          <option value="transport">transport</option>
          <option value="certificate">certificate</option>
          <option value="protocol">protocol</option>
          <option value="message">message</option>
          <option value="drift">drift</option>
          <option value="anomaly">anomaly</option>
        </select>
      </div>

      {/* Table */}
      {loading ? (
        <Skeleton />
      ) : error ? (
        <div className="text-xs font-mono font-bold text-sev-critical border-2 border-black bg-sev-critical-bg px-3 py-2 brutal-shadow-sm">{error}</div>
      ) : view === "findings" ? (
        filtered.length === 0 ? (
          <div className="text-xs font-mono text-muted border-2 border-black bg-surface-0 px-3 py-8 text-center brutal-shadow">no findings match</div>
        ) : (
          <div className="border-2 border-black bg-surface-0 overflow-hidden brutal-shadow">
            <div className="overflow-x-auto max-h-[700px] overflow-y-auto">
              <table className="w-full text-xs font-mono text-left">
                <thead className="sticky top-0 bg-surface-1 border-b-2 border-black text-[11px] font-bold text-black uppercase z-10">
                  <tr>
                    <th onClick={() => toggleSort("rank")} className="py-2 px-3 cursor-pointer hover:bg-accent/20 w-12">
                      # {sortField === "rank" ? (sortAsc ? "↑" : "↓") : ""}
                    </th>
                    <th onClick={() => toggleSort("severity")} className="py-2 px-3 cursor-pointer hover:bg-accent/20 w-18">
                      sev {sortField === "severity" ? (sortAsc ? "↑" : "↓") : ""}
                    </th>
                    <th className="py-2 px-3 w-32">rule</th>
                    <th className="py-2 px-3">finding</th>
                    <th className="py-2 px-3 w-24">category</th>
                    <th className="py-2 px-3 w-36">target</th>
                    <th className="py-2 px-3 w-52">wireshark filter</th>
                    <th onClick={() => toggleSort("impact")} className="py-2 px-3 text-right cursor-pointer hover:bg-accent/20 w-16">
                      pts {sortField === "impact" ? (sortAsc ? "↑" : "↓") : ""}
                    </th>
                    <th className="py-2 px-3 text-right w-20">action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-black/20">
                  {filtered.map((f) => (
                    <tr
                      key={f.id}
                      onClick={() => openDrawer(f)}
                      className={`hover:bg-accent/10 cursor-pointer transition-colors ${sel?.id === f.id ? "bg-accent/20" : ""}`}
                    >
                      <td className="py-2 px-3 text-muted font-bold tabular-nums">{f.priority_rank}</td>
                      <td className="py-2 px-3"><SeverityBadge severity={f.severity} /></td>
                      <td className="py-2 px-3 text-black font-bold">{f.rule_id}</td>
                      <td className="py-2 px-3 max-w-sm">
                        <span className="text-black font-bold block leading-tight truncate">{f.title}</span>
                        <span className="text-muted text-[11px] block truncate leading-tight mt-0.5">{f.description}</span>
                      </td>
                      <td className="py-2 px-3 text-black font-semibold text-[10px] uppercase">{f.category}</td>
                      <td className="py-2 px-3 text-muted text-[11px]">
                        {f.evidence.server ? `${f.evidence.server}:${f.evidence.server_port}` : "capture-wide"}
                      </td>
                      <td className="py-2 px-3">
                        <code className="text-[10px] text-foreground bg-surface-1 px-1.5 py-0.5 border border-black/30 truncate block max-w-[180px]">{f.wireshark_filter}</code>
                      </td>
                      <td className="py-2 px-3 text-right tabular-nums font-bold text-red-600">
                        -{f.score_impact}
                      </td>
                      <td className="py-2 px-3 text-right">
                        <button
                          onClick={(e) => { e.stopPropagation(); openDrawer(f); }}
                          className="px-2 py-0.5 bg-accent hover:bg-accent-hover text-black border border-black text-[11px] font-bold shadow-[1px_1px_0_#000]"
                        >
                          view
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
        /* Incident view */
        <div className="space-y-3">
          {incidents.map((inc) => {
            const open = openIncidentIds.has(inc.id);
            const incFindings = findings.filter((f) => inc.finding_ids.includes(f.id));
            return (
              <div key={inc.id} className="border-2 border-black bg-surface-0 brutal-shadow">
                <div
                  onClick={() => toggleIncident(inc.id)}
                  className="px-3 py-2 bg-surface-1 border-b-2 border-black flex items-center justify-between cursor-pointer hover:bg-accent/15 transition-colors"
                >
                  <div className="flex items-center gap-2">
                    {open ? <CaretDown size={14} weight="bold" /> : <CaretRight size={14} weight="bold" />}
                    <SeverityBadge severity={inc.severity} />
                    <span className="text-black font-bold text-xs">{inc.title}</span>
                    <span className="text-muted text-[11px]">({incFindings.length} findings)</span>
                  </div>
                  <div className="flex items-center gap-3 text-xs">
                    <span className="text-muted font-bold">confidence:</span>
                    <ConfidenceBadge level={inc.confidence} />
                    <span className="text-red-600 font-bold tabular-nums">-{incFindings.reduce((sum, f) => sum + f.score_impact, 0)} pts</span>
                  </div>
                </div>
                {open && (
                  <div className="border-t border-black/20 divide-y divide-black/20">
                    {incFindings.map((f) => (
                      <div
                        key={f.id}
                        onClick={() => openDrawer(f)}
                        className="px-3 py-2 flex items-center justify-between hover:bg-accent/10 cursor-pointer"
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <SeverityBadge severity={f.severity} />
                          <span className="font-bold text-black">{f.rule_id}</span>
                          <span className="text-foreground truncate">{f.title}</span>
                        </div>
                        <div className="flex items-center gap-3 text-muted text-[11px] shrink-0">
                          <span>{f.evidence.server || "capture-wide"}</span>
                          <span className="text-red-600 font-bold">-{f.score_impact}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Drawer */}
      {drawerOpen && sel && (
        <div className="fixed inset-0 z-50 bg-black/60 flex justify-end">
          <div className="w-full max-w-xl bg-surface-0 h-full border-l-3 border-black flex flex-col overflow-hidden brutal-shadow">
            <div className="px-4 py-3 bg-surface-1 border-b-2 border-black flex items-center justify-between shrink-0">
              <div className="min-w-0 pr-3">
                <div className="flex items-center gap-2 text-xs font-mono">
                  <SeverityBadge severity={sel.severity} />
                  <span className="text-black font-bold text-sm">{sel.rule_id}</span>
                  <span className="text-muted font-bold">rank {sel.priority_rank}</span>
                  <span className="bg-red-500 text-white font-bold px-1.5 py-0.5 border border-black tabular-nums">-{sel.score_impact} pts</span>
                </div>
                <div className="text-xs text-foreground font-bold mt-1 truncate">{sel.title}</div>
              </div>
              <button onClick={() => setDrawerOpen(false)} className="p-1 bg-surface-0 border border-black text-black hover:bg-accent shrink-0 cursor-pointer">
                <X size={16} weight="bold" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs font-mono">
              <div className="border-2 border-black bg-surface-1 p-3 space-y-1.5 brutal-shadow-sm">
                <div className="text-[10px] text-black font-bold uppercase tracking-wider">description</div>
                <p className="text-foreground leading-relaxed font-sans text-xs font-medium">{sel.description}</p>
              </div>

              <div className="grid grid-cols-2 gap-2.5 text-[11px]">
                <div className="border-2 border-black p-2 bg-surface-0 brutal-shadow-sm">
                  <span className="text-muted block text-[10px] font-bold uppercase">target</span>
                  <span className="text-foreground font-bold">{sel.evidence.server || "capture-wide"}{sel.evidence.server_port ? `:${sel.evidence.server_port}` : ""}</span>
                </div>
                <div className="border-2 border-black p-2 bg-surface-0 brutal-shadow-sm">
                  <span className="text-muted block text-[10px] font-bold uppercase">client</span>
                  <span className="text-foreground font-bold">{sel.evidence.client || "all"}</span>
                </div>
                <div className="border-2 border-black p-2 bg-surface-0 brutal-shadow-sm">
                  <span className="text-muted block text-[10px] font-bold uppercase">frames</span>
                  <span className="text-foreground font-bold tabular-nums">{sel.evidence.frames.length}</span>
                </div>
                <div className="border-2 border-black p-2 bg-surface-0 brutal-shadow-sm">
                  <span className="text-muted block text-[10px] font-bold uppercase">session</span>
                  <span className="text-foreground font-bold">{sel.session_id || "none"}</span>
                </div>
              </div>

              <div className="border-2 border-black p-3 space-y-2 bg-surface-0 brutal-shadow-sm">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-black font-bold uppercase tracking-wider">wireshark filter</span>
                  <button
                    onClick={() => copyText(sel.wireshark_filter, "filter")}
                    className="flex items-center gap-1 text-[11px] font-bold text-black bg-accent px-2 py-0.5 border border-black cursor-pointer hover:bg-accent-hover"
                  >
                    {copiedKey === "filter" ? <><Check size={11} weight="bold" /> copied</> : <><Copy size={11} weight="bold" /> copy</>}
                  </button>
                </div>
                <div className="p-2 bg-surface-1 border border-black text-[11px] text-black font-bold break-all select-all">
                  {sel.wireshark_filter}
                </div>
              </div>

              <div className="border-2 border-black p-3 space-y-2.5 bg-surface-0 brutal-shadow-sm">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-black font-bold uppercase tracking-wider">remediation</span>
                  <button
                    onClick={() => copyText(`${sel.remediation.summary}\n${sel.remediation.steps.join("\n")}`, "fix")}
                    className="flex items-center gap-1 text-[11px] font-bold text-black bg-accent px-2 py-0.5 border border-black cursor-pointer hover:bg-accent-hover"
                  >
                    {copiedKey === "fix" ? <><Check size={11} weight="bold" /> copied</> : <><Copy size={11} weight="bold" /> copy</>}
                  </button>
                </div>
                <div className="text-xs text-foreground font-sans font-medium">{sel.remediation.summary}</div>
                <div className="space-y-1.5">
                  {sel.remediation.steps.map((st, i) => (
                    <div key={i} className="p-2 bg-surface-1 border border-black text-[11px] text-black flex items-start gap-2">
                      <span className="font-bold text-black shrink-0">{i + 1}.</span>
                      <span className="break-all font-medium">{st}</span>
                    </div>
                  ))}
                </div>
                {sel.remediation.references.length > 0 && (
                  <div className="pt-2 border-t-2 border-black/20 space-y-1">
                    {sel.remediation.references.map((r, i) => (
                      <div key={i} className="flex items-center gap-1.5 text-[11px] text-muted font-bold">
                        <ArrowSquareOut size={12} weight="bold" className="shrink-0 text-black" />
                        <span className="truncate">{r}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {sel.confidence_basis.length > 0 && (
                <div className="border-2 border-black p-3 space-y-1.5 bg-surface-0 brutal-shadow-sm">
                  <span className="text-[10px] text-black font-bold uppercase tracking-wider">confidence basis</span>
                  <ul className="list-disc list-inside space-y-1 text-[11px] text-foreground font-sans font-medium">
                    {sel.confidence_basis.map((cb, i) => <li key={i}>{cb}</li>)}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
