"use client";

import { useState, useEffect, useMemo, Suspense } from "react";
import { useSearchParams, useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import type { Finding, Severity, FindingCategory, Incident } from "@/types";
import { getFindings, getIncidents } from "@/data";
import { SeverityBadge } from "@/components/severity";
import {
  Copy,
  Check,
  ArrowRight,
  ShieldWarning,
  SlidersHorizontal,
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
    <div className="w-full px-4 2xl:px-6 py-3 space-y-3 animate-pulse select-none">
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-3 h-[calc(100vh-112px)]">
        <div className="xl:col-span-7 bg-surface-0 border border-border rounded-[var(--radius-md)] p-3" />
        <div className="xl:col-span-5 bg-surface-0 border border-border rounded-[var(--radius-md)] p-3" />
      </div>
    </div>
  );
}

function FindingsContent() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const capId = searchParams.get("capture") ?? "cap-001";
  const urlSelectedId = searchParams.get("selected") ?? searchParams.get("finding");

  const [findings, setFindings] = useState<Finding[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [sev, setSev] = useState<string>("");
  const [cat, setCat] = useState<string>("");
  const [selId, setSelId] = useState<string | null>(urlSelectedId);
  const [copiedFilter, setCopiedFilter] = useState(false);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    Promise.all([getFindings(capId), getIncidents(capId)])
      .then(([fList, incList]) => {
        if (!active) return;
        setFindings(fList);
        setIncidents(incList);
        setLoading(false);
      })
      .catch((e: unknown) => {
        if (!active) return;
        setError(e instanceof Error ? e.message : "Failed to load findings");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [capId]);

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (sev && f.severity !== sev) return false;
      if (cat && f.category !== cat) return false;
      if (!query) return true;
      const q = query.toLowerCase();
      return (
        f.id.toLowerCase().includes(q) ||
        f.rule_id.toLowerCase().includes(q) ||
        f.title.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        f.evidence?.server?.toLowerCase().includes(q)
      );
    });
  }, [findings, sev, cat, query]);

  const activeId = selId ?? filteredFindings[0]?.id ?? null;
  const selFinding = filteredFindings.find((f) => f.id === activeId) ?? filteredFindings[0] ?? null;

  function selectFinding(id: string) {
    setSelId(id);
    const next = new URLSearchParams(searchParams.toString());
    next.set("selected", id);
    router.replace(`${pathname}?${next.toString()}`, { scroll: false });
  }

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement) return;
      if (filteredFindings.length === 0) return;

      const currentIndex = filteredFindings.findIndex((f) => f.id === activeId);

      if (e.key === "ArrowDown") {
        e.preventDefault();
        const nextIndex = currentIndex < filteredFindings.length - 1 ? currentIndex + 1 : 0;
        selectFinding(filteredFindings[nextIndex].id);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        const prevIndex = currentIndex > 0 ? currentIndex - 1 : filteredFindings.length - 1;
        selectFinding(filteredFindings[prevIndex].id);
      } else if (e.key === "Escape") {
        e.preventDefault();
        setSelId(null);
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [filteredFindings, activeId]);

  function copyText(txt: string, cb: () => void) {
    navigator.clipboard.writeText(txt);
    cb();
  }

  const endpointText = selFinding?.evidence
    ? `${selFinding.evidence.client || "192.168.1.50"} → ${selFinding.evidence.server || "mail.company.com"}:${selFinding.evidence.server_port || 587}`
    : "—";

  return (
    <div className="w-full px-4 2xl:px-6 py-3 select-none text-[13px] h-[calc(100vh-88px)] flex flex-col overflow-hidden">
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-3 flex-1 min-h-0">
        {/* ================= LEFT 60%: FINDINGS TABLE ================= */}
        <section
          className="col-span-12 xl:col-span-7 flex flex-col bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 xcor-shadow min-h-0 overflow-hidden"
          aria-label="Findings master table"
        >
          {/* Filter Bar */}
          <div className="flex items-center justify-between gap-2 pb-2.5 border-b border-border shrink-0 flex-wrap">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[14px] font-semibold text-foreground">Findings</span>
              <span className="text-[11px] font-mono px-1.5 py-0.5 bg-surface-1 border border-border rounded-[var(--radius-xs)] text-muted">
                {filteredFindings.length}
              </span>

              <select
                value={sev}
                onChange={(e) => setSev(e.target.value)}
                className="bg-surface-1 border border-border rounded-[var(--radius-xs)] px-2 py-1 text-[12px] font-medium text-foreground cursor-pointer focus-ring"
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
                className="bg-surface-1 border border-border rounded-[var(--radius-xs)] px-2 py-1 text-[12px] font-medium text-foreground cursor-pointer focus-ring"
              >
                <option value="">All categories</option>
                <option value="transport">Transport</option>
                <option value="certificate">Certificate</option>
                <option value="protocol">Protocol</option>
                <option value="message">Message</option>
                <option value="anomaly">Anomaly</option>
                <option value="drift">Drift</option>
              </select>

              <input
                type="text"
                placeholder="Search rule, title, host…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="bg-surface-1 border border-border rounded-[var(--radius-xs)] px-2.5 py-1 text-[12px] text-foreground placeholder:text-muted focus-ring w-44 font-mono"
              />
            </div>
          </div>

          {/* Master Table */}
          <div className="flex-1 overflow-y-auto min-h-0 pt-1">
            <table className="w-full text-left text-[12px]">
              <thead className="sticky top-0 bg-surface-1 border-b border-border text-muted font-medium h-8 z-10">
                <tr>
                  <th className="px-2.5 py-1 w-24">Severity</th>
                  <th className="px-2 py-1 w-24">Rule ID</th>
                  <th className="px-2 py-1">Title</th>
                  <th className="px-2 py-1 w-24">Category</th>
                  <th className="px-2.5 py-1 w-16 text-right">Deduction</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {loading ? (
                  <tr>
                    <td colSpan={5} className="p-4 text-center text-muted">
                      Loading findings…
                    </td>
                  </tr>
                ) : filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="p-6 text-center text-muted">
                      No findings matching current filters.
                    </td>
                  </tr>
                ) : (
                  filteredFindings.map((f) => {
                    const isSel = f.id === activeId;
                    const deduction = f.score_impact ?? 0;

                    return (
                      <tr
                        key={f.id}
                        onClick={() => selectFinding(f.id)}
                        className={`h-8 cursor-pointer transition-colors ${
                          isSel
                            ? "bg-accent-soft border-l-2 border-l-accent font-medium"
                            : "hover:bg-surface-1"
                        }`}
                      >
                        <td className="px-2.5 py-1">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="px-2 py-1 font-mono text-[11px] text-muted font-medium">
                          {f.rule_id}
                        </td>
                        <td className="px-2 py-1 text-foreground font-medium truncate max-w-[220px]">
                          {f.title}
                        </td>
                        <td className="px-2 py-1 text-muted text-[11px] capitalize">
                          {f.category}
                        </td>
                        <td className="px-2.5 py-1 font-mono text-right font-semibold tabular-nums text-sev-critical">
                          {deduction < 0 ? deduction : deduction > 0 ? `-${deduction}` : "0"}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* ================= RIGHT 40%: PERSISTENT DETAIL PANE ================= */}
        <section
          className="col-span-12 xl:col-span-5 flex flex-col bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 xcor-shadow min-h-0 overflow-hidden"
          aria-label="Finding detail inspector"
        >
          {selFinding ? (
            <>
              {/* Detail Header */}
              <div className="flex items-start justify-between pb-2 border-b border-border shrink-0 gap-2">
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={selFinding.severity} />
                    <span className="font-mono text-[11px] text-muted">{selFinding.rule_id}</span>
                    <span className="font-mono text-[11px] text-muted">[{selFinding.id}]</span>
                  </div>
                  <h2 className="text-[14px] font-semibold text-foreground leading-snug">
                    {selFinding.title}
                  </h2>
                </div>

                <div className="flex flex-col items-end shrink-0">
                  <span className="font-mono text-[11px] font-bold text-sev-critical bg-sev-critical-bg px-2 py-0.5 rounded-[var(--radius-xs)] tabular-nums">
                    {selFinding.score_impact ?? -10} pts posture impact
                  </span>
                </div>
              </div>

              {/* Scrollable Content */}
              <div className="flex-1 overflow-y-auto pr-1 pt-2 space-y-3">
                {/* Description */}
                <div className="space-y-1">
                  <h3 className="text-[12px] font-semibold text-foreground">Observation details</h3>
                  <p className="text-[12px] text-muted leading-relaxed text-prose-cap">
                    {selFinding.description}
                  </p>
                </div>

                {/* Affected Endpoints */}
                <div className="space-y-1.5">
                  <h3 className="text-[12px] font-semibold text-foreground">Affected endpoints</h3>
                  <div className="bg-surface-1/60 border border-border rounded-[var(--radius-xs)] p-2.5 space-y-1.5 text-[11px] font-mono">
                    <div className="flex justify-between items-center">
                      <span className="text-muted font-sans">Network path</span>
                      <span className="text-foreground font-semibold">{endpointText}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-muted font-sans">Sessions affected</span>
                      <span className="text-foreground font-semibold tabular-nums">
                        {selFinding.context?.sessions_affected ?? 1} session(s)
                      </span>
                    </div>
                    {selFinding.evidence?.frames && selFinding.evidence.frames.length > 0 && (
                      <div className="flex justify-between items-center">
                        <span className="text-muted font-sans">Evidence packet frame(s)</span>
                        <span className="text-foreground font-semibold">
                          {selFinding.evidence.frames.slice(0, 5).join(", ")}
                          {selFinding.evidence.frames.length > 5 ? "…" : ""}
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Wireshark Display Filter */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[11px]">
                    <h3 className="font-semibold text-foreground">Wireshark display filter</h3>
                    <button
                      onClick={() =>
                        copyText(selFinding.wireshark_filter, () => {
                          setCopiedFilter(true);
                          setTimeout(() => setCopiedFilter(false), 2000);
                        })
                      }
                      className="inline-flex items-center gap-1 text-muted hover:text-foreground cursor-pointer font-sans"
                    >
                      {copiedFilter ? (
                        <>
                          <Check size={11} weight="bold" className="text-sev-pass" />
                          <span className="text-sev-pass">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy size={11} weight="bold" />
                          <span>Copy filter</span>
                        </>
                      )}
                    </button>
                  </div>

                  <code className="block bg-surface-1 border border-border px-2.5 py-1.5 rounded-[var(--radius-xs)] font-mono text-[11px] text-foreground select-all break-all">
                    {selFinding.wireshark_filter}
                  </code>
                </div>

                {/* Remediation Guidance */}
                <div className="space-y-2 pt-1 border-t border-border">
                  <h3 className="text-[12px] font-semibold text-foreground">Remediation guidance</h3>

                  <div className="bg-surface-1/60 border border-border rounded-[var(--radius-xs)] p-2.5 space-y-2">
                    <p className="text-[12px] text-foreground font-medium leading-snug">
                      {typeof selFinding.remediation === "string"
                        ? selFinding.remediation
                        : selFinding.remediation?.summary ?? "Apply recommended RFC 8314 TLS hardening."}
                    </p>

                    {selFinding.remediation?.steps && selFinding.remediation.steps.length > 0 && (
                      <div className="space-y-1 pt-1 border-t border-border/70">
                        <span className="text-[11px] text-muted font-medium block">Action steps:</span>
                        <ol className="list-decimal pl-4 space-y-1 text-[11px] text-muted">
                          {selFinding.remediation.steps.map((st, i) => (
                            <li key={i} className="leading-snug">
                              {st}
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}

                    {selFinding.policy_refs && selFinding.policy_refs.length > 0 && (
                      <div className="space-y-1 pt-1 border-t border-border/70">
                        <span className="text-[11px] text-muted font-medium block">Policy references:</span>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {selFinding.policy_refs.map((ref, idx) => (
                            <span
                              key={idx}
                              className="px-1.5 py-0.5 bg-surface-0 border border-border rounded-[var(--radius-xs)] font-mono text-[10px] text-foreground"
                            >
                              {ref.document} §{ref.section}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Direct Link to Sessions */}
                <div className="pt-2 border-t border-border">
                  <Link
                    href={
                      selFinding.session_id
                        ? `/sessions?capture=${capId}&session=${selFinding.session_id}`
                        : `/sessions?capture=${capId}&finding=${selFinding.rule_id}`
                    }
                    className="w-full flex items-center justify-center gap-1.5 py-1.5 bg-accent hover:bg-accent-hover text-white rounded-[var(--radius-xs)] text-[12px] font-semibold transition-colors focus-ring"
                  >
                    <span>View affected session in stream inspector</span>
                    <ArrowRight size={12} weight="bold" />
                  </Link>
                </div>
              </div>
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center p-6 text-muted">
              <p className="text-[13px] font-medium">Select a finding to inspect forensic details.</p>
              <p className="text-[11px] mt-1">Use the arrow keys or click a row on the left table.</p>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
