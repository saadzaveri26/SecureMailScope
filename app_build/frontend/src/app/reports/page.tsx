"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import type { Capture, Summary, Finding } from "@/types";
import { getCaptures, getSummary, getFindings, getReportUrl } from "@/data";
import { ScoreGauge } from "@/components/score-gauge";
import { SeverityBadge } from "@/components/severity";

export default function ReportsPage() {
  return (
    <Suspense fallback={<ReportsSkeleton />}>
      <ReportsContent />
    </Suspense>
  );
}

function ReportsSkeleton() {
  return (
    <div className="w-full px-4 2xl:px-6 py-4 space-y-4 animate-pulse">
      <div className="space-y-1">
        <div className="h-5 w-44 bg-surface-2 rounded" />
        <div className="h-4 w-72 bg-surface-2 rounded" />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
        <div className="h-32 bg-surface-0 rounded-[var(--radius-md)] border border-border p-3" />
        <div className="h-32 bg-surface-0 rounded-[var(--radius-md)] border border-border p-3" />
        <div className="h-32 bg-surface-0 rounded-[var(--radius-md)] border border-border p-3" />
      </div>
    </div>
  );
}

function ReportsContent() {
  const searchParams = useSearchParams();
  const [caps, setCaps] = useState<Capture[]>([]);
  const [selectedCapId, setSelectedCapId] = useState<string>(searchParams.get("capture") ?? "cap-001");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function loadReport(targetId: string) {
    setLoading(true);
    setError(null);
    Promise.all([
      getSummary(targetId),
      getFindings(targetId),
    ])
      .then(([s, f]) => {
        setSummary(s);
        setFindings(f);
        setLoading(false);
      })
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : "Failed to load report data");
        setLoading(false);
      });
  }

  useEffect(() => {
    let active = true;
    getCaptures()
      .then(async (cList) => {
        if (!active) return;
        setCaps(cList);
        const targetId = searchParams.get("capture") ?? cList.find((c) => c.status === "complete")?.id ?? "cap-001";
        setSelectedCapId(targetId);
        const s = await getSummary(targetId);
        const f = await getFindings(targetId);
        if (active) {
          setSummary(s);
          setFindings(f);
          setLoading(false);
        }
      })
      .catch((e: unknown) => {
        if (active) {
          setError(e instanceof Error ? e.message : "Failed to load report data");
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [searchParams]);

  function handleCaptureChange(id: string) {
    setSelectedCapId(id);
    loadReport(id);
  }

  function downloadJson() {
    if (!summary) return;
    const blob = new Blob([JSON.stringify({ summary, findings }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `securemailscope-report-${selectedCapId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const selectedCap = caps.find((c) => c.id === selectedCapId);
  const completeCaps = caps.filter((c) => c.status === "complete");

  const shaVal = selectedCap?.custody?.sha256 ?? selectedCap?.sha256 ?? "—";
  const toolVer = selectedCap?.analysis?.tool_version ?? "1.0.0";
  const ruleVer = selectedCap?.analysis?.ruleset_version ?? "2025.03.1";

  return (
    <div className="w-full px-4 2xl:px-6 py-4 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-[20px] font-semibold text-foreground">Security posture reports</h1>
          <p className="text-[13px] text-muted text-prose-cap">
            Export executive summaries and forensic audit records for compliance reporting
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-[13px] text-muted font-medium">Capture:</label>
          <select
            value={selectedCapId}
            onChange={(e) => handleCaptureChange(e.target.value)}
            className="text-[13px] bg-surface-0 border border-border rounded-[var(--radius-xs)] px-2.5 py-1 focus-ring"
          >
            {completeCaps.map((c) => (
              <option key={c.id} value={c.id}>
                {c.filename} ({c.id})
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 grid grid-cols-1 sm:grid-cols-3 gap-3 text-[13px] xcor-shadow-subtle">
        <div>
          <span className="text-muted block text-[11px]">Capture SHA-256</span>
          <span className="font-mono text-foreground font-medium text-[12px] break-all">{shaVal}</span>
        </div>
        <div>
          <span className="text-muted block text-[11px]">Tool version</span>
          <span className="font-mono text-foreground font-medium text-[12px]">{toolVer}</span>
        </div>
        <div>
          <span className="text-muted block text-[11px]">Ruleset version</span>
          <span className="font-mono text-foreground font-medium text-[12px]">{ruleVer}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <div className="bg-surface-0 rounded-[var(--radius-sm)] border border-border p-5 flex flex-col justify-between">
          <div>
            <span className="text-xs font-medium text-muted font-mono">JSON export</span>
            <h3 className="text-base font-semibold text-foreground mt-1">Structured export</h3>
            <p className="text-xs text-muted mt-1 leading-relaxed">
              Full programmatic schema payload including scores, evidence, findings, and Wireshark filters.
            </p>
          </div>
          <div className="mt-5 pt-3 border-t border-border">
            <button
              onClick={downloadJson}
              className="w-full flex items-center justify-center text-xs font-medium bg-surface-2 hover:bg-surface-1 text-foreground border border-border rounded-[var(--radius-sm)] py-2 transition-colors"
            >
              Download JSON
            </button>
          </div>
        </div>

        <div className="bg-surface-0 rounded-[var(--radius-sm)] border border-border p-5 flex flex-col justify-between">
          <div>
            <span className="text-xs font-medium text-muted font-mono">HTML brief</span>
            <h3 className="text-base font-semibold text-foreground mt-1">Interactive web report</h3>
            <p className="text-xs text-muted mt-1 leading-relaxed">
              Self-contained offline document with tables, posture meters, and remediations.
            </p>
          </div>
          <div className="mt-5 pt-3 border-t border-border">
            <a
              href={getReportUrl(selectedCapId, "html")}
              target="_blank"
              rel="noreferrer"
              className="w-full flex items-center justify-center text-xs font-medium bg-surface-2 hover:bg-surface-1 text-foreground border border-border rounded-[var(--radius-sm)] py-2 transition-colors"
            >
              Export HTML
            </a>
          </div>
        </div>

        <div className="bg-surface-0 rounded-[var(--radius-sm)] border border-border p-5 flex flex-col justify-between">
          <div>
            <span className="text-xs font-medium text-muted font-mono">PDF document</span>
            <h3 className="text-base font-semibold text-foreground mt-1">Executive summary</h3>
            <p className="text-xs text-muted mt-1 leading-relaxed">
              Print-ready executive summary for CISOs, compliance auditors, and security reviews.
            </p>
          </div>
          <div className="mt-5 pt-3 border-t border-border">
            <a
              href={getReportUrl(selectedCapId, "pdf")}
              target="_blank"
              rel="noreferrer"
              className="w-full flex items-center justify-center text-xs font-medium bg-surface-2 hover:bg-surface-1 text-foreground border border-border rounded-[var(--radius-sm)] py-2 transition-colors"
            >
              Export PDF
            </a>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="bg-surface-0 rounded-[var(--radius-sm)] border border-border p-6 space-y-4 animate-pulse">
          <div className="h-6 w-44 bg-surface-2 rounded" />
          <div className="h-32 bg-surface-1 rounded" />
        </div>
      ) : error ? (
        <div className="bg-sev-critical-bg border border-sev-critical/20 rounded-[var(--radius-sm)] p-4 space-y-2">
          <p className="text-xs font-semibold text-sev-critical">Failed to compile report preview</p>
          <p className="text-xs text-sev-critical/90">{error}</p>
          <button
            onClick={() => loadReport(selectedCapId)}
            className="text-xs font-medium text-sev-critical underline"
          >
            Retry
          </button>
        </div>
      ) : summary && (
        <div className="bg-surface-0 rounded-[var(--radius-sm)] border border-border overflow-hidden">
          <div className="px-6 py-4 border-b border-border bg-surface-1 flex items-center justify-between">
            <div>
              <h2 className="text-[16px] font-sans font-semibold text-foreground">Executive posture summary</h2>
              <p className="text-xs font-mono text-muted">
                Audit target: {selectedCap?.filename ?? selectedCapId}
              </p>
            </div>
            {selectedCap && (
              <div className="flex items-center gap-4 text-xs text-muted">
                <span className="tabular-nums">
                  {new Date(selectedCap.created_at).toLocaleDateString()}
                </span>
                <span className="font-mono tabular-nums">
                  {selectedCap.packet_count.toLocaleString()} packets
                </span>
              </div>
            )}
          </div>

          <div className="p-6 space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
              <div className="p-4 bg-surface-1 rounded-[var(--radius-sm)] border border-border flex flex-col items-center">
                <ScoreGauge score={summary.posture.score} grade={summary.posture.grade} />
              </div>

              <div className="md:col-span-2 space-y-3">
                <h3 className="text-xs font-medium text-muted">
                  Key posture penalties & credits
                </h3>
                <div className="space-y-2">
                  {summary.posture.factors.map((f) => (
                    <div key={f.name} className="flex items-center justify-between text-xs bg-surface-1 px-3 py-2 rounded-[3px] border border-border">
                      <div>
                        <span className="font-medium text-foreground">{f.name}</span>
                        <span className="text-muted block text-[11px]">{f.detail}</span>
                      </div>
                      <span className={`font-mono font-semibold tabular-nums ${f.impact < 0 ? "text-sev-critical" : "text-foreground"}`}>
                        {f.impact > 0 ? `+${f.impact}` : f.impact}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-4 pt-4 border-t border-border">
              <div className="p-3 bg-surface-1 rounded-[3px] border border-border">
                <span className="text-[11px] font-medium text-muted block mb-2">Severity breakdown</span>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between"><span>Critical:</span><span className="font-mono font-semibold text-sev-critical tabular-nums">{summary.severity_counts.critical}</span></div>
                  <div className="flex justify-between"><span>High:</span><span className="font-mono font-semibold text-sev-high tabular-nums">{summary.severity_counts.high}</span></div>
                  <div className="flex justify-between"><span>Medium:</span><span className="font-mono font-semibold text-sev-medium tabular-nums">{summary.severity_counts.medium}</span></div>
                  <div className="flex justify-between"><span>Low / Info:</span><span className="font-mono tabular-nums">{summary.severity_counts.low + summary.severity_counts.info}</span></div>
                </div>
              </div>

              <div className="p-3 bg-surface-1 rounded-[3px] border border-border">
                <span className="text-[11px] font-medium text-muted block mb-2">Transport security</span>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between"><span>Implicit TLS:</span><span className="font-mono text-foreground font-semibold tabular-nums">{summary.transport_counts.implicit_tls}</span></div>
                  <div className="flex justify-between"><span>STARTTLS:</span><span className="font-mono text-foreground font-semibold tabular-nums">{summary.transport_counts.starttls}</span></div>
                  <div className="flex justify-between"><span>Plaintext:</span><span className="font-mono text-sev-critical font-semibold tabular-nums">{summary.transport_counts.plaintext}</span></div>
                </div>
              </div>

              <div className="p-3 bg-surface-1 rounded-[3px] border border-border">
                <span className="text-[11px] font-medium text-muted block mb-2">Protocol distribution</span>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between"><span>SMTP:</span><span className="font-mono tabular-nums">{summary.protocol_counts.smtp}</span></div>
                  <div className="flex justify-between"><span>IMAP:</span><span className="font-mono tabular-nums">{summary.protocol_counts.imap}</span></div>
                  <div className="flex justify-between"><span>POP3:</span><span className="font-mono tabular-nums">{summary.protocol_counts.pop3}</span></div>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-border">
              <h3 className="text-xs font-medium text-muted mb-3">
                Remediation priorities ({findings.length} findings)
              </h3>
              <div className="space-y-2">
                {findings.slice(0, 5).map((f) => (
                  <div key={f.id} className="flex items-center justify-between p-3 bg-surface-1 rounded-[3px] border border-border text-xs">
                    <div className="flex items-center gap-3">
                      <SeverityBadge severity={f.severity} />
                      <div>
                        <span className="font-medium text-foreground">{f.title}</span>
                        <span className="text-muted block text-[11px] mt-0.5">{f.remediation.summary}</span>
                      </div>
                    </div>
                    <span className="font-mono font-semibold text-sev-critical shrink-0 tabular-nums">
                      {f.score_impact}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
