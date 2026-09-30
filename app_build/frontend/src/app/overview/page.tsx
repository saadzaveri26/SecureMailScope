"use client";

import { useState, useEffect, useCallback, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import type { Capture, Summary, Finding } from "@/types";
import { getCaptures, getSummary, getFindings } from "@/data";
import { SeverityBadge } from "@/components/severity";
import { PostureTrend } from "@/components/posture-trend";
import Link from "next/link";

export default function OverviewPage() {
  return (
    <Suspense fallback={<OverviewSkeleton />}>
      <OverviewContent />
    </Suspense>
  );
}

function OverviewSkeleton() {
  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8 space-y-6 animate-pulse">
      <div className="h-6 w-32 bg-surface-2 rounded" />
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-surface-0 rounded-lg border border-border-subtle p-6 space-y-4">
          <div className="h-12 w-24 bg-surface-2 rounded" />
          <div className="space-y-3 pt-4 border-t border-border-subtle">
            <div className="h-4 w-full bg-surface-2 rounded" />
            <div className="h-4 w-full bg-surface-2 rounded" />
            <div className="h-4 w-full bg-surface-2 rounded" />
          </div>
        </div>
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-surface-0 rounded-lg border border-border-subtle p-5 space-y-4">
            <div className="h-4 w-32 bg-surface-2 rounded" />
            <div className="h-3 w-full bg-surface-2 rounded" />
            <div className="h-3 w-full bg-surface-2 rounded" />
          </div>
          <div className="bg-surface-0 rounded-lg border border-border-subtle p-5 space-y-3">
            <div className="h-4 w-28 bg-surface-2 rounded" />
            <div className="h-8 w-full bg-surface-2 rounded" />
            <div className="h-8 w-full bg-surface-2 rounded" />
          </div>
        </div>
      </div>
    </div>
  );
}

function OverviewContent() {
  const params = useSearchParams();
  const captureId = params.get("capture") ?? "cap-001";

  const [caps, setCaps] = useState<Capture[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [c, s, f] = await Promise.all([
        getCaptures(),
        getSummary(captureId),
        getFindings(captureId),
      ]);
      setCaps(c);
      setSummary(s);
      setFindings(f);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load overview");
    } finally {
      setLoading(false);
    }
  }, [captureId]);

  useEffect(() => {
    let active = true;
    Promise.all([
      getCaptures(),
      getSummary(captureId),
      getFindings(captureId),
    ])
      .then(([c, s, f]) => {
        if (active) {
          setCaps(c);
          setSummary(s);
          setFindings(f);
          setLoading(false);
        }
      })
      .catch((e: unknown) => {
        if (active) {
          setError(e instanceof Error ? e.message : "Failed to load overview");
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [captureId]);

  if (loading) {
    return <OverviewSkeleton />;
  }

  if (error) {
    return (
      <div className="max-w-[1400px] mx-auto px-4 py-8">
        <div className="bg-sev-critical-bg border border-sev-critical/20 rounded-md p-4 space-y-2">
          <p className="text-xs font-semibold text-sev-critical">Unable to load posture overview</p>
          <p className="text-xs text-sev-critical/90">{error}</p>
          <button
            onClick={() => {
              setLoading(true);
              setError(null);
              load();
            }}
            className="text-xs font-medium text-sev-critical underline"
          >
            Retry analysis
          </button>
        </div>
      </div>
    );
  }

  if (!summary) return null;

  const topFindings = findings.slice(0, 5);
  const completeCaps = caps.filter((c) => c.status === "complete" && c.posture_score !== null);

  const totalSev =
    summary.severity_counts.critical +
    summary.severity_counts.high +
    summary.severity_counts.medium +
    summary.severity_counts.low +
    summary.severity_counts.info;

  const totalProto =
    summary.protocol_counts.smtp +
    summary.protocol_counts.imap +
    summary.protocol_counts.pop3 +
    summary.protocol_counts.unknown;

  const totalTrans =
    summary.transport_counts.implicit_tls +
    summary.transport_counts.starttls +
    summary.transport_counts.plaintext;

  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8 space-y-6">
      <h1 className="text-xl font-semibold">Overview</h1>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 bg-surface-0 rounded-lg border border-border-subtle p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-baseline gap-3 pb-4 border-b border-border-subtle">
              <span className="text-4xl font-bold font-mono text-foreground tabular-nums">
                {summary.posture.score}
              </span>
              <span className="text-lg font-bold font-mono text-sev-high">
                Grade {summary.posture.grade}
              </span>
              <span className="text-xs text-muted ml-auto">Posture score</span>
            </div>

            <div className="mt-5 space-y-3.5">
              <h3 className="text-xs font-medium text-muted">Score factors</h3>
              {summary.posture.factors.map((f) => (
                <div key={f.name} className="space-y-1">
                  <div className="flex items-start justify-between gap-2 text-xs">
                    <span className="font-medium text-foreground">{f.name}</span>
                    <span className={`font-mono font-semibold tabular-nums ${f.impact < 0 ? "text-sev-critical" : "text-foreground"}`}>
                      {f.impact > 0 ? "+" : ""}{f.impact}
                    </span>
                  </div>
                  <div className="h-1.5 w-full bg-surface-2 rounded-[3px] overflow-hidden">
                    <div
                      className="h-full bg-sev-critical rounded-[3px]"
                      style={{ width: `${Math.min(100, Math.abs(f.impact) * 4)}%` }}
                    />
                  </div>
                  <p className="text-[11px] text-muted truncate">{f.detail}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="lg:col-span-7 space-y-6">
          <div className="bg-surface-0 rounded-lg border border-border-subtle p-5 space-y-5">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium text-foreground">Severity distribution</span>
                <span className="text-muted font-mono tabular-nums">{totalSev} findings</span>
              </div>
              <div className="h-3 w-full bg-surface-2 rounded-[3px] overflow-hidden flex">
                {summary.severity_counts.critical > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.critical / totalSev) * 100}%` }}
                    className="bg-sev-critical h-full"
                    title={`Critical: ${summary.severity_counts.critical}`}
                  />
                )}
                {summary.severity_counts.high > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.high / totalSev) * 100}%` }}
                    className="bg-sev-high h-full"
                    title={`High: ${summary.severity_counts.high}`}
                  />
                )}
                {summary.severity_counts.medium > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.medium / totalSev) * 100}%` }}
                    className="bg-sev-medium h-full"
                    title={`Medium: ${summary.severity_counts.medium}`}
                  />
                )}
                {summary.severity_counts.low > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.low / totalSev) * 100}%` }}
                    className="bg-sev-low h-full"
                    title={`Low: ${summary.severity_counts.low}`}
                  />
                )}
                {summary.severity_counts.info > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.info / totalSev) * 100}%` }}
                    className="bg-sev-info h-full"
                    title={`Info: ${summary.severity_counts.info}`}
                  />
                )}
              </div>
              <div className="flex items-center gap-4 text-xs font-mono pt-1 text-muted">
                <span>Critical: <strong className="text-sev-critical tabular-nums">{summary.severity_counts.critical}</strong></span>
                <span>High: <strong className="text-sev-high tabular-nums">{summary.severity_counts.high}</strong></span>
                <span>Medium: <strong className="text-sev-medium tabular-nums">{summary.severity_counts.medium}</strong></span>
                <span>Low: <strong className="text-sev-low tabular-nums">{summary.severity_counts.low}</strong></span>
                <span>Info: <strong className="text-sev-info tabular-nums">{summary.severity_counts.info}</strong></span>
              </div>
            </div>

            <div className="space-y-2 pt-4 border-t border-border-subtle">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium text-foreground">Protocol distribution</span>
                <span className="text-muted font-mono tabular-nums">{totalProto} sessions</span>
              </div>
              <div className="h-3 w-full bg-surface-2 rounded-[3px] overflow-hidden flex">
                {summary.protocol_counts.smtp > 0 && (
                  <div
                    style={{ width: `${(summary.protocol_counts.smtp / totalProto) * 100}%` }}
                    className="bg-[#334155] h-full"
                    title={`SMTP: ${summary.protocol_counts.smtp}`}
                  />
                )}
                {summary.protocol_counts.imap > 0 && (
                  <div
                    style={{ width: `${(summary.protocol_counts.imap / totalProto) * 100}%` }}
                    className="bg-[#64748b] h-full"
                    title={`IMAP: ${summary.protocol_counts.imap}`}
                  />
                )}
                {summary.protocol_counts.pop3 > 0 && (
                  <div
                    style={{ width: `${(summary.protocol_counts.pop3 / totalProto) * 100}%` }}
                    className="bg-[#94a3b8] h-full"
                    title={`POP3: ${summary.protocol_counts.pop3}`}
                  />
                )}
              </div>
              <div className="flex items-center gap-4 text-xs font-mono pt-1 text-muted">
                <span>SMTP: <strong className="text-foreground tabular-nums">{summary.protocol_counts.smtp}</strong></span>
                <span>IMAP: <strong className="text-foreground tabular-nums">{summary.protocol_counts.imap}</strong></span>
                <span>POP3: <strong className="text-foreground tabular-nums">{summary.protocol_counts.pop3}</strong></span>
              </div>
            </div>

            <div className="space-y-2 pt-4 border-t border-border-subtle">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium text-foreground">Transport distribution</span>
                <span className="text-muted font-mono tabular-nums">{totalTrans} sessions</span>
              </div>
              <div className="h-3 w-full bg-surface-2 rounded-[3px] overflow-hidden flex">
                {summary.transport_counts.implicit_tls > 0 && (
                  <div
                    style={{ width: `${(summary.transport_counts.implicit_tls / totalTrans) * 100}%` }}
                    className="bg-[#475569] h-full"
                    title={`Implicit TLS: ${summary.transport_counts.implicit_tls}`}
                  />
                )}
                {summary.transport_counts.starttls > 0 && (
                  <div
                    style={{ width: `${(summary.transport_counts.starttls / totalTrans) * 100}%` }}
                    className="bg-sev-medium h-full"
                    title={`STARTTLS: ${summary.transport_counts.starttls}`}
                  />
                )}
                {summary.transport_counts.plaintext > 0 && (
                  <div
                    style={{ width: `${(summary.transport_counts.plaintext / totalTrans) * 100}%` }}
                    className="bg-sev-critical h-full"
                    title={`Plaintext: ${summary.transport_counts.plaintext}`}
                  />
                )}
              </div>
              <div className="flex items-center gap-4 text-xs font-mono pt-1 text-muted">
                <span>Implicit TLS: <strong className="text-foreground tabular-nums">{summary.transport_counts.implicit_tls}</strong></span>
                <span>STARTTLS: <strong className="text-sev-medium tabular-nums">{summary.transport_counts.starttls}</strong></span>
                <span>Plaintext: <strong className="text-sev-critical tabular-nums">{summary.transport_counts.plaintext}</strong></span>
              </div>
            </div>
          </div>

          {summary.limitations.length > 0 && (
            <div className="bg-not-observable-bg border border-border-subtle rounded-md px-4 py-3">
              <p className="text-xs font-medium text-foreground mb-1">Limitations</p>
              {summary.limitations.map((l, i) => (
                <p key={i} className="text-xs text-muted">{l}</p>
              ))}
            </div>
          )}

          <div className="bg-surface-0 rounded-lg border border-border-subtle p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-foreground">Top findings</h3>
              <Link href={`/findings?capture=${captureId}`} className="text-xs text-brand hover:underline">
                All findings
              </Link>
            </div>
            {topFindings.length === 0 ? (
              <div className="text-center py-6 text-muted">
                <p className="text-xs">No findings for this capture.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {topFindings.map((f) => (
                  <div key={f.id} className="flex items-start gap-3 py-2 border-b border-border-subtle last:border-0">
                    <SeverityBadge severity={f.severity} />
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium text-foreground">{f.title}</p>
                      <p className="text-xs text-muted mt-0.5 truncate">{f.description}</p>
                    </div>
                    <span className="text-xs text-muted font-mono shrink-0">
                      {f.evidence.server ? f.evidence.server : "capture-level"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {completeCaps.length > 1 && (
        <div className="bg-surface-0 rounded-lg border border-border-subtle p-5">
          <h3 className="text-sm font-medium text-foreground mb-4">Posture trend</h3>
          <PostureTrend captures={completeCaps} />
        </div>
      )}
    </div>
  );
}
