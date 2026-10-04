"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import type { Capture, Summary, Finding, CustodyEvent } from "@/types";
import {
  getCaptures,
  getSummary,
  getFindings,
  getCustody,
  checkFactorArithmetic,
  formatBytes,
} from "@/data";
import { SeverityBadge } from "@/components/severity";
import { EvidenceTag } from "@/components/evidence-tag";
import {
  Copy,
  Check,
  WarningCircle,
  CheckCircle,
  FileCode,
  ShieldCheck,
  ShieldWarning,
  LockKeyOpen,
  ArrowRight,
  Fingerprint,
} from "@phosphor-icons/react";

export default function OverviewPage() {
  return (
    <Suspense fallback={<OverviewSkeleton />}>
      <OverviewContent />
    </Suspense>
  );
}

function OverviewSkeleton() {
  return (
    <div className="w-full px-4 2xl:px-6 py-3 space-y-3 animate-pulse select-none">
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-3 h-[calc(100vh-112px)]">
        <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-3" />
        <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-3" />
        <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-3" />
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
  const [custody, setCustody] = useState<CustodyEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [copiedSha, setCopiedSha] = useState(false);
  const [copiedFilterId, setCopiedFilterId] = useState<string | null>(null);

  function copy(text: string, cb: () => void) {
    navigator.clipboard.writeText(text);
    cb();
  }

  useEffect(() => {
    let active = true;
    Promise.all([
      getCaptures(),
      getSummary(captureId),
      getFindings(captureId),
      getCustody(captureId),
    ])
      .then(([c, s, f, cu]) => {
        if (!active) return;
        setCaps(c);
        setSummary(s);
        setFindings(f);
        setCustody(cu);
        setLoading(false);
      })
      .catch((e: unknown) => {
        if (!active) return;
        setError(e instanceof Error ? e.message : "Failed to load overview");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [captureId]);

  if (loading) return <OverviewSkeleton />;

  if (error || !summary) {
    return (
      <div className="w-full px-4 2xl:px-6 py-4">
        <div className="bg-sev-critical-bg border border-border rounded-[var(--radius-md)] p-4 space-y-2">
          <p className="text-[13px] font-semibold text-sev-critical">Unable to load posture overview</p>
          <p className="text-[12px] text-muted">{error ?? "Capture data unavailable"}</p>
        </div>
      </div>
    );
  }

  const currentCap = caps.find((c) => c.id === captureId) ?? caps[0];
  const score = summary.posture.score;
  const grade = summary.posture.grade;
  const arithmetic = checkFactorArithmetic(summary);
  const emailSessions =
    summary.protocol_counts.smtp +
    summary.protocol_counts.imap +
    summary.protocol_counts.pop3;
  const hasNoTraffic = score == null || grade == null || emailSessions === 0;
  const isHealthy = !hasNoTraffic && score >= 80;
  const isCritical = !hasNoTraffic && score < 60;
  const compliant = isHealthy;

  const totalProto = emailSessions + summary.protocol_counts.unknown || 1;

  const totalTrans =
    summary.transport_counts.implicit_tls +
    summary.transport_counts.starttls +
    summary.transport_counts.plaintext || 1;

  const cleartextCount = findings
    .filter(
      (f) =>
        f.rule_id === "TR-001" ||
        f.title.toLowerCase().includes("cleartext") ||
        f.description.toLowerCase().includes("cleartext")
    )
    .reduce((acc, f) => acc + (f.context?.sessions_affected ?? 1), 0);

  const downgradeCount = findings
    .filter(
      (f) =>
        f.rule_id === "STARTTLS-001" ||
        f.title.toLowerCase().includes("downgrade") ||
        f.title.toLowerCase().includes("strip")
    )
    .reduce((acc, f) => acc + (f.context?.sessions_affected ?? 1), 0);

  const noPfsCount = findings
    .filter(
      (f) =>
        f.rule_id === "CIPHER-001" ||
        f.title.toLowerCase().includes("forward secrecy") ||
        f.title.toLowerCase().includes("pfs")
    )
    .reduce((acc, f) => acc + (f.context?.sessions_affected ?? 1), 0);

  const verdictSummary = hasNoTraffic
    ? "No SMTP, IMAP, or POP3 email sessions were detected in this packet capture. SecureMailScope specifically evaluates email cryptographic protocols (ports 25, 465, 587, 110, 995, 143, and 993)."
    : score < 60
    ? "Critical posture degradation observed. Plaintext authentication was accepted before TLS negotiation, and legacy cipher suites lacking forward secrecy were negotiated across submission endpoints."
    : score < 80
    ? "Posture is degraded. Several email sessions rely on legacy transport parameters or unhardened STARTTLS configurations."
    : "All evaluated sessions satisfied RFC 8314 standards. Encrypted transports and modern TLS 1.3 cipher suites were enforced without cleartext authentication or downgrade vulnerabilities.";

  const prioritizedFixes = [...findings]
    .sort((a, b) => {
      const order: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      return (order[b.severity] ?? 0) - (order[a.severity] ?? 0);
    })
    .slice(0, 6);

  return (
    <div className="w-full px-4 2xl:px-6 py-3 select-none text-[13px] h-[calc(100vh-88px)] flex flex-col overflow-hidden">
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-3 flex-1 min-h-0">
        {/* ================= LANE 1: VERDICT ================= */}
        <section
          className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 xcor-shadow flex flex-col min-h-0 overflow-hidden"
          aria-label="Lane 1: Verdict"
        >
          <div className="flex items-center justify-between pb-2 border-b border-border shrink-0">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-accent" />
              <h2 className="text-[14px] font-semibold text-foreground">Verdict</h2>
            </div>
            <span className="text-[11px] text-muted font-medium">Capture posture score</span>
          </div>

          <div className="flex-1 overflow-y-auto pr-1 pt-2 space-y-3">
            {/* Score Block */}
            <div className="bg-surface-1 rounded-[var(--radius-sm)] p-3 border border-border space-y-2">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-baseline gap-2">
                  <span className="text-[44px] leading-none font-bold font-mono tabular-nums text-foreground">
                    {hasNoTraffic ? "—" : score ?? "—"}
                  </span>
                  <span className="text-muted text-[13px] font-mono">/ 100</span>
                </div>

                <div className="flex flex-col items-end gap-1">
                  <span
                    className={`font-mono text-[12px] font-bold px-2 py-0.5 rounded-[var(--radius-xs)] ${
                      hasNoTraffic
                        ? "bg-surface-2 text-muted"
                        : isHealthy
                        ? "bg-sev-pass text-white"
                        : isCritical
                        ? "bg-sev-critical text-white"
                        : "bg-sev-medium text-white"
                    }`}
                  >
                    {hasNoTraffic ? "Grade N/A" : `Grade ${grade ?? "—"}`}
                  </span>
                  <span
                    className={`text-[11px] font-semibold ${
                      hasNoTraffic
                        ? "text-muted"
                        : compliant
                        ? "text-sev-pass"
                        : "text-sev-critical"
                    }`}
                  >
                    {hasNoTraffic ? "No email traffic" : compliant ? "Compliant" : "Non-compliant"}
                  </span>
                </div>
              </div>

              <div className="pt-2 border-t border-border/80">
                <p className="text-[12px] text-muted text-prose-cap leading-relaxed">
                  {verdictSummary}
                </p>
              </div>
            </div>

            {/* Factor Deductions */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-[12px] font-semibold text-foreground">Factor deductions</h3>
                <span className="text-[11px] font-mono text-muted">{summary.posture.factors.length} factors</span>
              </div>

              {hasNoTraffic && summary.limitations && summary.limitations.length > 0 ? (
                <div className="p-2.5 bg-surface-1 border border-border rounded-[var(--radius-xs)] text-[12px] text-muted space-y-1">
                  {summary.limitations.map((lim, idx) => (
                    <div key={idx} className="flex items-start gap-1.5">
                      <WarningCircle size={14} className="text-sev-medium shrink-0 mt-0.5" />
                      <span>{lim}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="space-y-1.5">
                  {summary.posture.factors.map((f) => (
                    <div
                      key={f.name}
                      className="p-2 bg-surface-1/60 border border-border rounded-[var(--radius-xs)] flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0">
                        <span className="text-[12px] font-medium text-foreground block truncate">
                          {f.name}
                        </span>
                        <span className="text-[11px] text-muted block truncate">
                          {f.detail}
                        </span>
                      </div>
                      <span
                        className={`font-mono text-[11px] font-bold px-1.5 py-0.5 rounded-[var(--radius-xs)] shrink-0 tabular-nums ${
                          f.impact < 0
                            ? "bg-sev-critical-bg text-sev-critical"
                            : "bg-sev-pass-bg text-sev-pass"
                        }`}
                      >
                        {f.impact > 0 ? "+" : ""}
                        {f.impact} pts
                      </span>
                    </div>
                  ))}
                </div>
              )}

              <div className="p-2 bg-surface-1 border border-border rounded-[var(--radius-xs)] text-[11px] font-mono text-muted flex items-center justify-between">
                <span>Arithmetic verification:</span>
                <span className="text-foreground font-medium">
                  {hasNoTraffic ? "N/A (0 email sessions evaluated)" : arithmetic.arithmeticString}
                </span>
              </div>
            </div>

            {/* Custody Verification */}
            <div className="space-y-2 pt-2 border-t border-border">
              <div className="flex items-center justify-between">
                <h3 className="text-[12px] font-semibold text-foreground flex items-center gap-1.5">
                  <Fingerprint size={14} weight="bold" className="text-muted" />
                  <span>Custody verification</span>
                </h3>
              </div>

              <div className="bg-surface-1/60 border border-border rounded-[var(--radius-xs)] p-2 space-y-2 text-[11px]">
                <div>
                  <span className="text-muted block text-[10px] font-medium">SHA-256 custody hash:</span>
                  <div className="flex items-center justify-between gap-1 mt-0.5">
                    <code className="text-[11px] text-foreground font-mono truncate select-all">
                      {currentCap?.sha256}
                    </code>
                    <button
                      onClick={() =>
                        copy(currentCap?.sha256 ?? "", () => {
                          setCopiedSha(true);
                          setTimeout(() => setCopiedSha(false), 2000);
                        })
                      }
                      className="p-1 text-muted hover:text-foreground shrink-0 cursor-pointer"
                      title="Copy full SHA-256 hash"
                    >
                      {copiedSha ? <Check size={12} weight="bold" className="text-sev-pass" /> : <Copy size={12} weight="bold" />}
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-2 pt-1 border-t border-border font-mono">
                  <div>
                    <span className="text-muted block text-[10px] font-sans">Raw file size:</span>
                    <span className="text-foreground font-medium tabular-nums">
                      {formatBytes(currentCap?.size_bytes)}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted block text-[10px] font-sans">Packet count:</span>
                    <span className="text-foreground font-medium tabular-nums">
                      {currentCap?.packet_count?.toLocaleString()}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted block text-[10px] font-sans">Trace duration:</span>
                    <span className="text-foreground font-medium tabular-nums">
                      {currentCap?.duration_s != null ? `${currentCap.duration_s}s` : "—"}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ================= LANE 2: EVIDENCE ================= */}
        <section
          className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 xcor-shadow flex flex-col min-h-0 overflow-hidden"
          aria-label="Lane 2: Evidence"
        >
          <div className="flex items-center justify-between pb-2 border-b border-border shrink-0">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-accent" />
              <h2 className="text-[14px] font-semibold text-foreground">Evidence</h2>
            </div>
            <span className="text-[11px] text-muted font-medium">Protocol & transport observation</span>
          </div>

          <div className="flex-1 overflow-y-auto pr-1 pt-2 space-y-3">
            {/* Dynamic Impact Counters (3 required) */}
            <div className="space-y-1.5">
              <h3 className="text-[12px] font-semibold text-foreground">Impact observations</h3>

              <div className="space-y-1.5">
                {/* Cleartext Auth */}
                {cleartextCount > 0 ? (
                  <Link
                    href={`/sessions?capture=${captureId}&filter=cleartext`}
                    className="p-2 bg-sev-critical-bg/50 border border-sev-critical/30 rounded-[var(--radius-xs)] flex items-center justify-between gap-2 hover:bg-sev-critical-bg transition-colors"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <LockKeyOpen size={15} weight="bold" className="text-sev-critical shrink-0" />
                      <span className="text-[12px] font-medium text-sev-critical">
                        {cleartextCount} sessions exposed credentials in cleartext
                      </span>
                    </div>
                    <ArrowRight size={12} weight="bold" className="text-sev-critical shrink-0" />
                  </Link>
                ) : (
                  <div className="p-2 bg-surface-1 border border-border rounded-[var(--radius-xs)] flex items-center gap-2">
                    <CheckCircle size={15} weight="bold" className="text-sev-pass shrink-0" />
                    <span className="text-[12px] font-medium text-foreground">
                      0 sessions exposed cleartext credentials
                    </span>
                  </div>
                )}

                {/* STARTTLS Downgrade */}
                {downgradeCount > 0 ? (
                  <Link
                    href={`/sessions?capture=${captureId}&filter=starttls_downgrade`}
                    className="p-2 bg-sev-high-bg/50 border border-sev-high/30 rounded-[var(--radius-xs)] flex items-center justify-between gap-2 hover:bg-sev-high-bg transition-colors"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <WarningCircle size={15} weight="bold" className="text-sev-high shrink-0" />
                      <span className="text-[12px] font-medium text-sev-high">
                        {downgradeCount} sessions had STARTTLS stripped or failed
                      </span>
                    </div>
                    <ArrowRight size={12} weight="bold" className="text-sev-high shrink-0" />
                  </Link>
                ) : (
                  <div className="p-2 bg-surface-1 border border-border rounded-[var(--radius-xs)] flex items-center gap-2">
                    <CheckCircle size={15} weight="bold" className="text-sev-pass shrink-0" />
                    <span className="text-[12px] font-medium text-foreground">
                      0 sessions had STARTTLS stripped or failed
                    </span>
                  </div>
                )}

                {/* Forward Secrecy Missing */}
                {noPfsCount > 0 ? (
                  <Link
                    href={`/sessions?capture=${captureId}&filter=no_pfs`}
                    className="p-2 bg-sev-medium-bg/50 border border-sev-medium/30 rounded-[var(--radius-xs)] flex items-center justify-between gap-2 hover:bg-sev-medium-bg transition-colors"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <ShieldWarning size={15} weight="bold" className="text-sev-medium shrink-0" />
                      <span className="text-[12px] font-medium text-sev-medium">
                        {noPfsCount} sessions lack forward secrecy (RSA key exchange)
                      </span>
                    </div>
                    <ArrowRight size={12} weight="bold" className="text-sev-medium shrink-0" />
                  </Link>
                ) : (
                  <div className="p-2 bg-surface-1 border border-border rounded-[var(--radius-xs)] flex items-center gap-2">
                    <CheckCircle size={15} weight="bold" className="text-sev-pass shrink-0" />
                    <span className="text-[12px] font-medium text-foreground">
                      0 sessions lack forward secrecy
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Protocol Distribution */}
            <div className="space-y-1.5 pt-2 border-t border-border">
              <div className="flex items-center justify-between text-[12px]">
                <h3 className="font-semibold text-foreground">Protocol distribution</h3>
                <span className="font-mono text-muted text-[11px] tabular-nums">
                  {totalProto} sessions
                </span>
              </div>

              <div className="h-2.5 w-full bg-surface-1 rounded-full flex overflow-hidden">
                <div
                  style={{ width: `${(summary.protocol_counts.smtp / totalProto) * 100}%` }}
                  className="bg-sky-500 h-full"
                  title={`SMTP: ${summary.protocol_counts.smtp}`}
                />
                <div
                  style={{ width: `${(summary.protocol_counts.imap / totalProto) * 100}%` }}
                  className="bg-accent h-full"
                  title={`IMAP: ${summary.protocol_counts.imap}`}
                />
                <div
                  style={{ width: `${(summary.protocol_counts.pop3 / totalProto) * 100}%` }}
                  className="bg-purple-500 h-full"
                  title={`POP3: ${summary.protocol_counts.pop3}`}
                />
              </div>

              <div className="grid grid-cols-3 gap-2 pt-1 font-mono text-[11px]">
                <div className="p-1.5 bg-surface-1 rounded-[var(--radius-xs)] flex items-center justify-between">
                  <span className="text-muted font-sans">SMTP</span>
                  <span className="text-foreground font-semibold tabular-nums">{summary.protocol_counts.smtp}</span>
                </div>
                <div className="p-1.5 bg-surface-1 rounded-[var(--radius-xs)] flex items-center justify-between">
                  <span className="text-muted font-sans">IMAP</span>
                  <span className="text-foreground font-semibold tabular-nums">{summary.protocol_counts.imap}</span>
                </div>
                <div className="p-1.5 bg-surface-1 rounded-[var(--radius-xs)] flex items-center justify-between">
                  <span className="text-muted font-sans">POP3</span>
                  <span className="text-foreground font-semibold tabular-nums">{summary.protocol_counts.pop3}</span>
                </div>
              </div>
            </div>

            {/* Transport Encapsulation */}
            <div className="space-y-1.5 pt-2 border-t border-border">
              <div className="flex items-center justify-between text-[12px]">
                <h3 className="font-semibold text-foreground">Transport encapsulation</h3>
                <span className="font-mono text-muted text-[11px] tabular-nums">
                  {totalTrans} evaluated
                </span>
              </div>

              <div className="h-2.5 w-full bg-surface-1 rounded-full flex overflow-hidden">
                <div
                  style={{ width: `${(summary.transport_counts.implicit_tls / totalTrans) * 100}%` }}
                  className="bg-sev-pass h-full"
                  title={`Implicit TLS: ${summary.transport_counts.implicit_tls}`}
                />
                <div
                  style={{ width: `${(summary.transport_counts.starttls / totalTrans) * 100}%` }}
                  className="bg-accent h-full"
                  title={`STARTTLS: ${summary.transport_counts.starttls}`}
                />
                <div
                  style={{ width: `${(summary.transport_counts.plaintext / totalTrans) * 100}%` }}
                  className="bg-sev-critical h-full"
                  title={`Plaintext: ${summary.transport_counts.plaintext}`}
                />
              </div>

              <div className="grid grid-cols-3 gap-2 pt-1 font-mono text-[11px]">
                <div className="p-1.5 bg-surface-1 rounded-[var(--radius-xs)] flex items-center justify-between">
                  <span className="text-muted font-sans">Implicit</span>
                  <span className="text-foreground font-semibold tabular-nums">{summary.transport_counts.implicit_tls}</span>
                </div>
                <div className="p-1.5 bg-surface-1 rounded-[var(--radius-xs)] flex items-center justify-between">
                  <span className="text-muted font-sans">STARTTLS</span>
                  <span className="text-foreground font-semibold tabular-nums">{summary.transport_counts.starttls}</span>
                </div>
                <div className="p-1.5 bg-surface-1 rounded-[var(--radius-xs)] flex items-center justify-between">
                  <span className="text-muted font-sans">Plaintext</span>
                  <span className={`font-semibold tabular-nums ${summary.transport_counts.plaintext > 0 ? "text-sev-critical" : "text-foreground"}`}>
                    {summary.transport_counts.plaintext}
                  </span>
                </div>
              </div>
            </div>

            {/* Visibility Checklist */}
            <div className="space-y-1.5 pt-2 border-t border-border">
              <h3 className="text-[12px] font-semibold text-foreground">Forensic visibility checklist</h3>

              <div className="space-y-1.5 text-[12px]">
                <div className="p-2 bg-surface-1 rounded-[var(--radius-xs)] flex items-center justify-between">
                  <span className="text-muted">Handshake completion</span>
                  <span className="font-mono text-foreground font-medium tabular-nums">
                    {summary.visibility?.handshake_complete ?? 0} complete
                  </span>
                </div>

                <div className="p-2 bg-surface-1 rounded-[var(--radius-xs)] flex items-center justify-between">
                  <span className="text-muted">Certificate observation</span>
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-foreground font-medium tabular-nums">
                      {summary.visibility?.certificate_observable ?? 0} seen
                    </span>
                    {(summary.visibility?.certificate_hidden_tls13 ?? 0) > 0 && (
                      <EvidenceTag variant="yellow">Not observable</EvidenceTag>
                    )}
                  </div>
                </div>

                <div className="p-2 bg-surface-1 rounded-[var(--radius-xs)] flex items-center justify-between">
                  <span className="text-muted">Message layer payload</span>
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-foreground font-medium tabular-nums">
                      {summary.visibility?.message_layer_observable ?? 0} plaintext
                    </span>
                    {(summary.visibility?.message_layer_observable ?? 0) === 0 && (
                      <EvidenceTag variant="yellow">Not observable</EvidenceTag>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ================= LANE 3: FIX ================= */}
        <section
          className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 xcor-shadow flex flex-col min-h-0 overflow-hidden"
          aria-label="Lane 3: Fix"
        >
          <div className="flex items-center justify-between pb-2 border-b border-border shrink-0">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-accent" />
              <h2 className="text-[14px] font-semibold text-foreground">Fix</h2>
            </div>
            <span className="text-[11px] text-muted font-medium">Prioritized mitigations</span>
          </div>

          <div className="flex-1 overflow-y-auto pr-1 pt-2 space-y-2.5">
            {hasNoTraffic ? (
              <div className="p-4 bg-surface-1 border border-border rounded-[var(--radius-sm)] text-center space-y-2">
                <FileCode size={28} weight="bold" className="text-muted mx-auto" />
                <h3 className="text-[13px] font-semibold text-foreground">No email sessions to remediate</h3>
                <p className="text-[12px] text-muted text-prose-cap mx-auto">
                  This packet capture contains no SMTP, IMAP, or POP3 sessions. Mitigations are only generated when email security vulnerabilities are detected.
                </p>
                <div className="inline-block px-2 py-0.5 bg-surface-2 text-muted font-mono text-[11px] font-bold rounded-[var(--radius-xs)]">
                  Remediations N/A
                </div>
              </div>
            ) : prioritizedFixes.length === 0 ? (
              <div className="p-4 bg-surface-1 border border-border rounded-[var(--radius-sm)] text-center space-y-2">
                <ShieldCheck size={28} weight="bold" className="text-sev-pass mx-auto" />
                <h3 className="text-[13px] font-semibold text-foreground">No active remediations needed</h3>
                <p className="text-[12px] text-muted text-prose-cap mx-auto">
                  All traffic complies with RFC 8314 standards. Encrypted transports and modern cipher suites are actively enforced.
                </p>
                <div className="inline-block px-2 py-0.5 bg-sev-pass text-white font-mono text-[11px] font-bold rounded-[var(--radius-xs)]">
                  +0 pts posture recovery (100/100 A)
                </div>
              </div>
            ) : (
              prioritizedFixes.map((f) => {
                const recoveryPts =
                  f.severity === "critical"
                    ? 25
                    : f.severity === "high"
                    ? 15
                    : f.severity === "medium"
                    ? 10
                    : 5;

                return (
                  <div
                    key={f.id}
                    className="p-2.5 bg-surface-1/70 border border-border hover:border-accent/40 rounded-[var(--radius-sm)] space-y-2 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-0.5 min-w-0">
                        <div className="flex items-center gap-1.5">
                          <SeverityBadge severity={f.severity} />
                          <span className="font-mono text-[11px] text-muted">{f.rule_id}</span>
                        </div>
                        <h3 className="text-[12px] font-semibold text-foreground leading-snug">
                          {f.title}
                        </h3>
                      </div>

                      <span className="bg-sev-pass-bg text-sev-pass font-mono text-[10px] font-bold px-1.5 py-0.5 rounded-[var(--radius-xs)] shrink-0 whitespace-nowrap">
                        +{recoveryPts} pts recovery
                      </span>
                    </div>

                    <div className="text-[11px] text-muted font-sans leading-tight">
                      <strong className="text-foreground">Implementation: </strong>
                      {typeof f.remediation === "string"
                        ? f.remediation
                        : f.remediation?.summary ?? "Apply recommended RFC 8314 TLS hardening."}
                    </div>

                    <div className="space-y-1 pt-1.5 border-t border-border/70">
                      <div className="flex items-center justify-between text-[10px] font-mono text-muted">
                        <span>Wireshark filter</span>
                        <button
                          onClick={() =>
                            copy(f.wireshark_filter, () => {
                              setCopiedFilterId(f.id);
                              setTimeout(() => setCopiedFilterId(null), 2000);
                            })
                          }
                          className="hover:text-foreground inline-flex items-center gap-1 cursor-pointer font-sans"
                        >
                          {copiedFilterId === f.id ? (
                            <>
                              <Check size={10} weight="bold" className="text-sev-pass" />
                              <span className="text-sev-pass">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy size={10} weight="bold" />
                              <span>Copy filter</span>
                            </>
                          )}
                        </button>
                      </div>

                      <code className="block bg-surface-0 border border-border px-2 py-1 rounded-[var(--radius-xs)] font-mono text-[11px] text-foreground truncate select-all">
                        {f.wireshark_filter}
                      </code>
                    </div>

                    <div className="flex items-center justify-between pt-1 text-[11px]">
                      <span className="text-muted font-mono">
                        {f.context?.sessions_affected ?? 1} session(s) affected
                      </span>
                      <Link
                        href={`/sessions?capture=${captureId}&finding=${f.rule_id}`}
                        className="text-accent hover:underline inline-flex items-center gap-1 font-medium"
                      >
                        <span>View affected sessions</span>
                        <ArrowRight size={10} weight="bold" />
                      </Link>
                    </div>
                  </div>
                );
              })
            )}

            <div className="pt-2 border-t border-border">
              <Link
                href={`/findings?capture=${captureId}`}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 bg-surface-1 hover:bg-surface-2 border border-border rounded-[var(--radius-xs)] text-[12px] font-medium text-foreground transition-colors"
              >
                <span>View all findings</span>
                <ArrowRight size={12} weight="bold" />
              </Link>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
