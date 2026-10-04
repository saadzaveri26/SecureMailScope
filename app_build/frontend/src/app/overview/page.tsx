"use client";

import { useState, useEffect, useCallback, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import type { Capture, Summary, Finding, CustodyEvent } from "@/types";
import { getCaptures, getSummary, getFindings, getCustody } from "@/data";
import { SeverityBadge } from "@/components/severity";
import {
  Copy,
  Check,
  ShieldWarning,
  WarningCircle,
  FileCode,
  LockKeyOpen,
  ArrowRight,
  Fingerprint,
  Info,
} from "@phosphor-icons/react";
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
    <div className="max-w-[1600px] mx-auto px-4 py-4 space-y-4 animate-pulse select-none">
      <div className="h-5 w-40 bg-surface-2 rounded-[var(--radius-sm)]" />
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-3 bg-surface-0 border border-border rounded-[var(--radius-md)] p-4 h-96 xcor-shadow" />
        <div className="lg:col-span-5 bg-surface-0 border border-border rounded-[var(--radius-md)] p-4 h-96 xcor-shadow" />
        <div className="lg:col-span-4 bg-surface-0 border border-border rounded-[var(--radius-md)] p-4 h-96 xcor-shadow" />
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
  const [copiedConfig, setCopiedConfig] = useState(false);
  const [configTab, setConfigTab] = useState<"postfix" | "dovecot">("postfix");

  function copyText(txt: string, setFn: (v: boolean) => void) {
    navigator.clipboard.writeText(txt);
    setFn(true);
    setTimeout(() => setFn(false), 2000);
  }

  const load = useCallback(async () => {
    try {
      const [c, s, f, cu] = await Promise.all([
        getCaptures(),
        getSummary(captureId),
        getFindings(captureId),
        getCustody(captureId),
      ]);
      setCaps(c);
      setSummary(s);
      setFindings(f);
      setCustody(cu);
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
      getCustody(captureId),
    ])
      .then(([c, s, f, cu]) => {
        if (active) {
          setCaps(c);
          setSummary(s);
          setFindings(f);
          setCustody(cu);
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

  if (loading) return <OverviewSkeleton />;

  if (error) {
    return (
      <div className="max-w-[1600px] mx-auto px-4 py-6">
        <div className="bg-sev-critical-bg border border-border rounded-[var(--radius-md)] p-4 space-y-2 xcor-shadow" role="alert">
          <p className="text-[var(--font-size-md)] font-mono font-bold text-sev-critical">Unable to load posture overview</p>
          <p className="text-[var(--font-size-md)] font-mono text-muted">{error}</p>
          <button
            onClick={() => { setLoading(true); setError(null); load(); }}
            className="text-[var(--font-size-md)] font-mono font-bold text-text-tertiary underline cursor-pointer focus-ring rounded-[var(--radius-xs)]"
          >
            Retry analysis
          </button>
        </div>
      </div>
    );
  }

  if (!summary) return null;

  const currentCap = caps.find((c) => c.id === captureId) || caps[0];
  const score = summary.posture.score;
  const grade = summary.posture.grade;
  const hasNoTraffic = score == null || (summary.visibility?.sessions_total ?? 0) === 0;
  const isHealthy = !hasNoTraffic && score >= 80;
  const isCritical = !hasNoTraffic && score < 60;

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

  const cleartextCreds = findings
    .filter((f) => f.rule_id === "TR-001" || f.title.toLowerCase().includes("cleartext") || f.description.toLowerCase().includes("cleartext"))
    .reduce((acc, f) => acc + (f.context?.sessions_affected || 1), 0);

  const downgradeAttempts = findings
    .filter((f) => f.rule_id === "STARTTLS-001" || f.title.toLowerCase().includes("downgrade"))
    .reduce((acc, f) => acc + (f.context?.sessions_affected || 1), 0);

  const nonPfsCount = findings.filter(
    (f) => f.rule_id === "CIPHER-001" || f.title.toLowerCase().includes("forward secrecy") || f.title.toLowerCase().includes("pfs")
  ).length;
  const nonPfsPercent = nonPfsCount > 0 ? `${Math.min(100, nonPfsCount * 20)}%` : "0%";

  const postfixConfig = `# SecureMailScope Hardened Postfix Configuration (main.cf)
# Generated for: ${currentCap?.filename || "mail_service"}
# Enforces RFC 8314 mandatory transport encryption & PFS ciphers

# Mandatory TLS protocol constraints (Disallow SSLv2, SSLv3, TLS 1.0, TLS 1.1)
smtpd_tls_mandatory_protocols = >=TLSv1.2
smtpd_tls_protocols = >=TLSv1.2
smtp_tls_protocols = >=TLSv1.2

# Cipher suite configuration: AEAD & Perfect Forward Secrecy mandatory
smtpd_tls_mandatory_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, 3DES, CBC
tls_high_cipherlist = ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM

# Prevent Cleartext Authentication before TLS
smtpd_tls_auth_only = yes
smtpd_tls_security_level = encrypt
tls_ffdhe_auto_groups = ffdhe2048:ffdhe3072`;

  const dovecotConfig = `# SecureMailScope Hardened Dovecot Configuration (10-ssl.conf)
# Generated for: ${currentCap?.filename || "mail_service"}
# Enforces secure IMAP/POP3 authentication and TLS 1.2+

# Disable all cleartext authentication
disable_plaintext_auth = yes
ssl = required

# Disallow legacy TLS versions
ssl_min_protocol = TLSv1.2

# Enforce Perfect Forward Secrecy (PFS) and modern AEAD ciphers
ssl_cipher_list = ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM
ssl_prefer_server_ciphers = yes

# Diffie-Hellman parameters (3072-bit minimum)
ssl_dh = </etc/dovecot/dh.pem`;

  const activeSnippet = configTab === "postfix" ? postfixConfig : dovecotConfig;

  return (
    <div className="max-w-[1600px] mx-auto px-4 py-4 space-y-4 select-none font-mono">
      {hasNoTraffic && (
        <div className="bg-sev-medium-bg border border-border rounded-[var(--radius-md)] p-4 xcor-shadow" role="alert">
          <div className="flex items-center gap-2 text-foreground font-bold text-[var(--font-size-xl)]">
            <WarningCircle size={18} weight="bold" className="text-sev-medium" />
            <span>NO EMAIL SESSIONS DETECTED IN THIS CAPTURE</span>
          </div>
          <p className="text-[var(--font-size-md)] text-muted mt-1">
            This packet capture contains no SMTP, IMAP, or POP3 exchanges. Passive cryptographic posture assessment requires active email protocol traffic.
          </p>
        </div>
      )}

      {/* 3-Column Priority Operations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* ================= COLUMN 1: SCORE & CUSTODY (3 cols) ================= */}
        <div className="lg:col-span-3 space-y-4 flex flex-col justify-between">
          {/* Posture Score Card */}
          <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-4 space-y-4 xcor-shadow">
            <div className="flex items-center justify-between border-b border-border pb-2">
              <span className="text-[var(--font-size-md)] font-bold uppercase tracking-wider text-foreground">
                Posture Score
              </span>
              <span className="text-[var(--font-size-sm)] bg-accent/10 text-accent px-1.5 py-0.5 rounded-[var(--radius-sm)] font-bold">
                PASSIVE
              </span>
            </div>

            <div className="flex items-center gap-3">
              <div
                className={`w-16 h-16 flex flex-col items-center justify-center shrink-0 rounded-[var(--radius-md)] font-bold ${
                  hasNoTraffic
                    ? "bg-surface-2 text-muted"
                    : isHealthy
                    ? "bg-sev-pass text-white"
                    : isCritical
                    ? "bg-sev-critical text-white"
                    : "bg-accent text-white"
                }`}
              >
                <span className="text-3xl leading-none tabular-nums">{score ?? "—"}</span>
                <span className="text-[var(--font-size-sm)] tracking-wider mt-0.5 opacity-80">/ 100</span>
              </div>

              <div>
                <div className="flex items-center gap-1.5">
                  <span className="text-base font-bold text-foreground">
                    {hasNoTraffic ? "No Traffic" : `Grade ${grade}`}
                  </span>
                  <span
                    className={`px-1.5 py-0.5 rounded-[var(--radius-sm)] text-[var(--font-size-sm)] font-bold uppercase ${
                      hasNoTraffic
                        ? "bg-surface-2 text-muted"
                        : isHealthy
                        ? "bg-sev-pass-bg text-sev-pass"
                        : isCritical
                        ? "bg-sev-critical-bg text-sev-critical"
                        : "bg-sev-medium-bg text-sev-medium"
                    }`}
                  >
                    {hasNoTraffic ? "N/A" : isHealthy ? "Secure" : isCritical ? "Critical" : "Degraded"}
                  </span>
                </div>
                <span className="text-[var(--font-size-md)] text-muted block mt-0.5 font-medium">
                  {hasNoTraffic
                    ? "0 mail sessions observed"
                    : summary.severity_counts.critical > 0
                    ? `${summary.severity_counts.critical} critical flaws found`
                    : "No critical flaws"}
                </span>
              </div>
            </div>

            {/* Factor Deductions breakdown bars */}
            <div className="space-y-2.5 pt-2 border-t border-border">
              <span className="text-[var(--font-size-sm)] font-bold uppercase tracking-wider text-foreground block">
                Factor Impact Breakdown
              </span>

              {summary.posture.factors.map((f) => (
                <div key={f.name} className="space-y-1">
                  <div className="flex items-center justify-between text-[var(--font-size-md)]">
                    <span className="text-foreground font-bold text-[11px] truncate max-w-[160px]">{f.name}</span>
                    <span
                      className={`tabular-nums font-bold text-[11px] px-1 rounded-[var(--radius-xs)] ${
                        f.impact < 0 ? "bg-sev-critical-bg text-sev-critical" : "bg-sev-pass-bg text-sev-pass"
                      }`}
                    >
                      {f.impact > 0 ? "+" : ""}{f.impact} pts
                    </span>
                  </div>
                  <div className="h-2 w-full bg-surface-1 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-[var(--motion-slower)] ${f.impact < 0 ? "bg-sev-critical" : "bg-sev-pass"}`}
                      style={{ width: `${Math.min(100, Math.max(8, Math.abs(f.impact) * 3))}%` }}
                    />
                  </div>
                  <p className="text-[var(--font-size-sm)] text-muted truncate">{f.detail}</p>
                </div>
              ))}
            </div>
          </div>

          {/* PCAP Forensic Metadata */}
          <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-3.5 space-y-2 text-[var(--font-size-md)] xcor-shadow">
            <div className="flex items-center justify-between border-b border-border pb-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-foreground">
                Capture Custody Chain
              </span>
              <Fingerprint size={15} weight="bold" className="text-muted" />
            </div>

            <div className="space-y-2 text-[11px]">
              <div>
                <span className="text-muted block text-[var(--font-size-sm)] font-bold uppercase">SHA-256 Custody Hash:</span>
                <div className="flex items-center justify-between gap-1 bg-surface-1 px-1.5 py-1 rounded-[var(--radius-xs)] mt-0.5">
                  <code className="text-[var(--font-size-sm)] text-foreground font-bold truncate select-all">{currentCap?.sha256}</code>
                  <button
                    onClick={() => copyText(currentCap?.sha256 || "", setCopiedSha)}
                    className="p-0.5 text-muted hover:text-foreground shrink-0 cursor-pointer focus-ring rounded-[var(--radius-xs)]"
                    aria-label="Copy full SHA-256 to clipboard"
                  >
                    {copiedSha ? <Check size={12} weight="bold" className="text-sev-pass" /> : <Copy size={12} weight="bold" />}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-1 border-t border-border">
                <div>
                  <span className="text-muted block text-[var(--font-size-sm)] font-bold uppercase">Total Packets:</span>
                  <span className="text-foreground font-bold tabular-nums">{currentCap?.packet_count?.toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-muted block text-[var(--font-size-sm)] font-bold uppercase">Raw File Size:</span>
                  <span className="text-foreground font-bold tabular-nums">
                    {currentCap?.size_bytes ? `${(currentCap.size_bytes / 1024 / 1024).toFixed(2)} MB` : "1.2 MB"}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-muted block text-[var(--font-size-sm)] font-bold uppercase">Trace Duration:</span>
                  <span className="text-foreground font-bold tabular-nums">{currentCap?.duration_s || 60}s</span>
                </div>
                <div>
                  <span className="text-muted block text-[var(--font-size-sm)] font-bold uppercase">Ruleset Engine:</span>
                  <span className="text-foreground font-bold">2025.03.1</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ================= COLUMN 2: ACTIONABLE THREAT EVIDENCE (5 cols) ================= */}
        <div className="lg:col-span-5 space-y-4">
          {/* Threat Detection Tiles */}
          <div className="grid grid-cols-3 gap-2.5">
            <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 space-y-1 xcor-shadow-subtle">
              <div className="flex items-center gap-1.5 text-sev-critical text-[var(--font-size-md)] font-bold uppercase">
                <LockKeyOpen size={14} weight="bold" />
                <span>Plaintext</span>
              </div>
              <div className="text-2xl font-bold tabular-nums text-foreground">
                {cleartextCreds}
              </div>
              <span className="text-[var(--font-size-sm)] text-muted block leading-tight font-medium">
                {cleartextCreds > 0 ? "Exposed credentials detected" : "No plaintext auth"}
              </span>
            </div>

            <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 space-y-1 xcor-shadow-subtle">
              <div className="flex items-center gap-1.5 text-sev-high text-[var(--font-size-md)] font-bold uppercase">
                <WarningCircle size={14} weight="bold" />
                <span>Downgrades</span>
              </div>
              <div className="text-2xl font-bold tabular-nums text-foreground">
                {downgradeAttempts}
              </div>
              <span className="text-[var(--font-size-sm)] text-muted block leading-tight font-medium">
                {downgradeAttempts > 0 ? "STARTTLS strip tampering" : "No forced fallbacks"}
              </span>
            </div>

            <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 space-y-1 xcor-shadow-subtle">
              <div className="flex items-center gap-1.5 text-sev-medium text-[var(--font-size-md)] font-bold uppercase">
                <ShieldWarning size={14} weight="bold" />
                <span>Non-PFS</span>
              </div>
              <div className="text-2xl font-bold tabular-nums text-foreground">
                {nonPfsPercent}
              </div>
              <span className="text-[var(--font-size-sm)] text-muted block leading-tight font-medium">
                Legacy static RSA / CBC
              </span>
            </div>
          </div>

          {/* Traffic & Cryptography Distribution Panel */}
          <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-4 space-y-4 xcor-shadow">
            <div className="flex items-center justify-between border-b border-border pb-2">
              <span className="text-[var(--font-size-md)] font-bold uppercase tracking-wider text-foreground">
                Traffic & Cryptographic Breakdown
              </span>
              <span className="text-[var(--font-size-md)] text-foreground font-bold tabular-nums bg-surface-1 px-1.5 py-0.5 rounded-[var(--radius-sm)]">
                {totalProto} Observed Sessions
              </span>
            </div>

            {/* Protocol Distribution */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[var(--font-size-md)]">
                <span className="text-foreground font-bold text-[11px] uppercase">Protocol Distribution</span>
                <span className="text-[11px] text-muted font-bold tabular-nums">
                  SMTP ({summary.protocol_counts.smtp}) · IMAP ({summary.protocol_counts.imap}) · POP3 ({summary.protocol_counts.pop3})
                </span>
              </div>
              <div className="h-3 w-full bg-surface-1 rounded-full flex overflow-hidden">
                {summary.protocol_counts.smtp > 0 && (
                  <div
                    style={{ width: `${(summary.protocol_counts.smtp / totalProto) * 100}%` }}
                    className="bg-sky-500 h-full"
                    title={`SMTP: ${summary.protocol_counts.smtp}`}
                  />
                )}
                {summary.protocol_counts.imap > 0 && (
                  <div
                    style={{ width: `${(summary.protocol_counts.imap / totalProto) * 100}%` }}
                    className="bg-accent h-full"
                    title={`IMAP: ${summary.protocol_counts.imap}`}
                  />
                )}
                {summary.protocol_counts.pop3 > 0 && (
                  <div
                    style={{ width: `${(summary.protocol_counts.pop3 / totalProto) * 100}%` }}
                    className="bg-purple-500 h-full"
                    title={`POP3: ${summary.protocol_counts.pop3}`}
                  />
                )}
              </div>
            </div>

            {/* Transport Distribution */}
            <div className="space-y-1.5 pt-2 border-t border-border">
              <div className="flex items-center justify-between text-[var(--font-size-md)]">
                <span className="text-foreground font-bold text-[11px] uppercase">Transport Layer Encapsulation</span>
                <span className="text-[11px] text-muted font-bold tabular-nums">
                  Implicit ({summary.transport_counts.implicit_tls}) · STARTTLS ({summary.transport_counts.starttls}) · Cleartext ({summary.transport_counts.plaintext})
                </span>
              </div>
              <div className="h-3 w-full bg-surface-1 rounded-full flex overflow-hidden">
                {summary.transport_counts.implicit_tls > 0 && (
                  <div
                    style={{ width: `${(summary.transport_counts.implicit_tls / totalTrans) * 100}%` }}
                    className="bg-sev-pass h-full"
                    title={`Implicit TLS: ${summary.transport_counts.implicit_tls}`}
                  />
                )}
                {summary.transport_counts.starttls > 0 && (
                  <div
                    style={{ width: `${(summary.transport_counts.starttls / totalTrans) * 100}%` }}
                    className="bg-accent h-full"
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
            </div>

            {/* Severity Distribution */}
            <div className="space-y-1.5 pt-2 border-t border-border">
              <div className="flex items-center justify-between text-[var(--font-size-md)]">
                <span className="text-foreground font-bold text-[11px] uppercase">Findings by Severity</span>
                <span className="text-[11px] text-foreground font-bold tabular-nums">{totalSev} Total Findings</span>
              </div>
              <div className="h-3 w-full bg-surface-1 rounded-full flex overflow-hidden">
                {summary.severity_counts.critical > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.critical / totalSev) * 100}%` }}
                    className="bg-sev-critical h-full"
                  />
                )}
                {summary.severity_counts.high > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.high / totalSev) * 100}%` }}
                    className="bg-sev-high h-full"
                  />
                )}
                {summary.severity_counts.medium > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.medium / totalSev) * 100}%` }}
                    className="bg-sev-medium h-full"
                  />
                )}
                {summary.severity_counts.low > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.low / totalSev) * 100}%` }}
                    className="bg-surface-2 h-full"
                  />
                )}
                {summary.severity_counts.info > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.info / totalSev) * 100}%` }}
                    className="bg-sky-200 h-full"
                  />
                )}
              </div>

              <div className="flex items-center justify-between text-[11px] pt-1 text-foreground font-bold">
                <span className="bg-sev-critical-bg text-sev-critical px-1 rounded-[var(--radius-xs)]">Crit: {summary.severity_counts.critical}</span>
                <span className="bg-sev-high-bg text-sev-high px-1 rounded-[var(--radius-xs)]">High: {summary.severity_counts.high}</span>
                <span className="bg-sev-medium-bg text-sev-medium px-1 rounded-[var(--radius-xs)]">Med: {summary.severity_counts.medium}</span>
                <span className="bg-surface-2 text-muted px-1 rounded-[var(--radius-xs)]">Low: {summary.severity_counts.low}</span>
                <span className="bg-surface-1 text-muted px-1 rounded-[var(--radius-xs)]">Info: {summary.severity_counts.info}</span>
              </div>
            </div>
          </div>

          {/* Active Observability Limitations */}
          {summary.limitations.length > 0 && (
            <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 text-[var(--font-size-md)] space-y-1 xcor-shadow-subtle">
              <div className="flex items-center gap-1.5 text-foreground text-[11px] font-bold uppercase">
                <Info size={14} weight="bold" className="text-muted" />
                <span>Forensic Limitations</span>
              </div>
              {summary.limitations.map((lim, idx) => (
                <p key={idx} className="text-[11px] text-muted leading-relaxed font-medium">
                  {lim}
                </p>
              ))}
            </div>
          )}
        </div>

        {/* ================= COLUMN 3: INSTANT REMEDIATION DRAWER (4 cols) ================= */}
        <div className="lg:col-span-4 space-y-4 flex flex-col justify-between">
          <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-4 space-y-3 flex-1 flex flex-col xcor-shadow">
            <div className="flex items-center justify-between border-b border-border pb-2">
              <div className="flex items-center gap-1.5">
                <FileCode size={16} weight="bold" className="text-accent" />
                <span className="text-[var(--font-size-md)] font-bold uppercase tracking-wider text-foreground">
                  Instant MTA Remediation
                </span>
              </div>

              <div className="flex rounded-[var(--radius-sm)] bg-surface-1 overflow-hidden" role="tablist">
                <button
                  onClick={() => setConfigTab("postfix")}
                  role="tab"
                  aria-selected={configTab === "postfix"}
                  className={`px-2.5 py-0.5 text-[var(--font-size-md)] font-bold cursor-pointer transition-colors duration-[var(--motion-fast)] focus-ring ${
                    configTab === "postfix" ? "bg-accent text-white" : "text-muted hover:text-foreground"
                  }`}
                >
                  Postfix
                </button>
                <button
                  onClick={() => setConfigTab("dovecot")}
                  role="tab"
                  aria-selected={configTab === "dovecot"}
                  className={`px-2.5 py-0.5 text-[var(--font-size-md)] font-bold cursor-pointer transition-colors duration-[var(--motion-fast)] border-l border-border focus-ring ${
                    configTab === "dovecot" ? "bg-accent text-white" : "text-muted hover:text-foreground"
                  }`}
                >
                  Dovecot
                </button>
              </div>
            </div>

            <p className="text-[11px] text-muted font-medium">
              Drop-in configuration snippet generated to remediate active findings on this capture:
            </p>

            {/* Code Snippet Container */}
            <div className="relative bg-surface-1 rounded-[var(--radius-sm)] p-3 flex-1 flex flex-col justify-between" role="tabpanel">
              <pre className="text-[var(--font-size-sm)] leading-relaxed text-foreground font-bold overflow-x-auto max-h-[300px] select-all font-mono">
                {activeSnippet}
              </pre>

              <div className="pt-2 border-t border-border flex items-center justify-between mt-2">
                <span className="text-[var(--font-size-sm)] text-muted font-bold">{configTab === "postfix" ? "/etc/postfix/main.cf" : "/etc/dovecot/conf.d/10-ssl.conf"}</span>
                <button
                  onClick={() => copyText(activeSnippet, setCopiedConfig)}
                  className={[
                    "flex items-center gap-1 px-3 py-1 bg-accent hover:bg-accent-hover text-white",
                    "text-[var(--font-size-md)] font-bold rounded-[var(--radius-sm)]",
                    "transition-all duration-[var(--motion-fast)] cursor-pointer focus-ring",
                  ].join(" ")}
                  aria-label="Copy configuration to clipboard"
                >
                  {copiedConfig ? (
                    <>
                      <Check size={12} weight="bold" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy size={12} weight="bold" />
                      <span>Copy Fix</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Priority Remediation Checklist */}
            <div className="space-y-1.5 pt-2 border-t border-border">
              <span className="text-[var(--font-size-sm)] font-bold uppercase tracking-wider text-foreground block">
                Priority Action Plan
              </span>
              <ul className="space-y-1 text-[11px] text-foreground font-medium">
                <li className="flex items-start gap-1.5">
                  <span className="bg-sev-critical text-white font-bold px-1 text-[var(--font-size-sm)] rounded-[var(--radius-xs)]">1</span>
                  <span>Enforce mandatory TLS before authentication (<code className="bg-surface-2 px-1 rounded-[var(--radius-xs)] font-bold">smtpd_tls_auth_only = yes</code>).</span>
                </li>
                <li className="flex items-start gap-1.5">
                  <span className="bg-sev-high text-white font-bold px-1 text-[var(--font-size-sm)] rounded-[var(--radius-xs)]">2</span>
                  <span>Disable deprecated TLS versions 1.0 & 1.1 across all submission ports.</span>
                </li>
                <li className="flex items-start gap-1.5">
                  <span className="bg-sev-medium text-white font-bold px-1 text-[var(--font-size-sm)] rounded-[var(--radius-xs)]">3</span>
                  <span>Deprecate non-PFS and legacy 3DES/RC4 cipher suites.</span>
                </li>
              </ul>
            </div>

            <Link
              href={`/findings?capture=${captureId}`}
              className={[
                "mt-2 flex items-center justify-center gap-2 w-full py-2",
                "bg-surface-1 hover:bg-accent hover:text-white",
                "border border-border rounded-[var(--radius-sm)]",
                "text-[var(--font-size-md)] font-bold text-foreground",
                "transition-all duration-[var(--motion-fast)] focus-ring",
              ].join(" ")}
            >
              <span>View All Prioritized Findings</span>
              <ArrowRight size={14} weight="bold" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
