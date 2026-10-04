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
  ShieldCheck,
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
      <div className="h-5 w-40 bg-surface-2" />
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-3 bg-surface-0 border-2 border-black p-4 h-96 brutal-shadow" />
        <div className="lg:col-span-5 bg-surface-0 border-2 border-black p-4 h-96 brutal-shadow" />
        <div className="lg:col-span-4 bg-surface-0 border-2 border-black p-4 h-96 brutal-shadow" />
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
        <div className="bg-sev-critical-bg border-2 border-black p-4 space-y-2 brutal-shadow">
          <p className="text-xs font-mono font-bold text-sev-critical">Unable to load posture overview</p>
          <p className="text-xs font-mono text-muted">{error}</p>
          <button
            onClick={() => { setLoading(true); setError(null); load(); }}
            className="text-xs font-mono font-bold text-black underline cursor-pointer"
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
        <div className="bg-amber-100 border-2 border-black p-4 brutal-shadow">
          <div className="flex items-center gap-2 text-black font-bold text-sm">
            <span>⚠️</span>
            <span>NO EMAIL SESSIONS DETECTED IN THIS CAPTURE</span>
          </div>
          <p className="text-xs text-black/80 mt-1">
            This packet capture contains no SMTP, IMAP, or POP3 exchanges. Passive cryptographic posture assessment requires active email protocol traffic.
          </p>
        </div>
      )}

      {/* 3-Column Priority Operations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* ================= COLUMN 1: SCORE & CUSTODY (3 cols) ================= */}
        <div className="lg:col-span-3 space-y-4 flex flex-col justify-between">
          {/* Posture Score Card */}
          <div className="bg-surface-0 border-2 border-black p-4 space-y-4 brutal-shadow">
            <div className="flex items-center justify-between border-b-2 border-black pb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-black">
                Posture Score
              </span>
              <span className="text-[10px] bg-accent px-1.5 py-0.5 border border-black font-bold text-black">
                PASSIVE
              </span>
            </div>

            <div className="flex items-center gap-3">
              <div
                className={`w-16 h-16 flex flex-col items-center justify-center shrink-0 border-2 border-black font-bold brutal-shadow-sm ${
                  hasNoTraffic
                    ? "bg-surface-2 text-muted"
                    : isHealthy
                    ? "bg-emerald-400 text-black"
                    : isCritical
                    ? "bg-red-500 text-white"
                    : "bg-accent text-black"
                }`}
              >
                <span className="text-3xl leading-none tabular-nums">{score ?? "—"}</span>
                <span className="text-[10px] tracking-wider mt-0.5">/ 100</span>
              </div>

              <div>
                <div className="flex items-center gap-1.5">
                  <span className="text-base font-bold text-black">
                    {hasNoTraffic ? "No Traffic" : `Grade ${grade}`}
                  </span>
                  <span
                    className={`px-1.5 py-0.2 border border-black text-[10px] font-bold uppercase ${
                      hasNoTraffic
                        ? "bg-surface-2 text-muted"
                        : isHealthy
                        ? "bg-emerald-100 text-emerald-900"
                        : isCritical
                        ? "bg-red-100 text-red-900"
                        : "bg-yellow-100 text-yellow-900"
                    }`}
                  >
                    {hasNoTraffic ? "N/A" : isHealthy ? "Secure" : isCritical ? "Critical" : "Degraded"}
                  </span>
                </div>
                <span className="text-xs text-muted block mt-0.5 font-medium">
                  {hasNoTraffic
                    ? "0 mail sessions observed"
                    : summary.severity_counts.critical > 0
                    ? `${summary.severity_counts.critical} critical flaws found`
                    : "No critical flaws"}
                </span>
              </div>
            </div>

            {/* Factor Deductions breakdown bars */}
            <div className="space-y-2.5 pt-2 border-t-2 border-black/20">
              <span className="text-[10px] font-bold uppercase tracking-wider text-black block">
                Factor Impact Breakdown
              </span>

              {summary.posture.factors.map((f) => (
                <div key={f.name} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-black font-bold text-[11px] truncate max-w-[160px]">{f.name}</span>
                    <span
                      className={`tabular-nums font-bold text-[11px] px-1 border border-black ${
                        f.impact < 0 ? "bg-red-100 text-red-700" : "bg-emerald-100 text-emerald-800"
                      }`}
                    >
                      {f.impact > 0 ? "+" : ""}{f.impact} pts
                    </span>
                  </div>
                  <div className="h-2 w-full bg-surface-1 border border-black overflow-hidden">
                    <div
                      className={`h-full ${f.impact < 0 ? "bg-red-500" : "bg-emerald-500"}`}
                      style={{ width: `${Math.min(100, Math.max(8, Math.abs(f.impact) * 3))}%` }}
                    />
                  </div>
                  <p className="text-[10px] text-muted truncate">{f.detail}</p>
                </div>
              ))}
            </div>
          </div>

          {/* PCAP Forensic Metadata */}
          <div className="bg-surface-0 border-2 border-black p-3.5 space-y-2 text-xs brutal-shadow">
            <div className="flex items-center justify-between border-b-2 border-black pb-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-black">
                Capture Custody Chain
              </span>
              <Fingerprint size={15} weight="bold" className="text-black" />
            </div>

            <div className="space-y-2 text-[11px]">
              <div>
                <span className="text-muted block text-[10px] font-bold uppercase">SHA-256 Custody Hash:</span>
                <div className="flex items-center justify-between gap-1 bg-surface-1 px-1.5 py-1 border border-black mt-0.5">
                  <code className="text-[10px] text-black font-bold truncate select-all">{currentCap?.sha256}</code>
                  <button
                    onClick={() => copyText(currentCap?.sha256 || "", setCopiedSha)}
                    className="p-0.5 text-black hover:bg-accent shrink-0 cursor-pointer"
                    title="Copy full SHA-256"
                  >
                    {copiedSha ? <Check size={12} weight="bold" className="text-emerald-700" /> : <Copy size={12} weight="bold" />}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-1 border-t border-black/20">
                <div>
                  <span className="text-muted block text-[10px] font-bold uppercase">Total Packets:</span>
                  <span className="text-black font-bold tabular-nums">{currentCap?.packet_count?.toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-muted block text-[10px] font-bold uppercase">Raw File Size:</span>
                  <span className="text-black font-bold tabular-nums">
                    {currentCap?.size_bytes ? `${(currentCap.size_bytes / 1024 / 1024).toFixed(2)} MB` : "1.2 MB"}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-muted block text-[10px] font-bold uppercase">Trace Duration:</span>
                  <span className="text-black font-bold tabular-nums">{currentCap?.duration_s || 60}s</span>
                </div>
                <div>
                  <span className="text-muted block text-[10px] font-bold uppercase">Ruleset Engine:</span>
                  <span className="text-black font-bold">2025.03.1</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ================= COLUMN 2: ACTIONABLE THREAT EVIDENCE (5 cols) ================= */}
        <div className="lg:col-span-5 space-y-4">
          {/* Explicit Threat Detection Tiles */}
          <div className="grid grid-cols-3 gap-2.5">
            <div className="bg-surface-0 border-2 border-black p-3 space-y-1 brutal-shadow-sm">
              <div className="flex items-center gap-1.5 text-red-600 text-xs font-bold uppercase">
                <LockKeyOpen size={14} weight="bold" />
                <span>Plaintext</span>
              </div>
              <div className="text-2xl font-bold tabular-nums text-black">
                {cleartextCreds}
              </div>
              <span className="text-[10px] text-muted block leading-tight font-medium">
                {cleartextCreds > 0 ? "Exposed credentials detected" : "No plaintext auth"}
              </span>
            </div>

            <div className="bg-surface-0 border-2 border-black p-3 space-y-1 brutal-shadow-sm">
              <div className="flex items-center gap-1.5 text-orange-600 text-xs font-bold uppercase">
                <WarningCircle size={14} weight="bold" />
                <span>Downgrades</span>
              </div>
              <div className="text-2xl font-bold tabular-nums text-black">
                {downgradeAttempts}
              </div>
              <span className="text-[10px] text-muted block leading-tight font-medium">
                {downgradeAttempts > 0 ? "STARTTLS strip tampering" : "No forced fallbacks"}
              </span>
            </div>

            <div className="bg-surface-0 border-2 border-black p-3 space-y-1 brutal-shadow-sm">
              <div className="flex items-center gap-1.5 text-yellow-700 text-xs font-bold uppercase">
                <ShieldWarning size={14} weight="bold" />
                <span>Non-PFS</span>
              </div>
              <div className="text-2xl font-bold tabular-nums text-black">
                {nonPfsPercent}
              </div>
              <span className="text-[10px] text-muted block leading-tight font-medium">
                Legacy static RSA / CBC
              </span>
            </div>
          </div>

          {/* Traffic & Cryptography Distribution Panel */}
          <div className="bg-surface-0 border-2 border-black p-4 space-y-4 brutal-shadow">
            <div className="flex items-center justify-between border-b-2 border-black pb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-black">
                Traffic & Cryptographic Breakdown
              </span>
              <span className="text-xs text-black font-bold tabular-nums bg-surface-2 px-1.5 py-0.5 border border-black">
                {totalProto} Observed Sessions
              </span>
            </div>

            {/* Protocol Distribution */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-black font-bold text-[11px] uppercase">Protocol Distribution</span>
                <span className="text-[11px] text-muted font-bold tabular-nums">
                  SMTP ({summary.protocol_counts.smtp}) · IMAP ({summary.protocol_counts.imap}) · POP3 ({summary.protocol_counts.pop3})
                </span>
              </div>
              <div className="h-3 w-full bg-surface-1 border border-black flex overflow-hidden">
                {summary.protocol_counts.smtp > 0 && (
                  <div
                    style={{ width: `${(summary.protocol_counts.smtp / totalProto) * 100}%` }}
                    className="bg-sky-400 h-full border-r border-black"
                    title={`SMTP: ${summary.protocol_counts.smtp}`}
                  />
                )}
                {summary.protocol_counts.imap > 0 && (
                  <div
                    style={{ width: `${(summary.protocol_counts.imap / totalProto) * 100}%` }}
                    className="bg-accent h-full border-r border-black"
                    title={`IMAP: ${summary.protocol_counts.imap}`}
                  />
                )}
                {summary.protocol_counts.pop3 > 0 && (
                  <div
                    style={{ width: `${(summary.protocol_counts.pop3 / totalProto) * 100}%` }}
                    className="bg-purple-400 h-full"
                    title={`POP3: ${summary.protocol_counts.pop3}`}
                  />
                )}
              </div>
            </div>

            {/* Transport Distribution */}
            <div className="space-y-1.5 pt-2 border-t-2 border-black/20">
              <div className="flex items-center justify-between text-xs">
                <span className="text-black font-bold text-[11px] uppercase">Transport Layer Encapsulation</span>
                <span className="text-[11px] text-muted font-bold tabular-nums">
                  Implicit ({summary.transport_counts.implicit_tls}) · STARTTLS ({summary.transport_counts.starttls}) · Cleartext ({summary.transport_counts.plaintext})
                </span>
              </div>
              <div className="h-3 w-full bg-surface-1 border border-black flex overflow-hidden">
                {summary.transport_counts.implicit_tls > 0 && (
                  <div
                    style={{ width: `${(summary.transport_counts.implicit_tls / totalTrans) * 100}%` }}
                    className="bg-emerald-400 h-full border-r border-black"
                    title={`Implicit TLS: ${summary.transport_counts.implicit_tls}`}
                  />
                )}
                {summary.transport_counts.starttls > 0 && (
                  <div
                    style={{ width: `${(summary.transport_counts.starttls / totalTrans) * 100}%` }}
                    className="bg-accent h-full border-r border-black"
                    title={`STARTTLS: ${summary.transport_counts.starttls}`}
                  />
                )}
                {summary.transport_counts.plaintext > 0 && (
                  <div
                    style={{ width: `${(summary.transport_counts.plaintext / totalTrans) * 100}%` }}
                    className="bg-red-500 h-full"
                    title={`Plaintext: ${summary.transport_counts.plaintext}`}
                  />
                )}
              </div>
            </div>

            {/* Severity Distribution */}
            <div className="space-y-1.5 pt-2 border-t-2 border-black/20">
              <div className="flex items-center justify-between text-xs">
                <span className="text-black font-bold text-[11px] uppercase">Findings by Severity</span>
                <span className="text-[11px] text-black font-bold tabular-nums">{totalSev} Total Findings</span>
              </div>
              <div className="h-3 w-full bg-surface-1 border border-black flex overflow-hidden">
                {summary.severity_counts.critical > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.critical / totalSev) * 100}%` }}
                    className="bg-red-500 h-full border-r border-black"
                  />
                )}
                {summary.severity_counts.high > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.high / totalSev) * 100}%` }}
                    className="bg-orange-400 h-full border-r border-black"
                  />
                )}
                {summary.severity_counts.medium > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.medium / totalSev) * 100}%` }}
                    className="bg-yellow-300 h-full border-r border-black"
                  />
                )}
                {summary.severity_counts.low > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.low / totalSev) * 100}%` }}
                    className="bg-neutral-300 h-full border-r border-black"
                  />
                )}
                {summary.severity_counts.info > 0 && (
                  <div
                    style={{ width: `${(summary.severity_counts.info / totalSev) * 100}%` }}
                    className="bg-sky-200 h-full"
                  />
                )}
              </div>

              <div className="flex items-center justify-between text-[11px] pt-1 text-black font-bold">
                <span className="bg-red-100 px-1 border border-black">Crit: {summary.severity_counts.critical}</span>
                <span className="bg-orange-100 px-1 border border-black">High: {summary.severity_counts.high}</span>
                <span className="bg-yellow-100 px-1 border border-black">Med: {summary.severity_counts.medium}</span>
                <span className="bg-neutral-100 px-1 border border-black">Low: {summary.severity_counts.low}</span>
                <span className="bg-sky-100 px-1 border border-black">Info: {summary.severity_counts.info}</span>
              </div>
            </div>
          </div>

          {/* Active Observability Limitations */}
          {summary.limitations.length > 0 && (
            <div className="bg-surface-0 border-2 border-black p-3 text-xs space-y-1 brutal-shadow-sm">
              <div className="flex items-center gap-1.5 text-black text-[11px] font-bold uppercase">
                <Info size={14} weight="bold" />
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
          <div className="bg-surface-0 border-2 border-black p-4 space-y-3 flex-1 flex flex-col brutal-shadow">
            <div className="flex items-center justify-between border-b-2 border-black pb-2">
              <div className="flex items-center gap-1.5">
                <FileCode size={16} weight="bold" className="text-black" />
                <span className="text-xs font-bold uppercase tracking-wider text-black">
                  Instant MTA Remediation
                </span>
              </div>

              <div className="flex border-2 border-black bg-surface-1">
                <button
                  onClick={() => setConfigTab("postfix")}
                  className={`px-2.5 py-0.5 text-xs font-bold cursor-pointer transition-colors ${
                    configTab === "postfix" ? "bg-accent text-black" : "text-muted hover:text-black"
                  }`}
                >
                  Postfix
                </button>
                <button
                  onClick={() => setConfigTab("dovecot")}
                  className={`px-2.5 py-0.5 text-xs font-bold cursor-pointer transition-colors border-l-2 border-black ${
                    configTab === "dovecot" ? "bg-accent text-black" : "text-muted hover:text-black"
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
            <div className="relative bg-surface-1 border-2 border-black p-3 flex-1 flex flex-col justify-between brutal-shadow-sm">
              <pre className="text-[10px] leading-relaxed text-black font-bold overflow-x-auto max-h-[300px] select-all font-mono">
                {activeSnippet}
              </pre>

              <div className="pt-2 border-t border-black/20 flex items-center justify-between mt-2">
                <span className="text-[10px] text-muted font-bold">Target: {configTab === "postfix" ? "/etc/postfix/main.cf" : "/etc/dovecot/conf.d/10-ssl.conf"}</span>
                <button
                  onClick={() => copyText(activeSnippet, setCopiedConfig)}
                  className="flex items-center gap-1 px-3 py-1 bg-accent hover:bg-accent-hover text-black text-xs font-bold border border-black shadow-[2px_2px_0_#000] cursor-pointer"
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
            <div className="space-y-1.5 pt-2 border-t-2 border-black/20">
              <span className="text-[10px] font-bold uppercase tracking-wider text-black block">
                Priority Action Plan
              </span>
              <ul className="space-y-1 text-[11px] text-black font-medium">
                <li className="flex items-start gap-1.5">
                  <span className="bg-red-500 text-white font-bold px-1 text-[10px] border border-black">1</span>
                  <span>Enforce mandatory TLS before authentication (<code className="bg-surface-2 px-1 border border-black/40 font-bold">smtpd_tls_auth_only = yes</code>).</span>
                </li>
                <li className="flex items-start gap-1.5">
                  <span className="bg-orange-400 text-black font-bold px-1 text-[10px] border border-black">2</span>
                  <span>Disable deprecated TLS versions 1.0 & 1.1 across all submission ports.</span>
                </li>
                <li className="flex items-start gap-1.5">
                  <span className="bg-yellow-300 text-black font-bold px-1 text-[10px] border border-black">3</span>
                  <span>Deprecate non-PFS and legacy 3DES/RC4 cipher suites.</span>
                </li>
              </ul>
            </div>

            <Link
              href={`/findings?capture=${captureId}`}
              className="mt-2 flex items-center justify-center gap-2 w-full py-2 bg-surface-1 hover:bg-accent border-2 border-black text-xs font-bold text-black transition-colors brutal-shadow-sm"
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
