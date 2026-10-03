"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { SeverityBadge } from "@/components/severity";
import { EvidenceTag } from "@/components/evidence-tag";
import { summaryForCap001, findingsForCap001 } from "@/fixtures/data";
import { getEvaluation } from "@/data";
import type { Evaluation } from "@/types";
import { Copy, Check } from "@phosphor-icons/react";

export default function Home() {
  const [copied, setCopied] = useState(false);
  const [ev, setEv] = useState<Evaluation | null>(null);

  const sample = findingsForCap001[0];
  const topFindings = findingsForCap001.slice(0, 5);
  const factors = summaryForCap001.posture.factors;

  useEffect(() => {
    getEvaluation().then(setEv).catch(() => {});
  }, []);

  function copyFilter() {
    navigator.clipboard.writeText(sample.wireshark_filter);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="flex flex-col min-h-[calc(100vh-3rem)] bg-paper text-foreground">
      <section className="bg-ink text-white">
        <div className="max-w-[1400px] mx-auto px-4 py-8 lg:py-12 grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-10 items-center">
          <div className="lg:col-span-6 space-y-5">
            <h1 className="font-serif text-3xl sm:text-4xl lg:text-[42px] font-bold text-white leading-[1.14] tracking-tight">
              See what your mail servers actually negotiated.
            </h1>
            <p className="text-sm sm:text-base text-gray-300 leading-relaxed max-w-xl">
              Inspect mail cryptography in captured packet traces. SecureMailScope rebuilds each SMTP, IMAP and POP3 session, analyzes the TLS and STARTTLS exchange, and ties every weakness to the network frames that prove it.
            </p>
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <Link
                href="/overview?capture=cap-001"
                className="px-4 py-2.5 rounded-sm bg-evidence hover:bg-evidence/90 text-ink text-xs font-bold transition-colors focus:outline-none focus:ring-2 focus:ring-ink focus:ring-offset-2 focus:ring-offset-evidence"
              >
                Open Analysis
              </Link>
              <Link
                href="/evaluation"
                className="px-4 py-2.5 rounded-sm border border-white/40 hover:border-white text-white text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ink focus:ring-offset-2 focus:ring-offset-evidence"
              >
                See measured accuracy
              </Link>
            </div>
          </div>

          <div className="lg:col-span-6">
            <div className="bg-ink-2 rounded-sm border border-white/10 p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3">
                <span className="text-xs font-mono text-white/70">
                  Protocol Analysis Flow ({sample.rule_id})
                </span>
                <EvidenceTag>{sample.evidence.server}:{sample.evidence.server_port}</EvidenceTag>
              </div>

              <div className="space-y-3">
                <div>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-white/50 block mb-1.5">
                    Expected
                  </span>
                  <div className="grid grid-cols-4 gap-1.5 text-center">
                    <div className="bg-white/10 border border-white/20 text-white/90 text-[11px] font-mono py-1.5 px-1 rounded-[2px] truncate">
                      greeting
                    </div>
                    <div className="bg-white/10 border border-white/20 text-white/90 text-[11px] font-mono py-1.5 px-1 rounded-[2px] truncate">
                      STARTTLS offered
                    </div>
                    <div className="bg-white/10 border border-white/20 text-white/90 text-[11px] font-mono py-1.5 px-1 rounded-[2px] truncate">
                      TLS handshake
                    </div>
                    <div className="bg-white/10 border border-white/20 text-white/90 text-[11px] font-mono py-1.5 px-1 rounded-[2px] truncate">
                      authentication
                    </div>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-white/50 block mb-1.5">
                    On the wire
                  </span>
                  <div className="grid grid-cols-3 gap-1.5 text-center">
                    <div className="bg-white/10 border border-white/20 text-white/90 text-[11px] font-mono py-1.5 px-1 rounded-[2px] truncate">
                      greeting
                    </div>
                    <div className="border border-dashed border-sev-critical bg-sev-critical/10 text-sev-critical text-[11px] font-mono py-1.5 px-1 rounded-[2px] font-semibold truncate">
                      STARTTLS missing
                    </div>
                    <div className="border border-sev-critical bg-sev-critical text-white text-[11px] font-mono py-1.5 px-1 rounded-[2px] font-bold truncate">
                      cleartext auth
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2 pt-1">
                <span className="text-xs font-mono text-white/50">Frames:</span>
                <div className="flex items-center gap-1.5">
                  {sample.evidence.frames.map((f) => (
                    <EvidenceTag key={f}>#{f}</EvidenceTag>
                  ))}
                </div>
              </div>

              <div className="bg-ink border border-white/10 rounded-[2px] px-2.5 py-1.5 flex items-center justify-between gap-2">
                <code className="text-xs font-mono text-white/90 truncate">{sample.wireshark_filter}</code>
                <button
                  onClick={copyFilter}
                  className="p-1 hover:bg-white/10 rounded-sm text-white/60 hover:text-white transition-colors shrink-0"
                  title="Copy filter"
                >
                  {copied ? <Check size={14} className="text-white" /> : <Copy size={14} />}
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="bg-ink border-y border-white/10 py-6 text-white w-full">
        <div className="max-w-[1400px] mx-auto px-4 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold uppercase tracking-wider text-white/80">
                Measured, not claimed
              </h2>
              <p className="text-xs text-white/60 mt-0.5">
                {ev?.label ?? "Validated against standard RFC compliance benchmarks and protocol verification suites."}
              </p>
            </div>
            <Link
              href="/evaluation"
              className="text-xs text-white underline hover:text-white/80 shrink-0"
            >
              Full evaluation results
            </Link>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-3 bg-white/5 rounded-sm border border-white/10">
              <span className="text-[11px] text-white/60 block">Overall precision</span>
              <span className="text-3xl font-bold font-mono text-evidence tabular-nums">
                {ev ? `${(ev.overall.precision * 100).toFixed(1)}%` : "—"}
              </span>
            </div>
            <div className="p-3 bg-white/5 rounded-sm border border-white/10">
              <span className="text-[11px] text-white/60 block">Overall recall</span>
              <span className="text-3xl font-bold font-mono text-evidence tabular-nums">
                {ev ? `${(ev.overall.recall * 100).toFixed(1)}%` : "—"}
              </span>
            </div>
            <div className="p-3 bg-white/5 rounded-sm border border-white/10">
              <span className="text-[11px] text-white/60 block">Captures tested</span>
              <span className="text-3xl font-bold font-mono text-evidence tabular-nums">
                {ev ? ev.captures : "—"}
              </span>
            </div>
            <div className="p-3 bg-white/5 rounded-sm border border-white/10">
              <span className="text-[11px] text-white/60 block">Clean false alarms</span>
              <span className="text-3xl font-bold font-mono text-evidence tabular-nums">
                {ev ? ev.clean_capture_false_alarms : "—"}
              </span>
            </div>
          </div>
        </div>
      </section>

      <div className="flex-1 max-w-[1400px] w-full mx-auto px-4 py-8 lg:py-12 space-y-8">
        <section className="space-y-4">
          <div>
            <h2 className="text-base font-semibold text-foreground">
              Capture Analysis: securemail_drift.pcap
            </h2>
            <p className="text-xs text-muted mt-0.5">
              Summary posture score and key vulnerability detections from packet inspection
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-5 bg-surface-0 rounded-sm border border-border p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-4 pb-4 border-b border-border">
                  <div
                    className={`w-16 h-16 flex flex-col items-center justify-center rounded-[3px] text-white shrink-0 ${
                      summaryForCap001.posture.grade === "A" || summaryForCap001.posture.grade === "B"
                        ? "bg-sev-pass"
                        : summaryForCap001.posture.grade === "C"
                        ? "bg-sev-medium"
                        : summaryForCap001.posture.grade === "D"
                        ? "bg-sev-high"
                        : "bg-sev-critical"
                    }`}
                  >
                    <span className="text-3xl font-bold font-mono tabular-nums leading-none">
                      {summaryForCap001.posture.score}
                    </span>
                    <span className="text-[10px] font-mono font-semibold uppercase tracking-wider mt-1 opacity-90">
                      Grade {summaryForCap001.posture.grade}
                    </span>
                  </div>
                  <div>
                    <span className="text-base font-bold text-foreground block">
                      Grade {summaryForCap001.posture.grade}
                    </span>
                    <span className="text-xs text-muted block mt-0.5">Posture score</span>
                  </div>
                </div>

                <div className="space-y-3 mt-4">
                  <span className="text-xs font-medium text-muted block">Score factor impact</span>
                  {factors.map((f) => (
                    <div key={f.name} className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="font-medium text-foreground">{f.name}</span>
                        <span className="text-sev-critical font-medium tabular-nums">{f.impact}</span>
                      </div>
                      <div className="h-1.5 w-full bg-surface-2 rounded-[2px] overflow-hidden">
                        <div
                          className="h-full bg-sev-critical rounded-[2px]"
                          style={{ width: `${Math.min(100, Math.abs(f.impact) * 4)}%` }}
                        />
                      </div>
                      <span className="text-[11px] text-muted block truncate">{f.detail}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-4 mt-4 border-t border-border">
                <Link
                  href="/overview?capture=cap-001"
                  className="text-xs font-medium text-foreground underline hover:text-ink inline-flex items-center gap-1"
                >
                  View full overview for this capture
                </Link>
              </div>
            </div>

            <div className="lg:col-span-7 bg-surface-0 rounded-sm border border-border overflow-hidden">
              <div className="px-4 py-3 border-b border-border bg-surface-1">
                <h3 className="text-xs font-medium text-foreground">Top priority findings</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border bg-surface-1 text-left text-muted">
                      <th className="px-3 py-2 font-medium">Rank</th>
                      <th className="px-3 py-2 font-medium">Severity</th>
                      <th className="px-3 py-2 font-medium">Finding</th>
                      <th className="px-3 py-2 font-medium">Target</th>
                      <th className="px-3 py-2 font-medium text-right">Impact</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topFindings.map((f) => (
                      <tr
                        key={f.id}
                        className="border-b border-border last:border-0 hover:bg-surface-1 transition-colors"
                      >
                        <td className="px-3 py-2.5 font-mono text-muted tabular-nums">#{f.priority_rank}</td>
                        <td className="px-3 py-2.5">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="px-3 py-2.5">
                          <Link
                            href="/overview?capture=cap-001"
                            className="font-medium text-foreground underline hover:text-ink"
                          >
                            {f.title}
                          </Link>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-muted">
                          {f.evidence.server ? `${f.evidence.server}:${f.evidence.server_port}` : "Capture-wide"}
                        </td>
                        <td className="px-3 py-2.5 font-mono font-medium text-sev-critical text-right tabular-nums">
                          {f.score_impact}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </section>

        <section className="bg-surface-0 rounded-sm border border-border p-5 space-y-2">
          <h2 className="text-sm font-semibold text-foreground">What passive analysis cannot see</h2>
          <ul className="text-xs text-muted space-y-1.5 list-disc list-inside">
            <li>TLS 1.3 encrypts certificates. Chain validation is not possible for encrypted handshakes.</li>
            <li>Message content inside TLS is not visible. Only transport envelope and protocol commands are inspected.</li>
            <li>Anomaly flags are deviations from a baseline, not proof of attack.</li>
          </ul>
        </section>
      </div>

      <footer className="bg-ink border-t border-white/10 py-6">
        <div className="max-w-[1400px] mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-white/60">
          <span className="font-semibold text-evidence">SecureMailScope</span>
          <span>Passive cryptographic posture assessment of email traffic from PCAP files.</span>
        </div>
      </footer>
    </div>
  );
}
