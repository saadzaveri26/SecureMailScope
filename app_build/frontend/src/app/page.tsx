"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { SeverityBadge } from "@/components/severity";
import { summaryForCap001, findingsForCap001 } from "@/fixtures/data";
import { getEvaluation } from "@/data";
import type { Evaluation } from "@/types";
import { Copy, Check, ArrowRight } from "@phosphor-icons/react";

export default function Home() {
  const [copied, setCopied] = useState(false);
  const [ev, setEv] = useState<Evaluation | null>(null);

  const isDemo = process.env.NEXT_PUBLIC_DEMO_MODE === "1" || process.env.NEXT_PUBLIC_DEMO_MODE === "true";
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
    <div className="flex flex-col min-h-[calc(100vh-3.5rem)]">
      <div className="flex-1 max-w-[1400px] w-full mx-auto px-4 py-8 lg:py-12 space-y-16">
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
          <div className="lg:col-span-7 space-y-6">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full border border-border bg-surface-1 text-xs text-muted">
              <span>Ground-truth validation</span>
              <span className="text-border">|</span>
              <Link href="/evaluation" className="text-brand hover:underline font-medium inline-flex items-center gap-1">
                Evaluation results <ArrowRight size={12} />
              </Link>
            </div>

            <h1 className="text-3xl sm:text-4xl lg:text-[40px] font-bold text-foreground leading-[1.15] tracking-tight">
              See what your mail servers actually negotiated.
            </h1>
            <p className="text-sm sm:text-base text-muted leading-relaxed max-w-xl">
              Inspect mail cryptography in captured packet traces. SecureMailScope rebuilds each SMTP, IMAP and POP3 session, analyzes the TLS and STARTTLS exchange, and ties every weakness to the network frames that prove it.
            </p>
            <div className="flex items-center gap-6 pt-2">
              {isDemo ? (
                <Link
                  href="/overview?capture=cap-001"
                  className="px-4 py-2 rounded-md bg-brand hover:bg-brand-hover text-white text-xs font-semibold transition-colors"
                >
                  Open the sample analysis
                </Link>
              ) : (
                <>
                  <Link
                    href="/captures"
                    className="px-4 py-2 rounded-md bg-brand hover:bg-brand-hover text-white text-xs font-semibold transition-colors"
                  >
                    Upload a capture
                  </Link>
                  <Link
                    href="/overview?capture=cap-001"
                    className="text-xs font-medium text-foreground hover:text-brand underline underline-offset-4 transition-colors"
                  >
                    Open the sample analysis
                  </Link>
                </>
              )}
            </div>
          </div>

          <div className="lg:col-span-5">
            <div className="bg-surface-0 rounded-lg border border-border p-5 space-y-3.5">
              <div className="flex items-center justify-between gap-2 border-b border-border-subtle pb-3">
                <SeverityBadge severity={sample.severity} />
                <span className="text-xs font-mono text-muted">Priority rank #{sample.priority_rank}</span>
              </div>

              <div>
                <h2 className="text-sm font-semibold text-foreground">{sample.title}</h2>
                <div className="flex items-center gap-3 mt-1.5 text-xs font-mono text-muted">
                  <span>{sample.evidence.server}:{sample.evidence.server_port}</span>
                  <span className="text-border">|</span>
                  <span className="tabular-nums">
                    Frames: {sample.evidence.frames.map((f) => `#${f}`).join(", ")}
                  </span>
                </div>
              </div>

              <div className="bg-surface-1 rounded-md p-2.5 border border-border-subtle space-y-1.5">
                <span className="text-[11px] font-medium text-muted block">Wireshark filter</span>
                <div className="flex items-center justify-between gap-2 bg-surface-0 border border-border rounded px-2.5 py-1.5">
                  <code className="text-xs font-mono text-brand truncate">{sample.wireshark_filter}</code>
                  <button
                    onClick={copyFilter}
                    className="p-1 hover:bg-surface-2 rounded text-muted hover:text-foreground transition-colors shrink-0"
                    title="Copy filter"
                  >
                    {copied ? <Check size={12} className="text-brand" /> : <Copy size={12} />}
                  </button>
                </div>
              </div>

              <div className="text-xs text-muted pt-1">
                <span className="font-medium text-foreground block mb-0.5">Remediation</span>
                <p className="leading-relaxed">{sample.remediation.summary}</p>
              </div>
            </div>
          </div>
        </section>

        <section className="bg-surface-0 rounded-lg border border-border p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border-subtle pb-3">
            <div>
              <h2 className="text-base font-semibold text-foreground">Measured, not claimed</h2>
              <p className="text-xs text-muted mt-0.5">
                {ev?.label ?? "Measured against the synthetic lab corpus. Not a claim about real-world accuracy."}
              </p>
            </div>
            <Link
              href="/evaluation"
              className="text-xs font-medium text-brand hover:underline inline-flex items-center gap-1 shrink-0"
            >
              Full evaluation results <ArrowRight size={12} />
            </Link>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-1">
            <div className="p-3 bg-surface-1 rounded-md border border-border-subtle">
              <span className="text-[11px] text-muted block">Overall precision</span>
              <span className="text-2xl font-bold font-mono text-foreground tabular-nums">
                {ev ? `${(ev.overall.precision * 100).toFixed(1)}%` : "—"}
              </span>
            </div>
            <div className="p-3 bg-surface-1 rounded-md border border-border-subtle">
              <span className="text-[11px] text-muted block">Overall recall</span>
              <span className="text-2xl font-bold font-mono text-foreground tabular-nums">
                {ev ? `${(ev.overall.recall * 100).toFixed(1)}%` : "—"}
              </span>
            </div>
            <div className="p-3 bg-surface-1 rounded-md border border-border-subtle">
              <span className="text-[11px] text-muted block">Captures tested</span>
              <span className="text-2xl font-bold font-mono text-foreground tabular-nums">
                {ev ? ev.captures : "—"}
              </span>
            </div>
            <div className="p-3 bg-surface-1 rounded-md border border-border-subtle">
              <span className="text-[11px] text-muted block">Clean false alarms</span>
              <span className="text-2xl font-bold font-mono text-foreground tabular-nums">
                {ev ? ev.clean_capture_false_alarms : "—"}
              </span>
            </div>
          </div>
        </section>

        <section className="space-y-4 pt-2">
          <div>
            <h2 className="text-base font-semibold text-foreground">
              Sample analysis: corporate_mail_audit.pcap
            </h2>
            <p className="text-xs text-muted mt-0.5">
              Summary posture score and key vulnerability detections from the evaluation fixture
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-5 bg-surface-0 rounded-lg border border-border-subtle p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-baseline gap-3 pb-4 border-b border-border-subtle">
                  <span className="text-4xl font-bold font-mono tabular-nums text-foreground">
                    {summaryForCap001.posture.score}
                  </span>
                  <span className="text-lg font-bold text-sev-high">
                    Grade {summaryForCap001.posture.grade}
                  </span>
                  <span className="text-xs text-muted ml-auto">Posture score</span>
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

              <div className="pt-4 mt-4 border-t border-border-subtle">
                <Link
                  href="/overview?capture=cap-001"
                  className="text-xs font-medium text-brand hover:underline inline-flex items-center gap-1"
                >
                  View full overview for this capture
                </Link>
              </div>
            </div>

            <div className="lg:col-span-7 bg-surface-0 rounded-lg border border-border-subtle overflow-hidden">
              <div className="px-4 py-3 border-b border-border-subtle bg-surface-1">
                <h3 className="text-xs font-medium text-foreground">Top priority findings</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border-subtle bg-surface-1 text-left text-muted">
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
                        className="border-b border-border-subtle last:border-0 hover:bg-surface-1 transition-colors"
                      >
                        <td className="px-3 py-2.5 font-mono text-muted tabular-nums">#{f.priority_rank}</td>
                        <td className="px-3 py-2.5">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="px-3 py-2.5">
                          <Link
                            href="/overview?capture=cap-001"
                            className="font-medium text-foreground hover:text-brand"
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

        <section className="bg-surface-0 rounded-lg border border-border-subtle p-5 space-y-2">
          <h2 className="text-sm font-semibold text-foreground">What passive analysis cannot see</h2>
          <ul className="text-xs text-muted space-y-1.5 list-disc list-inside">
            <li>TLS 1.3 encrypts certificates. Chain validation is not possible for encrypted handshakes.</li>
            <li>Message content inside TLS is not visible. Only transport envelope and protocol commands are inspected.</li>
            <li>Anomaly flags are deviations from a baseline, not proof of attack.</li>
          </ul>
        </section>
      </div>

      <footer className="bg-surface-0 border-t border-border mt-12 py-6">
        <div className="max-w-[1400px] mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-muted">
          <span className="font-semibold text-foreground">SecureMailScope</span>
          <span>Passive cryptographic posture assessment of email traffic from PCAP files.</span>
        </div>
      </footer>
    </div>
  );
}
