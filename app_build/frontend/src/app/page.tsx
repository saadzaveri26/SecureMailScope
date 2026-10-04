"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { getCaptures, uploadCapture } from "@/data";
import type { Capture } from "@/types";
import {
  UploadSimple,
  Spinner,
  WarningCircle,
  ArrowRight,
  Info,
  X,
} from "@phosphor-icons/react";

export default function Home() {
  const router = useRouter();
  const [caps, setCaps] = useState<Capture[]>([]);
  const [loadingCaps, setLoadingCaps] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadErr, setUploadErr] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [showLimits, setShowLimits] = useState(false);

  const isDemo =
    process.env.NEXT_PUBLIC_USE_FIXTURES === "1" ||
    process.env.NEXT_PUBLIC_DEMO_MODE === "1";

  useEffect(() => {
    let active = true;
    getCaptures()
      .then((list) => {
        if (active) setCaps(list);
      })
      .finally(() => {
        if (active) setLoadingCaps(false);
      });
    return () => {
      active = false;
    };
  }, []);

  async function handleFile(file: File) {
    if (
      !file.name.endsWith(".pcap") &&
      !file.name.endsWith(".pcapng") &&
      !file.name.endsWith(".cap")
    ) {
      setUploadErr("Invalid format — .pcap, .pcapng, or .cap only");
      return;
    }
    setUploading(true);
    setUploadErr(null);
    try {
      const res = await uploadCapture(file);
      router.push(`/overview?capture=${res.capture_id}`);
    } catch (e: unknown) {
      setUploadErr(e instanceof Error ? e.message : "Upload failed");
      setUploading(false);
    }
  }

  function onDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  }

  function onFileInput(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (f) handleFile(f);
  }

  return (
    <div className="w-full px-4 2xl:px-6 py-3 space-y-3 select-none text-[13px] h-[calc(100vh-48px)] flex flex-col overflow-hidden">
      <div className="flex items-center justify-between shrink-0">
        <div className="flex items-baseline gap-3">
          <h1 className="text-[18px] font-semibold text-foreground tracking-tight">
            SecureMailScope
          </h1>
          <span className="text-muted text-[13px] hidden sm:inline">
            Passive cryptographic posture analysis for SMTP, IMAP and POP3 captures
          </span>
        </div>

        <button
          onClick={() => setShowLimits(true)}
          className="inline-flex items-center gap-1.5 text-[12px] font-medium text-text-tertiary hover:text-accent transition-colors cursor-pointer"
        >
          <Info size={14} weight="bold" />
          <span>What this cannot see</span>
        </button>
      </div>

      <div className="grid grid-cols-12 gap-3 flex-1 min-h-0">
        <section
          className="col-span-12 lg:col-span-7 flex flex-col bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 xcor-shadow min-h-0 overflow-y-auto"
          aria-label="Capture analysis workbench"
        >
          <div className="flex items-center justify-between pb-2 shrink-0">
            <h2 className="text-[14px] font-semibold text-foreground">
              Analyse a capture
            </h2>
            <span className="text-[11px] text-muted">
              Supported formats: .pcap, .pcapng, .cap
            </span>
          </div>

          <div
            id="upload"
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={onDrop}
            className={[
              "border-2 border-dashed border-border rounded-[var(--radius-md)] h-[180px] shrink-0 flex flex-col items-center justify-center bg-surface-1/50 transition-colors cursor-pointer",
              dragOver ? "bg-accent-soft border-accent" : "hover:bg-surface-1",
              uploading ? "opacity-50 pointer-events-none" : "",
            ].join(" ")}
          >
            {uploading ? (
              <div className="flex items-center gap-2 text-[13px] font-medium text-foreground">
                <Spinner size={16} className="animate-spin text-accent" />
                <span>Processing packet capture…</span>
              </div>
            ) : (
              <label className="cursor-pointer flex flex-col items-center gap-2 text-center p-4">
                <span className="p-2 bg-accent rounded-[var(--radius-sm)] text-white">
                  <UploadSimple size={18} weight="bold" />
                </span>
                <div className="space-y-0.5">
                  <p className="text-[13px] font-medium text-foreground">
                    Drop a <span className="font-mono text-[12px]">.pcap</span>,{" "}
                    <span className="font-mono text-[12px]">.pcapng</span>, or{" "}
                    <span className="font-mono text-[12px]">.cap</span> file here
                  </p>
                  <p className="text-[12px] text-muted">
                    or <span className="text-accent underline font-medium">browse filesystem</span>
                  </p>
                </div>
                <input
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  className="hidden"
                  onChange={onFileInput}
                />
              </label>
            )}
          </div>

          {uploadErr && (
            <div className="mt-2 shrink-0 flex items-center gap-2 text-[12px] text-sev-critical bg-sev-critical-bg border border-sev-critical/30 rounded-[var(--radius-xs)] px-3 py-1.5">
              <WarningCircle size={14} weight="bold" />
              <span>{uploadErr}</span>
            </div>
          )}

          {isDemo && (
            <div className="mt-2 shrink-0 flex items-center gap-2 text-[12px] text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 rounded-[var(--radius-xs)] px-3 py-1.5">
              <WarningCircle size={14} weight="bold" className="shrink-0" />
              <span>
                Uploads are disabled in the public demo. Use the samples below or run locally for local PCAP ingest.
              </span>
            </div>
          )}

          <div className="mt-3 pt-3 border-t border-border shrink-0 space-y-2">
            <span className="text-[12px] font-medium text-muted block">
              Reference sample captures
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <Link
                href="/overview?capture=cap-001"
                className="group flex flex-col justify-between p-2.5 bg-surface-1 border border-border hover:border-accent/40 rounded-[var(--radius-sm)] transition-colors focus-ring"
              >
                <div>
                  <div className="flex items-center justify-between gap-1">
                    <span className="font-mono text-[12px] font-semibold text-foreground group-hover:text-accent truncate">
                      securemail_drift.pcap
                    </span>
                    <span className="text-[10px] font-bold font-mono px-1.5 py-0.5 rounded-[var(--radius-xs)] bg-sev-critical text-white shrink-0">
                      40 F
                    </span>
                  </div>
                  <p className="text-[11px] text-muted mt-1 leading-snug">
                    Production incident · 8 findings · cleartext credentials detected
                  </p>
                </div>
                <div className="flex items-center gap-1 text-[11px] text-accent font-medium mt-2">
                  <span>Open capture</span>
                  <ArrowRight size={10} weight="bold" />
                </div>
              </Link>

              <Link
                href="/overview?capture=cap-002"
                className="group flex flex-col justify-between p-2.5 bg-surface-1 border border-border hover:border-accent/40 rounded-[var(--radius-sm)] transition-colors focus-ring"
              >
                <div>
                  <div className="flex items-center justify-between gap-1">
                    <span className="font-mono text-[12px] font-semibold text-foreground group-hover:text-accent truncate">
                      securemail_baseline.pcap
                    </span>
                    <span className="text-[10px] font-bold font-mono px-1.5 py-0.5 rounded-[var(--radius-xs)] bg-sev-pass text-white shrink-0">
                      100 A
                    </span>
                  </div>
                  <p className="text-[11px] text-muted mt-1 leading-snug">
                    Hardened baseline · 0 findings · TLS 1.3 enforced
                  </p>
                </div>
                <div className="flex items-center gap-1 text-[11px] text-accent font-medium mt-2">
                  <span>Open capture</span>
                  <ArrowRight size={10} weight="bold" />
                </div>
              </Link>
            </div>
          </div>
        </section>

        <section
          className="col-span-12 lg:col-span-5 flex flex-col bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 xcor-shadow min-h-0"
          aria-label="Recent captures table"
        >
          <div className="flex items-center justify-between pb-2 shrink-0">
            <div className="flex items-center gap-2">
              <h2 className="text-[14px] font-semibold text-foreground">
                Recent captures
              </h2>
              <span className="text-[11px] font-mono px-1.5 py-0.5 bg-surface-1 border border-border rounded-[var(--radius-xs)] text-muted">
                {caps.length}
              </span>
            </div>
            <Link
              href="/captures"
              className="text-[11px] font-medium text-text-tertiary hover:text-accent"
            >
              All captures →
            </Link>
          </div>

          <div className="flex-1 border border-border rounded-[var(--radius-sm)] overflow-hidden flex flex-col min-h-0 bg-surface-0">
            <div className="overflow-y-auto flex-1">
              <table className="w-full text-left text-[12px]">
                <thead className="sticky top-0 bg-surface-1 border-b border-border text-muted font-medium h-8 z-10">
                  <tr>
                    <th className="px-2.5 py-1">Filename</th>
                    <th className="px-2 py-1">Protocols</th>
                    <th className="px-2 py-1 text-right">Packets</th>
                    <th className="px-2 py-1 text-center">Score</th>
                    <th className="px-2.5 py-1 text-right">Date</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {loadingCaps ? (
                    <tr>
                      <td colSpan={5} className="p-4 text-center text-muted">
                        Loading captures…
                      </td>
                    </tr>
                  ) : caps.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-6 text-center text-muted">
                        No captures available. Upload a PCAP to begin.
                      </td>
                    </tr>
                  ) : (
                    caps.map((c) => {
                      const score = c.posture_score;
                      const grade = c.grade;
                      const dateStr = c.created_at
                        ? new Date(c.created_at).toLocaleDateString("en-US", {
                            month: "short",
                            day: "numeric",
                          })
                        : "—";

                      return (
                        <tr
                          key={c.id}
                          onClick={() => router.push(`/overview?capture=${c.id}`)}
                          className="h-8 hover:bg-surface-1 cursor-pointer transition-colors"
                        >
                          <td className="px-2.5 py-1 font-mono text-foreground font-medium truncate max-w-[120px]">
                            {c.filename}
                          </td>
                          <td className="px-2 py-1 text-muted text-[11px]">
                            SMTP, IMAP
                          </td>
                          <td className="px-2 py-1 font-mono text-muted text-right tabular-nums">
                            {c.packet_count?.toLocaleString() ?? "—"}
                          </td>
                          <td className="px-2 py-1 text-center">
                            {score !== null ? (
                              <span
                                className={`font-mono text-[10px] font-bold px-1.5 py-0.5 rounded-[var(--radius-xs)] ${
                                  score >= 80
                                    ? "bg-sev-pass text-white"
                                    : score >= 60
                                    ? "bg-sev-medium text-white"
                                    : "bg-sev-critical text-white"
                                }`}
                              >
                                {score} {grade}
                              </span>
                            ) : (
                              <span className="text-muted">—</span>
                            )}
                          </td>
                          <td className="px-2.5 py-1 font-mono text-muted text-right text-[11px]">
                            {dateStr}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      </div>

      {showLimits && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="limits-title"
          className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4 backdrop-blur-[2px]"
        >
          <div className="bg-surface-0 border border-border rounded-[var(--radius-md)] p-4 max-w-md w-full xcor-shadow space-y-3">
            <div className="flex items-center justify-between border-b border-border pb-2">
              <div className="flex items-center gap-1.5 text-foreground font-semibold text-[14px]">
                <Info size={16} className="text-accent" />
                <h3 id="limits-title">What this cannot see</h3>
              </div>
              <button
                onClick={() => setShowLimits(false)}
                className="text-muted hover:text-foreground p-1 rounded-[var(--radius-xs)]"
                aria-label="Close"
              >
                <X size={14} weight="bold" />
              </button>
            </div>
            <div className="text-[13px] text-foreground space-y-2 text-prose-cap leading-relaxed">
              <p className="text-muted text-[12px]">
                Passive packet inspection evaluates cryptographic handshakes and plaintext transitions visible on the wire. The following items fall outside its inspection scope:
              </p>
              <ul className="space-y-2 text-[12px] list-disc pl-4 text-foreground">
                <li>
                  <strong className="text-foreground">Ephemeral sessions:</strong> Sessions that completed or terminated before packet capture commenced cannot be observed.
                </li>
                <li>
                  <strong className="text-foreground">End-to-end encrypted payloads:</strong> S/MIME and PGP message layer contents where TLS transport is terminated correctly cannot be decrypted without local keys.
                </li>
                <li>
                  <strong className="text-foreground">Out-of-band credential compromises:</strong> Compromised account credentials used within correctly negotiated TLS handshakes appear cryptographically valid on the wire.
                </li>
              </ul>
            </div>
            <div className="flex justify-end pt-2 border-t border-border">
              <button
                onClick={() => setShowLimits(false)}
                className="px-3 py-1 bg-surface-1 hover:bg-surface-2 border border-border text-[12px] font-medium rounded-[var(--radius-xs)] text-foreground cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
