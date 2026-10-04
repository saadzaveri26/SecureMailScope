"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { SeverityBadge } from "@/components/severity";
import { uploadCapture } from "@/data";
import { findingsForCap001 } from "@/fixtures/data";
import {
  UploadSimple,
  Spinner,
  WarningCircle,
  ArrowRight,
} from "@phosphor-icons/react";

export default function Home() {
  const router = useRouter();
  const [uploading, setUploading] = useState(false);
  const [uploadErr, setUploadErr] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);

  async function handleFile(file: File) {
    if (!file.name.endsWith(".pcap") && !file.name.endsWith(".pcapng")) {
      setUploadErr("Invalid format — .pcap and .pcapng only");
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
    <div className="flex flex-col min-h-[calc(100vh-2.75rem)] bg-background text-foreground select-none">
      <div className="max-w-[1400px] w-full mx-auto px-4 py-5 space-y-5 flex-1">
        {/* Dropzone */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          className={[
            "border-2 border-dashed border-border rounded-[var(--radius-md)] h-28 flex items-center justify-center bg-surface-0 xcor-shadow",
            `transition-all duration-[var(--motion-normal)]`,
            dragOver
              ? "bg-accent-soft border-accent"
              : "hover:bg-surface-1",
            uploading ? "opacity-50 pointer-events-none" : "",
          ].join(" ")}
          role="region"
          aria-label="PCAP file upload zone"
        >
          {uploading ? (
            <div className="flex items-center gap-2 text-[var(--font-size-md)] font-mono font-bold text-foreground">
              <Spinner size={16} className="animate-spin" />
              <span>Processing capture…</span>
            </div>
          ) : (
            <label className="cursor-pointer flex items-center gap-3 text-[var(--font-size-md)] font-mono font-bold focus-ring rounded-[var(--radius-sm)]">
              <span className="p-1.5 bg-accent rounded-[var(--radius-sm)] text-white">
                <UploadSimple size={16} weight="bold" />
              </span>
              <span className="text-foreground">
                Drop a <code className="bg-surface-2 px-1 rounded-[var(--radius-xs)] text-foreground">
                  .pcap
                </code> or <code className="bg-surface-2 px-1 rounded-[var(--radius-xs)] text-foreground">
                  .pcapng
                </code> file here, or{" "}
                <span className="text-text-tertiary underline decoration-1 hover:text-accent px-0.5">browse</span>
              </span>
              <input type="file" accept=".pcap,.pcapng" className="hidden" onChange={onFileInput} />
            </label>
          )}
        </div>

        {uploadErr && (
          <div className="flex items-center gap-2 text-[var(--font-size-md)] font-mono font-bold text-sev-critical bg-sev-critical-bg rounded-[var(--radius-sm)] px-3 py-2" role="alert">
            <WarningCircle size={14} weight="bold" />
            <span>{uploadErr}</span>
          </div>
        )}

        {/* Pre-loaded captures */}
        <div className="flex items-center gap-2 text-[var(--font-size-md)] font-mono">
          <span className="text-muted font-bold">samples:</span>
          <Link
            href="/overview?capture=cap-001"
            className={[
              "inline-flex items-center gap-2 px-2.5 py-1.5 bg-surface-0 border border-border text-foreground",
              "rounded-[var(--radius-sm)] xcor-shadow-subtle",
              "hover:bg-accent-soft hover:border-accent/30",
              "transition-all duration-[var(--motion-fast)] focus-ring",
            ].join(" ")}
          >
            <span className="font-bold">synthetic_mail_incident.pcap</span>
            <span className="bg-sev-critical text-white text-[var(--font-size-sm)] font-bold px-1.5 py-0.5 rounded-[var(--radius-xs)] tabular-nums">40/F</span>
            <ArrowRight size={11} weight="bold" className="text-muted" />
          </Link>
          <Link
            href="/overview?capture=cap-002"
            className={[
              "inline-flex items-center gap-2 px-2.5 py-1.5 bg-surface-0 border border-border text-foreground",
              "rounded-[var(--radius-sm)] xcor-shadow-subtle",
              "hover:bg-accent-soft hover:border-accent/30",
              "transition-all duration-[var(--motion-fast)] focus-ring",
            ].join(" ")}
          >
            <span className="font-bold">securemail_baseline.pcap</span>
            <span className="bg-sev-pass text-white text-[var(--font-size-sm)] font-bold px-1.5 py-0.5 rounded-[var(--radius-xs)] tabular-nums">100/A</span>
            <ArrowRight size={11} weight="bold" className="text-muted" />
          </Link>
        </div>

        {/* Detection rules table */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-[var(--font-size-md)] font-mono">
            <span className="font-bold uppercase tracking-wider text-foreground">active detection rules</span>
            <span className="font-semibold text-muted">44 rules · v2025.03.1</span>
          </div>
          <div className="border border-border bg-surface-0 rounded-[var(--radius-md)] overflow-hidden xcor-shadow">
            <table className="w-full text-[var(--font-size-md)] font-mono text-left">
              <thead className="bg-surface-1 text-[11px] font-bold text-foreground uppercase border-b border-border">
                <tr>
                  <th scope="col" className="py-2 px-3 w-14">Status</th>
                  <th scope="col" className="py-2 px-3">Capability</th>
                  <th scope="col" className="py-2 px-3">Detection Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border text-foreground font-medium">
                {[
                  { cap: "STARTTLS Strip Detection", scope: "MITM 250-STARTTLS tampering, forced cleartext auth fallback" },
                  { cap: "JA3/JA3S Fingerprinting", scope: "Client/server handshake MD5 signatures for MTA identification" },
                  { cap: "RFC 8314 Compliance", scope: "Cleartext credential deprecation on ports 110, 143, 587" },
                  { cap: "EFAIL / MDC Validation", scope: "OpenPGP PKESK algorithm and modification detection code checks" },
                  { cap: "Post-Quantum Readiness", scope: "X25519MLKEM768 hybrid key exchange, HNDL exposure ratio" },
                  { cap: "X.509 Chain Custody", scope: "Certificate expiry, self-signed detection, SAN hostname matching" },
                ].map((rule) => (
                  <tr key={rule.cap} className="hover:bg-accent-soft transition-colors duration-[var(--motion-fast)]">
                    <td className="py-2 px-3">
                      <span className="inline-block w-2.5 h-2.5 bg-sev-pass rounded-full" aria-label="Active" />
                    </td>
                    <td className="py-2 px-3 font-bold text-foreground">{rule.cap}</td>
                    <td className="py-2 px-3 text-muted">{rule.scope}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Evidence feed table */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-[var(--font-size-md)] font-mono">
            <span className="font-bold uppercase tracking-wider text-foreground">evidence feed · cap-001</span>
            <Link
              href="/findings?capture=cap-001"
              className="font-bold text-text-tertiary hover:text-accent flex items-center gap-1.5 underline decoration-1 focus-ring rounded-[var(--radius-xs)]"
            >
              all findings <ArrowRight size={11} weight="bold" />
            </Link>
          </div>
          <div className="border border-border bg-surface-0 rounded-[var(--radius-md)] overflow-hidden xcor-shadow">
            <div className="overflow-x-auto">
              <table className="w-full text-[var(--font-size-md)] font-mono text-left">
                <thead className="bg-surface-1 text-[11px] font-bold text-foreground uppercase border-b border-border">
                  <tr>
                    <th scope="col" className="py-2 px-3 w-24">Severity</th>
                    <th scope="col" className="py-2 px-3 w-32">Rule ID</th>
                    <th scope="col" className="py-2 px-3">Finding</th>
                    <th scope="col" className="py-2 px-3 w-40">Target</th>
                    <th scope="col" className="py-2 px-3 w-60">Wireshark Filter</th>
                    <th scope="col" className="py-2 px-3 w-24 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {findingsForCap001.slice(0, 8).map((f) => (
                    <tr key={f.id} className="hover:bg-accent-soft transition-colors duration-[var(--motion-fast)]">
                      <td className="py-2 px-3">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="py-2 px-3 text-foreground font-bold">
                        {f.rule_id}
                      </td>
                      <td className="py-2 px-3">
                        <span className="text-foreground font-bold block leading-tight">{f.title}</span>
                        <span className="text-muted text-[11px] block truncate max-w-md leading-tight mt-0.5">{f.description}</span>
                      </td>
                      <td className="py-2 px-3 text-muted text-[11px] font-medium">
                        {f.evidence.server}:{f.evidence.server_port}
                      </td>
                      <td className="py-2 px-3">
                        <code className="text-[var(--font-size-sm)] text-foreground bg-surface-1 px-1.5 py-0.5 rounded-[var(--radius-xs)] block truncate max-w-xs">{f.wireshark_filter}</code>
                      </td>
                      <td className="py-2 px-3 text-right">
                        <Link
                          href={`/sessions?capture=cap-001&session=${f.session_id}`}
                          className={[
                            "inline-block px-2 py-0.5 bg-accent hover:bg-accent-hover text-white",
                            "rounded-[var(--radius-sm)] text-[11px] font-bold",
                            "transition-all duration-[var(--motion-fast)] focus-ring",
                          ].join(" ")}
                        >
                          inspect →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
