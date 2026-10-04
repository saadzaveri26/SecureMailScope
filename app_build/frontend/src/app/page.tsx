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
        {/* Dropzone — Neo-Brutalist upload zone with 2px black border & offset shadow */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          className={[
            "border-2 border-dashed border-black h-28 flex items-center justify-center transition-all brutal-shadow bg-surface-0",
            dragOver
              ? "bg-accent/20 border-black translate-x-0.5 translate-y-0.5 shadow-none"
              : "hover:bg-accent/5",
            uploading ? "opacity-50 pointer-events-none" : "",
          ].join(" ")}
        >
          {uploading ? (
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-foreground">
              <Spinner size={16} className="animate-spin" />
              <span>Processing capture…</span>
            </div>
          ) : (
            <label className="cursor-pointer flex items-center gap-3 text-xs font-mono font-bold">
              <span className="p-1.5 bg-accent border border-black">
                <UploadSimple size={16} weight="bold" className="text-black" />
              </span>
              <span className="text-foreground">
                Drop a <code className="bg-surface-2 px-1 border border-black text-black">.pcap</code> or <code className="bg-surface-2 px-1 border border-black text-black">.pcapng</code> file here, or{" "}
                <span className="text-black underline decoration-2 hover:bg-accent px-0.5">browse</span>
              </span>
              <input type="file" accept=".pcap,.pcapng" className="hidden" onChange={onFileInput} />
            </label>
          )}
        </div>

        {uploadErr && (
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-sev-critical bg-sev-critical-bg border-2 border-black px-3 py-2 brutal-shadow-sm">
            <WarningCircle size={14} weight="bold" />
            <span>{uploadErr}</span>
          </div>
        )}

        {/* Pre-loaded captures — Neo-Brutalist chips with box-shadows */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-muted font-bold">samples:</span>
          <Link
            href="/overview?capture=cap-001"
            className="inline-flex items-center gap-2 px-2.5 py-1.5 bg-surface-0 border-2 border-black text-foreground hover:bg-accent/15 transition-all brutal-shadow-sm hover:translate-x-[-1px] hover:translate-y-[-1px]"
          >
            <span className="font-bold">synthetic_mail_incident.pcap</span>
            <span className="bg-red-500 text-white border border-black text-[10px] font-bold px-1 py-0.2 tabular-nums">40/F</span>
            <ArrowRight size={11} weight="bold" className="text-black" />
          </Link>
          <Link
            href="/overview?capture=cap-002"
            className="inline-flex items-center gap-2 px-2.5 py-1.5 bg-surface-0 border-2 border-black text-foreground hover:bg-accent/15 transition-all brutal-shadow-sm hover:translate-x-[-1px] hover:translate-y-[-1px]"
          >
            <span className="font-bold">securemail_baseline.pcap</span>
            <span className="bg-emerald-400 text-black border border-black text-[10px] font-bold px-1 py-0.2 tabular-nums">100/A</span>
            <ArrowRight size={11} weight="bold" className="text-black" />
          </Link>
        </div>

        {/* Detection rules — compact 2-column Neo-Brutalist table */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="font-bold uppercase tracking-wider text-black">active detection rules</span>
            <span className="font-semibold text-muted">44 rules · v2025.03.1</span>
          </div>
          <div className="border-2 border-black bg-surface-0 overflow-hidden brutal-shadow">
            <table className="w-full text-xs font-mono text-left">
              <thead className="bg-surface-1 text-[11px] font-bold text-black uppercase border-b-2 border-black">
                <tr>
                  <th className="py-2 px-3 w-14">Status</th>
                  <th className="py-2 px-3">Capability</th>
                  <th className="py-2 px-3">Detection Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-black/20 text-foreground font-medium">
                <tr className="hover:bg-accent/10 transition-colors">
                  <td className="py-2 px-3"><span className="inline-block w-2.5 h-2.5 bg-emerald-400 border border-black" /></td>
                  <td className="py-2 px-3 font-bold text-black">STARTTLS Strip Detection</td>
                  <td className="py-2 px-3 text-muted">MITM 250-STARTTLS tampering, forced cleartext auth fallback</td>
                </tr>
                <tr className="hover:bg-accent/10 transition-colors">
                  <td className="py-2 px-3"><span className="inline-block w-2.5 h-2.5 bg-emerald-400 border border-black" /></td>
                  <td className="py-2 px-3 font-bold text-black">JA3/JA3S Fingerprinting</td>
                  <td className="py-2 px-3 text-muted">Client/server handshake MD5 signatures for MTA identification</td>
                </tr>
                <tr className="hover:bg-accent/10 transition-colors">
                  <td className="py-2 px-3"><span className="inline-block w-2.5 h-2.5 bg-emerald-400 border border-black" /></td>
                  <td className="py-2 px-3 font-bold text-black">RFC 8314 Compliance</td>
                  <td className="py-2 px-3 text-muted">Cleartext credential deprecation on ports 110, 143, 587</td>
                </tr>
                <tr className="hover:bg-accent/10 transition-colors">
                  <td className="py-2 px-3"><span className="inline-block w-2.5 h-2.5 bg-emerald-400 border border-black" /></td>
                  <td className="py-2 px-3 font-bold text-black">EFAIL / MDC Validation</td>
                  <td className="py-2 px-3 text-muted">OpenPGP PKESK algorithm and modification detection code checks</td>
                </tr>
                <tr className="hover:bg-accent/10 transition-colors">
                  <td className="py-2 px-3"><span className="inline-block w-2.5 h-2.5 bg-emerald-400 border border-black" /></td>
                  <td className="py-2 px-3 font-bold text-black">Post-Quantum Readiness</td>
                  <td className="py-2 px-3 text-muted">X25519MLKEM768 hybrid key exchange, HNDL exposure ratio</td>
                </tr>
                <tr className="hover:bg-accent/10 transition-colors">
                  <td className="py-2 px-3"><span className="inline-block w-2.5 h-2.5 bg-emerald-400 border border-black" /></td>
                  <td className="py-2 px-3 font-bold text-black">X.509 Chain Custody</td>
                  <td className="py-2 px-3 text-muted">Certificate expiry, self-signed detection, SAN hostname matching</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Forensic evidence feed — Neo-Brutalist data table */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="font-bold uppercase tracking-wider text-black">evidence feed · cap-001</span>
            <Link href="/findings?capture=cap-001" className="font-bold text-black hover:text-accent-orange flex items-center gap-1.5 underline decoration-2">
              all findings <ArrowRight size={11} weight="bold" />
            </Link>
          </div>
          <div className="border-2 border-black bg-surface-0 overflow-hidden brutal-shadow">
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-mono text-left">
                <thead className="bg-surface-1 text-[11px] font-bold text-black uppercase border-b-2 border-black">
                  <tr>
                    <th className="py-2 px-3 w-24">Severity</th>
                    <th className="py-2 px-3 w-32">Rule ID</th>
                    <th className="py-2 px-3">Finding</th>
                    <th className="py-2 px-3 w-40">Target</th>
                    <th className="py-2 px-3 w-60">Wireshark Filter</th>
                    <th className="py-2 px-3 w-24 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-black/20">
                  {findingsForCap001.slice(0, 8).map((f) => (
                    <tr key={f.id} className="hover:bg-accent/10 transition-colors">
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
                        <code className="text-[10px] text-foreground bg-surface-1 px-1.5 py-0.5 border border-black/30 block truncate max-w-xs">{f.wireshark_filter}</code>
                      </td>
                      <td className="py-2 px-3 text-right">
                        <Link
                          href={`/sessions?capture=cap-001&session=${f.session_id}`}
                          className="inline-block px-2 py-0.5 bg-accent hover:bg-accent-hover text-black border border-black text-[11px] font-bold shadow-[1px_1px_0_#000] hover:shadow-none transition-all"
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
