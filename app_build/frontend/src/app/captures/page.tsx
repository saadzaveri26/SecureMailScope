"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import Link from "next/link";
import type { Capture } from "@/types";
import { getCaptures, uploadCapture, getCapture } from "@/data";
import {
  UploadSimple,
  Spinner,
  CheckCircle,
  XCircle,
  Clock,
} from "@phosphor-icons/react";

function gradeColor(g: string | null) {
  if (!g) return "text-muted";
  if (g === "A" || g === "B") return "text-sev-pass";
  if (g === "C") return "text-sev-medium";
  if (g === "D") return "text-sev-high";
  return "text-sev-critical";
}

function statusIcon(s: string) {
  if (s === "complete") return <CheckCircle size={15} weight="bold" className="text-sev-pass" />;
  if (s === "processing") return <Spinner size={15} weight="bold" className="text-accent animate-spin" />;
  if (s === "failed") return <XCircle size={15} weight="bold" className="text-sev-critical" />;
  return <Clock size={15} weight="bold" className="text-muted" />;
}

function formatBytes(b: number) {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1048576).toFixed(1)} MB`;
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function CapturesPage() {
  const [caps, setCaps] = useState<Capture[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadErr, setUploadErr] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [polling, setPolling] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await getCaptures();
      setCaps(data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load captures");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    getCaptures()
      .then((data) => {
        if (active) {
          setCaps(data);
          setLoading(false);
        }
      })
      .catch((e: unknown) => {
        if (active) {
          setError(e instanceof Error ? e.message : "Failed to load captures");
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!polling) return;
    let delay = 1000;
    let cancelled = false;
    let attempts = 0;

    async function poll() {
      if (cancelled) return;
      attempts += 1;
      try {
        const c = await getCapture(polling!);
        if (c.status === "complete" || c.status === "failed" || attempts >= 10) {
          setPolling(null);
          load();
          return;
        }
      } catch {
        if (attempts >= 10) {
          setPolling(null);
          load();
          return;
        }
      }
      delay = Math.min(delay * 1.5, 5000);
      pollRef.current = setTimeout(poll, delay);
    }

    pollRef.current = setTimeout(poll, delay);
    return () => {
      cancelled = true;
      if (pollRef.current) clearTimeout(pollRef.current);
    };
  }, [polling, load]);

  async function handleUpload(file: File) {
    if (!file.name.endsWith(".pcap") && !file.name.endsWith(".pcapng")) {
      setUploadErr("Only .pcap and .pcapng files are accepted");
      return;
    }
    setUploading(true);
    setUploadErr(null);
    try {
      const res = await uploadCapture(file);
      setPolling(res.capture_id);
      load();
    } catch (e: unknown) {
      setUploadErr(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  }

  function onDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) handleUpload(f);
  }

  function onFileInput(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (f) handleUpload(f);
  }

  return (
    <div className="w-full px-4 2xl:px-6 py-4 space-y-4">
      <h1 className="text-[20px] font-semibold text-foreground">Captures</h1>

      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        className={[
          "border border-dashed border-border rounded-[var(--radius-md)] p-4 text-center bg-surface-0 xcor-shadow-subtle",
          `transition-all duration-[var(--motion-normal)]`,
          dragOver ? "border-accent bg-accent-soft" : "hover:bg-surface-1",
          uploading ? "opacity-60 pointer-events-none" : "",
        ].join(" ")}
        role="region"
        aria-label="PCAP file upload zone"
      >
        {uploading ? (
          <div className="flex items-center justify-center gap-2 py-2">
            <Spinner size={18} className="text-accent animate-spin" />
            <p className="text-[13px] text-muted">Uploading capture…</p>
          </div>
        ) : (
          <label className="cursor-pointer flex items-center justify-center gap-2 py-2 focus-ring rounded-[var(--radius-md)]">
            <UploadSimple size={18} className="text-accent" />
            <span className="text-[13px] text-foreground font-medium">
              Drop a .pcap or .pcapng file here, or <span className="text-accent underline">browse</span>
            </span>
            <input type="file" accept=".pcap,.pcapng" className="hidden" onChange={onFileInput} />
          </label>
        )}
        {uploadErr && (
          <p className="text-[13px] text-sev-critical mt-2 font-medium" role="alert">{uploadErr}</p>
        )}
      </div>

      {polling && (
        <div className="flex items-center justify-between text-[var(--font-size-md)] text-foreground bg-surface-1 px-4 py-2 rounded-[var(--radius-sm)] mb-4 border border-border">
          <div className="flex items-center gap-2">
            <Spinner size={14} className="animate-spin text-accent" />
            <span>Processing capture... polling for status</span>
          </div>
          <button
            onClick={() => { setPolling(null); load(); }}
            className="text-[var(--font-size-md)] text-muted hover:text-foreground underline ml-4 cursor-pointer focus-ring rounded-[var(--radius-xs)]"
          >
            Dismiss
          </button>
        </div>
      )}

      {loading && !caps.length ? (
        <div className="bg-surface-0 rounded-[var(--radius-md)] border border-border overflow-hidden animate-pulse xcor-shadow">
          <div className="h-10 bg-surface-1 border-b border-border" />
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-10 border-b border-border flex items-center px-4 gap-4">
              <div className="h-4 w-6 bg-surface-2 rounded-[var(--radius-xs)]" />
              <div className="h-4 w-48 bg-surface-2 rounded-[var(--radius-xs)]" />
              <div className="h-4 w-16 bg-surface-2 rounded-[var(--radius-xs)]" />
              <div className="h-4 w-16 bg-surface-2 rounded-[var(--radius-xs)]" />
              <div className="h-4 w-12 bg-surface-2 rounded-[var(--radius-xs)]" />
            </div>
          ))}
        </div>
      ) : error ? (
        <div className="bg-sev-critical-bg border border-border rounded-[var(--radius-md)] p-4 space-y-2 mb-4" role="alert">
          <p className="text-[var(--font-size-md)] font-bold text-sev-critical">Failed to load captures</p>
          <p className="text-[var(--font-size-md)] text-sev-critical/90">{error}</p>
          <button
            onClick={() => {
              setLoading(true);
              setError(null);
              load();
            }}
            className="text-[var(--font-size-md)] font-medium text-text-tertiary underline cursor-pointer focus-ring rounded-[var(--radius-xs)]"
          >
            Retry
          </button>
        </div>
      ) : caps.length === 0 ? (
        <div className="text-center py-12 bg-surface-0 rounded-[var(--radius-md)] border border-border text-muted xcor-shadow-subtle">
          <p className="text-[14px] font-medium text-foreground">No captures yet</p>
          <p className="text-[13px] text-muted mt-1">Upload a PCAP or PCAPNG file to begin passive analysis.</p>
        </div>
      ) : (
        <div className="bg-surface-0 rounded-[var(--radius-md)] border border-border overflow-hidden xcor-shadow-subtle">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-b border-border bg-surface-1 text-left text-muted h-8">
                <th scope="col" className="px-3 py-1 font-medium">Status</th>
                <th scope="col" className="px-3 py-1 font-medium">Filename</th>
                <th scope="col" className="px-3 py-1 font-medium">Size</th>
                <th scope="col" className="px-3 py-1 font-medium">Packets</th>
                <th scope="col" className="px-3 py-1 font-medium text-right">Score</th>
                <th scope="col" className="px-3 py-1 font-medium text-right">Grade</th>
                <th scope="col" className="px-3 py-1 font-medium">Date</th>
              </tr>
            </thead>
            <tbody>
              {caps.map((c) => (
                <tr key={c.id} className="border-b border-border last:border-0 hover:bg-surface-1 transition-colors h-8">
                  <td className="px-3 py-1">{statusIcon(c.status)}</td>
                  <td className="px-3 py-1">
                    {c.status === "complete" ? (
                      <Link href={`/overview?capture=${c.id}`} className="text-text-tertiary hover:text-accent font-medium focus-ring rounded-[var(--radius-xs)]">
                        {c.filename}
                      </Link>
                    ) : (
                      <span className="font-medium text-foreground">{c.filename}</span>
                    )}
                    {c.status === "failed" && c.error && (
                      <p className="text-[11px] text-sev-critical">{c.error}</p>
                    )}
                  </td>
                  <td className="px-3 py-1 text-muted tabular-nums">{formatBytes(c.size_bytes)}</td>
                  <td className="px-3 py-1 text-muted font-mono tabular-nums">
                    {c.packet_count.toLocaleString()}
                  </td>
                  <td className="px-3 py-1 text-right font-mono tabular-nums">
                    {c.posture_score !== null ? c.posture_score : (
                      <span className="text-not-observable">—</span>
                    )}
                  </td>
                  <td className={`px-3 py-1 text-right font-mono font-bold ${gradeColor(c.grade)}`}>
                    {c.grade ?? <span className="text-not-observable font-normal">—</span>}
                  </td>
                  <td className="px-3 py-1 text-muted tabular-nums">{formatDate(c.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
