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
  if (g === "A" || g === "B") return "text-foreground";
  if (g === "C") return "text-sev-medium";
  if (g === "D") return "text-sev-high";
  return "text-sev-critical";
}

function statusIcon(s: string) {
  if (s === "complete") return <CheckCircle size={15} weight="bold" className="text-foreground" />;
  if (s === "processing") return <Spinner size={15} weight="bold" className="text-brand animate-spin" />;
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
  const isDemo = process.env.NEXT_PUBLIC_DEMO_MODE === "1" || process.env.NEXT_PUBLIC_DEMO_MODE === "true";
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
    <div className="max-w-[1400px] mx-auto px-4 py-8">
      <h1 className="text-xl font-semibold mb-6">Captures</h1>

      {isDemo ? (
        <div className="rounded-lg border border-border bg-surface-1 p-6 text-center text-xs text-muted mb-8">
          Uploads are disabled in the public demo
        </div>
      ) : (
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          className={[
            "border-2 border-dashed rounded-lg p-8 text-center transition-colors mb-8",
            dragOver ? "border-brand bg-brand-light" : "border-border-subtle bg-surface-1",
            uploading ? "opacity-60 pointer-events-none" : "",
          ].join(" ")}
        >
          {uploading ? (
            <div className="flex flex-col items-center gap-2">
              <Spinner size={28} className="text-brand animate-spin" />
              <p className="text-sm text-muted">Uploading capture...</p>
            </div>
          ) : (
            <label className="cursor-pointer flex flex-col items-center gap-2">
              <UploadSimple size={24} className="text-muted" />
              <p className="text-sm text-foreground font-medium">
                Drop a PCAP file here or click to browse
              </p>
              <p className="text-xs text-muted">
                Accepts .pcap and .pcapng files
              </p>
              <input type="file" accept=".pcap,.pcapng" className="hidden" onChange={onFileInput} />
            </label>
          )}
          {uploadErr && (
            <p className="text-xs text-sev-critical mt-3">{uploadErr}</p>
          )}
        </div>
      )}

      {polling && (
        <div className="flex items-center justify-between text-xs text-brand bg-brand-light px-4 py-2 rounded-md mb-4 border border-brand/20">
          <div className="flex items-center gap-2">
            <Spinner size={14} className="animate-spin" />
            <span>Processing capture... polling for status</span>
          </div>
          <button
            onClick={() => { setPolling(null); load(); }}
            className="text-xs text-muted hover:text-foreground underline ml-4 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {loading && !caps.length ? (
        <div className="bg-surface-0 rounded-lg border border-border-subtle overflow-hidden animate-pulse">
          <div className="h-10 bg-surface-1 border-b border-border-subtle" />
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-10 border-b border-border-subtle flex items-center px-4 gap-4">
              <div className="h-4 w-6 bg-surface-2 rounded" />
              <div className="h-4 w-48 bg-surface-2 rounded" />
              <div className="h-4 w-16 bg-surface-2 rounded" />
              <div className="h-4 w-16 bg-surface-2 rounded" />
              <div className="h-4 w-12 bg-surface-2 rounded" />
            </div>
          ))}
        </div>
      ) : error ? (
        <div className="bg-sev-critical-bg border border-sev-critical/20 rounded-md p-4 space-y-2 mb-4">
          <p className="text-xs font-semibold text-sev-critical">Failed to load captures</p>
          <p className="text-xs text-sev-critical/90">{error}</p>
          <button
            onClick={() => {
              setLoading(true);
              setError(null);
              load();
            }}
            className="text-xs font-medium text-sev-critical underline"
          >
            Retry
          </button>
        </div>
      ) : caps.length === 0 ? (
        <div className="text-center py-16 bg-surface-0 rounded-lg border border-border-subtle text-muted">
          <p className="text-xs font-medium text-foreground">No captures yet</p>
          <p className="text-xs text-muted mt-1">Upload a PCAP or PCAPNG file to begin passive analysis.</p>
        </div>
      ) : (
        <div className="bg-surface-0 rounded-lg border border-border-subtle overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-surface-1 text-left text-muted h-9">
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Filename</th>
                <th className="px-4 py-2 font-medium">Size</th>
                <th className="px-4 py-2 font-medium">Packets</th>
                <th className="px-4 py-2 font-medium text-right">Score</th>
                <th className="px-4 py-2 font-medium text-right">Grade</th>
                <th className="px-4 py-2 font-medium">Date</th>
              </tr>
            </thead>
            <tbody>
              {(isDemo ? caps.filter((c) => c.id.startsWith("cap-00")) : caps).map((c) => (
                <tr key={c.id} className="border-b border-border-subtle last:border-0 hover:bg-surface-1 transition-colors h-10">
                  <td className="px-4 py-2">{statusIcon(c.status)}</td>
                  <td className="px-4 py-2">
                    {c.status === "complete" ? (
                      <Link href={`/overview?capture=${c.id}`} className="text-brand hover:underline font-medium">
                        {c.filename}
                      </Link>
                    ) : (
                      <span className="font-medium text-foreground">{c.filename}</span>
                    )}
                    {c.status === "failed" && c.error && (
                      <p className="text-[11px] text-sev-critical mt-0.5">{c.error}</p>
                    )}
                  </td>
                  <td className="px-4 py-2 text-muted tabular-nums">{formatBytes(c.size_bytes)}</td>
                  <td className="px-4 py-2 text-muted font-mono tabular-nums">
                    {c.packet_count.toLocaleString()}
                  </td>
                  <td className="px-4 py-2 text-right font-mono tabular-nums">
                    {c.posture_score !== null ? c.posture_score : (
                      <span className="text-not-observable">—</span>
                    )}
                  </td>
                  <td className={`px-4 py-2 text-right font-mono ${gradeColor(c.grade)}`}>
                    {c.grade ?? <span className="text-not-observable font-normal text-xs">—</span>}
                  </td>
                  <td className="px-4 py-2 text-muted tabular-nums">{formatDate(c.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
