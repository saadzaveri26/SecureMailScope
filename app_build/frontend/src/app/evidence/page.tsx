"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { getEvidence, getCustody } from "@/data";
import type { Evidence, CustodyEvent } from "@/types";
import { CustodyTimeline } from "@/components/custody-timeline";
import { Copy, Check } from "@phosphor-icons/react";

export default function EvidencePage() {
  return (
    <Suspense fallback={<div className="max-w-[1400px] mx-auto px-4 py-8 animate-pulse"><div className="h-6 w-40 bg-surface-2 rounded" /></div>}>
      <EvidenceContent />
    </Suspense>
  );
}

const TYPE_LABELS: Record<string, string> = {
  session: "Session",
  starttls_exchange: "STARTTLS exchange",
  handshake: "TLS handshake",
  certificate: "Certificate",
  cleartext_auth: "Cleartext auth",
  message_marker: "Message marker",
  baseline_deviation: "Baseline deviation",
};

function EvidenceContent() {
  const params = useSearchParams();
  const captureId = params.get("capture") ?? "cap-001";
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [custody, setCustody] = useState<CustodyEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"evidence" | "custody">("evidence");
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    Promise.all([getEvidence(captureId), getCustody(captureId)])
      .then(([ev, cu]) => { if (active) { setEvidence(ev); setCustody(cu); setLoading(false); } })
      .catch(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [captureId]);

  function copyFilter(id: string, filter: string) {
    navigator.clipboard.writeText(filter);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  }

  if (loading) {
    return (
      <div className="max-w-[1400px] mx-auto px-4 py-8 space-y-4 animate-pulse">
        <div className="h-6 w-40 bg-surface-2 rounded" />
        <div className="h-64 bg-surface-0 rounded-lg border border-border-subtle" />
      </div>
    );
  }

  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Evidence chain</h1>
        <span className="text-xs text-muted font-mono">{captureId}</span>
      </div>

      <div className="flex items-center gap-1 border-b border-border-subtle">
        <button
          onClick={() => setTab("evidence")}
          className={`px-3 py-2 text-sm border-b-2 transition-colors ${tab === "evidence" ? "border-brand text-brand font-medium" : "border-transparent text-muted hover:text-foreground"}`}
        >
          Evidence ({evidence.length})
        </button>
        <button
          onClick={() => setTab("custody")}
          className={`px-3 py-2 text-sm border-b-2 transition-colors ${tab === "custody" ? "border-brand text-brand font-medium" : "border-transparent text-muted hover:text-foreground"}`}
        >
          Integrity record ({custody.length})
        </button>
      </div>

      {tab === "evidence" ? (
        <div className="bg-surface-0 rounded-lg border border-border-subtle overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border-subtle bg-surface-1 text-left text-muted">
                <th className="px-3 py-2 font-medium">ID</th>
                <th className="px-3 py-2 font-medium">Type</th>
                <th className="px-3 py-2 font-medium">Session</th>
                <th className="px-3 py-2 font-medium">Summary</th>
                <th className="px-3 py-2 font-medium">Frames</th>
                <th className="px-3 py-2 font-medium">Filter</th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((ev) => (
                <tr key={ev.id} className="border-b border-border-subtle last:border-0 hover:bg-surface-1 transition-colors">
                  <td className="px-3 py-2.5 font-mono text-brand">{ev.id}</td>
                  <td className="px-3 py-2.5">
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-surface-2 text-[11px] font-medium text-foreground">
                      {TYPE_LABELS[ev.type] ?? ev.type}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 font-mono text-muted">{ev.session_id ?? "—"}</td>
                  <td className="px-3 py-2.5 text-foreground max-w-xs truncate">{ev.summary}</td>
                  <td className="px-3 py-2.5 font-mono text-muted tabular-nums">
                    {ev.frames.map((f) => `#${f}`).join(", ")}
                  </td>
                  <td className="px-3 py-2.5">
                    {ev.wireshark_filter ? (
                      <div className="flex items-center gap-1.5 max-w-[220px]">
                        <code className="font-mono text-brand truncate">{ev.wireshark_filter}</code>
                        <button
                          onClick={() => copyFilter(ev.id, ev.wireshark_filter)}
                          className="p-0.5 hover:bg-surface-2 rounded text-muted hover:text-foreground transition-colors shrink-0"
                          title="Copy filter"
                        >
                          {copied === ev.id ? <Check size={11} className="text-brand" /> : <Copy size={11} />}
                        </button>
                      </div>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </td>
                </tr>
              ))}
              {evidence.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-8 text-center text-muted">
                    No evidence items for this capture.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="bg-surface-0 rounded-lg border border-border-subtle p-5">
          <h3 className="text-sm font-medium text-foreground mb-4">Integrity record and audit trail</h3>
          <CustodyTimeline events={custody} />
        </div>
      )}
    </div>
  );
}
