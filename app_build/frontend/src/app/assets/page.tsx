"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { getCaptures, getAssets } from "@/data";
import type { Capture, Asset } from "@/types";

function AssetsContent() {
  const sp = useSearchParams();
  const capParam = sp.get("capture");

  const [caps, setCaps] = useState<Capture[]>([]);
  const [activeCap, setActiveCap] = useState<string>("");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [roleFilter, setRoleFilter] = useState<string>("all");

  useEffect(() => {
    getCaptures().then((c) => {
      setCaps(c);
      const chosen = capParam && c.some((x) => x.id === capParam) ? capParam : c[0]?.id ?? "";
      setActiveCap(chosen);
    });
  }, [capParam]);

  useEffect(() => {
    if (!activeCap) return;
    setLoading(true);
    getAssets(activeCap)
      .then((a) => {
        setAssets(a);
        setSelectedAsset(a[0] ?? null);
      })
      .finally(() => setLoading(false));
  }, [activeCap]);

  const filteredAssets = assets.filter((a) => {
    if (roleFilter !== "all" && a.server_role !== roleFilter) return false;
    return true;
  });

  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-foreground">Endpoint Inventory</h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-blue-50 text-brand border border-blue-200">
              Contract 0.2 §9
            </span>
          </div>
          <p className="text-xs text-muted mt-1">
            Observed mail endpoints, cipher suites, certificates, and post-quantum readiness across captured traffic.
          </p>
        </div>

        {/* Capture selector */}
        {caps.length > 1 && (
          <select
            value={activeCap}
            onChange={(e) => setActiveCap(e.target.value)}
            className="text-xs bg-surface-0 border border-border rounded px-3 py-1.5 font-mono text-foreground"
          >
            {caps.map((c) => (
              <option key={c.id} value={c.id}>
                {c.filename} ({c.id})
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Forensic Disclaimer Notice */}
      <div className="p-3.5 rounded-lg bg-amber-50/70 border border-amber-200 text-xs text-amber-900 flex items-start gap-2.5">
        <span className="font-bold shrink-0">Observed vs Supported:</span>
        <span>
          This inventory reflects only the cryptographic parameters <strong>observed</strong> in this packet capture. It is not an active probe and does not represent the full capabilities supported by the remote server.
        </span>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-2 border-b border-border pb-3">
        <span className="text-xs text-muted font-medium">Filter by role:</span>
        {["all", "submission", "inbound_relay", "mailbox"].map((role) => (
          <button
            key={role}
            onClick={() => setRoleFilter(role)}
            className={[
              "px-2.5 py-1 rounded text-xs transition-colors",
              roleFilter === role
                ? "bg-brand text-white font-medium"
                : "bg-surface-0 text-muted hover:text-foreground border border-border",
            ].join(" ")}
          >
            {role === "all" ? "All Endpoints" : role}
          </button>
        ))}
        <span className="ml-auto text-xs text-muted font-mono">{filteredAssets.length} observed endpoints</span>
      </div>

      {loading ? (
        <div className="py-12 text-center text-xs text-muted">Loading observed endpoint inventory...</div>
      ) : filteredAssets.length === 0 ? (
        <div className="py-12 text-center text-xs text-muted">No endpoints observed matching the filter.</div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Endpoint List */}
          <div className="lg:col-span-5 space-y-3">
            {filteredAssets.map((asset) => {
              const isSelected = selectedAsset?.id === asset.id;
              return (
                <div
                  key={asset.id}
                  onClick={() => setSelectedAsset(asset)}
                  className={[
                    "p-4 rounded-lg border transition-all cursor-pointer",
                    isSelected
                      ? "bg-surface-0 border-brand shadow-sm ring-1 ring-brand"
                      : "bg-surface-0 border-border hover:border-slate-300",
                  ].join(" ")}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <span className="font-mono text-xs font-semibold text-foreground">{asset.id}</span>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-100 text-slate-700">
                          {asset.server_role}
                        </span>
                        <span className="text-[11px] text-muted font-mono">
                          {asset.protocols.map((p) => p.toUpperCase()).join(", ")}
                        </span>
                      </div>
                    </div>

                    <div className="text-right">
                      <span className="text-[11px] text-muted font-mono block">
                        {asset.sessions_observed} sess · {asset.clients_observed} cli
                      </span>
                      {asset.pqc && asset.pqc.hybrid_group_negotiated && (
                        <span className="inline-block mt-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          PQ-Hybrid
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="mt-3 pt-3 border-t border-border/60 grid grid-cols-2 gap-2 text-[11px]">
                    <div>
                      <span className="text-muted block text-[10px]">TLS Versions Observed</span>
                      <span className="font-mono text-foreground">
                        {asset.tls_versions_observed.length > 0
                          ? asset.tls_versions_observed.join(", ")
                          : "None (Plaintext)"}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted block text-[10px]">Forward Secrecy</span>
                      <span
                        className={[
                          "font-mono font-medium",
                          asset.forward_secrecy === "all"
                            ? "text-emerald-600"
                            : asset.forward_secrecy === "none"
                            ? "text-rose-600"
                            : "text-amber-600",
                        ].join(" ")}
                      >
                        {asset.forward_secrecy}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Endpoint Detail Card */}
          <div className="lg:col-span-7">
            {selectedAsset ? (
              <div className="bg-surface-0 border border-border rounded-lg p-5 space-y-6">
                <div className="flex items-start justify-between border-b border-border pb-4">
                  <div>
                    <h2 className="text-sm font-semibold text-foreground font-mono">{selectedAsset.id}</h2>
                    <p className="text-xs text-muted mt-0.5">
                      Server: <span className="text-foreground font-mono">{selectedAsset.server}</span> (Port {selectedAsset.port})
                    </p>
                  </div>
                  <div className="text-right text-xs">
                    <span className="text-muted text-[10px] block">First seen: {new Date(selectedAsset.first_seen).toLocaleTimeString()}</span>
                    <span className="text-muted text-[10px] block">Last seen: {new Date(selectedAsset.last_seen).toLocaleTimeString()}</span>
                  </div>
                </div>

                {/* Cryptographic Observations */}
                <div className="space-y-3">
                  <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider text-muted">
                    Observed Cryptographic Parameters
                  </h3>

                  <div className="grid grid-cols-2 gap-4 text-xs">
                    <div className="p-3 rounded border border-border bg-slate-50/50">
                      <span className="text-muted text-[11px] block">STARTTLS Observed Support</span>
                      <span className="font-mono font-medium text-foreground mt-0.5 block">
                        {selectedAsset.starttls_support}
                      </span>
                    </div>
                    <div className="p-3 rounded border border-border bg-slate-50/50">
                      <span className="text-muted text-[11px] block">Forward Secrecy Observed</span>
                      <span className="font-mono font-medium text-foreground mt-0.5 block">
                        {selectedAsset.forward_secrecy}
                      </span>
                    </div>
                  </div>

                  <div>
                    <span className="text-xs text-muted block mb-1">Cipher Suites Observed:</span>
                    {selectedAsset.cipher_suites_observed.length > 0 ? (
                      <div className="space-y-1">
                        {selectedAsset.cipher_suites_observed.map((cs) => (
                          <div key={cs} className="font-mono text-xs p-2 rounded bg-slate-50 border border-border text-foreground">
                            {cs}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-xs text-muted italic">No TLS cipher suites observed</span>
                    )}
                  </div>

                  {selectedAsset.key_exchange_groups_observed.length > 0 && (
                    <div>
                      <span className="text-xs text-muted block mb-1">Key Exchange Groups Observed:</span>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedAsset.key_exchange_groups_observed.map((grp) => (
                          <span key={grp} className="px-2 py-1 rounded bg-slate-100 font-mono text-xs text-foreground">
                            {grp}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Certificates Observed */}
                <div className="space-y-3 border-t border-border pt-4">
                  <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider text-muted">
                    Observed Certificates ({selectedAsset.certificates.length})
                  </h3>

                  {selectedAsset.certificates.length > 0 ? (
                    <div className="space-y-2">
                      {selectedAsset.certificates.map((cert) => (
                        <div key={cert.sha256} className="p-3 rounded border border-border bg-slate-50/50 text-xs space-y-1.5">
                          <div>
                            <span className="text-muted text-[10px] block">Subject:</span>
                            <span className="font-mono text-foreground font-medium">{cert.subject}</span>
                          </div>
                          <div>
                            <span className="text-muted text-[10px] block">Issuer:</span>
                            <span className="font-mono text-muted">{cert.issuer}</span>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                            <div>
                              <span className="text-muted text-[10px] block">Key / Algorithm:</span>
                              <span className="font-mono">{cert.key_algorithm} {cert.key_bits}-bit</span>
                            </div>
                            <div>
                              <span className="text-muted text-[10px] block">Expires:</span>
                              <span className="font-mono">{cert.not_after}</span>
                            </div>
                          </div>
                          <div className="pt-1">
                            <span className="text-muted text-[10px] block">SHA-256 Fingerprint:</span>
                            <span className="font-mono text-[10px] text-muted break-all">{cert.sha256}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted italic">
                      No certificate observed on wire (either plaintext connection or TLS 1.3 encrypted handshake).
                    </p>
                  )}
                </div>

                {/* PQC / Post-Quantum Analysis (§12) */}
                <div className="space-y-3 border-t border-border pt-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider text-muted">
                      Post-Quantum Cryptography Assessment (§12)
                    </h3>
                    <span className="text-[10px] font-mono text-muted">Informational only — No score impact</span>
                  </div>

                  {selectedAsset.pqc ? (
                    <div className="p-3.5 rounded-lg border border-border bg-slate-50 text-xs space-y-2">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-foreground">Hybrid Groups:</span>
                        <span className="font-mono text-muted">
                          {selectedAsset.pqc.groups_seen.length > 0
                            ? selectedAsset.pqc.groups_seen.join(", ")
                            : "None observed"}
                        </span>
                      </div>
                      <p className="text-xs text-muted leading-relaxed">
                        {selectedAsset.pqc.note}
                      </p>
                      <div className="text-[11px] text-muted italic pt-1">
                        Framing: Evaluates potential exposure of long-retained mail to retrospective "harvest now, decrypt later" attacks. Never framed as an active today vulnerability.
                      </div>
                    </div>
                  ) : (
                    <div className="p-3 rounded border border-border/60 bg-slate-50/40 text-xs text-muted">
                      PQC status null: No post-quantum cryptographic groups or negotiations observed in capture.
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-xs text-muted border border-dashed border-border rounded-lg">
                Select an observed endpoint to view details
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function AssetsPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-xs text-muted">Loading...</div>}>
      <AssetsContent />
    </Suspense>
  );
}
