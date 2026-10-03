"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import type { Session, Protocol, Transport, PaginatedSessions, Asset } from "@/types";
import { getSessions, getSession, getAssets } from "@/data";
import { EvidenceTag } from "@/components/evidence-tag";
import { X, Copy, Check } from "@phosphor-icons/react";

export default function SessionsPage() {
  return (
    <Suspense fallback={<SessionsSkeleton />}>
      <SessionsContent />
    </Suspense>
  );
}

function SessionsSkeleton() {
  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8 space-y-6 animate-pulse">
      <div className="flex justify-between items-center">
        <div className="space-y-1">
          <div className="h-6 w-36 bg-surface-2 rounded" />
          <div className="h-4 w-64 bg-surface-2 rounded" />
        </div>
        <div className="h-8 w-48 bg-surface-2 rounded" />
      </div>
      <div className="bg-surface-0 rounded-sm border border-border overflow-hidden">
        <div className="h-10 bg-surface-1 border-b border-border" />
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-10 border-b border-border flex items-center px-4 gap-4">
            <div className="h-4 w-28 bg-surface-2 rounded" />
            <div className="h-4 w-16 bg-surface-2 rounded" />
            <div className="h-4 w-20 bg-surface-2 rounded" />
            <div className="h-4 w-32 bg-surface-2 rounded" />
            <div className="h-4 w-24 bg-surface-2 rounded" />
          </div>
        ))}
      </div>
    </div>
  );
}

function SessionsContent() {
  const params = useSearchParams();
  const capId = params.get("capture") ?? "cap-001";
  const initSessionId = params.get("session");

  const [view, setView] = useState<"sessions" | "endpoint">("sessions");
  const [data, setData] = useState<PaginatedSessions>({ items: [], total: 0, page: 1, page_size: 25 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [proto, setProto] = useState<string>("");
  const [trans, setTrans] = useState<string>("");
  const [page, setPage] = useState(1);
  const [selSession, setSelSession] = useState<Session | null>(null);
  const [copied, setCopied] = useState(false);

  const [assets, setAssets] = useState<Asset[]>([]);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [selAsset, setSelAsset] = useState<Asset | null>(null);
  const [roleFilter, setRoleFilter] = useState<string>("all");

  function loadSessions() {
    setLoading(true);
    setError(null);
    getSessions(capId, {
      protocol: proto ? (proto as Protocol) : undefined,
      transport: trans ? (trans as Transport) : undefined,
      page,
      page_size: 25,
    })
      .then((res) => {
        setData(res);
        setLoading(false);
      })
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : "Failed to load sessions");
        setLoading(false);
      });
  }

  useEffect(() => {
    let active = true;
    getSessions(capId, {
      protocol: proto ? (proto as Protocol) : undefined,
      transport: trans ? (trans as Transport) : undefined,
      page,
      page_size: 25,
    })
      .then((res) => {
        if (active) {
          setData(res);
          setLoading(false);
        }
      })
      .catch((e: unknown) => {
        if (active) {
          setError(e instanceof Error ? e.message : "Failed to load sessions");
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [capId, proto, trans, page]);

  useEffect(() => {
    if (!initSessionId) return;
    let active = true;
    getSession(capId, initSessionId).then((s) => {
      if (active && s) setSelSession(s);
    });
    return () => {
      active = false;
    };
  }, [capId, initSessionId]);

  useEffect(() => {
    if (view !== "endpoint") return;
    let active = true;
    getAssets(capId)
      .then((a) => {
        if (!active) return;
        setAssets(a);
        setSelAsset((prev) => prev ?? (a.length > 0 ? a[0] : null));
        setAssetsLoading(false);
      })
      .catch(() => {
        if (active) setAssetsLoading(false);
      });
    return () => {
      active = false;
    };
  }, [view, capId]);

  function copyText(txt: string) {
    navigator.clipboard.writeText(txt);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const filteredAssets = assets.filter((a) => {
    if (roleFilter !== "all" && a.server_role !== roleFilter) return false;
    return true;
  });

  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div>
          <h1 className="text-xl font-semibold">Sessions</h1>
          <p className="text-sm text-muted">
            Network email sessions extracted from capture <span className="font-mono text-foreground font-medium">{capId}</span>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex rounded-sm border border-border p-0.5 bg-surface-1">
            <button
              onClick={() => setView("sessions")}
              className={[
                "px-3 py-1.5 text-xs font-medium rounded transition-colors",
                view === "sessions"
                  ? "bg-surface-0 text-foreground"
                  : "text-muted hover:text-foreground",
              ].join(" ")}
            >
              Sessions
            </button>
            <button
              onClick={() => setView("endpoint")}
              className={[
                "px-3 py-1.5 text-xs font-medium rounded transition-colors",
                view === "endpoint"
                  ? "bg-surface-0 text-foreground"
                  : "text-muted hover:text-foreground",
              ].join(" ")}
            >
              By endpoint
            </button>
          </div>

          {view === "sessions" ? (
            <>
              <select
                value={proto}
                onChange={(e) => { setProto(e.target.value); setPage(1); }}
                className="text-xs bg-surface-0 border border-border rounded-sm px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-ink"
              >
                <option value="">All protocols</option>
                <option value="smtp">SMTP</option>
                <option value="imap">IMAP</option>
                <option value="pop3">POP3</option>
              </select>
              <select
                value={trans}
                onChange={(e) => { setTrans(e.target.value); setPage(1); }}
                className="text-xs bg-surface-0 border border-border rounded-sm px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-ink"
              >
                <option value="">All transports</option>
                <option value="implicit_tls">Implicit TLS</option>
                <option value="starttls">STARTTLS</option>
                <option value="plaintext">Plaintext</option>
              </select>
            </>
          ) : (
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              className="text-xs bg-surface-0 border border-border rounded-sm px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-ink"
            >
              <option value="all">All roles</option>
              <option value="submission">Submission</option>
              <option value="inbound_relay">Inbound relay</option>
              <option value="mailbox">Mailbox</option>
            </select>
          )}
        </div>
      </div>

      {view === "sessions" ? (
        loading ? (
          <SessionsSkeleton />
        ) : error ? (
          <div className="bg-sev-critical-bg border border-sev-critical/20 rounded-sm p-4 space-y-2">
            <p className="text-xs font-semibold text-sev-critical">Failed to load sessions</p>
            <p className="text-xs text-sev-critical/90">{error}</p>
            <button
              onClick={loadSessions}
              className="text-xs font-medium text-sev-critical underline"
            >
              Retry
            </button>
          </div>
        ) : data.items.length === 0 ? (
          <div className="text-center py-16 bg-surface-0 rounded-sm border border-border text-muted">
            <p className="text-xs font-medium text-foreground">No sessions match current filters</p>
            <p className="text-xs text-muted mt-1">Try adjusting the protocol or transport filter</p>
          </div>
        ) : (
          <div className="bg-surface-0 rounded-sm border border-border overflow-hidden">
            <div className="overflow-x-auto max-h-[750px] overflow-y-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-surface-1 z-10 border-b border-border shadow-none">
                  <tr className="text-left font-medium text-muted h-9">
                    <th className="px-4 py-2">Session</th>
                    <th className="px-4 py-2">Protocol</th>
                    <th className="px-4 py-2">Transport</th>
                    <th className="px-4 py-2">Security / TLS</th>
                    <th className="px-4 py-2">Frames</th>
                    <th className="px-4 py-2 text-right">Findings</th>
                    <th className="px-4 py-2 text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((s) => (
                    <tr
                      key={s.id}
                      onClick={() => getSession(capId, s.id).then((sess) => setSelSession(sess))}
                      className="border-b border-border last:border-0 hover:bg-surface-1 cursor-pointer transition-colors h-10"
                    >
                      <td className={`px-4 py-2 border-l-[3px] ${s.transport === "plaintext" ? "border-l-sev-critical" : "border-l-transparent"}`}>
                        <div className="font-mono text-xs font-medium text-foreground">{s.id}</div>
                        <div className="text-[11px] text-muted font-mono truncate max-w-xs">
                          {s.client} → {s.server}:{s.server_port}
                        </div>
                      </td>
                      <td className="px-4 py-2">
                        <span className="uppercase text-xs font-mono font-medium px-1.5 py-0.5 bg-surface-2 rounded-[3px] border border-border">
                          {s.protocol}
                        </span>
                      </td>
                      <td className="px-4 py-2">
                        <TransportBadge transport={s.transport} />
                      </td>
                      <td className="px-4 py-2">
                        {s.transport === "plaintext" ? (
                          <span className="text-xs text-sev-critical font-medium font-mono">
                            Plaintext (Unencrypted)
                          </span>
                        ) : s.tls ? (
                          <div>
                            <span className="text-xs font-mono font-medium text-foreground">{s.tls.version}</span>
                            <span className="text-[11px] text-muted block truncate max-w-[200px] font-mono">{s.tls.cipher_suite}</span>
                          </div>
                        ) : (
                          <span className="text-xs text-muted font-mono">—</span>
                        )}
                      </td>
                      <td className="px-4 py-2 font-mono">
                        <EvidenceTag>#{s.first_frame}–#{s.last_frame}</EvidenceTag>
                      </td>
                      <td className="px-4 py-2 text-right">
                        {s.findings_count > 0 ? (
                          <span className="font-mono font-semibold text-sev-critical tabular-nums">
                            {s.findings_count}
                          </span>
                        ) : (
                          <span className="text-muted font-mono tabular-nums">0</span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-right">
                        <button
                          onClick={(e) => { e.stopPropagation(); getSession(capId, s.id).then((sess) => setSelSession(sess)); }}
                          className="text-xs font-medium text-foreground underline hover:text-ink"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex items-center justify-between px-4 py-2.5 border-t border-border bg-surface-1 text-xs text-muted">
              <span className="tabular-nums">
                Showing {data.items.length} of {data.total} sessions
              </span>
              <div className="flex items-center gap-2">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="px-2.5 py-1 border border-border rounded-sm bg-surface-0 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-surface-2 text-foreground"
                >
                  Previous
                </button>
                <span className="text-foreground font-medium tabular-nums">{page}</span>
                <button
                  disabled={page * data.page_size >= data.total}
                  onClick={() => setPage((p) => p + 1)}
                  className="px-2.5 py-1 border border-border rounded-sm bg-surface-0 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-surface-2 text-foreground"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        )
      ) : (
        assetsLoading ? (
          <SessionsSkeleton />
        ) : filteredAssets.length === 0 ? (
          <div className="text-center py-16 bg-surface-0 rounded-sm border border-border text-muted">
            <p className="text-xs font-medium text-foreground">No endpoints observed</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-5 space-y-3">
              {filteredAssets.map((asset) => {
                const active = selAsset?.id === asset.id;
                return (
                  <div
                    key={asset.id}
                    onClick={() => setSelAsset(asset)}
                    className={[
                      "p-4 rounded-sm border transition-all cursor-pointer",
                      active
                        ? "bg-surface-0 border-ink ring-1 ring-ink"
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
                          <span className="text-[11px] text-muted font-mono uppercase">
                            {asset.protocols.join(", ")}
                          </span>
                        </div>
                      </div>
                      <div className="text-right">
                        <span className="text-[11px] text-muted font-mono block">
                          {asset.sessions_observed} sess · {asset.clients_observed} cli
                        </span>
                      </div>
                    </div>

                    <div className="mt-3 pt-3 border-t border-border/60 grid grid-cols-2 gap-2 text-[11px]">
                      <div>
                        <span className="text-muted block text-[10px]">TLS versions observed</span>
                        <span className="font-mono text-foreground">
                          {asset.tls_versions_observed.length > 0
                            ? asset.tls_versions_observed.join(", ")
                            : "None observed"}
                        </span>
                      </div>
                      <div>
                        <span className="text-muted block text-[10px]">Forward secrecy observed</span>
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

            <div className="lg:col-span-7">
              {selAsset ? (
                <div className="bg-surface-0 rounded-sm border border-border p-5 space-y-5">
                  <div className="flex items-start justify-between border-b border-border pb-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <h2 className="text-base font-semibold font-mono text-foreground">{selAsset.id}</h2>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-100 text-slate-800">
                          {selAsset.server_role}
                        </span>
                      </div>
                      <p className="text-xs text-muted mt-0.5">
                        Server: <span className="text-foreground font-mono">{selAsset.server}</span> (Port {selAsset.port})
                      </p>
                    </div>
                    <div className="text-right text-xs">
                      <span className="text-muted text-[10px] block">First seen: {new Date(selAsset.first_seen).toLocaleTimeString()}</span>
                      <span className="text-muted text-[10px] block">Last seen: {new Date(selAsset.last_seen).toLocaleTimeString()}</span>
                    </div>
                  </div>

                  <div className="space-y-3">
                    <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider text-muted">
                      Observed parameters
                    </h3>

                    <div className="grid grid-cols-2 gap-4 text-xs">
                      <div className="p-3 rounded border border-border bg-slate-50/50">
                        <span className="text-muted text-[11px] block">STARTTLS observed</span>
                        <span className="font-mono font-medium text-foreground mt-0.5 block">
                          {selAsset.starttls_support}
                        </span>
                      </div>
                      <div className="p-3 rounded border border-border bg-slate-50/50">
                        <span className="text-muted text-[11px] block">Forward secrecy observed</span>
                        <span className="font-mono font-medium text-foreground mt-0.5 block">
                          {selAsset.forward_secrecy}
                        </span>
                      </div>
                    </div>

                    <div className="p-3 rounded border border-border bg-slate-50/50 text-xs">
                      <span className="text-muted text-[11px] block">Hybrid key exchange</span>
                      <span className="font-mono font-medium text-foreground mt-0.5 block">
                        {selAsset.pqc
                          ? selAsset.pqc.hybrid_group_negotiated
                            ? "negotiated"
                            : selAsset.pqc.hybrid_groups_offered_by_clients
                            ? "offered"
                            : "not seen"
                          : "not observable"}
                      </span>
                    </div>

                    <div>
                      <span className="text-xs text-muted block mb-1">Cipher suites observed:</span>
                      {selAsset.cipher_suites_observed.length > 0 ? (
                        <div className="space-y-1">
                          {selAsset.cipher_suites_observed.map((cs) => (
                            <div key={cs} className="font-mono text-xs p-2 rounded bg-slate-50 border border-border text-foreground">
                              {cs}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <span className="text-xs text-muted italic">None observed</span>
                      )}
                    </div>

                    {selAsset.key_exchange_groups_observed.length > 0 && (
                      <div>
                        <span className="text-xs text-muted block mb-1">Key exchange groups observed:</span>
                        <div className="flex flex-wrap gap-1.5">
                          {selAsset.key_exchange_groups_observed.map((grp) => (
                            <span key={grp} className="px-2 py-1 rounded bg-slate-100 font-mono text-xs text-foreground">
                              {grp}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="space-y-3 border-t border-border pt-4">
                    <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider text-muted">
                      Observed certificates ({selAsset.certificates.length})
                    </h3>

                    {selAsset.certificates.length > 0 ? (
                      <div className="space-y-2">
                        {selAsset.certificates.map((cert) => (
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
                              <span className="text-muted text-[10px] block">SHA-256 fingerprint:</span>
                              <span className="font-mono text-[10px] text-muted break-all">{cert.sha256}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-muted italic">
                        No certificate observed on wire.
                      </p>
                    )}
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center text-xs text-muted border border-dashed border-border rounded-sm">
                  Select an observed endpoint to view details
                </div>
              )}
            </div>
          </div>
        )
      )}

      {selSession && (
        <div className="fixed inset-0 z-50 bg-black/40 flex justify-end animate-in fade-in duration-150">
          <div className="w-full max-w-2xl bg-surface-0 h-full shadow-2xl flex flex-col border-l border-border overflow-hidden">
            <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-surface-1">
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-base font-semibold font-mono">{selSession.id}</h2>
                  <span className="uppercase text-xs font-mono font-medium px-1.5 py-0.5 bg-surface-2 rounded-[3px] border border-border">
                    {selSession.protocol}
                  </span>
                  <TransportBadge transport={selSession.transport} />
                </div>
                <p className="text-xs font-mono text-muted mt-1">
                  {selSession.client} → {selSession.server}:{selSession.server_port}
                </p>
              </div>
              <button
                onClick={() => setSelSession(null)}
                className="p-1.5 rounded-sm hover:bg-surface-2 text-muted hover:text-foreground"
              >
                <X size={18} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              <div className="bg-surface-1 rounded-sm p-4 border border-border">
                <h3 className="text-xs font-medium text-muted mb-3">
                  Wireshark display filter
                </h3>
                <div className="flex items-center justify-between gap-2 bg-surface-0 border border-border rounded px-3 py-2">
                  <code className="text-xs font-mono text-foreground truncate">{selSession.wireshark_filter}</code>
                  <button
                    onClick={() => copyText(selSession.wireshark_filter)}
                    className="p-1 rounded hover:bg-surface-2 text-muted hover:text-foreground shrink-0 transition-colors"
                  >
                    {copied ? <Check size={14} className="text-sev-pass" /> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              <div className="bg-surface-1 rounded-sm p-4 border border-border">
                <h3 className="text-xs font-medium text-muted mb-3">
                  Handshake & transport
                </h3>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-muted block">Protocol confidence</span>
                    <span className="font-mono capitalize font-medium">{selSession.protocol_confidence}</span>
                  </div>
                  <div>
                    <span className="text-muted block mb-0.5">Associated frames</span>
                    <EvidenceTag>#{selSession.first_frame}–#{selSession.last_frame}</EvidenceTag>
                  </div>
                  <div>
                    <span className="text-muted block">STARTTLS advertised</span>
                    <span className="font-mono">{selSession.starttls.advertised ? "Yes" : "No"}</span>
                  </div>
                  <div>
                    <span className="text-muted block">STARTTLS initiated</span>
                    <span className="font-mono">{selSession.starttls.initiated ? "Yes" : "No"}</span>
                  </div>
                  {selSession.starttls.downgrade_suspected && (
                    <div className="col-span-2">
                      <span className="text-sev-critical font-medium text-xs">
                        STARTTLS downgrade suspected
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {selSession.tls && (
                <div className="bg-surface-1 rounded-sm p-4 border border-border">
                  <h3 className="text-xs font-medium text-muted mb-3">
                    TLS configuration
                  </h3>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <span className="text-muted block">Version</span>
                      <span className="font-mono font-medium">{selSession.tls.version}</span>
                    </div>
                    <div>
                      <span className="text-muted block">Key exchange</span>
                      <span className="font-mono font-medium">{selSession.tls.key_exchange}</span>
                    </div>
                    <div className="col-span-2">
                      <span className="text-muted block">Cipher suite</span>
                      <span className="font-mono font-medium break-all">{selSession.tls.cipher_suite}</span>
                    </div>
                    {selSession.tls.sni && (
                      <div className="col-span-2">
                        <span className="text-muted block">SNI</span>
                        <span className="font-mono">{selSession.tls.sni}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              <div className="bg-surface-1 rounded-sm p-4 border border-border">
                <h3 className="text-xs font-medium text-muted mb-3">
                  Certificate chain
                </h3>
                {selSession.certificate_chain && selSession.certificate_chain.length > 0 ? (
                  <div className="space-y-3">
                    {selSession.certificate_chain.map((c, i) => (
                      <div key={i} className="bg-surface-0 border border-border rounded p-3 text-xs space-y-1">
                        <div>
                          <span className="text-muted block text-[10px]">Subject:</span>
                          <span className="font-mono font-medium">{c.subject}</span>
                        </div>
                        <div>
                          <span className="text-muted block text-[10px]">Issuer:</span>
                          <span className="font-mono text-muted">{c.issuer}</span>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                          <div>
                            <span className="text-muted block text-[10px]">Key algorithm:</span>
                            <span className="font-mono">{c.key_algorithm} {c.key_bits}-bit</span>
                          </div>
                          <div>
                            <span className="text-muted block text-[10px]">Expires:</span>
                            <span className="font-mono">{c.not_after}</span>
                          </div>
                        </div>
                        <div className="pt-1">
                          <span className="text-muted block text-[10px]">SHA-256 fingerprint:</span>
                          <span className="font-mono text-[10px] text-muted break-all">{c.sha256_fingerprint}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="hatch-neutral p-3 rounded border border-border">
                    <p className="text-xs font-mono text-muted">
                      {selSession.certificate_note ?? "Certificate not observable"}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function TransportBadge({ transport }: { transport: Transport }) {
  if (transport === "implicit_tls") {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-sev-pass-bg text-sev-pass border border-sev-pass/30">
        Implicit TLS
      </span>
    );
  }
  if (transport === "starttls") {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-surface-2 text-foreground border border-border">
        STARTTLS
      </span>
    );
  }
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-sev-critical-bg text-sev-critical border border-sev-critical/30">
      Plaintext
    </span>
  );
}
