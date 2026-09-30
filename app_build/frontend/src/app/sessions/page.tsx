"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import type { Session, Protocol, Transport, PaginatedSessions } from "@/types";
import { getSessions, getSession } from "@/data";
import {
  X,
  Copy,
  Check,
} from "@phosphor-icons/react";

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
      <div className="bg-surface-0 rounded-lg border border-border-subtle overflow-hidden">
        <div className="h-10 bg-surface-1 border-b border-border-subtle" />
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-10 border-b border-border-subtle flex items-center px-4 gap-4">
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
  const captureId = params.get("capture") ?? "cap-001";
  const initialSessionId = params.get("session");

  const [data, setData] = useState<PaginatedSessions>({ items: [], total: 0, page: 1, page_size: 25 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [protocol, setProtocol] = useState<string>("");
  const [transport, setTransport] = useState<string>("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Session | null>(null);
  const [copied, setCopied] = useState(false);

  function loadSessions() {
    setLoading(true);
    setError(null);
    getSessions(captureId, {
      protocol: protocol ? (protocol as Protocol) : undefined,
      transport: transport ? (transport as Transport) : undefined,
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
    getSessions(captureId, {
      protocol: protocol ? (protocol as Protocol) : undefined,
      transport: transport ? (transport as Transport) : undefined,
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
  }, [captureId, protocol, transport, page]);

  useEffect(() => {
    if (!initialSessionId) return;
    let active = true;
    getSession(captureId, initialSessionId).then((s) => {
      if (active && s) setSelected(s);
    });
    return () => {
      active = false;
    };
  }, [captureId, initialSessionId]);

  function handleRowClick(sessionId: string) {
    getSession(captureId, sessionId).then((s) => setSelected(s));
  }

  function copyText(txt: string) {
    navigator.clipboard.writeText(txt);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div>
          <h1 className="text-xl font-semibold">Sessions</h1>
          <p className="text-sm text-muted">
            Network email sessions extracted from capture <span className="font-mono text-foreground font-medium">{captureId}</span>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={protocol}
            onChange={(e) => { setProtocol(e.target.value); setPage(1); }}
            className="text-xs bg-surface-0 border border-border rounded-md px-3 py-1.5 focus:outline-none focus:border-brand"
          >
            <option value="">All protocols</option>
            <option value="smtp">SMTP</option>
            <option value="imap">IMAP</option>
            <option value="pop3">POP3</option>
          </select>
          <select
            value={transport}
            onChange={(e) => { setTransport(e.target.value); setPage(1); }}
            className="text-xs bg-surface-0 border border-border rounded-md px-3 py-1.5 focus:outline-none focus:border-brand"
          >
            <option value="">All transports</option>
            <option value="implicit_tls">Implicit TLS</option>
            <option value="starttls">STARTTLS</option>
            <option value="plaintext">Plaintext</option>
          </select>
        </div>
      </div>

      {loading ? (
        <SessionsSkeleton />
      ) : error ? (
        <div className="bg-sev-critical-bg border border-sev-critical/20 rounded-md p-4 space-y-2">
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
        <div className="text-center py-16 bg-surface-0 rounded-lg border border-border-subtle text-muted">
          <p className="text-xs font-medium text-foreground">No sessions match current filters</p>
          <p className="text-xs text-muted mt-1">Try adjusting the protocol or transport filter</p>
        </div>
      ) : (
        <div className="bg-surface-0 rounded-lg border border-border-subtle overflow-hidden">
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
                    onClick={() => handleRowClick(s.id)}
                    className="border-b border-border-subtle last:border-0 hover:bg-surface-1 cursor-pointer transition-colors h-10"
                  >
                    <td className="px-4 py-2">
                      <div className="font-mono text-xs font-medium text-foreground">{s.id}</div>
                      <div className="text-[11px] text-muted font-mono truncate max-w-xs">
                        {s.client} → {s.server}:{s.server_port}
                      </div>
                    </td>
                    <td className="px-4 py-2">
                      <span className="uppercase text-xs font-mono font-medium px-1.5 py-0.5 bg-surface-2 rounded-[3px] border border-border-subtle">
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
                        <span className="text-xs text-muted">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2 font-mono text-muted tabular-nums">
                      #{s.first_frame}–#{s.last_frame}
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
                        onClick={(e) => { e.stopPropagation(); handleRowClick(s.id); }}
                        className="text-xs font-medium text-brand hover:underline"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between px-4 py-2.5 border-t border-border-subtle bg-surface-1 text-xs text-muted">
            <span className="tabular-nums">
              Showing {data.items.length} of {data.total} sessions
            </span>
            <div className="flex items-center gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="px-2.5 py-1 border border-border rounded-md bg-surface-0 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-surface-2 text-foreground"
              >
                Previous
              </button>
              <span className="text-foreground font-medium tabular-nums">{page}</span>
              <button
                disabled={page * data.page_size >= data.total}
                onClick={() => setPage((p) => p + 1)}
                className="px-2.5 py-1 border border-border rounded-md bg-surface-0 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-surface-2 text-foreground"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}

      {selected && (
        <div className="fixed inset-0 z-50 bg-black/40 flex justify-end animate-in fade-in duration-150">
          <div className="w-full max-w-2xl bg-surface-0 h-full shadow-2xl flex flex-col border-l border-border overflow-hidden">
            <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-surface-1">
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-base font-semibold font-mono">{selected.id}</h2>
                  <span className="uppercase text-xs font-mono font-medium px-1.5 py-0.5 bg-surface-2 rounded-[3px] border border-border-subtle">
                    {selected.protocol}
                  </span>
                  <TransportBadge transport={selected.transport} />
                </div>
                <p className="text-xs font-mono text-muted mt-1">
                  {selected.client} → {selected.server}:{selected.server_port}
                </p>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="p-1.5 rounded-md hover:bg-surface-2 text-muted hover:text-foreground"
              >
                <X size={18} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {selected.transport === "plaintext" && (
                <div className="p-3.5 bg-sev-critical-bg border border-sev-critical/20 rounded-md space-y-0.5 text-xs text-sev-critical">
                  <p className="font-semibold">Cleartext transmission alert</p>
                  <p className="text-sev-critical/90">
                    All mail payload, protocol commands, and transaction metadata were sent without encryption.
                  </p>
                </div>
              )}

              {selected.auth_before_tls && (
                <div className="p-3.5 bg-sev-critical-bg border border-sev-critical/20 rounded-md space-y-0.5 text-xs text-sev-critical">
                  <p className="font-semibold">Plaintext authentication observed</p>
                  <p className="text-sev-critical/90">
                    User credentials were submitted over cleartext before STARTTLS negotiation began.
                  </p>
                </div>
              )}

              {selected.starttls.downgrade_suspected && (
                <div className="p-3.5 bg-sev-high-bg border border-sev-high/20 rounded-md space-y-0.5 text-xs text-sev-high">
                  <p className="font-semibold">Suspected STARTTLS downgrade</p>
                  <p className="text-sev-high/90">
                    STARTTLS was offered but stripped or failed, causing client fallback to unencrypted communication.
                  </p>
                </div>
              )}

              <div className="bg-surface-1 rounded-md p-4 border border-border-subtle">
                <h3 className="text-xs font-medium text-muted mb-3">
                  Wireshark display filter
                </h3>
                <div className="flex items-center justify-between gap-2 bg-surface-0 border border-border rounded px-3 py-2">
                  <code className="text-xs font-mono text-brand truncate">{selected.wireshark_filter}</code>
                  <button
                    onClick={() => copyText(selected.wireshark_filter)}
                    className="p-1 rounded hover:bg-surface-2 text-muted hover:text-foreground shrink-0 transition-colors"
                    title="Copy filter"
                  >
                    {copied ? <Check size={14} className="text-brand" /> : <Copy size={14} />}
                  </button>
                </div>
                <div className="flex items-center justify-between text-xs text-muted mt-2">
                  <span className="tabular-nums">Frame range: #{selected.first_frame} – #{selected.last_frame}</span>
                  <span>Confidence: {selected.protocol_confidence}</span>
                </div>
              </div>

              {selected.tls && (
                <div className="bg-surface-1 rounded-md p-4 border border-border-subtle">
                  <h3 className="text-xs font-medium text-muted mb-3">
                    TLS configuration
                  </h3>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <span className="text-muted block">Version</span>
                      <span className="font-mono font-medium">{selected.tls.version}</span>
                    </div>
                    <div>
                      <span className="text-muted block">Forward secrecy</span>
                      <span className="font-medium">
                        {selected.tls.forward_secrecy === null
                          ? "—"
                          : selected.tls.forward_secrecy
                          ? "Supported"
                          : "None"}
                      </span>
                    </div>
                    <div className="col-span-2">
                      <span className="text-muted block">Cipher suite</span>
                      <span className="font-mono font-medium break-all">{selected.tls.cipher_suite}</span>
                    </div>
                    <div>
                      <span className="text-muted block">Key exchange</span>
                      <span className="font-mono font-medium">{selected.tls.key_exchange}</span>
                    </div>
                    <div>
                      <span className="text-muted block">SNI</span>
                      <span className="font-mono font-medium">{selected.tls.sni || "—"}</span>
                    </div>
                    <div>
                      <span className="text-muted block">ALPN</span>
                      <span className="font-mono font-medium">{selected.tls.alpn || "—"}</span>
                    </div>
                    <div>
                      <span className="text-muted block">JA3 fingerprint</span>
                      <span className="font-mono font-medium text-xs break-all">{selected.tls.ja3}</span>
                    </div>
                    <div className="col-span-2">
                      <span className="text-muted block">JA3S fingerprint</span>
                      <span className="font-mono font-medium text-xs break-all">{selected.tls.ja3s}</span>
                    </div>
                  </div>
                </div>
              )}

              <div className="bg-surface-1 rounded-md p-4 border border-border-subtle">
                <h3 className="text-xs font-medium text-muted mb-3">
                  STARTTLS negotiation
                </h3>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-muted block">Advertised in EHLO/CAPA</span>
                    <span className="font-medium">{selected.starttls.advertised ? "Yes" : "No"}</span>
                  </div>
                  <div>
                    <span className="text-muted block">Initiated by client</span>
                    <span className="font-medium">{selected.starttls.initiated ? "Yes" : "No"}</span>
                  </div>
                  <div>
                    <span className="text-muted block">Negotiation succeeded</span>
                    <span className="font-medium">
                      {selected.starttls.succeeded === null ? "—" : selected.starttls.succeeded ? "Yes" : "No"}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted block">Downgrade suspected</span>
                    <span className={`font-medium ${selected.starttls.downgrade_suspected ? "text-sev-high" : "text-muted"}`}>
                      {selected.starttls.downgrade_suspected ? "Yes" : "No"}
                    </span>
                  </div>
                </div>
              </div>

              <div className="bg-surface-1 rounded-md p-4 border border-border-subtle">
                <h3 className="text-xs font-medium text-muted mb-3">
                  Certificate observation
                </h3>
                {!selected.certificate_observable ? (
                  <div className="bg-surface-2 border border-border-subtle rounded p-3 text-xs">
                    <p className="font-medium text-muted">Certificate not observable</p>
                    <p className="text-muted/80 mt-1">{selected.certificate_note ?? "Handshake encrypted in passive capture."}</p>
                  </div>
                ) : selected.certificate_chain && selected.certificate_chain.length > 0 ? (
                  <div className="space-y-4">
                    {selected.certificate_chain.map((cert, idx) => (
                      <div key={idx} className="bg-surface-0 border border-border rounded p-3 space-y-2 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-foreground">Cert #{idx + 1}: {cert.subject}</span>
                          <span className={`px-1.5 py-0.5 rounded-[3px] text-[10px] font-medium border ${cert.expired ? "bg-sev-critical-bg text-sev-critical border-sev-critical/20" : "bg-surface-2 text-foreground border-border"}`}>
                            {cert.expired ? "Expired" : "Valid"}
                          </span>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-muted">
                          <div><span className="text-muted/70 block">Issuer</span>{cert.issuer}</div>
                          <div><span className="text-muted/70 block">Expires in</span><span className="tabular-nums">{cert.days_to_expiry}</span> days</div>
                          <div><span className="text-muted/70 block">Key</span>{cert.key_algorithm} {cert.key_bits}-bit</div>
                          <div><span className="text-muted/70 block">Self-signed</span>{cert.self_signed ? "Yes" : "No"}</div>
                        </div>
                        <div>
                          <span className="text-muted/70 block">SHA-256</span>
                          <span className="font-mono text-[11px] break-all">{cert.sha256_fingerprint}</span>
                        </div>
                        {cert.san.length > 0 && (
                          <div>
                            <span className="text-muted/70 block">SANs</span>
                            <span className="text-xs font-mono">{cert.san.join(", ")}</span>
                          </div>
                        )}
                        {cert.validation_notes.length > 0 && (
                          <div className="pt-1">
                            {cert.validation_notes.map((note, nIdx) => (
                              <p key={nIdx} className="text-xs text-sev-medium">• {note}</p>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted">No certificates detected.</p>
                )}
              </div>

              <div className="bg-surface-1 rounded-md p-4 border border-border-subtle">
                <h3 className="text-xs font-medium text-muted mb-2">
                  Message layer activity
                </h3>
                <div className="flex items-center justify-between text-xs mb-2">
                  <span className="text-muted">State:</span>
                  <span className="font-medium text-foreground">
                    {selected.message_layer.state === "not_observable" ? (
                      <span className="px-1.5 py-0.5 rounded-[3px] text-xs font-mono bg-surface-2 text-muted border border-border-subtle">
                        Not observable
                      </span>
                    ) : (
                      selected.message_layer.state
                    )}
                  </span>
                </div>
                {selected.message_layer.markers.length > 0 ? (
                  <div className="space-y-1">
                    {selected.message_layer.markers.map((m, idx) => (
                      <div key={idx} className="flex items-center justify-between text-xs py-1 border-t border-border-subtle">
                        <span className="font-mono text-foreground">{m.type}</span>
                        <span className="text-muted tabular-nums">{m.count} event{m.count > 1 ? "s" : ""}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted">No message markers observed.</p>
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
      <span className="inline-block px-1.5 py-0.5 rounded-[3px] text-xs font-mono bg-surface-2 text-foreground border border-border">
        Implicit TLS
      </span>
    );
  }
  if (transport === "starttls") {
    return (
      <span className="inline-block px-1.5 py-0.5 rounded-[3px] text-xs font-mono bg-sev-medium-bg text-sev-medium border border-sev-medium/20">
        STARTTLS
      </span>
    );
  }
  return (
    <span className="inline-block px-1.5 py-0.5 rounded-[3px] text-xs font-mono bg-sev-critical-bg text-sev-critical border border-sev-critical/20">
      Plaintext
    </span>
  );
}
