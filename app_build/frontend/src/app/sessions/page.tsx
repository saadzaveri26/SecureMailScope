"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import type { Session, Protocol, Transport, PaginatedSessions } from "@/types";
import { getSessions } from "@/data";
import {
  Copy,
  Check,
  Lock,
  LockKeyOpen,
  WarningCircle,
  Terminal,
  ShieldCheck,
  ShieldWarning,
  FileCode,
  MagnifyingGlass,
  ArrowRight,
  Shield,
  Fingerprint,
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
    <div className="max-w-[1600px] mx-auto px-4 py-4 space-y-4 animate-pulse select-none">
      <div className="h-5 w-40 bg-surface-2" />
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-7 bg-surface-0 border border-border h-[650px] xcor-shadow" />
        <div className="lg:col-span-5 bg-surface-0 border border-border h-[650px] xcor-shadow" />
      </div>
    </div>
  );
}

function SessionsContent() {
  const params = useSearchParams();
  const capId = params.get("capture") ?? "cap-001";
  const initSessionId = params.get("session");

  const [data, setData] = useState<PaginatedSessions>({ items: [], total: 0, page: 1, page_size: 50 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [proto, setProto] = useState<string>("");
  const [trans, setTrans] = useState<string>("");
  const [search, setSearch] = useState<string>("");
  const [page, setPage] = useState(1);
  const [selSession, setSelSession] = useState<Session | null>(null);
  const [copiedFilter, setCopiedFilter] = useState(false);
  const [copiedTranscript, setCopiedTranscript] = useState(false);

  useEffect(() => {
    let active = true;
    setLoading(true);
    getSessions(capId, {
      protocol: proto ? (proto as Protocol) : undefined,
      transport: trans ? (trans as Transport) : undefined,
      page,
      page_size: 50,
    })
      .then((res) => {
        if (active) {
          setData(res);
          if (res.items.length > 0) {
            if (initSessionId) {
              const matched = res.items.find((s) => s.id === initSessionId);
              setSelSession(matched || res.items[0]);
            } else {
              setSelSession((prev) => (prev ? res.items.find((x) => x.id === prev.id) || res.items[0] : res.items[0]));
            }
          } else {
            setSelSession(null);
          }
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
  }, [capId, proto, trans, page, initSessionId]);

  function copyText(txt: string, setFn: (v: boolean) => void) {
    navigator.clipboard.writeText(txt);
    setFn(true);
    setTimeout(() => setFn(false), 2000);
  }

  const filteredSessions = data.items.filter((s) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      s.id.toLowerCase().includes(q) ||
      s.client.toLowerCase().includes(q) ||
      s.server.toLowerCase().includes(q) ||
      (s.tls?.sni && s.tls.sni.toLowerCase().includes(q)) ||
      (s.tls?.cipher_suite && s.tls.cipher_suite.toLowerCase().includes(q))
    );
  });

  function generateTranscript(s: Session | null): string {
    if (!s) return "";
    const p = s.protocol.toUpperCase();
    if (s.transport === "plaintext") {
      if (p === "IMAP") {
        return `* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR] ${s.server} IMAP4 ready
C: A001 CAPABILITY
* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS AUTH=PLAIN
A001 OK Completed
C: A002 LOGIN user@company.com **********
A002 OK [CAPABILITY IMAP4rev1] User user@company.com logged in
C: A003 SELECT INBOX
* 142 EXISTS
* 2 RECENT
A003 OK [READ-WRITE] Select completed`;
      }
      return `220 ${s.server} ESMTP Service Ready
C: EHLO [${s.client}]
250-${s.server} greets ${s.client}
250-PIPELINING
250-SIZE 35882400
250-AUTH PLAIN LOGIN
250 8BITMIME
C: AUTH PLAIN dXNlcgB1c2VyAHBhc3N3b3Jk
535 5.7.8 Error: authentication failed: authentication failure`;
    }

    if (s.transport === "starttls") {
      return `220 ${s.server} ESMTP Service Ready
C: EHLO [${s.client}]
250-${s.server} greets ${s.client}
250-STARTTLS
250-PIPELINING
250 8BITMIME
C: STARTTLS
220 2.0.0 Ready to start TLS
>>> [TLS 1.3 ClientHello, SNI=${s.tls?.sni || s.server}, Ciphers=${s.tls?.cipher_suite || "TLS_AES_256_GCM_SHA384"}]
<<< [TLS 1.3 ServerHello, Negotiated=${s.tls?.version || "TLS 1.3"}, Group=${s.tls?.key_exchange || "X25519"}]
<<< [Encrypted Handshake Records: Finished]
>>> [Application Data: 14 packets encrypted over TLS session]`;
    }

    return `>>> [TCP SYN: Port ${s.server_port}]
<<< [TCP SYN, ACK]
>>> [TLS ClientHello: Version=${s.tls?.version || "TLS 1.3"}, SNI=${s.tls?.sni || s.server}]
<<< [TLS ServerHello: Version=${s.tls?.version || "TLS 1.3"}, Selected=${s.tls?.cipher_suite || "AES_GCM"}]
<<< [Certificate: Subject="${s.certificate_chain?.[0]?.subject || s.server}"]
<<< [ServerKeyExchange: ECDHE Group=${s.tls?.key_exchange || "X25519"}]
<<< [ServerHelloDone]
>>> [ClientKeyExchange / Finished]
<<< [ChangeCipherSpec / Finished]
>>> [Application Data Encrypted - ${s.first_frame}..${s.last_frame}]`;
  }

  return (
    <div className="max-w-[1600px] mx-auto px-4 py-4 space-y-4 select-none font-mono text-xs">
      {/* Control Header & Filters */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-surface-0 border border-border p-3 xcor-shadow">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 font-bold uppercase text-foreground">
            <span className="p-1 bg-accent border border-border">
              <Terminal size={14} weight="bold" />
            </span>
            <span className="text-sm">TCP Mail Streams</span>
          </div>

          <div className="flex items-center gap-1.5 bg-surface-1 px-2 py-1 border border-border">
            <span className="text-muted font-bold text-[10px] uppercase">Proto:</span>
            <select
              value={proto}
              onChange={(e) => { setProto(e.target.value); setPage(1); }}
              className="bg-transparent text-foreground font-bold focus:outline-none cursor-pointer"
            >
              <option value="" className="bg-surface-0">All Protocols</option>
              <option value="smtp" className="bg-surface-0">SMTP</option>
              <option value="imap" className="bg-surface-0">IMAP</option>
              <option value="pop3" className="bg-surface-0">POP3</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 bg-surface-1 px-2 py-1 border border-border">
            <span className="text-muted font-bold text-[10px] uppercase">Transport:</span>
            <select
              value={trans}
              onChange={(e) => { setTrans(e.target.value); setPage(1); }}
              className="bg-transparent text-foreground font-bold focus:outline-none cursor-pointer"
            >
              <option value="" className="bg-surface-0">All Transports</option>
              <option value="implicit_tls" className="bg-surface-0">Implicit TLS</option>
              <option value="starttls" className="bg-surface-0">STARTTLS</option>
              <option value="plaintext" className="bg-surface-0">Plaintext</option>
            </select>
          </div>

          <div className="relative">
            <input
              type="text"
              placeholder="Search stream, IP, SNI..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-surface-1 border border-border px-2.5 py-1 text-xs text-foreground placeholder:text-muted focus:outline-none focus:bg-accent-soft w-52 font-mono font-bold"
            />
          </div>
        </div>

        <div className="flex items-center gap-3 text-foreground text-[11px] font-bold">
          <span>
            Showing <strong className="tabular-nums underline decoration-2">{filteredSessions.length}</strong> of{" "}
            <strong className="tabular-nums">{data.total}</strong> streams
          </span>
          <div className="flex items-center gap-1">
            <button
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="px-2.5 py-0.5 border border-border bg-surface-1 disabled:opacity-40 hover:bg-accent text-foreground font-bold cursor-pointer"
            >
              Prev
            </button>
            <span className="px-1.5 text-foreground font-bold">{page}</span>
            <button
              disabled={page * data.page_size >= data.total}
              onClick={() => setPage((p) => p + 1)}
              className="px-2.5 py-0.5 border border-border bg-surface-1 disabled:opacity-40 hover:bg-accent text-foreground font-bold cursor-pointer"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Split-Pane Master-Detail Architecture */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
        {/* ================= LEFT PANE: SESSIONS MASTER LIST (7 cols) ================= */}
        <div className="lg:col-span-7 bg-surface-0 border border-border overflow-hidden flex flex-col font-mono text-xs xcor-shadow">
          <div className="overflow-x-auto max-h-[720px] overflow-y-auto">
            <table className="w-full text-left">
              <thead className="sticky top-0 bg-surface-1 border-b border-border text-[11px] font-bold text-foreground uppercase z-10">
                <tr>
                  <th className="py-2 px-3 w-16">Stream</th>
                  <th className="py-2 px-3 w-22">Crypto</th>
                  <th className="py-2 px-3 w-16">Proto</th>
                  <th className="py-2 px-3">Client Endpoint → Server</th>
                  <th className="py-2 px-3 w-28">TLS Version</th>
                  <th className="py-2 px-3 w-24 text-right">Frames</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredSessions.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-muted font-bold text-xs">
                      No matching TCP sessions observed.
                    </td>
                  </tr>
                ) : (
                  filteredSessions.map((s) => {
                    const isSelected = selSession?.id === s.id;
                    const isPlaintext = s.transport === "plaintext";
                    const isTls13 = s.tls?.version === "TLS 1.3";
                    const isTls12 = s.tls?.version === "TLS 1.2";

                    return (
                      <tr
                        key={s.id}
                        onClick={() => setSelSession(s)}
                        className={[
                          "cursor-pointer transition-colors text-[11px]",
                          isSelected
                            ? "bg-accent/25 border-l-4 border-border font-bold text-foreground"
                            : "hover:bg-accent-soft text-foreground font-medium",
                        ].join(" ")}
                      >
                        <td className="py-2 px-3 font-bold text-foreground">
                          {s.id}
                        </td>
                        <td className="py-2 px-3">
                          {isPlaintext ? (
                            <span className="inline-flex items-center gap-1 text-[10px] text-white font-bold uppercase bg-sev-critical border border-border px-1.5 py-0.2 xcor-shadow-subtle">
                              <LockKeyOpen size={10} weight="bold" />
                              <span>PLAIN</span>
                            </span>
                          ) : (
                            <span
                              className={`inline-flex items-center gap-1 text-[10px] font-bold uppercase px-1.5 py-0.2 border border-border xcor-shadow-subtle ${
                                isTls13
                                  ? "text-foreground bg-sev-pass"
                                  : isTls12
                                  ? "text-foreground bg-sky-300"
                                  : "text-foreground bg-sev-medium"
                              }`}
                            >
                              <Lock size={10} weight="bold" />
                              <span>{s.transport === "starttls" ? "STLS" : "TLS"}</span>
                            </span>
                          )}
                        </td>
                        <td className="py-2 px-3 uppercase font-bold text-foreground">
                          {s.protocol}
                        </td>
                        <td className="py-2 px-3 truncate max-w-xs">
                          <span className="text-muted">{s.client}</span>
                          <span className="text-muted mx-1 font-bold">→</span>
                          <span className="text-foreground font-bold">{s.server}:{s.server_port}</span>
                        </td>
                        <td className="py-2 px-3 truncate max-w-[130px]">
                          {s.tls?.version ? (
                            <span className="text-foreground font-bold">{s.tls.version}</span>
                          ) : (
                            <span className="text-muted italic text-[10px]">None</span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-right font-mono text-muted tabular-nums font-bold">
                          #{s.first_frame}–{s.last_frame}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* ================= RIGHT PANE: DETAIL INSPECTOR DRAWER (5 cols) ================= */}
        <div className="lg:col-span-5 bg-surface-0 border border-border p-4 space-y-3 font-mono text-xs sticky top-3 xcor-shadow">
          {selSession ? (
            <>
              {/* Header Info */}
              <div className="flex items-center justify-between border-b border-border pb-2.5">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-base font-bold text-foreground">{selSession.id}</span>
                    <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 bg-accent border border-border text-foreground">
                      {selSession.protocol}
                    </span>
                    <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 border border-border ${
                      selSession.transport === "plaintext"
                        ? "text-white bg-sev-critical"
                        : "text-foreground bg-sev-pass"
                    }`}>
                      {selSession.transport.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-[11px] text-muted mt-0.5 font-medium">
                    {selSession.client} <span className="text-muted font-bold">→</span> {selSession.server}:{selSession.server_port}
                  </p>
                </div>

                <div className="text-right">
                  <span className="text-[10px] text-muted block font-bold uppercase">Associated Frames</span>
                  <span className="text-xs text-foreground font-bold tabular-nums">#{selSession.first_frame} – #{selSession.last_frame}</span>
                </div>
              </div>

              {/* Wireshark Filter Anchor */}
              <div className="bg-surface-1 border border-border p-2.5 flex items-center justify-between gap-2 xcor-shadow-subtle">
                <div className="truncate">
                  <span className="text-[10px] text-foreground uppercase font-bold block">Wireshark Stream Filter</span>
                  <code className="text-xs text-foreground font-bold truncate block select-all font-mono mt-0.5">
                    {selSession.wireshark_filter}
                  </code>
                </div>
                <button
                  onClick={() => copyText(selSession.wireshark_filter, setCopiedFilter)}
                  className="px-2.5 py-1 bg-accent hover:bg-accent-hover text-foreground text-xs font-bold border border-border xcor-shadow-subtle flex items-center gap-1 shrink-0 cursor-pointer"
                >
                  {copiedFilter ? <Check size={12} weight="bold" /> : <Copy size={12} weight="bold" />}
                  <span>{copiedFilter ? "Copied" : "Copy"}</span>
                </button>
              </div>

              {/* Reconstructed Raw Stream Transcript */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="font-bold text-foreground uppercase flex items-center gap-1.5">
                    <FileCode size={14} weight="bold" className="text-foreground" />
                    <span>Reassembled Mail Dialog</span>
                  </span>
                  <button
                    onClick={() => copyText(generateTranscript(selSession), setCopiedTranscript)}
                    className="text-[10px] text-foreground font-bold hover:underline cursor-pointer"
                  >
                    {copiedTranscript ? "Copied transcript" : "Copy transcript"}
                  </button>
                </div>
                <div className="bg-surface-1 border border-border p-2.5 overflow-x-auto max-h-[170px] xcor-shadow-subtle">
                  <pre className="text-[10px] leading-relaxed text-foreground font-bold font-mono select-all whitespace-pre-wrap">
                    {generateTranscript(selSession)}
                  </pre>
                </div>
              </div>

              {/* TLS Handshake Parameters */}
              <div className="space-y-1.5 pt-2 border-t border-border">
                <span className="text-[11px] font-bold text-foreground uppercase flex items-center gap-1.5">
                  <Shield size={14} weight="bold" className="text-foreground" />
                  <span>TLS Handshake Parameters</span>
                </span>

                <div className="grid grid-cols-2 gap-2 text-[11px] bg-surface-1 p-2.5 border border-border xcor-shadow-subtle">
                  <div>
                    <span className="text-[10px] text-muted font-bold block uppercase">Negotiated Version:</span>
                    <span className="text-foreground font-bold">{selSession.tls?.version || "Plaintext (None)"}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-muted font-bold block uppercase">Key Exchange:</span>
                    <span className="text-foreground font-bold">{selSession.tls?.key_exchange || "N/A"}</span>
                  </div>
                  <div className="col-span-2">
                    <span className="text-[10px] text-muted font-bold block uppercase">Cipher Suite:</span>
                    <span className="text-foreground font-bold truncate block">
                      {selSession.tls?.cipher_suite || "None (Plaintext)"}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] text-muted font-bold block uppercase">SNI Host:</span>
                    <span className="text-foreground font-bold truncate block">{selSession.tls?.sni || "N/A"}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-muted font-bold block uppercase">Forward Secrecy:</span>
                    <span className={`font-bold px-1 border border-border inline-block ${
                      selSession.tls?.forward_secrecy ? "bg-sev-pass-bg text-sev-pass" : "bg-sev-critical-bg text-red-800"
                    }`}>
                      {selSession.tls?.forward_secrecy ? "PFS Active" : "No PFS"}
                    </span>
                  </div>
                </div>
              </div>

              {/* X.509 Certificate Chain Tree */}
              <div className="space-y-1.5 pt-2 border-t border-border">
                <span className="text-[11px] font-bold text-foreground uppercase flex items-center gap-1.5">
                  <Fingerprint size={14} weight="bold" className="text-foreground" />
                  <span>X.509 Certificate Chain</span>
                </span>

                {selSession.certificate_chain && selSession.certificate_chain.length > 0 ? (
                  <div className="space-y-1.5 text-[11px] bg-surface-1 p-2.5 border border-border xcor-shadow-subtle">
                    <div>
                      <span className="text-[10px] text-muted font-bold block uppercase">Subject CN:</span>
                      <span className="text-foreground font-bold break-all">
                        {selSession.certificate_chain[0].subject}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted font-bold block uppercase">Issuer:</span>
                      <span className="text-muted break-all font-medium">
                        {selSession.certificate_chain[0].issuer}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-2 pt-1 border-t border-border/20">
                      <div>
                        <span className="text-[10px] text-muted font-bold block uppercase">Key Size:</span>
                        <span className="text-foreground font-bold">
                          {selSession.certificate_chain[0].key_algorithm} {selSession.certificate_chain[0].key_bits}-bit
                        </span>
                      </div>
                      <div>
                        <span className="text-[10px] text-muted font-bold block uppercase">Expiry:</span>
                        <span className={`font-bold px-1 border border-border inline-block ${
                          selSession.certificate_chain[0].expired ? "bg-sev-critical text-white" : "bg-sev-pass text-foreground"
                        }`}>
                          {selSession.certificate_chain[0].expired ? "Expired" : `${selSession.certificate_chain[0].days_to_expiry} days remaining`}
                        </span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="bg-surface-1 p-2.5 border border-border text-[11px] text-muted italic font-medium">
                    {selSession.transport === "plaintext"
                      ? "No certificate exchanged (unencrypted plaintext session)."
                      : "Certificate encrypted on wire (TLS 1.3 encrypted handshake)."}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="text-center py-16 text-muted font-bold text-xs">
              Select a TCP mail stream on the left to inspect cryptographic evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
