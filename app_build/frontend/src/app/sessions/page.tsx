"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams, useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import type { Session, Protocol, Transport, PaginatedSessions, Finding } from "@/types";
import { getSessions, getFindings } from "@/data";
import { SeverityBadge } from "@/components/severity";
import { EvidenceTag } from "@/components/evidence-tag";
import {
  Copy,
  Check,
  Terminal,
  ShieldCheck,
  ShieldWarning,
  LockKeyOpen,
  ArrowRight,
  X,
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
    <div className="w-full px-4 2xl:px-6 py-3 space-y-3 animate-pulse select-none">
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-3 h-[calc(100vh-112px)]">
        <div className="xl:col-span-7 bg-surface-0 border border-border rounded-[var(--radius-md)] p-3" />
        <div className="xl:col-span-5 bg-surface-0 border border-border rounded-[var(--radius-md)] p-3" />
      </div>
    </div>
  );
}

function SessionsContent() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const capId = searchParams.get("capture") ?? "cap-001";
  const urlSessionId = searchParams.get("session") ?? searchParams.get("selected");
  const urlFilter = searchParams.get("filter") ?? "";
  const urlFinding = searchParams.get("finding") ?? "";

  const [data, setData] = useState<PaginatedSessions>({ items: [], total: 0, page: 1, page_size: 50 });
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [proto, setProto] = useState<string>("");
  const [trans, setTrans] = useState<string>(urlFilter === "cleartext" ? "plaintext" : "");
  const [search, setSearch] = useState<string>("");
  const [page, setPage] = useState(1);
  const [selId, setSelId] = useState<string | null>(urlSessionId);
  const [copiedFilter, setCopiedFilter] = useState(false);

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.all([
      getSessions(capId, {
        protocol: proto ? (proto as Protocol) : undefined,
        transport: trans ? (trans as Transport) : undefined,
        page,
        page_size: 50,
      }),
      getFindings(capId),
    ])
      .then(([res, fList]) => {
        if (!active) return;
        setData(res);
        setAllFindings(fList);
        setLoading(false);
      })
      .catch((e: unknown) => {
        if (!active) return;
        setError(e instanceof Error ? e.message : "Failed to load sessions");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [capId, proto, trans, page]);

  const filteredSessions = data.items.filter((s) => {
    if (urlFilter === "starttls_downgrade") {
      if (s.transport !== "starttls" || s.starttls?.downgrade_suspected !== true) {
        if (!s.auth_before_tls && s.transport !== "plaintext") return false;
      }
    }
    if (urlFilter === "no_pfs") {
      if (s.tls?.forward_secrecy !== false && !s.tls?.cipher_suite?.includes("RSA_WITH")) return false;
    }
    if (urlFinding) {
      const match = allFindings.some(
        (f) => f.rule_id === urlFinding && (f.session_id === s.id || f.evidence?.frames?.includes(s.first_frame))
      );
      if (!match) return false;
    }
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

  const activeId = selId ?? filteredSessions[0]?.id ?? null;
  const selSession = filteredSessions.find((s) => s.id === activeId) ?? filteredSessions[0] ?? null;

  function selectSession(id: string) {
    setSelId(id);
    const next = new URLSearchParams(searchParams.toString());
    next.set("session", id);
    router.replace(`${pathname}?${next.toString()}`, { scroll: false });
  }

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement) return;
      if (filteredSessions.length === 0) return;

      const currentIndex = filteredSessions.findIndex((s) => s.id === activeId);

      if (e.key === "ArrowDown") {
        e.preventDefault();
        const nextIndex = currentIndex < filteredSessions.length - 1 ? currentIndex + 1 : 0;
        selectSession(filteredSessions[nextIndex].id);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        const prevIndex = currentIndex > 0 ? currentIndex - 1 : filteredSessions.length - 1;
        selectSession(filteredSessions[prevIndex].id);
      } else if (e.key === "Escape") {
        e.preventDefault();
        setSelId(null);
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [filteredSessions, activeId]);

  function copyText(txt: string, cb: () => void) {
    navigator.clipboard.writeText(txt);
    cb();
  }

  function getTranscript(s: Session | null): string {
    if (!s) return "";
    const p = s.protocol.toUpperCase();
    if (s.transport === "plaintext") {
      if (p === "IMAP") {
        return `* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR] ${s.server} IMAP4 ready\nC: A001 CAPABILITY\n* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS AUTH=PLAIN\nA001 OK Completed\nC: A002 LOGIN user@company.com **********\nA002 OK [CAPABILITY IMAP4rev1] User user@company.com logged in\nC: A003 SELECT INBOX\n* 142 EXISTS\n* 2 RECENT\nA003 OK [READ-WRITE] Select completed`;
      }
      return `220 ${s.server} ESMTP Service Ready\nC: EHLO [${s.client}]\n250-${s.server} greets ${s.client}\n250-PIPELINING\n250-SIZE 35882400\n250-AUTH PLAIN LOGIN\n250 8BITMIME\nC: AUTH PLAIN dXNlcgB1c2VyAHBhc3N3b3Jk\n535 5.7.8 Error: authentication failed: authentication failure`;
    }

    if (s.transport === "starttls") {
      return `220 ${s.server} ESMTP Service Ready\nC: EHLO [${s.client}]\n250-${s.server} greets ${s.client}\n250-STARTTLS\n250-PIPELINING\n250 8BITMIME\nC: STARTTLS\n220 2.0.0 Ready to start TLS\n>>> [TLS ClientHello, SNI=${s.tls?.sni || s.server}, Ciphers=${s.tls?.cipher_suite || "TLS_AES_256_GCM_SHA384"}]\n<<< [TLS ServerHello, Negotiated=${s.tls?.version || "TLS 1.3"}, Group=${s.tls?.key_exchange || "X25519"}]\n<<< [Encrypted Handshake Records: Finished]\n>>> [Application Data: 14 packets encrypted over TLS session]`;
    }

    return `>>> [TCP SYN: Port ${s.server_port}]\n<<< [TCP SYN, ACK]\n>>> [TLS ClientHello: Version=${s.tls?.version || "TLS 1.3"}, SNI=${s.tls?.sni || s.server}]\n<<< [TLS ServerHello: Version=${s.tls?.version || "TLS 1.3"}, Selected=${s.tls?.cipher_suite || "AES_GCM"}]\n<<< [Certificate: Subject="${s.certificate_chain?.[0]?.subject || s.server}"]\n<<< [ServerKeyExchange: ECDHE Group=${s.tls?.key_exchange || "X25519"}]\n<<< [ServerHelloDone]\n>>> [ClientKeyExchange / Finished]\n<<< [ChangeCipherSpec / Finished]\n>>> [Application Data Encrypted - frames ${s.first_frame}..${s.last_frame}]`;
  }

  const sessionFindings = selSession
    ? allFindings.filter(
        (f) =>
          f.session_id === selSession.id ||
          (f.evidence?.server_port === selSession.server_port && f.evidence?.frames?.includes(selSession.first_frame))
      )
    : [];

  const cert = selSession?.certificate_chain?.[0];
  const isTls13Hidden = selSession?.tls?.version === "TLS 1.3" && !selSession.certificate_observable;

  return (
    <div className="w-full px-4 2xl:px-6 py-3 select-none text-[13px] h-[calc(100vh-88px)] flex flex-col overflow-hidden">
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-3 flex-1 min-h-0">
        {/* ================= LEFT 60%: SESSIONS TABLE ================= */}
        <section
          className="col-span-12 xl:col-span-7 flex flex-col bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 xcor-shadow min-h-0 overflow-hidden"
          aria-label="Sessions master table"
        >
          {/* Filter Bar */}
          <div className="flex items-center justify-between gap-2 pb-2.5 border-b border-border shrink-0 flex-wrap">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[14px] font-semibold text-foreground">Sessions</span>
              <span className="text-[11px] font-mono px-1.5 py-0.5 bg-surface-1 border border-border rounded-[var(--radius-xs)] text-muted">
                {filteredSessions.length}
              </span>

              <select
                value={proto}
                onChange={(e) => {
                  setProto(e.target.value);
                  setPage(1);
                }}
                className="bg-surface-1 border border-border rounded-[var(--radius-xs)] px-2 py-1 text-[12px] font-medium text-foreground cursor-pointer focus-ring"
              >
                <option value="">All protocols</option>
                <option value="smtp">SMTP</option>
                <option value="imap">IMAP</option>
                <option value="pop3">POP3</option>
              </select>

              <select
                value={trans}
                onChange={(e) => {
                  setTrans(e.target.value);
                  setPage(1);
                }}
                className="bg-surface-1 border border-border rounded-[var(--radius-xs)] px-2 py-1 text-[12px] font-medium text-foreground cursor-pointer focus-ring"
              >
                <option value="">All transports</option>
                <option value="implicit_tls">Implicit TLS</option>
                <option value="starttls">STARTTLS</option>
                <option value="plaintext">Plaintext</option>
              </select>

              <input
                type="text"
                placeholder="Filter stream, IP, SNI, cipher…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="bg-surface-1 border border-border rounded-[var(--radius-xs)] px-2.5 py-1 text-[12px] text-foreground placeholder:text-muted focus-ring w-44 font-mono"
              />
            </div>

            <div className="flex items-center gap-1.5 text-[11px] font-mono text-muted">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="px-2 py-0.5 border border-border bg-surface-1 disabled:opacity-40 hover:bg-surface-2 rounded-[var(--radius-xs)] text-foreground cursor-pointer"
              >
                Prev
              </button>
              <span className="px-1 text-foreground">{page}</span>
              <button
                disabled={page * data.page_size >= data.total}
                onClick={() => setPage((p) => p + 1)}
                className="px-2 py-0.5 border border-border bg-surface-1 disabled:opacity-40 hover:bg-surface-2 rounded-[var(--radius-xs)] text-foreground cursor-pointer"
              >
                Next
              </button>
            </div>
          </div>

          {/* Master Table */}
          <div className="flex-1 overflow-y-auto min-h-0 pt-1">
            <table className="w-full text-left text-[12px]">
              <thead className="sticky top-0 bg-surface-1 border-b border-border text-muted font-medium h-8 z-10">
                <tr>
                  <th className="px-2.5 py-1 w-20">ID</th>
                  <th className="px-2 py-1 w-16">Protocol</th>
                  <th className="px-2 py-1 w-20">Transport</th>
                  <th className="px-2 py-1 w-16">TLS Ver</th>
                  <th className="px-2 py-1">Cipher suite</th>
                  <th className="px-2 py-1 w-28">SNI</th>
                  <th className="px-2 py-1 w-16 text-center">Auth</th>
                  <th className="px-2.5 py-1 w-16 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {loading ? (
                  <tr>
                    <td colSpan={8} className="p-4 text-center text-muted">
                      Loading session streams…
                    </td>
                  </tr>
                ) : filteredSessions.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-6 text-center text-muted">
                      No matching sessions observed.
                    </td>
                  </tr>
                ) : (
                  filteredSessions.map((s) => {
                    const isSel = s.id === activeId;
                    const hasPlaintextAuth = s.auth_before_tls === true || s.transport === "plaintext";
                    const isSecure = s.transport !== "plaintext" && s.tls?.version === "TLS 1.3";

                    return (
                      <tr
                        key={s.id}
                        onClick={() => selectSession(s.id)}
                        className={`h-8 cursor-pointer transition-colors ${
                          isSel
                            ? "bg-accent-soft border-l-2 border-l-accent font-medium"
                            : "hover:bg-surface-1"
                        }`}
                      >
                        <td className="px-2.5 py-1 font-mono text-foreground">{s.id}</td>
                        <td className="px-2 py-1 text-muted text-[11px] uppercase">{s.protocol}</td>
                        <td className="px-2 py-1 font-mono text-[11px]">
                          <span
                            className={
                              s.transport === "plaintext"
                                ? "text-sev-critical font-semibold"
                                : s.transport === "starttls"
                                ? "text-accent"
                                : "text-sev-pass"
                            }
                          >
                            {s.transport === "implicit_tls"
                              ? "Implicit"
                              : s.transport === "starttls"
                              ? "STARTTLS"
                              : "Plaintext"}
                          </span>
                        </td>
                        <td className="px-2 py-1 font-mono text-muted text-[11px]">
                          {s.tls?.version ?? "—"}
                        </td>
                        <td className="px-2 py-1 font-mono text-foreground text-[11px] truncate max-w-[140px]">
                          {s.tls?.cipher_suite ?? "—"}
                        </td>
                        <td className="px-2 py-1 font-mono text-muted text-[11px] truncate max-w-[110px]">
                          {s.tls?.sni || s.server}
                        </td>
                        <td className="px-2 py-1 text-center font-mono text-[10px]">
                          {hasPlaintextAuth ? (
                            <span className="text-sev-critical font-bold">Clear</span>
                          ) : (
                            <span className="text-muted">TLS</span>
                          )}
                        </td>
                        <td className="px-2.5 py-1 text-right">
                          {hasPlaintextAuth ? (
                            <span className="inline-block w-2 h-2 rounded-full bg-sev-critical" title="Vulnerable" />
                          ) : isSecure ? (
                            <span className="inline-block w-2 h-2 rounded-full bg-sev-pass" title="Hardened" />
                          ) : (
                            <span className="inline-block w-2 h-2 rounded-full bg-sev-medium" title="Legacy" />
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* ================= RIGHT 40%: PERSISTENT DETAIL PANE ================= */}
        <section
          className="col-span-12 xl:col-span-5 flex flex-col bg-surface-0 border border-border rounded-[var(--radius-md)] p-3 xcor-shadow min-h-0 overflow-hidden"
          aria-label="Session detail inspector"
        >
          {selSession ? (
            <>
              {/* Detail Header */}
              <div className="flex items-center justify-between pb-2 border-b border-border shrink-0">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="font-mono text-[13px] font-semibold text-foreground">
                    {selSession.id}
                  </span>
                  <span className="text-muted text-[11px]">
                    {selSession.client} → {selSession.server}:{selSession.server_port}
                  </span>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    onClick={() =>
                      copyText(selSession.wireshark_filter, () => {
                        setCopiedFilter(true);
                        setTimeout(() => setCopiedFilter(false), 2000);
                      })
                    }
                    className="inline-flex items-center gap-1 px-2 py-1 bg-surface-1 hover:bg-surface-2 border border-border rounded-[var(--radius-xs)] text-[11px] font-mono text-foreground cursor-pointer"
                    title="Copy Wireshark stream filter"
                  >
                    {copiedFilter ? (
                      <>
                        <Check size={11} weight="bold" className="text-sev-pass" />
                        <span className="text-sev-pass">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy size={11} weight="bold" />
                        <span>Filter</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Scrollable Content */}
              <div className="flex-1 overflow-y-auto pr-1 pt-2 space-y-3">
                {/* Associated Findings */}
                {sessionFindings.length > 0 && (
                  <div className="space-y-1.5">
                    <h3 className="text-[12px] font-semibold text-foreground">Associated findings</h3>
                    <div className="space-y-1">
                      {sessionFindings.map((f) => (
                        <Link
                          key={f.id}
                          href={`/findings?capture=${capId}&selected=${f.id}`}
                          className="p-2 bg-surface-1 border border-border hover:border-accent/40 rounded-[var(--radius-xs)] flex items-center justify-between gap-2 transition-colors"
                        >
                          <div className="flex items-center gap-1.5 min-w-0">
                            <SeverityBadge severity={f.severity} />
                            <span className="font-mono text-[11px] text-muted">{f.rule_id}</span>
                            <span className="text-[12px] text-foreground font-medium truncate">{f.title}</span>
                          </div>
                          <ArrowRight size={11} weight="bold" className="text-accent shrink-0" />
                        </Link>
                      ))}
                    </div>
                  </div>
                )}

                {/* TLS Handshake Parameters */}
                <div className="space-y-1.5">
                  <h3 className="text-[12px] font-semibold text-foreground">TLS handshake parameters</h3>
                  <div className="bg-surface-1/60 border border-border rounded-[var(--radius-xs)] p-2.5 space-y-1.5 text-[11px] font-mono">
                    <div className="flex justify-between items-center">
                      <span className="text-muted font-sans">Negotiated version</span>
                      <span className="text-foreground font-semibold">{selSession.tls?.version ?? "None (Plaintext)"}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-muted font-sans">Cipher suite</span>
                      <span className="text-foreground font-semibold truncate max-w-[200px]">{selSession.tls?.cipher_suite ?? "—"}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-muted font-sans">Key exchange</span>
                      <span className="text-foreground font-semibold">{selSession.tls?.key_exchange ?? "—"}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-muted font-sans">SNI host</span>
                      <span className="text-foreground font-semibold truncate max-w-[200px]">{selSession.tls?.sni || selSession.server}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-muted font-sans">Forward secrecy</span>
                      <span className="text-foreground font-semibold">
                        {selSession.tls?.forward_secrecy === true
                          ? "Enforced (ECDHE)"
                          : selSession.tls?.forward_secrecy === false
                          ? "Missing (Static RSA)"
                          : "—"}
                      </span>
                    </div>
                  </div>
                </div>

                {/* X.509 Certificate Chain */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <h3 className="text-[12px] font-semibold text-foreground">X.509 certificate</h3>
                    {isTls13Hidden && (
                      <EvidenceTag variant="yellow">Not observable (TLS 1.3 encrypted)</EvidenceTag>
                    )}
                  </div>

                  {cert ? (
                    <div className="bg-surface-1/60 border border-border rounded-[var(--radius-xs)] p-2.5 space-y-1.5 text-[11px] font-mono">
                      <div className="flex justify-between items-center">
                        <span className="text-muted font-sans">Subject CN</span>
                        <span className="text-foreground font-semibold truncate max-w-[200px]">{cert.subject}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted font-sans">Issuer</span>
                        <span className="text-foreground font-semibold truncate max-w-[200px]">{cert.issuer}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted font-sans">Key size & algorithm</span>
                        <span className="text-foreground font-semibold">{cert.key_bits} bits ({cert.key_algorithm})</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted font-sans">Validity status</span>
                        <span className={cert.expired ? "text-sev-critical font-bold" : "text-sev-pass font-semibold"}>
                          {cert.expired ? "Expired" : `${cert.days_to_expiry} days remaining`}
                        </span>
                      </div>
                      {cert.san && cert.san.length > 0 && (
                        <div className="pt-1 border-t border-border">
                          <span className="text-muted block font-sans text-[10px]">Subject alternative names:</span>
                          <span className="text-foreground text-[10px] break-all">{cert.san.join(", ")}</span>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="p-3 bg-surface-1/50 border border-border rounded-[var(--radius-xs)] text-center text-muted text-[11px]">
                      {isTls13Hidden
                        ? "Certificate transmission encrypted by TLS 1.3 specification."
                        : "No X.509 certificate exchange recorded on this transport."}
                    </div>
                  )}
                </div>

                {/* Protocol Negotiation Transcript */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <h3 className="text-[12px] font-semibold text-foreground flex items-center gap-1.5">
                      <Terminal size={13} weight="bold" className="text-muted" />
                      <span>Negotiation transcript</span>
                    </h3>
                  </div>

                  <div className="bg-surface-1 border border-border rounded-[var(--radius-xs)] p-2.5 overflow-x-auto">
                    <pre className="text-[11px] font-mono leading-relaxed text-foreground select-all whitespace-pre">
                      {getTranscript(selSession)}
                    </pre>
                  </div>
                </div>

                {/* Wireshark Stream Filter Block */}
                <div className="space-y-1 pt-1 border-t border-border">
                  <span className="text-[10px] text-muted font-mono block">Wireshark stream filter:</span>
                  <code className="block bg-surface-1 border border-border px-2 py-1 rounded-[var(--radius-xs)] font-mono text-[11px] text-foreground select-all truncate">
                    {selSession.wireshark_filter}
                  </code>
                </div>
              </div>
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center p-6 text-muted">
              <p className="text-[13px] font-medium">Select a session stream to inspect forensic evidence.</p>
              <p className="text-[11px] mt-1">Use the arrow keys or click a row on the left table.</p>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
