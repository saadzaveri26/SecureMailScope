"use client";

import type { VisibilitySummary } from "@/types";

export function VisibilityPanel({ v }: { v: VisibilitySummary }) {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Stat label="Sessions total" val={v.sessions_total} />
        <Stat label="Handshake complete" val={v.handshake_complete} />
        <Stat label="Handshake partial" val={v.handshake_partial} warn={v.handshake_partial > 0} />
        <Stat label="Plaintext sessions" val={v.plaintext_sessions} warn={v.plaintext_sessions > 0} />
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Stat label="Cert observable" val={v.certificate_observable} />
        <Stat label="Cert hidden (TLS 1.3)" val={v.certificate_hidden_tls13} muted={v.certificate_hidden_tls13 === 0} />
        <Stat label="Cert resumed" val={v.certificate_resumed} muted={v.certificate_resumed === 0} />
        <Stat label="Message layer observable" val={v.message_layer_observable} />
      </div>

      {v.checks_not_performed.length > 0 && (
        <div className="space-y-1.5 pt-2 border-t border-border">
          <span className="text-[11px] font-medium text-muted block">Checks not performed</span>
          {v.checks_not_performed.map((c, i) => (
            <div key={i} className="flex items-start justify-between gap-2 text-[var(--font-size-md)]">
              <div className="min-w-0">
                <span className="font-medium text-foreground">{c.check}</span>
                <span className="text-muted ml-1.5">— {c.reason}</span>
              </div>
              <span className="shrink-0 font-mono text-muted tabular-nums">
                {c.sessions} session{c.sessions !== 1 ? "s" : ""}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Stat({ label, val, warn, muted }: { label: string; val: number; warn?: boolean; muted?: boolean }) {
  return (
    <div className="space-y-0.5">
      <span className="text-[11px] text-muted block">{label}</span>
      <span
        className={[
          "text-lg font-bold font-mono tabular-nums",
          warn ? "text-sev-critical" : muted ? "text-muted" : "text-foreground",
        ].join(" ")}
      >
        {val}
      </span>
    </div>
  );
}
