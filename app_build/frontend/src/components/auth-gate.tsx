"use client";

import { useState } from "react";
import { useAuth } from "./auth-context";

export function AuthGate({ children }: { children: React.ReactNode }) {
  const { token, actor, ready, setCredentials } = useAuth();
  const [t, setT] = useState("");
  const [a, setA] = useState("");
  const [err, setErr] = useState("");

  if (!ready) return null;

  const isDemo = process.env.NEXT_PUBLIC_DEMO_MODE === "1" || process.env.NEXT_PUBLIC_DEMO_MODE === "true";
  if (isDemo || (token && actor)) return <>{children}</>;

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!t.trim()) return setErr("Access token is required");
    if (!a.trim()) return setErr("Analyst name is required");
    if (a.trim().length > 64) return setErr("Analyst name must be at most 64 characters");
    setCredentials(t.trim(), a.trim());
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-foreground/40 backdrop-blur-sm">
      <form
        onSubmit={submit}
        className="bg-surface-0 border border-border rounded-sm p-6 w-full max-w-sm space-y-4 shadow-drawer"
      >
        <div>
          <h2 className="text-base font-semibold text-foreground">Sign in to SecureMailScope</h2>
          <p className="text-xs text-muted mt-1">
            Enter your access token and analyst name. These are stored in your browser session only.
          </p>
        </div>
        {err && <p className="text-xs text-sev-critical">{err}</p>}
        <div className="space-y-3">
          <div className="space-y-1">
            <label className="text-xs font-medium text-foreground block">Access Token</label>
            <input
              type="password"
              value={t}
              onChange={(e) => { setT(e.target.value); setErr(""); }}
              className="w-full rounded-sm border border-border bg-surface-1 px-3 py-2 text-sm text-foreground placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-ink focus:ring-offset-2 focus:ring-offset-evidence"
              placeholder="Paste your token"
              autoFocus
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-foreground block">Analyst Name</label>
            <input
              type="text"
              value={a}
              onChange={(e) => { setA(e.target.value); setErr(""); }}
              maxLength={64}
              className="w-full rounded-sm border border-border bg-surface-1 px-3 py-2 text-sm text-foreground placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-ink focus:ring-offset-2 focus:ring-offset-evidence"
              placeholder="e.g. jdoe"
            />
            <span className="text-[11px] text-muted">Self-asserted. Recorded in audit trail, not proof of identity.</span>
          </div>
        </div>
        <button
          type="submit"
          className="w-full rounded-sm bg-ink hover:bg-ink-2 text-white text-sm font-semibold py-2 transition-colors"
        >
          Continue
        </button>
      </form>
    </div>
  );
}
