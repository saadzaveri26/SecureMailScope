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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" role="dialog" aria-modal="true" aria-label="SecureMailScope access gate">
      <form
        onSubmit={submit}
        className="bg-surface-0 rounded-[var(--radius-md)] p-6 w-full max-w-sm space-y-4 xcor-shadow"
      >
        <div className="border-b border-border pb-3">
          <div className="flex items-center gap-1.5 text-[var(--font-size-xl)] font-bold text-foreground">
            <span className="p-1 bg-accent rounded-[var(--radius-xs)] text-white text-[var(--font-size-sm)]">▸</span>
            <span>SecureMailScope Access</span>
          </div>
          <p className="text-[var(--font-size-md)] text-muted mt-1">
            Enter your access token and analyst identity to authenticate session.
          </p>
        </div>
        {err && (
          <div className="text-[var(--font-size-md)] font-bold text-sev-critical bg-sev-critical-bg rounded-[var(--radius-sm)] p-2" role="alert">
            {err}
          </div>
        )}
        <div className="space-y-3">
          <div className="space-y-1">
            <label htmlFor="auth-token" className="text-[var(--font-size-sm)] font-bold text-foreground block uppercase tracking-wider">Access Token</label>
            <input
              id="auth-token"
              type="password"
              value={t}
              onChange={(e) => { setT(e.target.value); setErr(""); }}
              className="w-full border border-border bg-surface-1 rounded-[var(--radius-sm)] px-3 py-2 text-[var(--font-size-xl)] font-medium text-foreground placeholder:text-muted focus-ring"
              placeholder="e.g. admin or custom key"
              autoFocus
            />
          </div>
          <div className="space-y-1">
            <label htmlFor="auth-analyst" className="text-[var(--font-size-sm)] font-bold text-foreground block uppercase tracking-wider">Analyst Handle</label>
            <input
              id="auth-analyst"
              type="text"
              value={a}
              onChange={(e) => { setA(e.target.value); setErr(""); }}
              maxLength={64}
              className="w-full border border-border bg-surface-1 rounded-[var(--radius-sm)] px-3 py-2 text-[var(--font-size-xl)] font-medium text-foreground placeholder:text-muted focus-ring"
              placeholder="e.g. admin or jdoe"
            />
            <span className="text-[var(--font-size-sm)] text-muted">Self-asserted X-Actor audit identifier.</span>
          </div>
        </div>
        <button
          type="submit"
          className={[
            "w-full bg-accent hover:bg-accent-hover text-white rounded-[var(--radius-sm)]",
            "text-[var(--font-size-xl)] font-bold py-2.5",
            "transition-all duration-[var(--motion-fast)]",
            "active:scale-[0.98] focus-ring cursor-pointer",
          ].join(" ")}
        >
          Enter Workspace →
        </button>
      </form>
    </div>
  );
}
