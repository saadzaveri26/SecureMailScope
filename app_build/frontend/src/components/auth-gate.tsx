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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 font-mono">
      <form
        onSubmit={submit}
        className="bg-surface-0 border-3 border-black p-6 w-full max-w-sm space-y-4 brutal-shadow"
      >
        <div className="border-b-2 border-black pb-3">
          <div className="flex items-center gap-1.5 text-xs font-bold text-black uppercase">
            <span className="p-1 bg-accent border border-black">▸</span>
            <span>SecureMailScope Access</span>
          </div>
          <p className="text-xs text-muted mt-1 font-medium">
            Enter your access token and analyst identity to authenticate session.
          </p>
        </div>
        {err && (
          <div className="text-xs font-bold text-sev-critical bg-sev-critical-bg border-2 border-black p-2">
            {err}
          </div>
        )}
        <div className="space-y-3">
          <div className="space-y-1">
            <label className="text-xs font-bold text-black block uppercase tracking-wider">Access Token</label>
            <input
              type="password"
              value={t}
              onChange={(e) => { setT(e.target.value); setErr(""); }}
              className="w-full border-2 border-black bg-surface-1 px-3 py-2 text-sm font-bold text-black placeholder:text-muted focus:outline-none focus:bg-accent/15"
              placeholder="e.g. admin or custom key"
              autoFocus
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-bold text-black block uppercase tracking-wider">Analyst Handle</label>
            <input
              type="text"
              value={a}
              onChange={(e) => { setA(e.target.value); setErr(""); }}
              maxLength={64}
              className="w-full border-2 border-black bg-surface-1 px-3 py-2 text-sm font-bold text-black placeholder:text-muted focus:outline-none focus:bg-accent/15"
              placeholder="e.g. admin or jdoe"
            />
            <span className="text-[10px] text-muted font-medium">Self-asserted X-Actor audit identifier.</span>
          </div>
        </div>
        <button
          type="submit"
          className="w-full bg-accent hover:bg-accent-hover text-black border-2 border-black text-sm font-bold py-2.5 transition-all brutal-shadow-sm hover:translate-x-[-1px] hover:translate-y-[-1px] cursor-pointer"
        >
          Enter Workspace →
        </button>
      </form>
    </div>
  );
}
