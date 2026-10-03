"use client";

import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from "react";

interface AuthState {
  token: string;
  actor: string;
}

interface AuthCtx extends AuthState {
  ready: boolean;
  setCredentials: (token: string, actor: string) => void;
  clearCredentials: () => void;
  headers: () => Record<string, string>;
}

const K_TOKEN = "sms_access_token";
const K_ACTOR = "sms_actor";

const Ctx = createContext<AuthCtx>({
  token: "",
  actor: "",
  ready: false,
  setCredentials: () => {},
  clearCredentials: () => {},
  headers: () => ({}),
});

export function useAuth() {
  return useContext(Ctx);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState("");
  const [actor, setActor] = useState("");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const t = sessionStorage.getItem(K_TOKEN) ?? "";
    const a = sessionStorage.getItem(K_ACTOR) ?? "";
    queueMicrotask(() => {
      setToken(t);
      setActor(a);
      setReady(true);
    });
  }, []);

  const setCredentials = useCallback((t: string, a: string) => {
    sessionStorage.setItem(K_TOKEN, t);
    sessionStorage.setItem(K_ACTOR, a);
    setToken(t);
    setActor(a);
  }, []);

  const clearCredentials = useCallback(() => {
    sessionStorage.removeItem(K_TOKEN);
    sessionStorage.removeItem(K_ACTOR);
    setToken("");
    setActor("");
  }, []);

  const headers = useCallback((): Record<string, string> => {
    const h: Record<string, string> = {};
    if (token) h["X-Access-Token"] = token;
    if (actor) h["X-Actor"] = actor;
    return h;
  }, [token, actor]);

  return (
    <Ctx.Provider value={{ token, actor, ready, setCredentials, clearCredentials, headers }}>
      {children}
    </Ctx.Provider>
  );
}
