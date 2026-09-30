import type {
  Capture, Summary, Session, Finding, Drift, PaginatedSessions,
} from "@/types";
import {
  captures as capFixtures,
  summaryForCap001,
  sessionsForCap001,
  findingsForCap001,
  driftFixture,
  paginatedSessionsForCap001,
} from "@/fixtures/data";

const USE_FIXTURES = process.env.NEXT_PUBLIC_USE_FIXTURES === "1";
const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function get<T>(path: string, fixture: T): Promise<T> {
  if (USE_FIXTURES) return fixture;
  const r = await fetch(`${API}${path}`);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function getCaptures(): Promise<Capture[]> {
  return get("/api/captures", capFixtures);
}

export async function getCapture(id: string): Promise<Capture> {
  const c = capFixtures.find((c) => c.id === id);
  return get(`/api/captures/${id}`, c ?? capFixtures[0]);
}

export async function uploadCapture(file: File): Promise<{ capture_id: string; status: string }> {
  if (USE_FIXTURES) return { capture_id: "cap-003", status: "queued" };
  const fd = new FormData();
  fd.append("file", file);
  const r = await fetch(`${API}/api/captures`, { method: "POST", body: fd });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function deleteCapture(id: string): Promise<void> {
  if (USE_FIXTURES) return;
  const r = await fetch(`${API}/api/captures/${id}`, { method: "DELETE" });
  if (!r.ok) throw new Error(await r.text());
}

export async function getSummary(captureId: string): Promise<Summary> {
  return get(`/api/captures/${captureId}/summary`, summaryForCap001);
}

export async function getSessions(
  captureId: string,
  params?: { protocol?: string; transport?: string; page?: number; page_size?: number }
): Promise<PaginatedSessions> {
  const sp = new URLSearchParams();
  if (params?.protocol) sp.set("protocol", params.protocol);
  if (params?.transport) sp.set("transport", params.transport);
  if (params?.page) sp.set("page", String(params.page));
  if (params?.page_size) sp.set("page_size", String(params.page_size));
  const qs = sp.toString() ? `?${sp}` : "";

  if (USE_FIXTURES) {
    let items = sessionsForCap001;
    if (params?.protocol) items = items.filter((s) => s.protocol === params.protocol);
    if (params?.transport) items = items.filter((s) => s.transport === params.transport);
    const page = params?.page ?? 1;
    const size = params?.page_size ?? 25;
    const start = (page - 1) * size;
    return { items: items.slice(start, start + size), total: items.length, page, page_size: size };
  }
  return get(`/api/captures/${captureId}/sessions${qs}`, paginatedSessionsForCap001);
}

export async function getSession(captureId: string, sessionId: string): Promise<Session> {
  const s = sessionsForCap001.find((s) => s.id === sessionId);
  return get(`/api/captures/${captureId}/sessions/${sessionId}`, s ?? sessionsForCap001[0]);
}

export async function getFindings(
  captureId: string,
  params?: { severity?: string; category?: string; protocol?: string }
): Promise<Finding[]> {
  const sp = new URLSearchParams();
  if (params?.severity) sp.set("severity", params.severity);
  if (params?.category) sp.set("category", params.category);
  if (params?.protocol) sp.set("protocol", params.protocol);
  const qs = sp.toString() ? `?${sp}` : "";

  if (USE_FIXTURES) {
    let items = findingsForCap001;
    if (params?.severity) items = items.filter((f) => f.severity === params.severity);
    if (params?.category) items = items.filter((f) => f.category === params.category);
    return items;
  }
  return get(`/api/captures/${captureId}/findings${qs}`, findingsForCap001);
}

export async function getDrift(baselineId: string, currentId: string): Promise<Drift> {
  return get(`/api/drift?baseline=${baselineId}&current=${currentId}`, driftFixture);
}

export function getReportUrl(captureId: string, format: "json" | "html" | "pdf"): string {
  if (USE_FIXTURES) return "#";
  return `${API}/api/captures/${captureId}/report?format=${format}`;
}
