import type {
  Capture, Summary, Session, Finding, Drift, PaginatedSessions,
  CustodyEvent, Evidence, Rule, RulesetVersion, Evaluation,
  Asset, Incident, TriageEvent, IncidentState,
} from "@/types";
import {
  captures as capFixtures,
  summaryForCap001,
  sessionsForCap001,
  findingsForCap001,
  driftFixture,
  paginatedSessionsForCap001,
  custodyEventsForCap001,
  evidenceForCap001,
  rulesFixture,
  rulesetVersionFixture,
  evaluationFixture,
  assetsForCap001,
  incidentsForCap001,
  triageHistoryForInc001,
} from "@/fixtures/data";
import evaluationSnapshot from "../demo-data/evaluation.json";

const USE_FIXTURES = process.env.NEXT_PUBLIC_USE_FIXTURES === "1";
const IS_DEMO = process.env.NEXT_PUBLIC_DEMO_MODE === "1" || process.env.NEXT_PUBLIC_DEMO_MODE === "true";
const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

function authHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const t = sessionStorage.getItem("sms_access_token");
  const a = sessionStorage.getItem("sms_actor");
  const h: Record<string, string> = {};
  if (t) h["X-Access-Token"] = t;
  if (a) h["X-Actor"] = a;
  return h;
}

async function get<T>(path: string, fixture: T): Promise<T> {
  if (IS_DEMO || USE_FIXTURES) return fixture;
  const r = await fetch(`${API}${path}`, { headers: authHeaders() });
  if (r.status === 401) throw new Error("Unauthorized — check your access token");
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

async function mutate<T>(method: string, path: string, body?: FormData | object): Promise<T> {
  const h: Record<string, string> = { ...authHeaders() };
  let b: BodyInit | undefined;
  if (body instanceof FormData) {
    b = body;
  } else if (body) {
    h["Content-Type"] = "application/json";
    b = JSON.stringify(body);
  }
  const r = await fetch(`${API}${path}`, { method, headers: h, body: b });
  if (r.status === 401) throw new Error("Unauthorized — check your access token");
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

let fixtureCaps: Capture[] = [...capFixtures];

export async function getCaptures(): Promise<Capture[]> {
  const list = await get<Capture[]>("/api/captures", fixtureCaps);
  const seen = new Set<string>();
  return list.filter((c) => {
    if (!c?.id || seen.has(c.id)) return false;
    seen.add(c.id);
    return true;
  });
}

export async function getCapture(id: string): Promise<Capture> {
  const c = fixtureCaps.find((c) => c.id === id);
  if (USE_FIXTURES && c && c.status === "processing") {
    setTimeout(() => {
      c.status = "complete";
      c.posture_score = c.posture_score ?? 78;
      c.grade = c.grade ?? "C";
      c.packet_count = c.packet_count || 14200;
    }, 2000);
  }
  return get(`/api/captures/${id}`, c ?? fixtureCaps[0]);
}

export async function uploadCapture(file: File): Promise<{ capture_id: string; status: string }> {
  if (IS_DEMO) throw new Error("Uploads disabled in demo mode");
  if (USE_FIXTURES) {
    const newId = `cap-${Date.now()}`;
    const newCap: Capture = {
      id: newId,
      filename: file.name,
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      size_bytes: file.size || 1048576,
      packet_count: 0,
      duration_s: 120.0,
      status: "processing",
      error: null,
      created_at: new Date().toISOString(),
      posture_score: null,
      grade: null,
      custody: null,
      analysis: null,
    };
    fixtureCaps = [newCap, ...fixtureCaps];
    setTimeout(() => {
      newCap.status = "complete";
      newCap.posture_score = 78;
      newCap.grade = "C";
      newCap.packet_count = 14200;
    }, 2500);
    return { capture_id: newId, status: "queued" };
  }
  const fd = new FormData();
  fd.append("file", file);
  return mutate("POST", "/api/captures", fd);
}

export async function deleteCapture(id: string): Promise<void> {
  if (USE_FIXTURES) return;
  await mutate("DELETE", `/api/captures/${id}`);
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

export async function getCustody(captureId: string): Promise<CustodyEvent[]> {
  return get(`/api/captures/${captureId}/custody`, custodyEventsForCap001);
}

export async function getEvidence(captureId: string): Promise<Evidence[]> {
  return get(`/api/captures/${captureId}/evidence`, evidenceForCap001);
}

export async function getEvidenceById(captureId: string, eid: string): Promise<Evidence> {
  const ev = evidenceForCap001.find((e) => e.id === eid);
  return get(`/api/captures/${captureId}/evidence/${eid}`, ev ?? evidenceForCap001[0]);
}

export async function getRules(): Promise<Rule[]> {
  return get("/api/rules", rulesFixture);
}

export async function getRulesetVersion(): Promise<RulesetVersion> {
  return get("/api/rules/version", rulesetVersionFixture);
}

export async function getEvaluation(): Promise<Evaluation> {
  return get("/api/evaluation", (IS_DEMO ? evaluationSnapshot : evaluationFixture) as Evaluation);
}

export async function downloadReport(captureId: string, format: "json" | "html" | "pdf"): Promise<void> {
  if (USE_FIXTURES) return;
  const r = await fetch(`${API}/api/captures/${captureId}/report?format=${format}`, {
    headers: authHeaders(),
  });
  if (!r.ok) throw new Error(await r.text());
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `SecureMailScope_${captureId}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function getReportUrl(captureId: string, format: "json" | "html" | "pdf"): string {
  if (USE_FIXTURES) return "#";
  return `${API}/api/captures/${captureId}/report?format=${format}`;
}

const fixtureIncidents: Incident[] = [...incidentsForCap001];

export async function getAssets(captureId: string): Promise<Asset[]> {
  return get(`/api/captures/${captureId}/assets`, assetsForCap001);
}

export async function getIncidents(
  captureId: string,
  params?: { state?: string; severity?: string }
): Promise<Incident[]> {
  const sp = new URLSearchParams();
  if (params?.state) sp.set("state", params.state);
  if (params?.severity) sp.set("severity", params.severity);
  const qs = sp.toString() ? `?${sp}` : "";

  if (USE_FIXTURES) {
    let items = fixtureIncidents;
    if (params?.state) items = items.filter((i) => i.state === params.state);
    if (params?.severity) items = items.filter((i) => i.severity === params.severity);
    return items;
  }
  return get(`/api/captures/${captureId}/incidents${qs}`, fixtureIncidents);
}

export async function patchIncidentState(
  incidentId: string,
  state: IncidentState,
  note?: string
): Promise<Incident> {
  if (USE_FIXTURES) {
    const inc = fixtureIncidents.find((i) => i.id === incidentId);
    if (!inc) throw new Error("Incident not found");
    inc.state = state;
    return { ...inc };
  }
  return mutate("PATCH", `/api/incidents/${incidentId}/state`, { state, note });
}

export async function getIncidentHistory(incidentId: string): Promise<TriageEvent[]> {
  return get(`/api/incidents/${incidentId}/history`, triageHistoryForInc001);
}

export async function pinBaseline(captureId: string): Promise<{ baseline_capture_id: string }> {
  return mutate("PUT", "/api/baseline", { capture_id: captureId });
}

export async function getBaseline(): Promise<{ baseline_capture_id: string | null }> {
  return get("/api/baseline", { baseline_capture_id: "cap-002" });
}

export async function getFeatures(): Promise<{ key_assisted: boolean; artifact_assisted: boolean }> {
  return get("/api/features", { key_assisted: true, artifact_assisted: true });
}

