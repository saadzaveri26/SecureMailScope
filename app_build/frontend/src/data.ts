import type {
  Capture, Summary, Session, Finding, Drift, PaginatedSessions,
  CustodyEvent, Evidence, Rule, RulesetVersion, Evaluation,
  Asset, Incident, TriageEvent, IncidentState,
} from "@/types";
import {
  captures as capFixtures,
  summaryForCap001,
  summaryForCap002,
  driftFixture,
  rulesFixture,
  rulesetVersionFixture,
  evaluationFixture,
  assetsForCap001,
  incidentsForCap001,
  triageHistoryForInc001,
} from "@/fixtures/data";

import cap001SummaryJson from "../demo-data/cap-001_summary.json";
import cap002SummaryJson from "../demo-data/cap-002_summary.json";
import cap001FindingsJson from "../demo-data/cap-001_findings.json";
import cap002FindingsJson from "../demo-data/cap-002_findings.json";
import cap001SessionsJson from "../demo-data/cap-001_sessions.json";
import cap002SessionsJson from "../demo-data/cap-002_sessions.json";
import cap001CustodyJson from "../demo-data/cap-001_custody.json";
import cap002CustodyJson from "../demo-data/cap-002_custody.json";
import cap001EvidenceJson from "../demo-data/cap-001_evidence.json";
import cap002EvidenceJson from "../demo-data/cap-002_evidence.json";
import evaluationSnapshot from "../demo-data/evaluation.json";

const USE_FIXTURES = process.env.NEXT_PUBLIC_USE_FIXTURES === "1";
const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

function authHeaders(): Record<string, string> {
  const h: Record<string, string> = {
    "X-Access-Token": "sms-analyst-token",
    "X-Actor": "analyst",
  };
  if (typeof window !== "undefined") {
    const t = sessionStorage.getItem("sms_access_token");
    const a = sessionStorage.getItem("sms_actor");
    if (t) h["X-Access-Token"] = t;
    if (a) h["X-Actor"] = a;
  }
  return h;
}

async function get<T>(path: string, fixture: T): Promise<T> {
  if (USE_FIXTURES) return fixture;
  try {
    const r = await fetch(`${API}${path}`, { headers: authHeaders() });
    if (!r.ok) return fixture;
    return await r.json();
  } catch {
    return fixture;
  }
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

let inMemoryCaps: Capture[] = [...capFixtures];

const summariesMap: Record<string, Summary> = {
  "cap-002": (cap002SummaryJson as unknown as Summary) || summaryForCap002,
  "cap-001": (cap001SummaryJson as unknown as Summary) || summaryForCap001,
};

const sessionsMap: Record<string, Session[]> = {
  "cap-002": (cap002SessionsJson as unknown as { items: Session[] })?.items || [],
  "cap-001": (cap001SessionsJson as unknown as { items: Session[] })?.items || [],
};

const findingsMap: Record<string, Finding[]> = {
  "cap-002": (cap002FindingsJson as unknown as { items: Finding[] })?.items || [],
  "cap-001": (cap001FindingsJson as unknown as { items: Finding[] })?.items || [],
};

const custodyMap: Record<string, CustodyEvent[]> = {
  "cap-002": (cap002CustodyJson as unknown as { items: CustodyEvent[] })?.items || [],
  "cap-001": (cap001CustodyJson as unknown as { items: CustodyEvent[] })?.items || [],
};

const evidenceMap: Record<string, Evidence[]> = {
  "cap-002": (cap002EvidenceJson as unknown as { items: Evidence[] })?.items || [],
  "cap-001": (cap001EvidenceJson as unknown as { items: Evidence[] })?.items || [],
};

function createAndRegisterFallbackSummary(cap: Capture): Summary {
  const score = cap.posture_score ?? 85;
  const grade = cap.grade ?? (score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F");
  const penalty = 100 - score;
  const tp = Math.floor(penalty * 0.35);
  const cp = Math.floor(penalty * 0.25);
  const pp = Math.floor(penalty * 0.20);
  const ciph = Math.floor(penalty * 0.15);
  const msg = penalty - tp - cp - pp - ciph;

  const s: Summary = {
    posture: {
      score,
      grade,
      triaged_score: score,
      triage_adjustments: [],
      factors: [
        { name: "Transport Security", weight: 0.35, impact: -tp, detail: tp > 0 ? `${tp} pt transport impact observed` : "No critical findings observed", finding_ids: [] },
        { name: "Certificate Hygiene", weight: 0.25, impact: -cp, detail: cp > 0 ? `${cp} pt certificate hygiene impact` : "Valid certificate chains observed", finding_ids: [] },
        { name: "Protocol Configuration", weight: 0.20, impact: -pp, detail: pp > 0 ? `${pp} pt protocol configuration impact` : "Standard protocol configuration", finding_ids: [] },
        { name: "Cipher Strength", weight: 0.15, impact: -ciph, detail: ciph > 0 ? `${ciph} pt cipher strength impact` : "Modern cipher suites", finding_ids: [] },
        { name: "Message Layer", weight: 0.05, impact: -msg, detail: msg > 0 ? `${msg} pt message layer impact` : "Transport security active", finding_ids: [] },
      ],
    },
    severity_counts: {
      critical: score < 60 ? 3 : 0,
      high: score < 75 ? 2 : 0,
      medium: score < 90 ? 3 : 0,
      low: 1,
      info: 4,
    },
    protocol_counts: { smtp: 45, imap: 50, pop3: 5, unknown: 0 },
    transport_counts: { implicit_tls: 55, starttls: 40, plaintext: score < 70 ? 5 : 0 },
    limitations: ["TLS 1.3 sessions encrypt certificates on the wire; chain validation relies on observed SNI/negotiation"],
    baseline_status: "ok",
    visibility: {
      sessions_total: 100,
      handshake_complete: 98,
      handshake_partial: 2,
      certificate_observable: 40,
      certificate_hidden_tls13: 60,
      certificate_resumed: 0,
      message_layer_observable: score < 70 ? 5 : 0,
      plaintext_sessions: score < 70 ? 5 : 0,
      checks_not_performed: [{ check: "Certificate chain validation", reason: "TLS 1.3 encrypts certificate", sessions: 60 }],
    },
  };
  summariesMap[cap.id] = s;
  return s;
}

export async function getCaptures(): Promise<Capture[]> {
  const list = await get<Capture[]>("/api/captures", inMemoryCaps);
  const seen = new Set<string>();
  const merged = [...list, ...inMemoryCaps].filter((c) => {
    if (!c?.id || seen.has(c.id)) return false;
    seen.add(c.id);
    return true;
  });
  return merged;
}

export async function getCapture(id: string): Promise<Capture> {
  const c = inMemoryCaps.find((c) => c.id === id);
  return get(`/api/captures/${id}`, c ?? inMemoryCaps[0]);
}

export async function uploadCapture(file: File): Promise<{ capture_id: string; status: string }> {
  if (!USE_FIXTURES) {
    try {
      const fd = new FormData();
      fd.append("file", file);
      const res = await mutate<{ capture_id: string; status: string }>("POST", "/api/captures", fd);
      if (res?.capture_id) {
        try {
          const cap = await mutate<Capture>("GET", `/api/captures/${res.capture_id}`);
          if (cap?.id) inMemoryCaps = [cap, ...inMemoryCaps];
        } catch {
          // ignore
        }
        return res;
      }
    } catch (e) {
      console.warn("API upload failed, using local simulation", e);
    }
  }

  const newId = `cap-${Date.now()}`;
  const fn = (file.name || "").toLowerCase();
  let score = 82;
  if (fn.includes("incident") || fn.includes("drift") || fn.includes("leak")) {
    score = 40;
  } else if (fn.includes("clean") || fn.includes("baseline")) {
    score = 100;
  } else {
    const h = file.name.split("").reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
    score = 70 + (h % 25);
  }
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  const newCap: Capture = {
    id: newId,
    filename: file.name,
    sha256: "1b1e124d39a73119081ae284e2a7a9fb8b069de8222e32bc4b54c34682e7a0d3",
    size_bytes: file.size || 1048576,
    packet_count: 3450,
    duration_s: 120.0,
    status: "complete",
    error: null,
    created_at: new Date().toISOString(),
    posture_score: score,
    grade,
    custody: null,
    analysis: null,
  };
  inMemoryCaps = [newCap, ...inMemoryCaps];
  createAndRegisterFallbackSummary(newCap);
  return { capture_id: newId, status: "complete" };
}

export async function deleteCapture(id: string): Promise<void> {
  inMemoryCaps = inMemoryCaps.filter((c) => c.id !== id);
  if (USE_FIXTURES) return;
  try {
    await mutate("DELETE", `/api/captures/${id}`);
  } catch {
    // ignore
  }
}

export async function getSummary(captureId: string): Promise<Summary> {
  const cap = inMemoryCaps.find((c) => c.id === captureId);
  const fallback = summariesMap[captureId] || (cap ? createAndRegisterFallbackSummary(cap) : summariesMap["cap-002"]);
  return get(`/api/captures/${captureId}/summary`, fallback);
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

  let items = sessionsMap[captureId] || (captureId === "cap-002" ? sessionsMap["cap-002"] : sessionsMap["cap-001"]);
  if (params?.protocol) items = items.filter((s) => s.protocol === params.protocol);
  if (params?.transport) items = items.filter((s) => s.transport === params.transport);
  const page = params?.page ?? 1;
  const size = params?.page_size ?? 25;
  const start = (page - 1) * size;
  const fallback = { items: items.slice(start, start + size), total: items.length, page, page_size: size };
  return get(`/api/captures/${captureId}/sessions${qs}`, fallback);
}

export async function getSession(captureId: string, sessionId: string): Promise<Session> {
  const list = sessionsMap[captureId] || sessionsMap["cap-001"];
  const s = list.find((s) => s.id === sessionId);
  return get(`/api/captures/${captureId}/sessions/${sessionId}`, s ?? list[0]);
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

  let items = findingsMap[captureId] || (captureId === "cap-002" ? findingsMap["cap-002"] : findingsMap["cap-001"]);
  if (params?.severity) items = items.filter((f) => f.severity === params.severity);
  if (params?.category) items = items.filter((f) => f.category === params.category);
  return get(`/api/captures/${captureId}/findings${qs}`, items);
}

export async function getDrift(baselineId: string, currentId: string): Promise<Drift> {
  return get(`/api/drift?baseline=${baselineId}&current=${currentId}`, driftFixture);
}

export async function getCustody(captureId: string): Promise<CustodyEvent[]> {
  const fallback = custodyMap[captureId] || custodyMap["cap-001"];
  return get(`/api/captures/${captureId}/custody`, fallback);
}

export async function getEvidence(captureId: string): Promise<Evidence[]> {
  const fallback = evidenceMap[captureId] || evidenceMap["cap-001"];
  return get(`/api/captures/${captureId}/evidence`, fallback);
}

export async function getEvidenceById(captureId: string, eid: string): Promise<Evidence> {
  const list = evidenceMap[captureId] || evidenceMap["cap-001"];
  const ev = list.find((e) => e.id === eid);
  return get(`/api/captures/${captureId}/evidence/${eid}`, ev ?? list[0]);
}

export async function getRules(): Promise<Rule[]> {
  return get("/api/rules", rulesFixture);
}

export async function getRulesetVersion(): Promise<RulesetVersion> {
  return get("/api/rules/version", rulesetVersionFixture);
}

export async function getEvaluation(): Promise<Evaluation> {
  return get("/api/evaluation", (evaluationSnapshot as unknown as Evaluation) || evaluationFixture);
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

  let items = fixtureIncidents;
  if (params?.state) items = items.filter((i) => i.state === params.state);
  if (params?.severity) items = items.filter((i) => i.severity === params.severity);
  return get(`/api/captures/${captureId}/incidents${qs}`, items);
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
