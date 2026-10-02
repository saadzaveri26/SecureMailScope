"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { getCaptures, getIncidents, patchIncidentState, getIncidentHistory, getSummary } from "@/data";
import type { Capture, Incident, TriageEvent, IncidentState, Summary } from "@/types";
import { ConfidenceBadge } from "@/components/confidence-badge";

const INCIDENT_STATES: IncidentState[] = [
  "open",
  "under_investigation",
  "confirmed",
  "false_positive",
  "accepted_risk",
  "remediated",
];

const STATE_COLORS: Record<IncidentState, string> = {
  open: "bg-red-50 text-red-700 border-red-200",
  under_investigation: "bg-amber-50 text-amber-700 border-amber-200",
  confirmed: "bg-purple-50 text-purple-700 border-purple-200",
  false_positive: "bg-emerald-50 text-emerald-700 border-emerald-200",
  accepted_risk: "bg-blue-50 text-blue-700 border-blue-200",
  remediated: "bg-slate-100 text-slate-700 border-slate-300",
};

const SEV_COLORS: Record<string, string> = {
  critical: "bg-rose-50 text-rose-700 border-rose-200",
  high: "bg-orange-50 text-orange-700 border-orange-200",
  medium: "bg-amber-50 text-amber-700 border-amber-200",
  low: "bg-blue-50 text-blue-700 border-blue-200",
  info: "bg-slate-100 text-slate-700 border-slate-200",
};

function IncidentsContent() {
  const sp = useSearchParams();
  const capParam = sp.get("capture");

  const [caps, setCaps] = useState<Capture[]>([]);
  const [activeCap, setActiveCap] = useState<string>("");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [stateFilter, setStateFilter] = useState<string>("all");

  // Triage state update modal
  const [targetIncident, setTargetIncident] = useState<Incident | null>(null);
  const [nextState, setNextState] = useState<IncidentState>("open");
  const [triageNote, setTriageNote] = useState<string>("");
  const [noteError, setNoteError] = useState<string>("");
  const [submitting, setSubmitting] = useState(false);

  // History modal
  const [historyIncident, setHistoryIncident] = useState<Incident | null>(null);
  const [historyEvents, setHistoryEvents] = useState<TriageEvent[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  useEffect(() => {
    getCaptures().then((c) => {
      setCaps(c);
      const chosen = capParam && c.some((x) => x.id === capParam) ? capParam : c[0]?.id ?? "";
      setActiveCap(chosen);
    });
  }, [capParam]);

  const loadData = (capId: string) => {
    setLoading(true);
    Promise.all([getIncidents(capId), getSummary(capId)])
      .then(([incs, sum]) => {
        setIncidents(incs);
        setSummary(sum);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (!activeCap) return;
    loadData(activeCap);
  }, [activeCap]);

  const handleOpenTriage = (inc: Incident, newState: IncidentState) => {
    setTargetIncident(inc);
    setNextState(newState);
    setTriageNote("");
    setNoteError("");
  };

  const handleConfirmTriage = async () => {
    if (!targetIncident) return;
    const isNoteRequired = nextState === "false_positive" || nextState === "accepted_risk";
    if (isNoteRequired && !triageNote.trim()) {
      setNoteError(`A justification note is strictly required when transitioning to ${nextState.replace("_", " ")}.`);
      return;
    }

    setSubmitting(true);
    try {
      await patchIncidentState(targetIncident.id, nextState, triageNote.trim());
      setTargetIncident(null);
      loadData(activeCap);
    } catch (e: any) {
      setNoteError(e?.message || "Failed to update triage state");
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenHistory = (inc: Incident) => {
    setHistoryIncident(inc);
    setHistoryLoading(true);
    getIncidentHistory(inc.id)
      .then(setHistoryEvents)
      .finally(() => setHistoryLoading(false));
  };

  const filtered = incidents.filter((i) => {
    if (stateFilter !== "all" && i.state !== stateFilter) return false;
    return true;
  });

  return (
    <div className="max-w-[1400px] mx-auto px-4 py-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-foreground">Incidents & Triage</h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-blue-50 text-brand border border-blue-200">
              Contract 0.2 §10
            </span>
          </div>
          <p className="text-xs text-muted mt-1">
            Grouped findings by server and rule. Manage investigation states, false positive justifications, and posture adjustments.
          </p>
        </div>

        {/* Capture selector */}
        {caps.length > 1 && (
          <select
            value={activeCap}
            onChange={(e) => setActiveCap(e.target.value)}
            className="text-xs bg-surface-0 border border-border rounded px-3 py-1.5 font-mono text-foreground"
          >
            {caps.map((c) => (
              <option key={c.id} value={c.id}>
                {c.filename} ({c.id})
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Posture Score vs Triaged Score Banner */}
      {summary && (
        <div className="p-4 rounded-lg bg-surface-0 border border-border grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
          <div className="flex items-center gap-4">
            <div className="text-center px-4 py-2 rounded bg-slate-50 border border-border">
              <span className="text-[10px] uppercase tracking-wider text-muted block font-semibold">Raw Score</span>
              <span className="text-2xl font-bold font-mono text-foreground">{summary.posture.score}</span>
            </div>
            <div className="text-center px-4 py-2 rounded bg-emerald-50/60 border border-emerald-200">
              <span className="text-[10px] uppercase tracking-wider text-emerald-700 block font-semibold">Triaged Score</span>
              <span className="text-2xl font-bold font-mono text-emerald-800">
                {summary.posture.triaged_score ?? summary.posture.score}
              </span>
            </div>
          </div>

          <div className="md:col-span-2 text-xs text-muted space-y-1">
            <span className="font-semibold text-foreground block">Triage Score Rules (§10):</span>
            <p>
              Only <code className="text-emerald-700 font-mono">false_positive</code> restorations remove penalties from the triaged score. <code className="font-mono">accepted_risk</code> and <code className="font-mono">remediated</code> maintain original penalties until confirmed in a subsequent capture.
            </p>
            {summary.posture.triage_adjustments && summary.posture.triage_adjustments.length > 0 && (
              <div className="pt-1 flex flex-wrap gap-2">
                {summary.posture.triage_adjustments.map((adj) => (
                  <span key={adj.incident_id} className="text-[11px] px-2 py-0.5 rounded bg-emerald-100/70 text-emerald-800 font-mono">
                    {adj.incident_id}: {adj.effect}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Filter tabs */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-border pb-3">
        <button
          onClick={() => setStateFilter("all")}
          className={[
            "px-2.5 py-1 rounded text-xs transition-colors",
            stateFilter === "all" ? "bg-brand text-white font-medium" : "bg-surface-0 text-muted hover:text-foreground border border-border",
          ].join(" ")}
        >
          All States ({incidents.length})
        </button>
        {INCIDENT_STATES.map((st) => {
          const count = incidents.filter((i) => i.state === st).length;
          return (
            <button
              key={st}
              onClick={() => setStateFilter(st)}
              className={[
                "px-2.5 py-1 rounded text-xs transition-colors font-mono",
                stateFilter === st ? "bg-brand text-white font-medium" : "bg-surface-0 text-muted hover:text-foreground border border-border",
              ].join(" ")}
            >
              {st} ({count})
            </button>
          );
        })}
      </div>

      {/* Incident List */}
      {loading ? (
        <div className="py-12 text-center text-xs text-muted">Loading incidents...</div>
      ) : filtered.length === 0 ? (
        <div className="py-12 text-center text-xs text-muted">No incidents found in this state.</div>
      ) : (
        <div className="space-y-3">
          {filtered.map((inc) => (
            <div
              key={inc.id}
              className="bg-surface-0 border border-border rounded-lg p-4 space-y-3 hover:border-slate-300 transition-colors"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs font-bold text-foreground">{inc.id}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase border ${SEV_COLORS[inc.severity]}`}>
                    {inc.severity}
                  </span>
                  <ConfidenceBadge level={inc.confidence} />
                  <span className="font-mono text-xs text-muted">Rule: {inc.rule_id}</span>
                  <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-700">
                    {inc.server} ({inc.server_role})
                  </span>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {/* Current State Dropdown */}
                  <select
                    value={inc.state}
                    onChange={(e) => handleOpenTriage(inc, e.target.value as IncidentState)}
                    className={`text-xs font-mono font-semibold px-2.5 py-1 rounded border ${STATE_COLORS[inc.state]} cursor-pointer`}
                  >
                    {INCIDENT_STATES.map((st) => (
                      <option key={st} value={st}>
                        {st}
                      </option>
                    ))}
                  </select>

                  <button
                    onClick={() => handleOpenHistory(inc)}
                    className="text-xs text-muted hover:text-brand px-2 py-1 rounded border border-border bg-slate-50 transition-colors"
                  >
                    Audit Trail
                  </button>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-foreground">{inc.title}</h3>
                <p className="text-xs text-muted mt-1">{inc.remediation.summary}</p>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-border/60 text-xs">
                <div className="flex items-center gap-4 text-muted font-mono text-[11px]">
                  <span>Sessions: {inc.sessions_affected}</span>
                  <span>Clients: {inc.clients_affected}</span>
                  <span>Priority Rank: #{inc.priority_rank}</span>
                </div>

                <div className="flex items-center gap-2 text-[11px]">
                  <span className="text-muted">Evidence:</span>
                  {inc.evidence_ids.map((eid) => (
                    <Link
                      key={eid}
                      href={`/evidence?capture=${activeCap}&eid=${eid}`}
                      className="font-mono text-brand hover:underline"
                    >
                      {eid}
                    </Link>
                  ))}
                  <span className="text-muted ml-2">Findings:</span>
                  {inc.finding_ids.map((fid) => (
                    <span key={fid} className="font-mono text-slate-700 bg-slate-100 px-1 py-0.5 rounded">
                      {fid}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Triage Modal */}
      {targetIncident && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-surface-0 border border-border rounded-xl shadow-xl max-w-lg w-full p-6 space-y-4">
            <div>
              <h3 className="text-sm font-bold text-foreground">Update Incident Triage State</h3>
              <p className="text-xs text-muted mt-1">
                Updating <span className="font-mono font-semibold text-foreground">{targetIncident.id}</span> from{" "}
                <span className="font-mono font-medium">{targetIncident.state}</span> to{" "}
                <span className="font-mono font-bold text-brand">{nextState}</span>.
              </p>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-foreground block">
                Justification Note{" "}
                {(nextState === "false_positive" || nextState === "accepted_risk") && (
                  <span className="text-rose-600 font-bold">* (Strictly required by Contract 0.2 §10)</span>
                )}
              </label>
              <textarea
                value={triageNote}
                onChange={(e) => {
                  setTriageNote(e.target.value);
                  setNoteError("");
                }}
                rows={3}
                placeholder="Enter justification, engineering rationale, or accepted risk reference..."
                className="w-full text-xs font-mono p-2.5 rounded border border-border bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-brand"
              />
              {noteError && <p className="text-xs text-rose-600 font-medium">{noteError}</p>}
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setTargetIncident(null)}
                className="px-3 py-1.5 text-xs text-muted hover:text-foreground transition-colors"
                disabled={submitting}
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmTriage}
                disabled={submitting}
                className="px-4 py-1.5 text-xs font-semibold rounded bg-brand text-white hover:bg-brand-hover transition-colors"
              >
                {submitting ? "Saving..." : "Confirm Transition"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* History Modal */}
      {historyIncident && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-surface-0 border border-border rounded-xl shadow-xl max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-foreground">Triage Audit Trail</h3>
                <p className="text-xs text-muted mt-0.5 font-mono">{historyIncident.id} — {historyIncident.title}</p>
              </div>
              <button
                onClick={() => setHistoryIncident(null)}
                className="text-xs text-muted hover:text-foreground"
              >
                Close
              </button>
            </div>

            <div className="space-y-3 max-h-[350px] overflow-y-auto">
              {historyLoading ? (
                <div className="py-6 text-center text-xs text-muted">Loading audit events...</div>
              ) : historyEvents.length === 0 ? (
                <div className="py-6 text-center text-xs text-muted">No prior triage events recorded.</div>
              ) : (
                historyEvents.map((ev) => (
                  <div key={ev.id} className="p-3 rounded border border-border bg-slate-50/60 text-xs space-y-1 font-mono">
                    <div className="flex items-center justify-between text-[11px] text-muted">
                      <span>Actor: <strong className="text-foreground">{ev.actor}</strong></span>
                      <span>{new Date(ev.ts).toLocaleString()}</span>
                    </div>
                    <div className="text-xs text-foreground font-semibold">
                      {ev.from_state} → {ev.to_state}
                    </div>
                    {ev.note && (
                      <p className="text-[11px] text-slate-600 bg-white p-2 rounded border border-border mt-1">
                        &quot;{ev.note}&quot;
                      </p>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function IncidentsPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-xs text-muted">Loading...</div>}>
      <IncidentsContent />
    </Suspense>
  );
}
