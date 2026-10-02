export type CaptureStatus = "queued" | "processing" | "complete" | "failed";
export type Grade = "A" | "B" | "C" | "D" | "F";
export type Protocol = "smtp" | "imap" | "pop3" | "unknown";
export type ProtocolConfidence = "high" | "low";
export type Transport = "implicit_tls" | "starttls" | "plaintext";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingCategory = "transport" | "certificate" | "protocol" | "message" | "anomaly" | "drift";
export type MessageLayerState = "encrypted" | "signed" | "none_observed" | "not_observable";
export type BaselineStatus = "ok" | "insufficient" | "not_configured";
export type DriftDirection = "improved" | "degraded" | "changed" | "appeared" | "disappeared";
export type DriftKind = "tls_version" | "cipher_suite" | "key_exchange" | "certificate" | "starttls" | "auth_before_tls" | "endpoint" | "issuer" | "key_size";
export type ReportFormat = "json" | "html" | "pdf";
export type Confidence = "high" | "medium" | "low";
export type HandshakeVisibility = "complete" | "partial" | "none";
export type CertificateVisibility = "observable" | "hidden_tls13" | "resumed" | "not_seen";
export type MessageLayerVisibility = "observable" | "hidden_by_tls" | "not_applicable";
export type CustodyAction = "uploaded" | "analysis_started" | "analysis_completed" | "report_exported" | "triage_changed" | "payload_deleted" | "keylog_attached" | "artifact_attached";
export type EvidenceType = "session" | "starttls_exchange" | "handshake" | "certificate" | "cleartext_auth" | "message_marker" | "baseline_deviation";
export type IncidentState = "open" | "under_investigation" | "confirmed" | "false_positive" | "accepted_risk" | "remediated";
export type ForwardSecrecyState = "all" | "some" | "none" | "unknown";
export type StarttlsSupport = "always" | "sometimes" | "never" | "not_applicable";

export interface Capture {
  id: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  packet_count: number;
  duration_s: number;
  status: CaptureStatus;
  error: string | null;
  created_at: string;
  posture_score: number | null;
  grade: Grade | null;
  custody: CustodyInfo | null;
  analysis: AnalysisInfo | null;
}

export interface CustodyInfo {
  sha256: string;
  original_filename: string;
  size_bytes: number;
  received_at: string;
  uploaded_by: string;
  payload_retained: boolean;
  payload_deleted_at: string | null;
}

export interface AnalysisInfo {
  tool_version: string;
  ruleset_version: string;
  ruleset_sha256: string;
  modes: string[];
  started_at: string;
  completed_at: string;
}

export interface CustodyEvent {
  id: string;
  ts: string;
  actor: string;
  action: CustodyAction;
  detail: string;
}

export interface Evidence {
  id: string;
  capture_id: string;
  type: EvidenceType;
  session_id: string | null;
  frames: number[];
  summary: string;
  wireshark_filter: string;
  certificate_sha256: string | null;
}

export interface PolicyRef {
  document: string;
  section: string;
  verified_on: string;
}

export interface Rule {
  id: string;
  version: string;
  title: string;
  description: string;
  severity: Severity;
  category: FindingCategory;
  enabled: boolean;
  policy_refs: PolicyRef[];
}

export interface RulesetVersion {
  ruleset_version: string;
  sha256: string;
}

export interface PostureFactor {
  name: string;
  weight: number;
  impact: number;
  detail: string;
  finding_ids: string[];
}

export interface TriageAdjustment {
  incident_id: string;
  state: IncidentState;
  effect: string;
}

export interface Posture {
  score: number;
  grade: Grade;
  factors: PostureFactor[];
  triaged_score?: number;
  triage_adjustments?: TriageAdjustment[];
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ProtocolCounts {
  smtp: number;
  imap: number;
  pop3: number;
  unknown: number;
}

export interface TransportCounts {
  implicit_tls: number;
  starttls: number;
  plaintext: number;
}

export interface CheckNotPerformed {
  check: string;
  reason: string;
  sessions: number;
}

export interface VisibilitySummary {
  sessions_total: number;
  handshake_complete: number;
  handshake_partial: number;
  certificate_observable: number;
  certificate_hidden_tls13: number;
  certificate_resumed: number;
  message_layer_observable: number;
  plaintext_sessions: number;
  checks_not_performed: CheckNotPerformed[];
}

export interface Summary {
  posture: Posture;
  severity_counts: SeverityCounts;
  protocol_counts: ProtocolCounts;
  transport_counts: TransportCounts;
  limitations: string[];
  baseline_status: BaselineStatus;
  visibility: VisibilitySummary | null;
}

export interface StarttlsInfo {
  advertised: boolean;
  initiated: boolean;
  succeeded: boolean | null;
  downgrade_suspected: boolean;
}

export interface TlsInfo {
  version: string;
  cipher_suite: string;
  key_exchange: string;
  forward_secrecy: boolean | null;
  sni: string;
  alpn: string;
  ja3: string;
  ja3s: string;
}

export interface MessageMarker {
  type: string;
  count: number;
}

export interface MessageLayer {
  state: MessageLayerState;
  markers: MessageMarker[];
}

export interface Certificate {
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  days_to_expiry: number;
  expired: boolean;
  self_signed: boolean;
  key_algorithm: string;
  key_bits: number;
  signature_algorithm: string;
  san: string[];
  sha256_fingerprint: string;
  chain_valid: boolean | null;
  hostname_match: boolean | null;
  validation_notes: string[];
}

export interface SessionVisibility {
  handshake: HandshakeVisibility;
  certificate: CertificateVisibility;
  message_layer: MessageLayerVisibility;
  partial_capture: boolean;
  reasons: string[];
}

export interface Session {
  id: string;
  protocol: Protocol;
  protocol_confidence: ProtocolConfidence;
  client: string;
  server: string;
  server_port: number;
  transport: Transport;
  starttls: StarttlsInfo;
  auth_before_tls: boolean | null;
  tls: TlsInfo | null;
  certificate_observable: boolean;
  certificate_note: string | null;
  certificate_chain: Certificate[] | null;
  message_layer: MessageLayer;
  first_frame: number;
  last_frame: number;
  wireshark_filter: string;
  findings_count: number;
  visibility: SessionVisibility | null;
}

export interface FindingEvidence {
  frames: number[];
  client: string;
  server: string;
  server_port: number;
  certificate_sha256: string | null;
}

export interface FindingContext {
  server_role: "inbound_relay" | "submission" | "mailbox" | "unknown";
  sessions_affected: number;
  clients_affected: number;
}

export interface AnomalyFeature {
  feature: string;
  observed: string;
  baseline: string;
}

export interface FindingAnomaly {
  deviating_features: AnomalyFeature[];
}

export interface Remediation {
  summary: string;
  steps: string[];
  references: string[];
}

export interface Finding {
  id: string;
  session_id: string | null;
  rule_id: string;
  rule_version: string | null;
  title: string;
  severity: Severity;
  category: FindingCategory;
  description: string;
  evidence: FindingEvidence;
  evidence_ids: string[];
  wireshark_filter: string;
  score_impact: number;
  priority_rank: number;
  confidence: Confidence;
  confidence_basis: string[];
  context: FindingContext;
  anomaly: FindingAnomaly | null;
  remediation: Remediation;
  policy_refs: PolicyRef[];
  incident_id: string | null;
}

export interface DriftChange {
  server: string;
  kind: DriftKind;
  before: string;
  after: string;
  direction: DriftDirection;
  severity: Severity;
}

export interface Drift {
  baseline_capture_id: string;
  current_capture_id: string;
  changes: DriftChange[];
}

export interface PaginatedSessions {
  items: Session[];
  total: number;
  page: number;
  page_size: number;
}

export interface EvalPerRule {
  rule_id: string;
  expected: number;
  detected: number;
  tp: number;
  fp: number;
  fn: number;
  precision: number | null;
  recall: number | null;
}

export interface Evaluation {
  corpus_version: string;
  ruleset_version: string;
  run_at: string;
  captures: number;
  per_rule: EvalPerRule[];
  overall: { precision: number; recall: number };
  clean_capture_false_alarms: number;
  label: string;
}

export interface AssetCertificate {
  sha256: string;
  subject: string;
  issuer: string;
  not_after: string;
  key_algorithm: string;
  key_bits: number;
  signature_algorithm: string;
}

export interface AssetPqc {
  hybrid_groups_offered_by_clients: boolean | null;
  hybrid_group_negotiated: boolean | null;
  groups_seen: string[];
  classical_public_key_in_chain: boolean | null;
  note: string;
}

export interface Asset {
  id: string;
  server: string;
  port: number;
  protocols: Protocol[];
  server_role: string;
  tls_versions_observed: string[];
  cipher_suites_observed: string[];
  key_exchange_groups_observed: string[];
  forward_secrecy: ForwardSecrecyState;
  starttls_support: StarttlsSupport;
  certificates: AssetCertificate[];
  sessions_observed: number;
  clients_observed: number;
  first_seen: string;
  last_seen: string;
  pqc: AssetPqc | null;
}

export interface Incident {
  id: string;
  rule_id: string;
  title: string;
  server: string;
  server_role: string;
  severity: Severity;
  confidence: Confidence;
  sessions_affected: number;
  clients_affected: number;
  first_seen: string;
  last_seen: string;
  finding_ids: string[];
  evidence_ids: string[];
  state: IncidentState;
  priority_rank: number;
  remediation: Remediation;
}

export interface TriageEvent {
  id: string;
  ts: string;
  actor: string;
  from_state: IncidentState;
  to_state: IncidentState;
  note: string;
}
