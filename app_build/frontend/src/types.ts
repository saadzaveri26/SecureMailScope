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
export type DriftKind = "tls_version" | "cipher_suite" | "key_exchange" | "certificate" | "starttls" | "auth_before_tls" | "endpoint";
export type ReportFormat = "json" | "html" | "pdf";

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
}

export interface PostureFactor {
  name: string;
  weight: number;
  impact: number;
  detail: string;
  finding_ids: string[];
}

export interface Posture {
  score: number;
  grade: Grade;
  factors: PostureFactor[];
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

export interface Summary {
  posture: Posture;
  severity_counts: SeverityCounts;
  protocol_counts: ProtocolCounts;
  transport_counts: TransportCounts;
  limitations: string[];
  baseline_status: BaselineStatus;
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
  title: string;
  severity: Severity;
  category: FindingCategory;
  description: string;
  evidence: FindingEvidence;
  wireshark_filter: string;
  score_impact: number;
  priority_rank: number;
  context: FindingContext;
  anomaly: FindingAnomaly | null;
  remediation: Remediation;
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
