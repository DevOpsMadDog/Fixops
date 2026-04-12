/**
 * API Types - TypeScript definitions matching backend Pydantic models
 * These types ensure type safety across the entire frontend-backend communication
 */

// ════════════════════════════════════════════════════════════════
// Common Types
// ════════════════════════════════════════════════════════════════

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page?: number;
  page_size?: number;
  has_more?: boolean;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  timestamp?: string;
}

export interface ApiResponse<T> {
  data: T;
  error?: ApiError;
  meta?: {
    timestamp: string;
    duration_ms?: number;
    request_id?: string;
  };
}

// ════════════════════════════════════════════════════════════════
// Finding Types (CTEM Pipeline)
// ════════════════════════════════════════════════════════════════

export enum FindingSeverity {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
  INFO = "info",
}

export enum FindingStatus {
  OPEN = "open",
  IN_PROGRESS = "in_progress",
  RESOLVED = "resolved",
  FALSE_POSITIVE = "false_positive",
  ACCEPTED_RISK = "accepted_risk",
  DUPLICATE = "duplicate",
}

export interface Finding {
  id: string;
  finding_id?: string;
  title: string;
  description?: string;
  severity: FindingSeverity;
  status: FindingStatus;
  cve?: string;
  cve_id?: string;
  source?: string;
  scanner?: string;
  affected_asset?: string;
  affected_assets?: string[];
  assignee?: string;
  tags?: string[];
  comments?: string[];
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  due_date?: string;
  sla_status?: "on_track" | "at_risk" | "breached";
  remediation?: RemediationPlan;
  evidence?: string[];
  metadata?: Record<string, unknown>;
}

export interface FindingTimeline {
  finding_id: string;
  status_changes: StatusChange[];
  comments: Comment[];
  assignments: Assignment[];
}

export interface StatusChange {
  timestamp: string;
  from_status: FindingStatus;
  to_status: FindingStatus;
  changed_by: string;
  reason?: string;
}

export interface Comment {
  id: string;
  author: string;
  content: string;
  created_at: string;
  edited_at?: string;
}

export interface Assignment {
  timestamp: string;
  assigned_from?: string;
  assigned_to: string;
}

export interface FindingSLA {
  finding_id: string;
  severity: FindingSeverity;
  response_time_minutes: number;
  resolution_time_minutes: number;
  response_deadline: string;
  resolution_deadline: string;
  status: "on_track" | "at_risk" | "breached";
  breach_time?: string;
}

export interface FindingSummary {
  total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_source: Record<string, number>;
  trending: TrendingData[];
}

export interface TrendingData {
  date: string;
  count: number;
  severity: FindingSeverity;
}

// ════════════════════════════════════════════════════════════════
// Pipeline Types
// ════════════════════════════════════════════════════════════════

export interface PipelineStage {
  id: string;
  name: string;
  description?: string;
  order: number;
  status: "pending" | "running" | "completed" | "failed";
  input_count?: number;
  output_count?: number;
  processing_time_ms?: number;
  error?: string;
  started_at?: string;
  completed_at?: string;
}

export interface PipelineBatch {
  batch_id: string;
  status: "queued" | "processing" | "completed" | "failed";
  findings_count: number;
  processed_count: number;
  error_count: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  stages: PipelineStage[];
}

export interface ThroughputMetrics {
  findings_per_second: number;
  findings_per_minute: number;
  findings_per_hour: number;
  total_processed: number;
  average_processing_time_ms: number;
  peak_throughput: number;
  timestamp: string;
}

export interface PipelineHealth {
  status: "healthy" | "degraded" | "failing";
  stages: PipelineStage[];
  last_batch_status?: PipelineBatch;
  throughput: ThroughputMetrics;
  error_rate: number;
  average_latency_ms: number;
  timestamp: string;
  details?: Record<string, unknown>;
}

// ════════════════════════════════════════════════════════════════
// Analytics & Dashboard Types
// ════════════════════════════════════════════════════════════════

export interface DashboardMetric {
  id: string;
  name: string;
  value: number;
  unit?: string;
  trend?: number;
  trend_direction?: "up" | "down" | "stable";
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface RiskPosture {
  overall_risk_score: number;
  critical_findings: number;
  high_findings: number;
  remediation_progress: number;
  top_risks: RiskItem[];
  risk_by_source: Record<string, number>;
  risk_trajectory: TrajectoryPoint[];
}

export interface RiskItem {
  finding_id: string;
  title: string;
  severity: FindingSeverity;
  risk_score: number;
  affected_assets: number;
  days_open: number;
}

export interface TrajectoryPoint {
  date: string;
  risk_score: number;
  critical_count: number;
  high_count: number;
}

export interface KPIs {
  mttd: number; // Mean Time To Detect (minutes)
  mttr: number; // Mean Time To Remediate (minutes)
  sla_compliance: number; // Percentage
  findings_per_day: number;
  remediation_rate: number; // Percentage
  detection_accuracy: number; // Percentage
  timestamp: string;
}

export interface ExecutiveReport {
  date_range: { start: string; end: string };
  executive_summary: string;
  key_metrics: KPIs;
  risk_posture: RiskPosture;
  top_findings: Finding[];
  remediation_status: RemediationStats;
  recommendations: string[];
}

export interface RemediationStats {
  total: number;
  completed: number;
  in_progress: number;
  pending: number;
  overdue: number;
}

// ════════════════════════════════════════════════════════════════
// Connector Types
// ════════════════════════════════════════════════════════════════

export interface Connector {
  id: string;
  name: string;
  type: string;
  description?: string;
  status: "connected" | "disconnected" | "error";
  last_sync?: string;
  next_sync?: string;
  sync_interval_minutes?: number;
  config?: Record<string, unknown>;
  credentials_stored?: boolean;
  error_message?: string;
}

export interface ConnectorHealth {
  connector_id: string;
  status: "healthy" | "degraded" | "failing";
  last_check: string;
  last_successful_sync?: string;
  error_count: number;
  recent_errors: string[];
  metrics: {
    items_fetched?: number;
    items_processed?: number;
    sync_duration_ms?: number;
  };
}

export interface ConnectorRegistry {
  total: number;
  connectors: Connector[];
  categories?: Record<string, Connector[]>;
}

export interface ConnectorMetrics {
  connector_id: string;
  total_syncs: number;
  successful_syncs: number;
  failed_syncs: number;
  average_duration_ms: number;
  items_processed: number;
  last_7_days: {
    syncs: number;
    items: number;
    success_rate: number;
  };
}

// ════════════════════════════════════════════════════════════════
// Playbook & Automation Types
// ════════════════════════════════════════════════════════════════

export interface Playbook {
  id: string;
  name: string;
  description?: string;
  trigger?: PlaybookTrigger;
  steps: PlaybookStep[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
  created_by?: string;
  run_count?: number;
  success_rate?: number;
}

export interface PlaybookTrigger {
  type: "manual" | "scheduled" | "webhook" | "finding";
  condition?: Record<string, unknown>;
  schedule?: string; // Cron expression
}

export interface PlaybookStep {
  id: string;
  order: number;
  action: string;
  params?: Record<string, unknown>;
  retry_policy?: RetryPolicy;
  timeout_seconds?: number;
}

export interface RetryPolicy {
  max_retries: number;
  backoff_multiplier: number;
  initial_delay_seconds: number;
}

export interface PlaybookRun {
  run_id: string;
  playbook_id: string;
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  started_at: string;
  completed_at?: string;
  triggered_by?: string;
  context?: Record<string, unknown>;
  steps: PlaybookStepResult[];
  error?: string;
}

export interface PlaybookStepResult {
  step_id: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  output?: Record<string, unknown>;
  error?: string;
  duration_ms?: number;
}

// ════════════════════════════════════════════════════════════════
// Compliance Types
// ════════════════════════════════════════════════════════════════

export interface ComplianceTemplate {
  id: string;
  framework: string; // SOC2, PCI-DSS, HIPAA, ISO27001, etc.
  version: string;
  controls: ComplianceControl[];
  description?: string;
}

export interface ComplianceControl {
  id: string;
  code: string;
  name: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  status?: "compliant" | "non_compliant" | "not_applicable";
  evidence?: ComplianceEvidence[];
  gaps?: string[];
}

export interface ComplianceEvidence {
  id: string;
  type: string;
  source: string;
  created_at: string;
  valid_until?: string;
  metadata?: Record<string, unknown>;
}

export interface ComplianceAssessment {
  id: string;
  framework: string;
  status: "pending" | "in_progress" | "completed" | "failed";
  started_at: string;
  completed_at?: string;
  results: AssessmentResult[];
  overall_compliance_score: number;
  gaps: ComplianceGap[];
}

export interface AssessmentResult {
  control_id: string;
  status: "compliant" | "non_compliant" | "not_applicable";
  findings: string[];
  evidence_count: number;
  remediation_required?: boolean;
}

export interface ComplianceGap {
  control_id: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  remediation_steps?: string[];
  estimated_effort_hours?: number;
}

// ════════════════════════════════════════════════════════════════
// TrustGraph / Knowledge Graph Types
// ════════════════════════════════════════════════════════════════

export interface TrustGraphEntity {
  id: string;
  type: string;
  name: string;
  labels?: string[];
  properties?: Record<string, unknown>;
  risk_score?: number;
  created_at?: string;
  updated_at?: string;
}

export interface TrustGraphRelationship {
  id: string;
  source_id: string;
  target_id: string;
  relationship_type: string;
  properties?: Record<string, unknown>;
  strength?: number;
  created_at?: string;
}

export interface GraphQueryResult {
  entities: TrustGraphEntity[];
  relationships: TrustGraphRelationship[];
  paths?: GraphPath[];
  query_time_ms: number;
}

export interface GraphPath {
  nodes: string[];
  edges: string[];
  length: number;
  risk_score?: number;
}

export interface GraphRAGResult {
  query: string;
  answer: string;
  context: TrustGraphEntity[];
  confidence: number;
  sources?: string[];
}

export interface GraphCore {
  core_id: string;
  entities: number;
  relationships: number;
  risk_score: number;
  description?: string;
}

export interface GraphCoreStats {
  total_cores: number;
  total_entities: number;
  total_relationships: number;
  average_risk_score: number;
  cores: GraphCore[];
}

// ════════════════════════════════════════════════════════════════
// MCP & Tool Types
// ════════════════════════════════════════════════════════════════

export interface MCPTool {
  name: string;
  description?: string;
  input_schema?: Record<string, unknown>;
  output_schema?: Record<string, unknown>;
  enabled: boolean;
  category?: string;
  version?: string;
}

export interface MCPToolResult {
  tool_name: string;
  status: "success" | "failure";
  result?: unknown;
  error?: string;
  duration_ms?: number;
  timestamp: string;
}

export interface MCPToolStats {
  total_tools: number;
  enabled_tools: number;
  categories: Record<string, number>;
  last_execution?: MCPToolResult[];
}

// ════════════════════════════════════════════════════════════════
// Event & Streaming Types
// ════════════════════════════════════════════════════════════════

export interface StreamEvent {
  event_id: string;
  type: string;
  source: string;
  timestamp: string;
  data: Record<string, unknown>;
  severity?: "info" | "warning" | "error" | "critical";
  metadata?: Record<string, unknown>;
}

export interface EventStats {
  total_events: number;
  events_per_second: number;
  by_type: Record<string, number>;
  by_source: Record<string, number>;
  recent_events: StreamEvent[];
}

// ════════════════════════════════════════════════════════════════
// Remediation Types
// ════════════════════════════════════════════════════════════════

export interface RemediationPlan {
  id: string;
  finding_id: string;
  description: string;
  steps: RemediationStep[];
  estimated_effort_hours?: number;
  priority?: "critical" | "high" | "medium" | "low";
  status: "draft" | "approved" | "in_progress" | "completed" | "failed";
  created_at: string;
  completed_at?: string;
}

export interface RemediationStep {
  id: string;
  order: number;
  description: string;
  responsible_team?: string;
  status: "pending" | "in_progress" | "completed" | "failed";
  due_date?: string;
  completed_date?: string;
  notes?: string;
}

// ════════════════════════════════════════════════════════════════
// Query/Filter Types
// ════════════════════════════════════════════════════════════════

export interface FindingFilters {
  severity?: FindingSeverity[];
  status?: FindingStatus[];
  source?: string[];
  assignee?: string;
  tags?: string[];
  date_range?: { start: string; end: string };
  search?: string;
  limit?: number;
  offset?: number;
}

export interface DashboardFilters {
  time_range?: "1d" | "7d" | "30d" | "90d" | "1y";
  persona?: string;
  exclude_false_positives?: boolean;
}
