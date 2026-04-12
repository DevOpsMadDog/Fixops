/**
 * API Module - Main Export
 * Re-exports all API client, types, endpoints, and hooks
 */

// ════════════════════════════════════════════════════════════════
// Client
// ════════════════════════════════════════════════════════════════

export {
  ApiClient,
  getApiClient,
  createApiClient,
  resetApiClient,
} from "./client";

// ════════════════════════════════════════════════════════════════
// Types
// ════════════════════════════════════════════════════════════════

export type {
  // Common
  PaginatedResponse,
  ApiError,
  ApiResponse,

  // Finding
  Finding,
  FindingSeverity,
  FindingStatus,
  FindingTimeline,
  FindingSLA,
  FindingSummary,
  StatusChange,
  Comment,
  Assignment,
  TrendingData,
  FindingFilters,

  // Pipeline
  PipelineStage,
  PipelineBatch,
  PipelineHealth,
  ThroughputMetrics,

  // Analytics
  DashboardMetric,
  RiskPosture,
  RiskItem,
  TrajectoryPoint,
  KPIs,
  ExecutiveReport,
  RemediationStats,

  // Connectors
  Connector,
  ConnectorHealth,
  ConnectorRegistry,
  ConnectorMetrics,

  // Playbooks
  Playbook,
  PlaybookTrigger,
  PlaybookStep,
  RetryPolicy,
  PlaybookRun,
  PlaybookStepResult,

  // Compliance
  ComplianceTemplate,
  ComplianceControl,
  ComplianceEvidence,
  ComplianceAssessment,
  AssessmentResult,
  ComplianceGap,

  // TrustGraph
  TrustGraphEntity,
  TrustGraphRelationship,
  GraphQueryResult,
  GraphPath,
  GraphRAGResult,
  GraphCore,
  GraphCoreStats,

  // MCP
  MCPTool,
  MCPToolResult,
  MCPToolStats,

  // Events
  StreamEvent,
  EventStats,

  // Remediation
  RemediationPlan,
  RemediationStep,

  // Misc
  DashboardFilters,
} from "./types";

// ════════════════════════════════════════════════════════════════
// Endpoints
// ════════════════════════════════════════════════════════════════

export {
  pipeline,
  findings,
  analytics,
  connectors,
  playbooks,
  compliance,
  trustgraph,
  mcp,
  events,
} from "./endpoints";

// ════════════════════════════════════════════════════════════════
// Hooks
// ════════════════════════════════════════════════════════════════

export {
  // Generic
  useApi,

  // Findings
  useFindingsList,
  useFinding,
  useFindingTimeline,
  useFindingSLA,
  useFindingsSummary,
  useUpdateFindingStatus,
  useAssignFinding,

  // Pipeline
  usePipelineHealth,
  usePipelineStages,
  usePipelineThroughput,

  // Dashboard & Analytics
  useDashboard,
  useKPIs,
  useRiskPosture,
  useExecutiveReport,
  useMetricTrend,

  // Connectors
  useConnectors,
  useConnectorHealth,
  useSyncConnector,

  // Playbooks
  usePlaybooks,
  usePlaybook,
  usePlaybookRuns,
  useExecutePlaybook,

  // Compliance
  useComplianceTemplates,
  useComplianceAssessment,

  // Events
  useEventStream,
  useRecentEvents,
  useEventStats,

  // Mutations
  useBulkUpdateFindings,
  useExportFindings,
} from "./hooks";

export type { UseApiOptions, UseApiResult } from "./hooks";
