/**
 * API Endpoints - Typed function calls for all backend routes
 * Organized by domain with full parameter and return type safety
 */

import { getApiClient } from "./client";
import type {
  Finding,
  FindingFilters,
  FindingSLA,
  FindingTimeline,
  FindingSummary,
  PaginatedResponse,
  PipelineStage,
  PipelineBatch,
  PipelineHealth,
  ThroughputMetrics,
  DashboardMetric,
  RiskPosture,
  KPIs,
  ExecutiveReport,
  Connector,
  ConnectorHealth,
  ConnectorRegistry,
  ConnectorMetrics,
  Playbook,
  PlaybookRun,
  ComplianceTemplate,
  ComplianceAssessment,
  ComplianceControl,
  ComplianceGap,
  TrustGraphEntity,
  TrustGraphRelationship,
  GraphQueryResult,
  GraphRAGResult,
  GraphCoreStats,
  MCPTool,
  MCPToolResult,
  MCPToolStats,
  StreamEvent,
  EventStats,
  RemediationPlan,
} from "./types";

const client = getApiClient();

// ════════════════════════════════════════════════════════════════
// Pipeline Endpoints
// ════════════════════════════════════════════════════════════════

export const pipeline = {
  /**
   * Ingest findings into the pipeline
   */
  async ingestFindings(findings: unknown[]): Promise<PipelineBatch> {
    return client.post("/api/v1/pipeline/ingest", { findings });
  },

  /**
   * Get status of a processing batch
   */
  async getBatchStatus(batchId: string): Promise<PipelineBatch> {
    return client.get(`/api/v1/pipeline/batches/${batchId}`);
  },

  /**
   * Get all pipeline stages
   */
  async getStages(): Promise<PipelineStage[]> {
    return client.get("/api/v1/pipeline/stages");
  },

  /**
   * Get details of a specific pipeline stage
   */
  async getStage(stageId: string): Promise<PipelineStage> {
    return client.get(`/api/v1/pipeline/stages/${stageId}`);
  },

  /**
   * Get throughput metrics
   */
  async getThroughput(): Promise<ThroughputMetrics> {
    return client.get("/api/v1/pipeline/throughput");
  },

  /**
   * Get overall pipeline health status
   */
  async getHealth(): Promise<PipelineHealth> {
    return client.get("/api/v1/pipeline/health");
  },
};

// ════════════════════════════════════════════════════════════════
// Findings Endpoints
// ════════════════════════════════════════════════════════════════

export const findings = {
  /**
   * List findings with optional filtering
   */
  async list(filters?: FindingFilters): Promise<PaginatedResponse<Finding>> {
    const params: Record<string, string | number | boolean> = {};
    if (filters?.severity?.length) params.severity = filters.severity.join(",");
    if (filters?.status?.length) params.status = filters.status.join(",");
    if (filters?.source?.length) params.source = filters.source.join(",");
    if (filters?.assignee) params.assignee = filters.assignee;
    if (filters?.tags?.length) params.tags = filters.tags.join(",");
    if (filters?.search) params.search = filters.search;
    if (filters?.limit) params.limit = filters.limit;
    if (filters?.offset) params.offset = filters.offset;

    return client.get("/api/v1/findings", params);
  },

  /**
   * Get detailed finding by ID
   */
  async getById(findingId: string): Promise<Finding> {
    return client.get(`/api/v1/findings/${findingId}`);
  },

  /**
   * Update finding status
   */
  async updateStatus(
    findingId: string,
    status: string,
    reason?: string
  ): Promise<Finding> {
    return client.put(`/api/v1/findings/${findingId}/status`, { status, reason });
  },

  /**
   * Assign finding to user
   */
  async assign(findingId: string, assignee: string): Promise<Finding> {
    return client.put(`/api/v1/findings/${findingId}/assign`, { assignee });
  },

  /**
   * Add comment to finding
   */
  async addComment(findingId: string, comment: string): Promise<Finding> {
    return client.post(`/api/v1/findings/${findingId}/comments`, { comment });
  },

  /**
   * Get finding timeline (status changes, comments, assignments)
   */
  async getTimeline(findingId: string): Promise<FindingTimeline> {
    return client.get(`/api/v1/findings/${findingId}/timeline`);
  },

  /**
   * Get finding summary statistics
   */
  async getSummary(filters?: FindingFilters): Promise<FindingSummary> {
    const params: Record<string, string | number | boolean> = {};
    if (filters?.severity?.length) params.severity = filters.severity.join(",");
    if (filters?.status?.length) params.status = filters.status.join(",");
    return client.get("/api/v1/findings/summary", params);
  },

  /**
   * Get SLA information for finding
   */
  async getSLA(findingId: string): Promise<FindingSLA> {
    return client.get(`/api/v1/findings/${findingId}/sla`);
  },

  /**
   * Bulk update findings
   */
  async bulkUpdate(
    findingIds: string[],
    updates: Record<string, unknown>
  ): Promise<{ updated: number; failed: number }> {
    return client.post("/api/v1/findings/bulk/update", { finding_ids: findingIds, updates });
  },

  /**
   * Export findings to file
   */
  async export(filters?: FindingFilters, format: "csv" | "json" = "csv"): Promise<Blob> {
    const params: Record<string, string | number | boolean> = { format };
    if (filters?.severity?.length) params.severity = filters.severity.join(",");
    if (filters?.status?.length) params.status = filters.status.join(",");

    const response = await client.getStream("/api/v1/findings/export", params);
    return response.blob();
  },
};

// ════════════════════════════════════════════════════════════════
// Analytics Endpoints
// ════════════════════════════════════════════════════════════════

export const analytics = {
  /**
   * Get dashboard overview metrics
   */
  async getDashboard(persona?: string): Promise<Record<string, DashboardMetric>> {
    const params: Record<string, string> = {};
    if (persona) params.persona = persona;
    return client.get("/api/v1/analytics/dashboard", params);
  },

  /**
   * Get specific metric
   */
  async getMetric(metricName: string): Promise<DashboardMetric> {
    return client.get(`/api/v1/analytics/metrics/${metricName}`);
  },

  /**
   * Get metric trends over time
   */
  async getTrend(metricName: string, days: number = 30): Promise<Array<{ date: string; value: number }>> {
    return client.get(`/api/v1/analytics/trends/${metricName}`, { days });
  },

  /**
   * Get KPIs
   */
  async getKPIs(): Promise<KPIs> {
    return client.get("/api/v1/analytics/kpis");
  },

  /**
   * Get current risk posture
   */
  async getPosture(): Promise<RiskPosture> {
    return client.get("/api/v1/analytics/posture");
  },

  /**
   * Get executive report
   */
  async getExecutiveReport(
    startDate?: string,
    endDate?: string
  ): Promise<ExecutiveReport> {
    const params: Record<string, string> = {};
    if (startDate) params.start_date = startDate;
    if (endDate) params.end_date = endDate;
    return client.get("/api/v1/analytics/executive-report", params);
  },

  /**
   * Get compliance report
   */
  async getComplianceReport(framework?: string): Promise<Record<string, unknown>> {
    const params: Record<string, string> = {};
    if (framework) params.framework = framework;
    return client.get("/api/v1/analytics/compliance-report", params);
  },
};

// ════════════════════════════════════════════════════════════════
// Connectors Endpoints
// ════════════════════════════════════════════════════════════════

export const connectors = {
  /**
   * Get connector registry
   */
  async getRegistry(): Promise<ConnectorRegistry> {
    return client.get("/api/v1/connectors/registry");
  },

  /**
   * Get status of all connectors
   */
  async getStatus(): Promise<ConnectorHealth[]> {
    return client.get("/api/v1/connectors/status");
  },

  /**
   * Get health for specific connector
   */
  async getConnectorHealth(connectorId: string): Promise<ConnectorHealth> {
    return client.get(`/api/v1/connectors/${connectorId}/health`);
  },

  /**
   * Get connector metrics
   */
  async getMetrics(connectorId?: string): Promise<ConnectorMetrics | ConnectorMetrics[]> {
    if (connectorId) {
      return client.get(`/api/v1/connectors/${connectorId}/metrics`);
    }
    return client.get("/api/v1/connectors/metrics");
  },

  /**
   * Trigger connector sync
   */
  async sync(connectorId: string): Promise<{ status: string; next_sync?: string }> {
    return client.post(`/api/v1/connectors/${connectorId}/sync`);
  },
};

// ════════════════════════════════════════════════════════════════
// Playbooks Endpoints
// ════════════════════════════════════════════════════════════════

export const playbooks = {
  /**
   * List all playbooks
   */
  async list(): Promise<Playbook[]> {
    return client.get("/api/v1/playbooks");
  },

  /**
   * Get playbook by ID
   */
  async getById(playbookId: string): Promise<Playbook> {
    return client.get(`/api/v1/playbooks/${playbookId}`);
  },

  /**
   * Create new playbook
   */
  async create(playbook: Partial<Playbook>): Promise<Playbook> {
    return client.post("/api/v1/playbooks", playbook);
  },

  /**
   * Execute playbook
   */
  async execute(
    playbookId: string,
    context?: Record<string, unknown>
  ): Promise<PlaybookRun> {
    return client.post(`/api/v1/playbooks/${playbookId}/execute`, { context });
  },

  /**
   * Get playbook runs
   */
  async getRuns(playbookId: string, limit: number = 20): Promise<PlaybookRun[]> {
    return client.get(`/api/v1/playbooks/${playbookId}/runs`, { limit });
  },

  /**
   * Get detailed run information
   */
  async getRunDetail(playbookId: string, runId: string): Promise<PlaybookRun> {
    return client.get(`/api/v1/playbooks/${playbookId}/runs/${runId}`);
  },
};

// ════════════════════════════════════════════════════════════════
// Compliance Endpoints
// ════════════════════════════════════════════════════════════════

export const compliance = {
  /**
   * Get compliance templates
   */
  async getTemplates(): Promise<ComplianceTemplate[]> {
    return client.get("/api/v1/compliance/templates");
  },

  /**
   * Get specific template
   */
  async getTemplate(framework: string): Promise<ComplianceTemplate> {
    return client.get(`/api/v1/compliance/templates/${framework}`);
  },

  /**
   * Instantiate assessment from template
   */
  async instantiate(framework: string): Promise<ComplianceAssessment> {
    return client.post(`/api/v1/compliance/assessments`, { framework });
  },

  /**
   * Run compliance assessment
   */
  async assess(assessmentId: string): Promise<ComplianceAssessment> {
    return client.post(`/api/v1/compliance/assessments/${assessmentId}/assess`);
  },

  /**
   * Get compliance controls
   */
  async getControls(framework?: string): Promise<ComplianceControl[]> {
    const params: Record<string, string> = {};
    if (framework) params.framework = framework;
    return client.get("/api/v1/compliance/controls", params);
  },

  /**
   * Get compliance gaps
   */
  async getGaps(framework?: string): Promise<ComplianceGap[]> {
    const params: Record<string, string> = {};
    if (framework) params.framework = framework;
    return client.get("/api/v1/compliance/gaps", params);
  },
};

// ════════════════════════════════════════════════════════════════
// TrustGraph Endpoints
// ════════════════════════════════════════════════════════════════

export const trustgraph = {
  /**
   * Query graph with Cypher-like syntax
   */
  async query(query: string): Promise<GraphQueryResult> {
    return client.post("/api/v1/trustgraph/query", { query });
  },

  /**
   * Search for entities by name/label
   */
  async search(
    term: string,
    entityType?: string
  ): Promise<TrustGraphEntity[]> {
    const params: Record<string, string> = { term };
    if (entityType) params.entity_type = entityType;
    return client.get("/api/v1/trustgraph/search", params);
  },

  /**
   * Ingest entities and relationships
   */
  async ingest(
    entities: TrustGraphEntity[],
    relationships: TrustGraphRelationship[]
  ): Promise<{ ingested: number; errors: number }> {
    return client.post("/api/v1/trustgraph/ingest", { entities, relationships });
  },

  /**
   * Create relationships between entities
   */
  async relate(
    sourceId: string,
    targetId: string,
    relationType: string
  ): Promise<TrustGraphRelationship> {
    return client.post("/api/v1/trustgraph/relationships", {
      source_id: sourceId,
      target_id: targetId,
      relationship_type: relationType,
    });
  },

  /**
   * Get entity by ID
   */
  async getEntity(entityId: string): Promise<TrustGraphEntity> {
    return client.get(`/api/v1/trustgraph/entities/${entityId}`);
  },

  /**
   * Get graph cores (critical threat groups)
   */
  async getCores(): Promise<GraphCoreStats> {
    return client.get("/api/v1/trustgraph/cores");
  },

  /**
   * Get core statistics
   */
  async getCoreStats(): Promise<GraphCoreStats> {
    return client.get("/api/v1/trustgraph/cores/stats");
  },

  /**
   * RAG query on graph
   */
  async ragQuery(question: string): Promise<GraphRAGResult> {
    return client.post("/api/v1/trustgraph/rag/query", { question });
  },
};

// ════════════════════════════════════════════════════════════════
// MCP Tools Endpoints
// ════════════════════════════════════════════════════════════════

export const mcp = {
  /**
   * List available MCP tools
   */
  async listTools(): Promise<MCPTool[]> {
    return client.get("/api/v1/mcp/tools");
  },

  /**
   * Execute MCP tool
   */
  async executeTool(
    toolName: string,
    args: Record<string, unknown>
  ): Promise<MCPToolResult> {
    return client.post("/api/v1/mcp/tools/execute", { tool_name: toolName, arguments: args });
  },

  /**
   * Get MCP statistics
   */
  async getStats(): Promise<MCPToolStats> {
    return client.get("/api/v1/mcp/stats");
  },
};

// ════════════════════════════════════════════════════════════════
// Events Endpoints
// ════════════════════════════════════════════════════════════════

export const events = {
  /**
   * Get recent events
   */
  async getRecent(limit: number = 50, types?: string[]): Promise<StreamEvent[]> {
    const params: Record<string, string | number> = { limit };
    if (types?.length) params.types = types.join(",");
    return client.get("/api/v1/events/recent", params);
  },

  /**
   * Get event statistics
   */
  async getStats(): Promise<EventStats> {
    return client.get("/api/v1/events/stats");
  },

  /**
   * Subscribe to WebSocket event stream
   * Returns URL for WebSocket connection
   */
  getStreamUrl(types?: string[]): string {
    const token = window.localStorage?.getItem("aldeci.authToken") || "";
    const params = new URLSearchParams();
    if (token) params.set("api_key", token);
    if (types?.length) params.set("types", types.join(","));
    const url = `${client.toString().split("/api")[0]}/ws/events`;
    return params.toString() ? `${url}?${params.toString()}` : url;
  },
};
