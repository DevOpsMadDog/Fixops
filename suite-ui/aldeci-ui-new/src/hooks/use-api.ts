import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  dashboardApi,
  nerveCenterApi,
  findingsApi,
  failApi,
  mpteApi,
  remediationApi,
  evidenceApi,
  complianceApi,
  copilotApi,
  changesApi,
  appsApi,
  integrationsApi,
  reportsApi,
  teamsApi,
  usersApi,
  workflowsApi,
  auditApi,
  policiesApi,
  systemApi,
  knowledgeGraphApi,
  threatFeedsApi,
  playbooks as playbooksApi,
  scannerApi,
  casesApi,
} from "@/lib/api";
import { toast } from "sonner";

// ═══════════════════════════════════════════
// Mission Control hooks
// ═══════════════════════════════════════════

export function useDashboardOverview() {
  return useQuery({
    queryKey: ["dashboard", "overview"],
    queryFn: async () => {
      const { data } = await dashboardApi.summary();
      return data;
    },
    refetchInterval: 30_000,
  });
}

export function useDashboardTopRisks() {
  return useQuery({
    queryKey: ["dashboard", "top-risks"],
    queryFn: async () => {
      const { data } = await dashboardApi.posture();
      return data;
    },
  });
}

export function useDashboardTrends(params?: Record<string, string>) {
  return useQuery({
    queryKey: ["dashboard", "trends", params],
    queryFn: async () => {
      const { data } = await dashboardApi.trends(params);
      return data;
    },
  });
}

export function useDashboardCompliance() {
  return useQuery({
    queryKey: ["dashboard", "compliance"],
    queryFn: async () => {
      const { data } = await dashboardApi.compliance();
      return data;
    },
  });
}

// ═══════════════════════════════════════════
// Nerve Center hooks
// ═══════════════════════════════════════════

export function useNervePulse() {
  return useQuery({
    queryKey: ["nerve-center", "pulse"],
    queryFn: async () => {
      const { data } = await nerveCenterApi.pulse();
      return data;
    },
    refetchInterval: 15_000,
  });
}

export function useNerveState() {
  return useQuery({
    queryKey: ["nerve-center", "state"],
    queryFn: async () => {
      const { data } = await nerveCenterApi.state();
      return data;
    },
    refetchInterval: 15_000,
  });
}

export function useNerveOverlay() {
  return useQuery({
    queryKey: ["nerve-center", "overlay"],
    queryFn: async () => {
      const { data } = await nerveCenterApi.overlay();
      return data;
    },
  });
}

export function useIntelligenceMap() {
  return useQuery({
    queryKey: ["nerve-center", "intelligence-map"],
    queryFn: async () => {
      const { data } = await nerveCenterApi.intelligenceMap();
      return data;
    },
  });
}

// ═══════════════════════════════════════════
// Findings hooks (analytics/findings)
// ═══════════════════════════════════════════

export function useFindings(params?: Record<string, unknown>) {
  return useQuery({
    queryKey: ["findings", params],
    queryFn: async () => {
      const { data } = await findingsApi.list(params);
      return data;
    },
  });
}

// ═══════════════════════════════════════════
// Exposure Cases hooks (real cases endpoint)
// ═══════════════════════════════════════════

export function useCases(params?: Record<string, unknown>) {
  return useQuery({
    queryKey: ["cases", params],
    queryFn: async () => {
      const { data } = await casesApi.list(params);
      return data;
    },
  });
}

export function useCase(id: string) {
  return useQuery({
    queryKey: ["cases", id],
    queryFn: async () => {
      const { data } = await casesApi.get(id);
      return data;
    },
    enabled: !!id,
  });
}

export function useTriageCase() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, action }: { id: string; action: string }) => {
      const { data } = await casesApi.transition(id, action);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cases"] });
      toast.success("Case updated successfully");
    },
    onError: () => toast.error("Failed to update case"),
  });
}

// ═══════════════════════════════════════════
// FAIL Engine hooks
// ═══════════════════════════════════════════

export function useFailScenarios() {
  return useQuery({
    queryKey: ["fail", "scenarios"],
    queryFn: async () => {
      const { data } = await failApi.getScenarios();
      return data;
    },
  });
}

export function useFailDrills(orgId = "default") {
  return useQuery({
    queryKey: ["fail", "drills", orgId],
    queryFn: async () => {
      const { data } = await failApi.getDrills({ org_id: orgId });
      return data;
    },
  });
}

export function useFailReadiness(orgId = "default") {
  return useQuery({
    queryKey: ["fail", "readiness", orgId],
    queryFn: async () => {
      const { data } = await failApi.getReadinessScore({ org_id: orgId });
      return data;
    },
  });
}

export function useFailHistory(orgId = "default") {
  return useQuery({
    queryKey: ["fail", "history", orgId],
    queryFn: async () => {
      const { data } = await failApi.getHistory({ org_id: orgId });
      return data;
    },
  });
}

export function useInjectFail() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (payload: unknown) => {
      const { data } = await failApi.inject(payload);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["fail"] });
      toast.success("FAIL scenario injected");
    },
    onError: () => toast.error("Failed to inject scenario"),
  });
}

// ═══════════════════════════════════════════
// MPTE hooks
// ═══════════════════════════════════════════

export function useMpteStatus() {
  return useQuery({
    queryKey: ["mpte", "status"],
    queryFn: async () => {
      const { data } = await mpteApi.status();
      return data;
    },
  });
}

export function useMpteStats() {
  return useQuery({
    queryKey: ["mpte", "stats"],
    queryFn: async () => {
      const { data } = await mpteApi.stats();
      return data;
    },
  });
}

export function useMpteResults(params?: Record<string, string>) {
  return useQuery({
    queryKey: ["mpte", "results", params],
    queryFn: async () => {
      const { data } = await mpteApi.results(params);
      return data;
    },
  });
}

export function useMpteRequests(params?: Record<string, string>) {
  return useQuery({
    queryKey: ["mpte", "requests", params],
    queryFn: async () => {
      const { data } = await mpteApi.requests(params);
      return data;
    },
  });
}

export function useMpteVerifications(params?: Record<string, string>) {
  return useQuery({
    queryKey: ["mpte", "verifications", params],
    queryFn: async () => {
      const { data } = await mpteApi.verifications(params);
      return data;
    },
  });
}

export function useMpteConfigs() {
  return useQuery({
    queryKey: ["mpte", "configs"],
    queryFn: async () => {
      const { data } = await mpteApi.configs();
      return data;
    },
  });
}

export function useRunMpteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (payload: unknown) => {
      const { data } = await mpteApi.comprehensiveScan(payload);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["mpte"] });
      toast.success("MPTE scan initiated");
    },
    onError: () => toast.error("Failed to start MPTE scan"),
  });
}

// ═══════════════════════════════════════════
// Remediation hooks
// ═══════════════════════════════════════════

export function useRemediationTasks(params?: Record<string, unknown>) {
  return useQuery({
    queryKey: ["remediation", "tasks", params],
    queryFn: async () => {
      const { data } = await remediationApi.list(params);
      return data;
    },
  });
}

export function useAutofix() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (findingId: string) => {
      const { data } = await remediationApi.autofix(findingId);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["remediation"] });
      toast.success("Autofix generated");
    },
    onError: () => toast.error("Autofix generation failed"),
  });
}

// ═══════════════════════════════════════════
// Evidence hooks
// ═══════════════════════════════════════════

export function useEvidenceBundles(params?: Record<string, unknown>) {
  return useQuery({
    queryKey: ["evidence", "bundles", params],
    queryFn: async () => {
      const { data } = await evidenceApi.bundles(params);
      return data;
    },
  });
}

export function useEvidenceComplianceStatus() {
  return useQuery({
    queryKey: ["evidence", "compliance-status"],
    queryFn: async () => {
      const { data } = await evidenceApi.complianceStatus();
      return data;
    },
  });
}

export function useGenerateEvidence() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (payload: unknown) => {
      const { data } = await evidenceApi.generate(payload);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["evidence"] });
      toast.success("Evidence bundle generated");
    },
    onError: () => toast.error("Evidence generation failed"),
  });
}

// ═══════════════════════════════════════════
// Compliance hooks
// ═══════════════════════════════════════════

export function useComplianceFrameworks() {
  return useQuery({
    queryKey: ["compliance", "frameworks"],
    queryFn: async () => {
      const { data } = await complianceApi.frameworks();
      return data;
    },
  });
}

export function useComplianceGaps() {
  return useQuery({
    queryKey: ["compliance", "gaps"],
    queryFn: async () => {
      const { data } = await complianceApi.gaps();
      return data;
    },
  });
}

export function useComplianceSoc2() {
  return useQuery({
    queryKey: ["compliance", "soc2"],
    queryFn: async () => {
      const { data } = await complianceApi.soc2Status();
      return data;
    },
  });
}

export function useCompliancePci() {
  return useQuery({
    queryKey: ["compliance", "pci"],
    queryFn: async () => {
      const { data } = await complianceApi.pciStatus();
      return data;
    },
  });
}

export function useComplianceStatus() {
  return useQuery({
    queryKey: ["compliance", "status"],
    queryFn: async () => {
      const { data } = await complianceApi.status();
      return data;
    },
  });
}

export function useAssessCompliance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data } = await complianceApi.assessAll();
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["compliance"] });
      toast.success("Compliance assessment started");
    },
    onError: () => toast.error("Assessment failed"),
  });
}

// ═══════════════════════════════════════════
// Apps hooks
// ═══════════════════════════════════════════

export function useApps(params?: Record<string, unknown>) {
  return useQuery({
    queryKey: ["apps", params],
    queryFn: async () => {
      const { data } = await appsApi.list(params);
      return data;
    },
  });
}

// ═══════════════════════════════════════════
// Copilot hooks
// ═══════════════════════════════════════════

export function useCopilotAgents() {
  return useQuery({
    queryKey: ["copilot", "agents"],
    queryFn: async () => {
      const { data } = await copilotApi.agents();
      return data;
    },
  });
}

export function useCopilotChat() {
  return useMutation({
    mutationFn: async (payload: unknown) => {
      const { data } = await copilotApi.chat(payload);
      return data;
    },
  });
}

// ═══════════════════════════════════════════
// System, Settings, Teams, Users
// ═══════════════════════════════════════════

export function useSystemHealth() {
  return useQuery({
    queryKey: ["system", "health"],
    queryFn: async () => {
      const { data } = await systemApi.health();
      return data;
    },
    refetchInterval: 30_000,
  });
}

export function useSystemMetrics() {
  return useQuery({
    queryKey: ["system", "metrics"],
    queryFn: async () => {
      const { data } = await systemApi.metrics();
      return data;
    },
    refetchInterval: 30_000,
  });
}

export function useIntegrations() {
  return useQuery({
    queryKey: ["integrations"],
    queryFn: async () => {
      const { data } = await integrationsApi.list();
      return data;
    },
  });
}

export function useTeams() {
  return useQuery({
    queryKey: ["teams"],
    queryFn: async () => {
      const { data } = await teamsApi.list();
      return data;
    },
  });
}

export function useUsers() {
  return useQuery({
    queryKey: ["users"],
    queryFn: async () => {
      const { data } = await usersApi.list();
      return data;
    },
  });
}

export function useWorkflowRules() {
  return useQuery({
    queryKey: ["workflows", "rules"],
    queryFn: async () => {
      const { data } = await workflowsApi.list();
      return data;
    },
  });
}

export function useAuditLog(params?: Record<string, unknown>) {
  return useQuery({
    queryKey: ["audit", params],
    queryFn: async () => {
      const { data } = await auditApi.list(params);
      return data;
    },
  });
}

export function usePolicies() {
  return useQuery({
    queryKey: ["policies"],
    queryFn: async () => {
      const { data } = await policiesApi.list();
      return data;
    },
  });
}

export function useReports() {
  return useQuery({
    queryKey: ["reports"],
    queryFn: async () => {
      const { data } = await reportsApi.list();
      return data;
    },
  });
}

export function usePlaybooks() {
  return useQuery({
    queryKey: ["playbooks"],
    queryFn: async () => {
      const { data } = await playbooksApi.list();
      return data;
    },
  });
}

// ═══════════════════════════════════════════
// Knowledge Graph, Threat Feeds, Scanner
// ═══════════════════════════════════════════

export function useKnowledgeGraph(params?: Record<string, string>) {
  return useQuery({
    queryKey: ["graph", "visualize", params],
    queryFn: async () => {
      const { data } = await knowledgeGraphApi.visualize(params);
      return data;
    },
  });
}

export function useThreatFeeds(params?: Record<string, string>) {
  return useQuery({
    queryKey: ["feeds", params],
    queryFn: async () => {
      const { data } = await threatFeedsApi.list(params);
      return data;
    },
  });
}

export function useThreatTrending() {
  return useQuery({
    queryKey: ["feeds", "trending"],
    queryFn: async () => {
      const { data } = await threatFeedsApi.trending();
      return data;
    },
  });
}

export function useScannerParsers() {
  return useQuery({
    queryKey: ["scanner", "parsers"],
    queryFn: async () => {
      const { data } = await scannerApi.list();
      return data;
    },
  });
}

// Changes hooks
export function useChangesRiskProfile(repo: string) {
  return useQuery({
    queryKey: ["changes", "risk-profile", repo],
    queryFn: async () => {
      const { data } = await changesApi.riskProfile(repo);
      return data;
    },
    enabled: !!repo,
  });
}

export function useChangesVelocity(repo: string) {
  return useQuery({
    queryKey: ["changes", "velocity", repo],
    queryFn: async () => {
      const { data } = await changesApi.velocity(repo);
      return data;
    },
    enabled: !!repo,
  });
}
