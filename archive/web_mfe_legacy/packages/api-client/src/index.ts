/**
 * FixOps API Client
 * 
 * Shared API client package for all FixOps frontend applications.
 * Provides unified data fetching, authentication, and mode management.
 */

// Configuration
export {
  getApiBaseUrl,
  getApiKey,
  getSystemMode,
  setSystemMode,
  getApiConfig,
  isDemoDataEnabled,
  setDemoDataEnabled,
  type SystemMode,
  type ApiConfig,
} from './config';

// Client
export {
  fetchApi,
  downloadFile,
  FixOpsApiClient,
  getApiClient,
  type ApiError,
  type ApiResponse,
  type FetchOptions,
} from './client';

// React Hooks
export {
  useApi,
  useSystemMode,
  useDemoMode,
  useReports,
  useReportDownload,
  usePentagiRequests,
  usePentagiResults,
  usePentagiStats,
  useMarketplaceBrowse,
  useMarketplaceStats,
  useCompliance,
  useFindings,
  useFindingDetail,
  useInventory,
  useUsers,
  useTeams,
  usePolicies,
  useWorkflows,
  useAuditLogs,
  useTriage,
  useTriageExport,
  useGraph,
  useEvidence,
} from './hooks';
