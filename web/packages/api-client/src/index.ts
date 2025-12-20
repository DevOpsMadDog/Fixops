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
  useReports,
  useReportDownload,
  usePentagiRequests,
  usePentagiResults,
  usePentagiStats,
  useMarketplaceBrowse,
  useMarketplaceStats,
  useCompliance,
  useFindings,
  useInventory,
  useUsers,
  useTeams,
  usePolicies,
  useWorkflows,
  useAuditLogs,
} from './hooks';
