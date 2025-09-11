import axios from 'axios';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API_BASE = `${BACKEND_URL}/api`;

const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    console.log(`🚀 ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
apiClient.interceptors.response.use(
  (response) => {
    console.log(`✅ ${response.config.method?.toUpperCase()} ${response.config.url} - ${response.status}`);
    return response;
  },
  (error) => {
    console.error(`❌ ${error.config?.method?.toUpperCase()} ${error.config?.url} - ${error.response?.status}`, error.response?.data);
    return Promise.reject(error);
  }
);

// API functions
export const api = {
  // Services
  getServices: () => apiClient.get('/services'),
  createService: (data) => apiClient.post('/services', data),
  getService: (id) => apiClient.get(`/services/${id}`),

  // Findings
  getFindings: (params = {}) => apiClient.get('/findings', { params }),
  createFinding: (data) => apiClient.post('/findings', data),

  // Cases
  getCases: () => apiClient.get('/cases'),
  getCase: (id) => apiClient.get(`/cases/${id}`),
  getFixSuggestions: (caseId) => apiClient.get(`/cases/${caseId}/fixes`),

  // Dashboard
  getDashboardMetrics: () => apiClient.get('/dashboard/metrics'),
  getFindingTrends: () => apiClient.get('/dashboard/trends'),

  // Policy
  evaluatePolicy: (context) => apiClient.post('/policy/evaluate', context),

  // Health check
  healthCheck: () => apiClient.get('/'),
};

export default apiClient;