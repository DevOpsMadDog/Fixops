import axios from 'axios'
import { toast } from 'react-hot-toast'

// Create axios instance with enterprise configuration
const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Track performance metrics
let requestCount = 0
let totalResponseTime = 0

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Add request timestamp for performance tracking
    config.metadata = { startTime: Date.now() }
    
    // Add correlation ID for request tracking
    config.headers['X-Correlation-ID'] = `web_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    // Log enterprise API calls
    console.log(`🚀 ${config.method?.toUpperCase()} ${config.url}`, {
      correlationId: config.headers['X-Correlation-ID'],
      timestamp: new Date().toISOString()
    })
    
    return config
  },
  (error) => {
    console.error('Request interceptor error:', error)
    return Promise.reject(error)
  }
)

// Response interceptor with enterprise features
api.interceptors.response.use(
  (response) => {
    // Calculate response time
    const responseTime = Date.now() - response.config.metadata.startTime
    requestCount++
    totalResponseTime += responseTime
    
    // Log performance metrics
    console.log(`✅ ${response.config.method?.toUpperCase()} ${response.config.url}`, {
      status: response.status,
      responseTime: `${responseTime}ms`,
      correlationId: response.config.headers['X-Correlation-ID'],
      processTime: response.headers['x-process-time'],
      averageResponseTime: `${Math.round(totalResponseTime / requestCount)}ms`
    })
    
    // Warn on slow requests
    if (responseTime > 1000) {
      console.warn(`🐌 Slow request detected: ${responseTime}ms`)
    }
    
    // Log hot path performance
    if (response.headers['x-process-time-us']) {
      const processTimeUs = parseFloat(response.headers['x-process-time-us'])
      if (processTimeUs > 299) {
        console.warn(`⚡ Hot path latency exceeded: ${processTimeUs}μs (target: 299μs)`)
      }
    }
    
    return response
  },
  async (error) => {
    const config = error.config
    const responseTime = Date.now() - (config?.metadata?.startTime || Date.now())
    
    console.error(`❌ ${config?.method?.toUpperCase()} ${config?.url}`, {
      status: error.response?.status,
      responseTime: `${responseTime}ms`,
      correlationId: config?.headers?.['X-Correlation-ID'],
      error: error.response?.data?.error?.message || error.message
    })

    // Handle authentication errors
    if (error.response?.status === 401) {
      const errorMessage = error.response.data?.error?.message || 'Authentication required'
      
      // Don't show toast for auth endpoints (avoid spam)
      if (!config?.url?.includes('/auth/')) {
        // Try to refresh token first
        const refreshToken = localStorage.getItem('refresh_token')
        
        if (refreshToken && !config._retry) {
          config._retry = true
          
          try {
            const refreshResponse = await api.post('/auth/refresh', {
              refresh_token: refreshToken
            })
            
            const { access_token } = refreshResponse.data
            localStorage.setItem('access_token', access_token)
            
            // Update authorization header
            api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`
            config.headers['Authorization'] = `Bearer ${access_token}`
            
            // Retry original request
            return api(config)
          } catch (refreshError) {
            // Refresh failed, redirect to login
            localStorage.removeItem('access_token')
            localStorage.removeItem('refresh_token')
            delete api.defaults.headers.common['Authorization']
            
            window.location.href = '/login'
            return Promise.reject(refreshError)
          }
        } else {
          // No refresh token or retry failed
          toast.error('Session expired. Please log in again.')
          window.location.href = '/login'
        }
      }
    }
    
    // Handle rate limiting
    if (error.response?.status === 429) {
      const retryAfter = error.response.headers['retry-after']
      toast.error(`Rate limit exceeded. Please try again in ${retryAfter || 60} seconds.`)
    }
    
    // Handle server errors
    if (error.response?.status >= 500) {
      toast.error('Server error. Please try again later.')
    }
    
    // Handle network errors
    if (!error.response) {
      toast.error('Network error. Please check your connection.')
    }
    
    return Promise.reject(error)
  }
)

// Enterprise API methods with performance tracking
const apiMethods = {
  // Authentication
  auth: {
    login: (credentials) => api.post('/auth/login', credentials),
    logout: () => api.post('/auth/logout'),
    refresh: (refreshToken) => api.post('/auth/refresh', { refresh_token: refreshToken }),
    me: () => api.get('/auth/me'),
    changePassword: (passwords) => api.post('/auth/change-password', passwords),
    setupMFA: () => api.post('/auth/setup-mfa'),
    verifyMFA: (code) => api.post('/auth/verify-mfa', { mfa_code: code }),
    getSessions: () => api.get('/auth/sessions'),
    revokeSession: (sessionId) => api.delete(`/auth/sessions/${sessionId}`)
  },
  
  // Users
  users: {
    list: (params) => api.get('/users', { params }),
    get: (id) => api.get(`/users/${id}`),
    create: (userData) => api.post('/users', userData),
    update: (id, userData) => api.put(`/users/${id}`, userData),
    delete: (id) => api.delete(`/users/${id}`),
    updateProfile: (userData) => api.put('/users/profile', userData)
  },
  
  // Incidents
  incidents: {
    list: (params) => api.get('/incidents', { params }),
    get: (id) => api.get(`/incidents/${id}`),
    create: (incidentData) => api.post('/incidents', incidentData),
    update: (id, incidentData) => api.put(`/incidents/${id}`, incidentData),
    delete: (id) => api.delete(`/incidents/${id}`),
    assign: (id, assigneeId) => api.post(`/incidents/${id}/assign`, { assignee_id: assigneeId }),
    resolve: (id, resolution) => api.post(`/incidents/${id}/resolve`, resolution),
    escalate: (id, level) => api.post(`/incidents/${id}/escalate`, { level })
  },
  
  // Analytics
  analytics: {
    metrics: () => api.get('/analytics/metrics'),
    trends: (timeframe) => api.get('/analytics/trends', { params: { timeframe } }),
    reports: (params) => api.post('/analytics/reports', params),
    export: (format, filters) => api.post('/analytics/export', { format, filters })
  },
  
  // Monitoring
  monitoring: {
    health: () => api.get('/monitoring/health'),
    metrics: () => api.get('/monitoring/metrics'),
    performance: () => api.get('/monitoring/performance'),
    alerts: () => api.get('/monitoring/alerts')
  },
  
  // Services
  services: {
    list: (params) => api.get('/services', { params }),
    get: (id) => api.get(`/services/${id}`),
    create: (serviceData) => api.post('/services', serviceData),
    update: (id, serviceData) => api.put(`/services/${id}`, serviceData),
    delete: (id) => api.delete(`/services/${id}`)
  },
  
  // Admin
  admin: {
    systemConfig: () => api.get('/admin/config'),
    updateConfig: (config) => api.put('/admin/config', config),
    auditLogs: (params) => api.get('/admin/audit-logs', { params }),
    systemHealth: () => api.get('/admin/system-health'),
    performance: () => api.get('/admin/performance')
  }
}

// Export both the axios instance and methods
export default api
export { apiMethods }

// Performance monitoring utilities
export const getApiPerformanceStats = () => ({
  requestCount,
  averageResponseTime: Math.round(totalResponseTime / requestCount) || 0,
  totalResponseTime
})

// Hot path performance checker
export const checkHotPathPerformance = (target = 299) => {
  const stats = getApiPerformanceStats()
  return {
    ...stats,
    targetLatencyUs: target,
    meetsTarget: stats.averageResponseTime * 1000 <= target,
    performanceGrade: stats.averageResponseTime * 1000 <= target ? 'A' : 
                     stats.averageResponseTime * 1000 <= target * 2 ? 'B' : 'C'
  }
}