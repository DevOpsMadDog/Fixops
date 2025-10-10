import axios from 'axios'
import { toast } from 'react-hot-toast'

// Resolve backend URL - use proxy in development, environment URL in production
// IMPORTANT: In development, Vite proxy handles API calls to /api
const BACKEND_BASE = (import.meta?.env?.VITE_API_BASE_URL || import.meta?.env?.REACT_APP_BACKEND_URL)

// Create axios instance with enterprise configuration
const api = axios.create({
  baseURL: BACKEND_BASE ? `${BACKEND_BASE}/api/v1` : '/api/v1',
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

// Chunked upload helpers
const DEFAULT_CHUNK_SIZE = 1024 * 1024 // 1MB

async function initUpload({ file_name, total_size, scan_type, service_name, environment = 'production' }) {
  const res = await api.post('/scans/upload/init', { file_name, total_size, scan_type, service_name, environment })
  return res.data.data // { upload_id }
}

async function uploadChunk({ upload_id, chunk_index, total_chunks, chunk_blob }) {
  const formData = new FormData()
  formData.append('upload_id', upload_id)
  formData.append('chunk_index', String(chunk_index))
  formData.append('total_chunks', String(total_chunks))
  formData.append('chunk', chunk_blob)

  const res = await api.post('/scans/upload/chunk', formData, { headers: { 'Content-Type': 'multipart/form-data' } })
  return res.data
}

async function completeUpload({ upload_id }) {
  const res = await api.post('/scans/upload/complete', { upload_id })
  return res.data
}

async function chunkedFileUpload(file, { scan_type, service_name, environment = 'production', chunkSize = DEFAULT_CHUNK_SIZE, onProgress } = {}) {
  const total_size = file.size
  const { upload_id } = await initUpload({ file_name: file.name, total_size, scan_type, service_name, environment })

  const total_chunks = Math.ceil(total_size / chunkSize)
  for (let i = 0; i < total_chunks; i++) {
    const start = i * chunkSize
    const end = Math.min(start + chunkSize, total_size)
    const blob = file.slice(start, end)
    await uploadChunk({ upload_id, chunk_index: i, total_chunks, chunk_blob: blob })
    if (onProgress) onProgress(Math.round(((i + 1) / total_chunks) * 100))
  }

  const completion = await completeUpload({ upload_id })
  return completion
}

// Enterprise API methods with performance tracking
const apiMethods = {
  // Enhanced endpoints
  enhanced: {
    capabilities: () => api.get('/enhanced/capabilities'),
    compare: (payload) => api.post('/enhanced/compare-llms', payload),
    analysis: (payload) => api.post('/enhanced/analysis', payload),
  },

  // Scans
  scans: {
    upload: (formData) => api.post('/scans/upload', formData, { headers: { 'Content-Type': 'multipart/form-data' } }),
    chunkedUpload: chunkedFileUpload,
  },
}

export default api
export { apiMethods, chunkedFileUpload }

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
