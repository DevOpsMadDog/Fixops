import { useEffect, useRef, useState, useCallback } from 'react'

// ═══════════════════════════════════════════════════════════════════════════
// Generic SSE Hook
// ═══════════════════════════════════════════════════════════════════════════

interface UseSSEOptions {
  /** Auto-reconnect on error (default: true) */
  reconnect?: boolean
  /** Reconnect delay in ms (default: 3000) */
  reconnectDelay?: number
  /** Max reconnect attempts (default: 5) */
  maxRetries?: number
  /** Only listen for this named event (default: 'message') */
  eventName?: string
}

interface UseSSEReturn<T> {
  data: T | null
  error: string | null
  status: 'connecting' | 'connected' | 'disconnected' | 'error'
  close: () => void
}

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export function useSSE<T = unknown>(
  path: string,
  options: UseSSEOptions = {}
): UseSSEReturn<T> {
  const {
    reconnect = true,
    reconnectDelay = 3000,
    maxRetries = 5,
    eventName,
  } = options

  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [status, setStatus] = useState<UseSSEReturn<T>['status']>('connecting')
  const sourceRef = useRef<EventSource | null>(null)
  const retriesRef = useRef(0)

  const close = useCallback(() => {
    if (sourceRef.current) {
      sourceRef.current.close()
      sourceRef.current = null
    }
    setStatus('disconnected')
  }, [])

  useEffect(() => {
    if (!path) return

    const url = path.startsWith('http') ? path : `${API_BASE}${path}`

    function connect() {
      const source = new EventSource(url)
      sourceRef.current = source

      source.onopen = () => {
        setStatus('connected')
        setError(null)
        retriesRef.current = 0
      }

      const handler = (e: MessageEvent) => {
        try {
          const parsed = JSON.parse(e.data) as T
          setData(parsed)
        } catch {
          setData(e.data as unknown as T)
        }
      }

      if (eventName) {
        source.addEventListener(eventName, handler)
      } else {
        source.onmessage = handler
      }

      source.onerror = () => {
        source.close()
        sourceRef.current = null

        if (reconnect && retriesRef.current < maxRetries) {
          setStatus('connecting')
          retriesRef.current++
          setTimeout(connect, reconnectDelay)
        } else {
          setStatus('error')
          setError('SSE connection failed')
        }
      }
    }

    connect()

    return () => {
      if (sourceRef.current) {
        sourceRef.current.close()
        sourceRef.current = null
      }
    }
  }, [path, reconnect, reconnectDelay, maxRetries, eventName])

  return { data, error, status, close }
}

// ═══════════════════════════════════════════════════════════════════════════
// Convenience: Pipeline progress hook
// ═══════════════════════════════════════════════════════════════════════════

export interface PipelineProgress {
  run_id: string
  status: string
  current_stage?: string
  progress: number
  stages_completed: number
  total_stages: number
  elapsed_seconds: number
  result?: Record<string, unknown>
}

export function usePipelineStream(runId: string | null) {
  return useSSE<PipelineProgress>(
    runId ? `/api/v1/stream/pipeline/${runId}` : '',
    { eventName: 'progress', reconnect: false }
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Convenience: EventBus live stream hook
// ═══════════════════════════════════════════════════════════════════════════

export interface LiveEvent {
  event_type: string
  source: string
  data: Record<string, unknown>
  org_id?: string
  timestamp?: string
}

export function useEventStream(types?: string[]) {
  const filter = types?.join(',') || ''
  return useSSE<LiveEvent>(
    `/api/v1/stream/events${filter ? `?types=${filter}` : ''}`,
    { eventName: 'event', reconnect: true }
  )
}

