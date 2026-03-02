import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, RefreshCw, Home, WifiOff, ShieldAlert, Server, Copy, CheckCircle2, Clock, Bug } from 'lucide-react'

// ═══════════════════════════════════════════════════════════════════════════
// Error Categories — intelligently classify errors for better UX
// ═══════════════════════════════════════════════════════════════════════════

type ErrorCategory = 'network' | 'auth' | 'server' | 'render' | 'chunk' | 'unknown'

function categorizeError(error: Error): ErrorCategory {
  const msg = error.message.toLowerCase()
  const name = error.name.toLowerCase()

  // Chunk/lazy load errors (common with code-splitting)
  if (msg.includes('loading chunk') || msg.includes('dynamically imported module') || msg.includes('failed to fetch dynamically')) {
    return 'chunk'
  }
  // Network errors
  if (msg.includes('network') || msg.includes('fetch') || msg.includes('econnrefused') || msg.includes('timeout') || name === 'typeerror' && msg.includes('failed to fetch')) {
    return 'network'
  }
  // Auth errors
  if (msg.includes('401') || msg.includes('403') || msg.includes('unauthorized') || msg.includes('forbidden')) {
    return 'auth'
  }
  // Server errors
  if (msg.includes('500') || msg.includes('502') || msg.includes('503') || msg.includes('internal server')) {
    return 'server'
  }
  // Render errors
  if (msg.includes('cannot read propert') || msg.includes('is not a function') || msg.includes('undefined') || msg.includes('is not defined')) {
    return 'render'
  }
  return 'unknown'
}

const categoryMeta: Record<ErrorCategory, {
  icon: ReactNode
  title: string
  description: string
  color: string
  autoRetry: boolean
  retryDelay: number
}> = {
  network: {
    icon: <WifiOff className="h-12 w-12" />,
    title: 'Network Error',
    description: 'Unable to reach the API server. Check your connection and ensure the backend is running on port 8000.',
    color: 'text-yellow-400',
    autoRetry: true,
    retryDelay: 3000,
  },
  auth: {
    icon: <ShieldAlert className="h-12 w-12" />,
    title: 'Authentication Error',
    description: 'Your session has expired or the API key is invalid. Check Settings → API Key.',
    color: 'text-red-400',
    autoRetry: false,
    retryDelay: 0,
  },
  server: {
    icon: <Server className="h-12 w-12" />,
    title: 'Server Error',
    description: 'The API server encountered an internal error. This has been logged for investigation.',
    color: 'text-orange-400',
    autoRetry: true,
    retryDelay: 5000,
  },
  render: {
    icon: <Bug className="h-12 w-12" />,
    title: 'Rendering Error',
    description: 'A component failed to render. This is likely a bug — the team has been notified.',
    color: 'text-purple-400',
    autoRetry: false,
    retryDelay: 0,
  },
  chunk: {
    icon: <RefreshCw className="h-12 w-12" />,
    title: 'Update Available',
    description: 'A new version of ALdeci was deployed. Click Refresh to load the latest version.',
    color: 'text-blue-400',
    autoRetry: true,
    retryDelay: 1000,
  },
  unknown: {
    icon: <AlertTriangle className="h-12 w-12" />,
    title: 'Unexpected Error',
    description: 'Something went wrong. Try refreshing the page.',
    color: 'text-gray-400',
    autoRetry: false,
    retryDelay: 0,
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// Telemetry — log errors to API for debugging (fire-and-forget)
// ═══════════════════════════════════════════════════════════════════════════

function reportError(error: Error, errorInfo: ErrorInfo | null, category: ErrorCategory) {
  try {
    const payload = {
      timestamp: new Date().toISOString(),
      category,
      message: error.message,
      name: error.name,
      stack: error.stack?.slice(0, 2000),
      componentStack: errorInfo?.componentStack?.slice(0, 1000),
      url: window.location.href,
      userAgent: navigator.userAgent,
    }

    // Fire-and-forget — don't block UI
    fetch('/api/v1/telemetry/errors', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).catch(() => {
      // Telemetry endpoint may not exist yet — silently ignore
    })

    // Also log to console for dev debugging
    console.error('[ErrorBoundary]', category, error, errorInfo)
  } catch {
    // Never let telemetry reporting throw
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// ErrorBoundary Component — auto-retry, telemetry, copy stack trace
// ═══════════════════════════════════════════════════════════════════════════

interface Props {
  children: ReactNode
  fallback?: ReactNode
  onError?: (error: Error, category: ErrorCategory) => void
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: ErrorInfo | null
  showDetails: boolean
  retryCount: number
  retryCountdown: number | null
  copied: boolean
}

const MAX_AUTO_RETRIES = 3

export class ErrorBoundary extends Component<Props, State> {
  state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
    showDetails: false,
    retryCount: 0,
    retryCountdown: null,
    copied: false,
  }

  private retryTimer: ReturnType<typeof setTimeout> | null = null
  private countdownTimer: ReturnType<typeof setInterval> | null = null

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo })

    const category = categorizeError(error)
    reportError(error, errorInfo, category)

    // Notify parent if callback provided
    if (this.props.onError) {
      this.props.onError(error, category)
    }

    // Auto-retry for recoverable errors
    const meta = categoryMeta[category]
    if (meta.autoRetry && this.state.retryCount < MAX_AUTO_RETRIES) {
      this.startAutoRetry(meta.retryDelay)
    }
  }

  componentWillUnmount() {
    this.clearTimers()
  }

  clearTimers = () => {
    if (this.retryTimer) clearTimeout(this.retryTimer)
    if (this.countdownTimer) clearInterval(this.countdownTimer)
    this.retryTimer = null
    this.countdownTimer = null
  }

  startAutoRetry = (delay: number) => {
    this.clearTimers()
    const seconds = Math.ceil(delay / 1000)
    this.setState({ retryCountdown: seconds })

    this.countdownTimer = setInterval(() => {
      this.setState(prev => {
        const next = (prev.retryCountdown ?? 1) - 1
        if (next <= 0) {
          this.clearTimers()
          return { retryCountdown: null }
        }
        return { retryCountdown: next }
      })
    }, 1000)

    this.retryTimer = setTimeout(() => {
      this.clearTimers()
      this.handleRetry()
    }, delay)
  }

  handleRetry = () => {
    this.clearTimers()
    this.setState(prev => ({
      hasError: false,
      error: null,
      errorInfo: null,
      showDetails: false,
      retryCount: prev.retryCount + 1,
      retryCountdown: null,
      copied: false,
    }))
  }

  handleHardReload = () => {
    window.location.reload()
  }

  handleHome = () => {
    window.location.href = '/'
  }

  handleCopyStack = async () => {
    const { error, errorInfo } = this.state
    const text = [
      `Error: ${error?.name}: ${error?.message}`,
      `URL: ${window.location.href}`,
      `Time: ${new Date().toISOString()}`,
      '',
      'Stack Trace:',
      error?.stack || '(none)',
      '',
      'Component Stack:',
      errorInfo?.componentStack || '(none)',
    ].join('\n')

    try {
      await navigator.clipboard.writeText(text)
      this.setState({ copied: true })
      setTimeout(() => this.setState({ copied: false }), 2000)
    } catch {
      // Clipboard API may not be available
    }
  }

  render() {
    if (!this.state.hasError) return this.props.children
    if (this.props.fallback) return this.props.fallback

    const { error, showDetails, retryCount, retryCountdown, copied } = this.state
    const category = error ? categorizeError(error) : 'unknown'
    const meta = categoryMeta[category]

    return (
      <div className="flex items-center justify-center min-h-[60vh] p-8">
        <div className="max-w-lg w-full rounded-xl border border-gray-700/30 bg-gray-900/80 backdrop-blur-md p-8 text-center shadow-2xl">
          {/* Icon */}
          <div className={`flex justify-center mb-4 ${meta.color}`}>{meta.icon}</div>

          {/* Title + Description */}
          <h2 className="text-xl font-semibold text-gray-100 mb-2">{meta.title}</h2>
          <p className="text-sm text-gray-400 mb-6">{meta.description}</p>

          {/* Auto-retry countdown */}
          {retryCountdown !== null && (
            <div className="mb-4 flex items-center justify-center gap-2 text-sm text-blue-400">
              <Clock className="h-4 w-4 animate-pulse" />
              Auto-retrying in {retryCountdown}s...
              <button
                onClick={() => {
                  this.clearTimers()
                  this.setState({ retryCountdown: null })
                }}
                className="text-xs text-gray-500 hover:text-gray-300 underline"
              >
                cancel
              </button>
            </div>
          )}

          {/* Retry count indicator */}
          {retryCount > 0 && (
            <p className="text-xs text-gray-500 mb-3">
              Retry attempt {retryCount}/{MAX_AUTO_RETRIES}
            </p>
          )}

          {/* Action Buttons */}
          <div className="flex gap-3 justify-center mb-4 flex-wrap">
            <button
              onClick={this.handleRetry}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
            >
              <RefreshCw className="h-4 w-4" /> Retry
            </button>

            {category === 'chunk' ? (
              <button
                onClick={this.handleHardReload}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-medium hover:bg-blue-500 transition-colors"
              >
                <RefreshCw className="h-4 w-4" /> Hard Refresh
              </button>
            ) : (
              <button
                onClick={this.handleHome}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-800 text-gray-200 text-sm font-medium hover:bg-gray-700 transition-colors border border-gray-700/30"
              >
                <Home className="h-4 w-4" /> Dashboard
              </button>
            )}
          </div>

          {/* Technical details toggle */}
          <div className="flex items-center justify-center gap-3">
            <button
              onClick={() => this.setState(s => ({ showDetails: !s.showDetails }))}
              className="text-xs text-gray-500 hover:text-gray-300 transition-colors underline"
            >
              {showDetails ? 'Hide' : 'Show'} technical details
            </button>

            {showDetails && (
              <button
                onClick={this.handleCopyStack}
                className="text-xs text-gray-500 hover:text-gray-300 transition-colors inline-flex items-center gap-1"
              >
                {copied ? (
                  <><CheckCircle2 className="h-3 w-3 text-green-400" /> Copied</>
                ) : (
                  <><Copy className="h-3 w-3" /> Copy</>
                )}
              </button>
            )}
          </div>

          {/* Technical details panel */}
          {showDetails && (
            <div className="mt-4 text-left rounded-lg bg-gray-950/60 border border-gray-700/20 p-4 overflow-auto max-h-48">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">
                  {category} — {error?.name}
                </span>
              </div>
              <p className="text-xs font-mono text-red-400 break-all">{error?.message}</p>
              {this.state.errorInfo?.componentStack && (
                <pre className="mt-2 text-xs font-mono text-gray-500 whitespace-pre-wrap leading-tight">
                  {this.state.errorInfo.componentStack}
                </pre>
              )}
            </div>
          )}

          {/* ALdeci branding */}
          <p className="mt-6 text-[10px] text-gray-600">
            ALdeci CTEM+ Platform • Error Reference: {category.toUpperCase()}-{Date.now().toString(36).slice(-6).toUpperCase()}
          </p>
        </div>
      </div>
    )
  }
}

export default ErrorBoundary
