import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, RefreshCw, Home, WifiOff, ShieldAlert, Server } from 'lucide-react'

// ═══════════════════════════════════════════════════════════════════════════
// Error Categories
// ═══════════════════════════════════════════════════════════════════════════

type ErrorCategory = 'network' | 'auth' | 'server' | 'render' | 'unknown'

function categorizeError(error: Error): ErrorCategory {
  const msg = error.message.toLowerCase()
  if (msg.includes('network') || msg.includes('fetch') || msg.includes('econnrefused') || msg.includes('timeout')) return 'network'
  if (msg.includes('401') || msg.includes('403') || msg.includes('unauthorized') || msg.includes('forbidden')) return 'auth'
  if (msg.includes('500') || msg.includes('502') || msg.includes('503') || msg.includes('internal server')) return 'server'
  if (msg.includes('cannot read propert') || msg.includes('is not a function') || msg.includes('undefined')) return 'render'
  return 'unknown'
}

const categoryMeta: Record<ErrorCategory, { icon: ReactNode; title: string; description: string; color: string }> = {
  network: {
    icon: <WifiOff className="h-12 w-12" />,
    title: 'Network Error',
    description: 'Unable to reach the API server. Please check your connection and ensure the backend is running on port 8000.',
    color: 'text-yellow-400',
  },
  auth: {
    icon: <ShieldAlert className="h-12 w-12" />,
    title: 'Authentication Error',
    description: 'Your session has expired or the API key is invalid. Please re-authenticate.',
    color: 'text-red-400',
  },
  server: {
    icon: <Server className="h-12 w-12" />,
    title: 'Server Error',
    description: 'The API server encountered an internal error. This has been logged for investigation.',
    color: 'text-orange-400',
  },
  render: {
    icon: <AlertTriangle className="h-12 w-12" />,
    title: 'Rendering Error',
    description: 'A component failed to render. This is likely a bug — please report it.',
    color: 'text-purple-400',
  },
  unknown: {
    icon: <AlertTriangle className="h-12 w-12" />,
    title: 'Unexpected Error',
    description: 'Something went wrong. Try refreshing the page.',
    color: 'text-gray-400',
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// ErrorBoundary Component
// ═══════════════════════════════════════════════════════════════════════════

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: ErrorInfo | null
  showDetails: boolean
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null, errorInfo: null, showDetails: false }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo })
    console.error('[ErrorBoundary]', error, errorInfo)
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null, errorInfo: null, showDetails: false })
  }

  handleHome = () => {
    window.location.href = '/'
  }

  render() {
    if (!this.state.hasError) return this.props.children
    if (this.props.fallback) return this.props.fallback

    const category = this.state.error ? categorizeError(this.state.error) : 'unknown'
    const meta = categoryMeta[category]

    return (
      <div className="flex items-center justify-center min-h-[60vh] p-8">
        <div className="max-w-lg w-full rounded-xl border border-border/50 bg-card p-8 text-center shadow-xl">
          <div className={`flex justify-center mb-4 ${meta.color}`}>{meta.icon}</div>
          <h2 className="text-xl font-semibold text-foreground mb-2">{meta.title}</h2>
          <p className="text-sm text-muted-foreground mb-6">{meta.description}</p>

          <div className="flex gap-3 justify-center mb-4">
            <button onClick={this.handleRetry} className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors">
              <RefreshCw className="h-4 w-4" /> Retry
            </button>
            <button onClick={this.handleHome} className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-secondary text-secondary-foreground text-sm font-medium hover:bg-secondary/80 transition-colors">
              <Home className="h-4 w-4" /> Dashboard
            </button>
          </div>

          <button
            onClick={() => this.setState((s) => ({ showDetails: !s.showDetails }))}
            className="text-xs text-muted-foreground underline hover:text-foreground transition-colors"
          >
            {this.state.showDetails ? 'Hide' : 'Show'} technical details
          </button>

          {this.state.showDetails && (
            <div className="mt-4 text-left rounded-lg bg-muted/50 p-4 overflow-auto max-h-48">
              <p className="text-xs font-mono text-destructive break-all">{this.state.error?.message}</p>
              {this.state.errorInfo?.componentStack && (
                <pre className="mt-2 text-xs font-mono text-muted-foreground whitespace-pre-wrap">{this.state.errorInfo.componentStack}</pre>
              )}
            </div>
          )}
        </div>
      </div>
    )
  }
}

export default ErrorBoundary

