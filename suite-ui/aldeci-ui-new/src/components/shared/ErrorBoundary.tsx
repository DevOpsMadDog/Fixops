import React from "react";
import { Shield, ChevronDown, ChevronUp, RefreshCw, LayoutDashboard } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ErrorBoundaryProps {
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: React.ErrorInfo | null;
  detailsExpanded: boolean;
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      detailsExpanded: false,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo): void {
    this.setState({ errorInfo });

    // Log full details for debugging / future telemetry integration
    console.error("[ErrorBoundary] Caught unhandled runtime error:", error);
    console.error("[ErrorBoundary] Component stack:", errorInfo.componentStack);
  }

  private handleReload = (): void => {
    window.location.reload();
  };

  private handleReturnToDashboard = (): void => {
    window.location.href = "/";
  };

  private toggleDetails = (): void => {
    this.setState((prev) => ({ detailsExpanded: !prev.detailsExpanded }));
  };

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    const { error, errorInfo, detailsExpanded } = this.state;

    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-6">
        <div className="w-full max-w-lg">
          {/* Icon + heading */}
          <div className="mb-6 flex flex-col items-center gap-4 text-center">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl border border-destructive/30 bg-destructive/10">
              <Shield className="h-8 w-8 text-destructive" />
            </div>
            <div>
              <h1 className="text-xl font-semibold text-foreground">Something went wrong</h1>
              <p className="mt-1.5 text-sm text-muted-foreground">
                An unexpected error occurred. The incident has been logged. If this
                problem persists, contact your system administrator.
              </p>
            </div>
          </div>

          {/* Error summary */}
          {error && (
            <div className="mb-4 rounded-lg border border-border bg-card px-4 py-3">
              <p className="font-mono text-xs text-destructive">
                {error.name}: {error.message}
              </p>
            </div>
          )}

          {/* Expandable stack trace */}
          {(error?.stack || errorInfo?.componentStack) && (
            <div className="mb-6">
              <button
                onClick={this.toggleDetails}
                className="flex w-full items-center justify-between rounded-lg border border-border bg-card px-4 py-2.5 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
                aria-expanded={detailsExpanded}
              >
                <span>Technical details</span>
                {detailsExpanded ? (
                  <ChevronUp className="h-4 w-4" />
                ) : (
                  <ChevronDown className="h-4 w-4" />
                )}
              </button>

              {detailsExpanded && (
                <div className="mt-1 max-h-60 overflow-auto rounded-b-lg border border-t-0 border-border bg-muted p-4">
                  {error?.stack && (
                    <>
                      <p className="mb-1 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                        Stack Trace
                      </p>
                      <pre className="whitespace-pre-wrap font-mono text-xs text-foreground/80">
                        {error.stack}
                      </pre>
                    </>
                  )}
                  {errorInfo?.componentStack && (
                    <>
                      <p className="mb-1 mt-4 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                        Component Stack
                      </p>
                      <pre className="whitespace-pre-wrap font-mono text-xs text-foreground/80">
                        {errorInfo.componentStack}
                      </pre>
                    </>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Actions */}
          <div className="flex flex-col gap-2 sm:flex-row">
            <Button
              variant="default"
              className="flex-1"
              onClick={this.handleReload}
            >
              <RefreshCw className="h-4 w-4" />
              Reload Page
            </Button>
            <Button
              variant="outline"
              className="flex-1"
              onClick={this.handleReturnToDashboard}
            >
              <LayoutDashboard className="h-4 w-4" />
              Return to Dashboard
            </Button>
          </div>
        </div>
      </div>
    );
  }
}

export default ErrorBoundary;
