/**
 * Shared test utilities — wrapper components & mock factories.
 *
 * Usage:
 *   import { renderPage, mockHook } from "../test-utils";
 *   mockHook("useDashboardOverview", { total_findings: 42 });
 *   renderPage(<CommandDashboard />);
 *   expect(screen.getByText("Command Dashboard")).toBeInTheDocument();
 */
import React, { type ReactElement } from "react";
import { render, type RenderOptions } from "@testing-library/react";
import { MemoryRouter, type MemoryRouterProps } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi } from "vitest";

// ── Auth context mock ──

const defaultAuth = {
  user: { id: "u1", email: "test@aldeci.com", first_name: "Test", last_name: "User", role: "admin" as const },
  loading: false,
  isAuthenticated: true,
  login: vi.fn(),
  logout: vi.fn(),
  hasRole: (..._r: string[]) => true,
  hasScope: (..._s: string[]) => true,
};

vi.mock("@/lib/auth", () => ({
  useAuth: () => defaultAuth,
  AuthProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  RequireAuth: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  RequireRole: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

// ── Query client (no retries, no refetch) ──

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchOnWindowFocus: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });
}

// ── All-providers wrapper ──

interface WrapperProps {
  routerProps?: MemoryRouterProps;
}

function AllProviders({ children, routerProps }: WrapperProps & { children: React.ReactNode }) {
  const qc = createTestQueryClient();
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter {...routerProps}>
        {children}
      </MemoryRouter>
    </QueryClientProvider>
  );
}

/**
 * Render a page component inside all required providers.
 */
export function renderPage(ui: ReactElement, opts?: RenderOptions & { routerProps?: MemoryRouterProps }) {
  const { routerProps, ...rest } = opts ?? {};
  return render(ui, {
    wrapper: ({ children }) => <AllProviders routerProps={routerProps}>{children}</AllProviders>,
    ...rest,
  });
}

/** Shape returned by all mock query helpers. */
interface MockQueryBase<T = unknown> {
  data: T;
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  isFetching: boolean;
  isSuccess: boolean;
  refetch: ReturnType<typeof vi.fn>;
  status: "success" | "pending" | "error";
  fetchStatus: "idle" | "fetching";
}

/**
 * Create a mock for a single use-api hook that returns the desired data.
 *
 * Call this at module level (or inside beforeEach) via vi.mock:
 *   vi.mocked(useXYZ).mockReturnValue(mockQueryResult({ ... }));
 */
export function mockQueryResult<T>(data: T, overrides?: Partial<MockQueryBase<T>>): MockQueryBase<T> {
  return {
    data,
    isLoading: false,
    isError: false,
    error: null,
    isFetching: false,
    isSuccess: true,
    refetch: vi.fn(),
    status: "success" as const,
    fetchStatus: "idle" as const,
    ...overrides,
  };
}

/** A loading-state mock. */
export function mockQueryLoading(): MockQueryBase<undefined> {
  return {
    data: undefined,
    isLoading: true,
    isError: false,
    error: null,
    isFetching: true,
    isSuccess: false,
    refetch: vi.fn(),
    status: "pending" as const,
    fetchStatus: "fetching" as const,
  };
}

/** An error-state mock. */
export function mockQueryError(message = "Network error"): MockQueryBase<undefined> {
  return {
    data: undefined,
    isLoading: false,
    isError: true,
    error: new Error(message),
    isFetching: false,
    isSuccess: false,
    refetch: vi.fn(),
    status: "error" as const,
    fetchStatus: "idle" as const,
  };
}

/** Mutation mock. */
export function mockMutationResult(overrides?: Record<string, unknown>) {
  return {
    mutate: vi.fn(),
    mutateAsync: vi.fn(),
    isPending: false,
    isSuccess: false,
    isError: false,
    error: null,
    data: undefined,
    reset: vi.fn(),
    ...overrides,
  };
}
