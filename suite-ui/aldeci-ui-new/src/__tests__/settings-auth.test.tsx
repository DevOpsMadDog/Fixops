/**
 * Settings, Auth & Onboarding screens — smoke tests.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderPage, mockQueryResult, mockMutationResult } from "./test-utils";

const mocks: Record<string, any> = {
  useSystemHealth: vi.fn(),
  useSystemMetrics: vi.fn(),
  useUsers: vi.fn(),
  useTeams: vi.fn(),
  useIntegrations: vi.fn(),
  usePolicies: vi.fn(),
  useAuditLog: vi.fn(),
  useApps: vi.fn(),
  useTestIntegration: vi.fn(),
  useSyncIntegration: vi.fn(),
  useConfigureIntegration: vi.fn(),
};

// Stub for removed pages — keeps describe blocks compilable
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const P = (() => null) as any;

vi.mock("@/hooks/use-api", () => mocks);
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }));
vi.mock("@/lib/api", () => ({
  systemApi: { getHealth: vi.fn().mockResolvedValue({ data: { status: "healthy" } }), getMetrics: vi.fn().mockResolvedValue({ data: {} }) },
  auditApi: { getEntries: vi.fn().mockResolvedValue({ data: [] }) },
  getStoredAuthStrategy: vi.fn().mockReturnValue("token"),
  getStoredAuthToken: vi.fn().mockReturnValue("test"),
  getStoredOrgId: vi.fn().mockReturnValue(""),
  setStoredAuthStrategy: vi.fn(),
  setStoredAuthToken: vi.fn(),
  setStoredOrgId: vi.fn(),
  streamApi: { connect: vi.fn() },
  webhookEventsApi: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) },
  buildApiUrl: vi.fn((p: string) => `http://localhost:8000${p}`),
}));
vi.mock("@tanstack/react-query", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tanstack/react-query")>();
  return {
    ...actual,
    useQuery: vi.fn().mockReturnValue({ data: undefined, isLoading: false, error: null }),
  };
});
vi.mock("framer-motion", async () => {
  const React = await import("react");
  const motionProxy = new Proxy({}, {
    get: (_target, prop) => {
      if (prop === "__esModule") return true;
      return React.forwardRef((props: any, ref: any) => {
        const { children, initial, animate, exit, transition, whileHover, whileTap, variants, layout, layoutId, ...rest } = props;
        return React.createElement(typeof prop === "string" ? prop : "div", { ...rest, ref }, children);
      });
    },
  });
  return { motion: motionProxy, AnimatePresence: ({ children }: any) => children, useAnimation: () => ({ start: vi.fn() }), useInView: () => true };
});
vi.mock("recharts", () => {
  const React = require("react");
  const S = (p: any) => React.createElement("div", p, p.children);
  return { ResponsiveContainer: S, AreaChart: S, Area: S, BarChart: S, Bar: S, LineChart: S, Line: S, PieChart: S, Pie: S, Cell: S, RadarChart: S, Radar: S, PolarGrid: S, PolarAngleAxis: S, PolarRadiusAxis: S, XAxis: S, YAxis: S, CartesianGrid: S, Tooltip: S, Legend: S, RadialBarChart: S, RadialBar: S, Treemap: S };
});

beforeEach(() => {
  mocks.useSystemHealth.mockReturnValue(mockQueryResult({ status: "healthy", services: [] }));
  mocks.useSystemMetrics.mockReturnValue(mockQueryResult({ cpu: 0, memory: 0 }));
  mocks.useUsers.mockReturnValue(mockQueryResult({ items: [] }));
  mocks.useTeams.mockReturnValue(mockQueryResult({ teams: [] }));
  mocks.useIntegrations.mockReturnValue(mockQueryResult({ integrations: [] }));
  mocks.usePolicies.mockReturnValue(mockQueryResult({ policies: [] }));
  mocks.useAuditLog.mockReturnValue(mockQueryResult({ entries: [] }));
  mocks.useApps.mockReturnValue(mockQueryResult({ apps: [] }));
  mocks.useTestIntegration.mockReturnValue(mockMutationResult());
  mocks.useSyncIntegration.mockReturnValue(mockMutationResult());
  mocks.useConfigureIntegration.mockReturnValue(mockMutationResult());
});

// ═══════════════════════════════════════
// Settings
// ═══════════════════════════════════════

// pruned in ui-prune branch (chore/ui-prune-plan-2026-05-24) — page removed
describe.skip("SettingsHub", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    expect(screen.getByRole("heading", { name: /Settings/i, level: 1 })).toBeInTheDocument();
  });
});

// pruned in ui-prune branch (chore/ui-prune-plan-2026-05-24) — page removed
describe.skip("Users", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    expect(screen.getByText("Users")).toBeInTheDocument();
  });
  it("fetches user list", async () => {
    renderPage(<P />);
    expect(mocks.useUsers).toHaveBeenCalled();
  });
});

// pruned in ui-prune branch (chore/ui-prune-plan-2026-05-24) — page removed
describe.skip("Teams", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    expect(screen.getByRole("heading", { name: /Teams/i })).toBeInTheDocument();
  });
});

describe("Integrations", () => {
  it("renders heading", async () => {
    const P = (await import("@/pages/settings/Integrations")).default;
    renderPage(<P />);
    expect(screen.getByText("Integrations")).toBeInTheDocument();
  });
});

describe("Marketplace", () => {
  it("renders heading", async () => {
    const P = (await import("@/pages/settings/Marketplace")).default;
    renderPage(<P />);
    expect(screen.getByText("Marketplace")).toBeInTheDocument();
  });
});

// pruned in ui-prune branch (chore/ui-prune-plan-2026-05-24) — page removed
describe.skip("Policies", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    expect(screen.getByText("Policies")).toBeInTheDocument();
  });
});

// pruned in ui-prune branch (chore/ui-prune-plan-2026-05-24) — page removed
describe.skip("SystemHealth", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    expect(screen.getByText("System Health")).toBeInTheDocument();
  });
});

describe("LogViewer", () => {
  it("renders heading", async () => {
    const P = (await import("@/pages/settings/LogViewer")).default;
    renderPage(<P />);
    expect(screen.getByText("Log Viewer")).toBeInTheDocument();
  });
});

// ═══════════════════════════════════════
// Auth
// ═══════════════════════════════════════

describe("LoginPage", () => {
  it("renders sign in form", async () => {
    const P = (await import("@/pages/auth/LoginPage")).default;
    renderPage(<P />);
    expect(screen.getAllByText(/Sign in/i).length).toBeGreaterThan(0);
  });
  it("renders email and password inputs", async () => {
    const P = (await import("@/pages/auth/LoginPage")).default;
    renderPage(<P />);
    // Label text is "Work Email" (not "Email") per the component's label copy
    await waitFor(() => expect(screen.getByLabelText("Work Email")).toBeInTheDocument());
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });
  it("has submit button", async () => {
    const P = (await import("@/pages/auth/LoginPage")).default;
    renderPage(<P />);
    // Multiple sign-in buttons render (form submit + hero CTA); assert at least one exists
    await waitFor(() => expect(screen.getAllByRole("button", { name: /sign in/i }).length).toBeGreaterThan(0));
  });
});

// pruned in ui-prune branch (chore/ui-prune-plan-2026-05-24) — page removed
describe.skip("AccessDenied", () => {
  it("renders access denied message", async () => {
    renderPage(<P />);
    expect(screen.getByText("Access Denied")).toBeInTheDocument();
  });
  it("has go back button", async () => {
    renderPage(<P />);
    expect(screen.getByRole("button", { name: /go back/i })).toBeInTheDocument();
  });
});

// ═══════════════════════════════════════
// Other
// ═══════════════════════════════════════

describe("NotFound", () => {
  it("renders 404", async () => {
    const P = (await import("@/pages/NotFound")).default;
    renderPage(<P />);
    // Multiple elements contain "404" (glitch text + footer); assert at least one exists
    expect(screen.getAllByText("404").length).toBeGreaterThan(0);
  });
});

describe("OnboardingWizard", () => {
  it("renders first step", async () => {
    const P = (await import("@/pages/onboarding/OnboardingWizard")).default;
    renderPage(<P />);
    // Step 1 of 4 — Connect Cloud Account (FEATURE-1, 2026-05-02)
    expect(screen.getByText(/Connect a cloud account/i)).toBeInTheDocument();
  });
});
