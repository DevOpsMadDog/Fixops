/**
 * Settings, Auth & Onboarding screens — smoke tests.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
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
}));
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
});

// ═══════════════════════════════════════
// Settings
// ═══════════════════════════════════════

describe("SettingsHub", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    expect(screen.getByRole("heading", { name: /Settings/i, level: 1 })).toBeInTheDocument();
  });
});

describe("Users", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    expect(screen.getByText("Users")).toBeInTheDocument();
  });
  it("fetches user list", async () => {
    renderPage(<P />);
    expect(mocks.useUsers).toHaveBeenCalled();
  });
});

describe("Teams", () => {
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

describe("Policies", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    expect(screen.getByText("Policies")).toBeInTheDocument();
  });
});

describe("SystemHealth", () => {
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
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });
  it("has submit button", async () => {
    const P = (await import("@/pages/auth/LoginPage")).default;
    renderPage(<P />);
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });
});

describe("AccessDenied", () => {
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
    expect(screen.getByText("404")).toBeInTheDocument();
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
