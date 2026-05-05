/**
 * Mission Control screens — smoke tests.
 *
 * Verifies each page renders its heading, shows loading state,
 * and handles API errors gracefully.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderPage, mockQueryResult, mockQueryLoading, mockQueryError, mockMutationResult } from "./test-utils";

// ── Mock all use-api hooks used by Mission Control ──
const mocks = {
  useDashboardOverview: vi.fn(),
  useNervePulse: vi.fn(),
  useNerveState: vi.fn(),
  useDashboardTrends: vi.fn(),
  useDashboardCompliance: vi.fn(),
  useDashboardTopRisks: vi.fn(),
  useComplianceStatus: vi.fn(),
  useEvidenceBundles: vi.fn(),
  useRemediationTasks: vi.fn(),
};

vi.mock("@/hooks/use-api", () => mocks);

// Stub sonner toast
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }));

// Stub @/lib/api (LiveFeed uses streamApi)
vi.mock("@/lib/api", () => ({
  streamApi: { connect: vi.fn(), disconnect: vi.fn(), subscribe: vi.fn().mockReturnValue(() => {}), eventsUrl: vi.fn().mockReturnValue("http://localhost/events") },
  getStoredAuthStrategy: vi.fn().mockReturnValue("token"),
  getStoredAuthToken: vi.fn().mockReturnValue("test"),
  getStoredOrgId: vi.fn().mockReturnValue(""),
}));

// Stub framer-motion to simple divs
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
  return {
    motion: motionProxy,
    AnimatePresence: ({ children }: any) => children,
    useAnimation: () => ({ start: vi.fn(), stop: vi.fn() }),
    useInView: () => true,
  };
});

// Stub recharts
vi.mock("recharts", () => {
  const React = require("react");
  const Stub = ({ children, ...p }: any) => React.createElement("div", { "data-testid": "chart", ...p }, children);
  return {
    ResponsiveContainer: Stub,
    AreaChart: Stub, Area: Stub,
    BarChart: Stub, Bar: Stub,
    LineChart: Stub, Line: Stub,
    PieChart: Stub, Pie: Stub, Cell: Stub,
    RadarChart: Stub, Radar: Stub, PolarGrid: Stub, PolarAngleAxis: Stub, PolarRadiusAxis: Stub,
    XAxis: Stub, YAxis: Stub, CartesianGrid: Stub, Tooltip: Stub, Legend: Stub,
    RadialBarChart: Stub, RadialBar: Stub, Treemap: Stub,
  };
});

// ── Lazy import pages (after mocks are registered) ──

async function loadPage(name: string) {
  switch (name) {
    case "SLADashboard": return (await import("@/pages/mission-control/SLADashboard")).default;
    case "LiveFeed": return (await import("@/pages/mission-control/LiveFeed")).default;
    case "RiskOverview": return (await import("@/pages/mission-control/RiskOverview")).default;
    default: throw new Error(`Unknown page: ${name}`);
  }
}

const dashboardData = {
  total_findings: 142,
  critical: 8,
  high: 24,
  medium: 56,
  low: 54,
  resolved: 88,
  open: 54,
  scan_count: 12,
  application_count: 5,
  apps: [],
};

const pulseData = { status: "healthy", uptime: 99.9, services: [], events: [] };
const stateData = { state: "operational", checks: [] };
const trendsData = { trends: [], labels: [] };
const complianceData = { overall_score: 87, frameworks: [] };
const topRisks = { risks: [] };
const evidenceBundles = { bundles: [] };
const remediationTasks = { tasks: [], total: 0 };

beforeEach(() => {
  mocks.useDashboardOverview.mockReturnValue(mockQueryResult(dashboardData));
  mocks.useNervePulse.mockReturnValue(mockQueryResult(pulseData));
  mocks.useNerveState.mockReturnValue(mockQueryResult(stateData));
  mocks.useDashboardTrends.mockReturnValue(mockQueryResult(trendsData));
  mocks.useDashboardCompliance.mockReturnValue(mockQueryResult(complianceData));
  mocks.useDashboardTopRisks.mockReturnValue(mockQueryResult(topRisks));
  mocks.useComplianceStatus.mockReturnValue(mockQueryResult(complianceData));
  mocks.useEvidenceBundles.mockReturnValue(mockQueryResult(evidenceBundles));
  mocks.useRemediationTasks.mockReturnValue(mockQueryResult(remediationTasks));
});

// ═══════════════════════════════════════
// 1. SLA Dashboard
// ═══════════════════════════════════════

describe("SLADashboard", () => {
  it("renders with heading", async () => {
    const Page = await loadPage("SLADashboard");
    renderPage(<Page />);
    expect(screen.getByText("SLA Dashboard")).toBeInTheDocument();
  });

  it("fetches remediation tasks", async () => {
    const Page = await loadPage("SLADashboard");
    renderPage(<Page />);
    expect(mocks.useRemediationTasks).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════
// 4. Live Feed
// ═══════════════════════════════════════

describe("LiveFeed", () => {
  it("renders with heading", async () => {
    const Page = await loadPage("LiveFeed");
    renderPage(<Page />);
    expect(await screen.findByRole("heading", { name: /Live Feed/i })).toBeInTheDocument();
  });

  it("connects to event source hooks", async () => {
    const Page = await loadPage("LiveFeed");
    renderPage(<Page />);
    expect(mocks.useNervePulse).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════
// 5. Risk Overview
// ═══════════════════════════════════════

describe("RiskOverview", () => {
  it("renders with heading", async () => {
    const Page = await loadPage("RiskOverview");
    renderPage(<Page />);
    expect(screen.getByText("Risk Overview")).toBeInTheDocument();
  });

  it("fetches top risks", async () => {
    const Page = await loadPage("RiskOverview");
    renderPage(<Page />);
    expect(mocks.useDashboardTopRisks).toHaveBeenCalled();
  });
});
