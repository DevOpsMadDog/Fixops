/**
 * Compliance Dashboard — component tests
 *
 * ComplianceDashboard uses useComplianceStatus, useComplianceFrameworks,
 * useComplianceGaps, and useAssessCompliance from @/hooks/use-api.
 *
 * NO MOCKS contract: the component renders framework cards ONLY from real API
 * data; when the frameworks API returns empty it shows no fabricated cards
 * (honest-empty). These tests assert exactly that — real data in -> cards out,
 * empty in -> no cards. (The old MOCK_FRAMEWORKS fallback was removed.)
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderPage, mockQueryResult, mockMutationResult } from "@/__tests__/test-utils";

// ── Mock use-api hooks ──
const mocks = {
  useComplianceStatus: vi.fn(),
  useComplianceFrameworks: vi.fn(),
  useComplianceGaps: vi.fn(),
  useAssessCompliance: vi.fn(),
  // Other hooks that may be transitively imported
  useDashboardOverview: vi.fn(),
  useComplianceSoc2: vi.fn(),
  useEvidenceBundles: vi.fn(),
  useApps: vi.fn(),
  useGenerateEvidence: vi.fn(),
  useAuditLog: vi.fn(),
  useReports: vi.fn(),
  useDashboardTrends: vi.fn(),
};

vi.mock("@/hooks/use-api", () => mocks);

// ── Stub @/lib/api (ComplianceDashboard imports analyticsApi indirectly) ──
vi.mock("@/lib/api", () => ({
  analyticsApi: { get: vi.fn().mockRejectedValue(new Error("No API in test")) },
  streamApi: {
    connect: vi.fn(), disconnect: vi.fn(),
    subscribe: vi.fn().mockReturnValue(() => {}),
    eventsUrl: vi.fn().mockReturnValue("http://localhost/events"),
  },
  getStoredAuthStrategy: vi.fn().mockReturnValue("token"),
  getStoredAuthToken: vi.fn().mockReturnValue("test"),
  getStoredOrgId: vi.fn().mockReturnValue(""),
}));

// ── Stub @/lib/api-utils ──
vi.mock("@/lib/api-utils", () => ({
  toArray: (d: unknown) => (Array.isArray(d) ? d : []),
  toObject: (d: unknown) => (d && typeof d === "object" ? d : {}),
  apiClient: vi.fn().mockResolvedValue({}),
}));

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }));

// ── Stub framer-motion ──
vi.mock("framer-motion", async () => {
  const React = await import("react");
  const motionProxy = new Proxy({}, {
    get: (_t, prop) => {
      if (prop === "__esModule") return true;
      return React.forwardRef((props: any, ref: any) => {
        const { children, initial, animate, exit, transition, whileHover, whileTap, variants, layout, layoutId, ...rest } = props;
        return React.createElement(typeof prop === "string" ? prop : "div", { ...rest, ref }, children);
      });
    },
  });
  return {
    motion: motionProxy,
    AnimatePresence: ({ children }: any) => <>{children}</>,
    useAnimation: () => ({ start: vi.fn(), stop: vi.fn() }),
    useInView: () => true,
  };
});

// ── Stub recharts ──
vi.mock("recharts", () => {
  const React = require("react");
  const S = ({ children, ...p }: any) => React.createElement("div", { "data-testid": "chart", ...p }, children);
  return {
    ResponsiveContainer: S, AreaChart: S, Area: S,
    BarChart: S, Bar: S, LineChart: S, Line: S,
    PieChart: S, Pie: S, Cell: S,
    RadarChart: S, Radar: S, PolarGrid: S, PolarAngleAxis: S, PolarRadiusAxis: S,
    XAxis: S, YAxis: S, CartesianGrid: S, Tooltip: S, Legend: S,
    RadialBarChart: S, RadialBar: S, Treemap: S,
  };
});

// ── Default mock return values ──
beforeEach(() => {
  mocks.useComplianceStatus.mockReturnValue(
    mockQueryResult({ overall_score: 87, frameworks: [] })
  );
  mocks.useComplianceFrameworks.mockReturnValue(
    mockQueryResult({ frameworks: [] })
  );
  mocks.useComplianceGaps.mockReturnValue(
    mockQueryResult({ gaps: [] })
  );
  mocks.useAssessCompliance.mockReturnValue(mockMutationResult());
  mocks.useDashboardOverview.mockReturnValue(mockQueryResult({ total_findings: 0 }));
  mocks.useComplianceSoc2.mockReturnValue(mockQueryResult({ controls: [], score: 0 }));
  mocks.useEvidenceBundles.mockReturnValue(mockQueryResult({ bundles: [] }));
  mocks.useApps.mockReturnValue(mockQueryResult({ apps: [] }));
  mocks.useGenerateEvidence.mockReturnValue(mockMutationResult());
  mocks.useAuditLog.mockReturnValue(mockQueryResult({ entries: [] }));
  mocks.useReports.mockReturnValue(mockQueryResult({ reports: [] }));
  mocks.useDashboardTrends.mockReturnValue(mockQueryResult({ trends: [], labels: [] }));
});

async function loadComplianceDashboard() {
  return (await import("@/pages/comply/ComplianceDashboard")).default;
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

describe("ComplianceDashboard", () => {
  it("renders without crashing", async () => {
    const Page = await loadComplianceDashboard();
    const { container } = renderPage(<Page />);
    expect(container.firstChild).toBeTruthy();
  });

  it("shows the Compliance & Governance heading", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(screen.getByText("Compliance & Governance")).toBeInTheDocument();
  });

  it("shows the P07 persona badge", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(screen.getByText("P07")).toBeInTheDocument();
  });

  it("shows Overall Score KPI card", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(screen.getByText("Overall Score")).toBeInTheDocument();
  });

  it("shows Fully Compliant KPI card", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(screen.getByText("Fully Compliant")).toBeInTheDocument();
  });

  it("shows Controls Passed KPI card", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(screen.getByText("Controls Passed")).toBeInTheDocument();
  });

  it("shows Evidence Overdue KPI card", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(screen.getByText("Evidence Overdue")).toBeInTheDocument();
  });

  it("shows the Export Report button", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(screen.getByRole("button", { name: /Export Report/i })).toBeInTheDocument();
  });

  it("renders the Framework Overview tab", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(screen.getByText("Framework Overview")).toBeInTheDocument();
  });

  it("renders the Evidence Collection tab", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(screen.getByText("Evidence Collection")).toBeInTheDocument();
  });

  it("renders the Control Mapping tab", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(screen.getByText("Control Mapping")).toBeInTheDocument();
  });

  it("renders the Trends tab", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(screen.getByText("Trends")).toBeInTheDocument();
  });

  // ── NO MOCKS: framework cards render from REAL API data only ──
  it("renders framework cards from real API data (no mock fallback)", async () => {
    // Supply real frameworks via the hook as an array (toArray returns it as-is).
    mocks.useComplianceFrameworks.mockReturnValue(
      mockQueryResult([
        {
          id: "soc2",
          name: "SOC 2 Type II",
          score: 91,
          controls_passed: 60,
          total_controls: 64,
          status: "compliant",
        },
        {
          id: "pci",
          name: "PCI-DSS v4.0",
          score: 78,
          controls_passed: 40,
          total_controls: 51,
          status: "partial",
        },
      ]),
    );
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(screen.getAllByText("SOC 2 Type II").length).toBeGreaterThan(0);
    expect(screen.getAllByText("PCI-DSS v4.0").length).toBeGreaterThan(0);
  });

  it("shows NO fabricated framework cards when the API returns empty (honest-empty)", async () => {
    // Default beforeEach already returns empty frameworks; assert none of the old
    // hardcoded fallback names leak into the DOM.
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    for (const name of ["SOC 2 Type II", "PCI-DSS v4.0", "HIPAA", "ISO 27001:2022"]) {
      expect(screen.queryByText(name)).not.toBeInTheDocument();
    }
  });

  it("switches to Evidence Collection tab when clicked", async () => {
    const user = userEvent.setup();
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);

    // Find the tab trigger by accessible role — Radix TabsTrigger renders as role="tab"
    const tabs = screen.getAllByRole("tab");
    // tabs[0]=overview, tabs[1]=evidence, tabs[2]=controls, tabs[3]=trends
    await user.click(tabs[1]);

    // Evidence tab renders EvidenceSection which has an Evidence Item column header
    await waitFor(() => {
      expect(screen.getByText("Evidence Item")).toBeInTheDocument();
    });
  });

  it("switches to Control Mapping tab when clicked", async () => {
    const user = userEvent.setup();
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);

    const tabs = screen.getAllByRole("tab");
    // tabs[2] = Control Mapping
    await user.click(tabs[2]);

    // ControlMappingTable renders a Control ID column header (unique to this tab)
    await waitFor(() => {
      expect(screen.getByText("Control ID")).toBeInTheDocument();
    });
  });

  it("calls useComplianceStatus hook", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(mocks.useComplianceStatus).toHaveBeenCalled();
  });

  it("calls useComplianceFrameworks hook", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(mocks.useComplianceFrameworks).toHaveBeenCalled();
  });

  it("calls useComplianceGaps hook", async () => {
    const Page = await loadComplianceDashboard();
    renderPage(<Page />);
    expect(mocks.useComplianceGaps).toHaveBeenCalled();
  });
});
