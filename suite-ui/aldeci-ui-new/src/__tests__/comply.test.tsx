/**
 * Comply screens — smoke tests.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import { renderPage, mockQueryResult, mockMutationResult } from "./test-utils";

const mocks: Record<string, any> = {
  useComplianceStatus: vi.fn(),
  useComplianceFrameworks: vi.fn(),
  useComplianceGaps: vi.fn(),
  useAssessCompliance: vi.fn(),
  useComplianceSoc2: vi.fn(),
  useEvidenceBundles: vi.fn(),
  useEvidenceSummary: vi.fn(),
  useComplianceEvidenceRequests: vi.fn(),
  useComplianceOverallStatus: vi.fn(),
  useApps: vi.fn(),
  useGenerateEvidence: vi.fn(),
  useAuditLog: vi.fn(),
  useReports: vi.fn(),
  useDashboardTrends: vi.fn(),
  useDashboardOverview: vi.fn(),
};

vi.mock("@/hooks/use-api", () => mocks);
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }));
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
  mocks.useComplianceStatus.mockReturnValue(mockQueryResult({ overall_score: 87, frameworks: [] }));
  mocks.useComplianceFrameworks.mockReturnValue(mockQueryResult({ frameworks: [] }));
  mocks.useComplianceGaps.mockReturnValue(mockQueryResult({ gaps: [] }));
  mocks.useAssessCompliance.mockReturnValue(mockMutationResult());
  mocks.useComplianceSoc2.mockReturnValue(mockQueryResult({ controls: [], score: 0 }));
  mocks.useEvidenceBundles.mockReturnValue(mockQueryResult({ bundles: [] }));
  mocks.useApps.mockReturnValue(mockQueryResult({ apps: [] }));
  mocks.useGenerateEvidence.mockReturnValue(mockMutationResult());
  mocks.useEvidenceSummary.mockReturnValue(mockQueryResult({ total: 0, collected: 0 }));
  mocks.useComplianceEvidenceRequests.mockReturnValue(mockQueryResult({ requests: [] }));
  mocks.useComplianceOverallStatus.mockReturnValue(mockQueryResult({ score: 0, status: "unknown" }));
  mocks.useAuditLog.mockReturnValue(mockQueryResult({ entries: [] }));
  mocks.useReports.mockReturnValue(mockQueryResult({ reports: [] }));
  mocks.useDashboardTrends.mockReturnValue(mockQueryResult({ trends: [], labels: [] }));
  mocks.useDashboardOverview.mockReturnValue(mockQueryResult({ total_findings: 0 }));
});

async function loadPage(name: string) {
  switch (name) {
    case "ComplianceDashboard": return (await import("@/pages/comply/ComplianceDashboard")).default;
    case "EvidenceExportCenter": return (await import("@/pages/comply/EvidenceExportCenter")).default;
    case "SOC2Evidence": return (await import("@/pages/comply/SOC2Evidence")).default;
    case "SLSAProvenance": return (await import("@/pages/comply/SLSAProvenance")).default;
    case "Reports": return (await import("@/pages/comply/Reports")).default;
    case "Analytics": return (await import("@/pages/comply/Analytics")).default;
    default: throw new Error(`Unknown: ${name}`);
  }
}

describe("ComplianceDashboard", () => {
  it("renders heading", async () => {
    const P = await loadPage("ComplianceDashboard");
    renderPage(<P />);
    expect(screen.getByText("Compliance & Governance")).toBeInTheDocument();
  });
  it("fetches compliance status", async () => {
    const P = await loadPage("ComplianceDashboard");
    renderPage(<P />);
    expect(mocks.useComplianceStatus).toHaveBeenCalled();
  });
});

describe("EvidenceExportCenter", () => {
  it("renders heading", async () => {
    const P = await loadPage("EvidenceExportCenter");
    renderPage(<P />);
    expect(screen.getByText("Evidence Export Center")).toBeInTheDocument();
  });
});

describe("SOC2Evidence", () => {
  it("renders heading", async () => {
    const P = await loadPage("SOC2Evidence");
    renderPage(<P />);
    expect(screen.getByRole("heading", { name: /SOC.?2/i })).toBeInTheDocument();
  });
});

describe("SLSAProvenance", () => {
  it("renders heading", async () => {
    const P = await loadPage("SLSAProvenance");
    renderPage(<P />);
    expect(screen.getByRole("heading", { name: /SLSA/i })).toBeInTheDocument();
  });
});

describe("Reports", () => {
  it("renders heading", async () => {
    const P = await loadPage("Reports");
    renderPage(<P />);
    expect(screen.getByText("Reports")).toBeInTheDocument();
  });
});

describe("Analytics", () => {
  it("renders heading", async () => {
    const P = await loadPage("Analytics");
    renderPage(<P />);
    expect(screen.getByText("Analytics")).toBeInTheDocument();
  });
});
