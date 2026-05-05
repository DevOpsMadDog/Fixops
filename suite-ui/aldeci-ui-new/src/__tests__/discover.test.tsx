/**
 * Discover screens — smoke tests.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import { renderPage, mockQueryResult, mockQueryLoading, mockMutationResult } from "./test-utils";

const mocks: Record<string, any> = {
  useFindings: vi.fn(),
  useScannerParsers: vi.fn(),
  useApps: vi.fn(),
  useKnowledgeGraph: vi.fn(),
  useThreatFeeds: vi.fn(),
  useThreatTrending: vi.fn(),
  useDashboardTrends: vi.fn(),
  useDashboardOverview: vi.fn(),
  useDashboardCompliance: vi.fn(),
  useIntegrations: vi.fn(),
  useRunScan: vi.fn(),
  useAutofix: vi.fn(),
  useIngestStats: vi.fn(),
  useIntegrationsStatus: vi.fn(),
};

vi.mock("@/hooks/use-api", () => mocks);
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }));
vi.mock("@/lib/api", () => ({
  secretsApi: { list: vi.fn().mockResolvedValue({ data: [] }) },
  sbomApi: {
    components: vi.fn().mockResolvedValue({ data: [] }),
    licenses: vi.fn().mockResolvedValue({ data: [] }),
  },
  reachabilityApi: { analysis: vi.fn().mockResolvedValue({ data: { components: [] } }) },
  knowledgeGraphApi: { attackPaths: vi.fn().mockResolvedValue({ data: [] }) },
  streamApi: { connect: vi.fn(), eventsUrl: vi.fn().mockReturnValue("http://localhost/events") },
  getStoredAuthStrategy: vi.fn().mockReturnValue("token"),
  getStoredAuthToken: vi.fn().mockReturnValue("test"),
  getStoredOrgId: vi.fn().mockReturnValue(""),
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

const findingsData = { findings: [], total: 0 };
const parsersData = { parsers: [] };
const appsData = { apps: [] };
const graphData = { nodes: [], edges: [] };
const feedsData = { feeds: [] };
const trendingData = { trending: [] };
const trendsData = { trends: [], labels: [] };
const overviewData = { total_findings: 0, critical: 0 };
const complianceData = { overall_score: 0, frameworks: [] };
const integrationsData = { integrations: [] };

beforeEach(() => {
  mocks.useFindings.mockReturnValue(mockQueryResult(findingsData));
  mocks.useScannerParsers.mockReturnValue(mockQueryResult(parsersData));
  mocks.useApps.mockReturnValue(mockQueryResult(appsData));
  mocks.useKnowledgeGraph.mockReturnValue(mockQueryResult(graphData));
  mocks.useThreatFeeds.mockReturnValue(mockQueryResult(feedsData));
  mocks.useThreatTrending.mockReturnValue(mockQueryResult(trendingData));
  mocks.useDashboardTrends.mockReturnValue(mockQueryResult(trendsData));
  mocks.useDashboardOverview.mockReturnValue(mockQueryResult(overviewData));
  mocks.useDashboardCompliance.mockReturnValue(mockQueryResult(complianceData));
  mocks.useIntegrations.mockReturnValue(mockQueryResult(integrationsData));
  mocks.useRunScan.mockReturnValue(mockMutationResult());
  mocks.useAutofix.mockReturnValue(mockQueryResult({ fixes: [] }));
  mocks.useIngestStats.mockReturnValue(mockQueryResult({ total: 0, sources: [] }));
  mocks.useIntegrationsStatus.mockReturnValue(mockQueryResult({ integrations: [] }));
});

async function loadPage(name: string) {
  switch (name) {
    case "FindingExplorer": return (await import("@/pages/discover/FindingExplorer")).default;
    case "CodeScanning": return (await import("@/pages/discover/CodeScanning")).default;
    case "IaCScanning": return (await import("@/pages/discover/IaCScanning")).default;
    case "CloudPosture": return (await import("@/pages/discover/CloudPosture")).default;
    case "ContainerSecurity": return (await import("@/pages/discover/ContainerSecurity")).default;
    case "SBOMInventory": return (await import("@/pages/discover/SBOMInventory")).default;
    case "AttackPaths": return (await import("@/pages/discover/AttackPaths")).default;
    case "ThreatFeeds": return (await import("@/pages/discover/ThreatFeeds")).default;
    case "CorrelationEngine": return (await import("@/pages/discover/CorrelationEngine")).default;
    case "DataFabric": return (await import("@/pages/discover/DataFabric")).default;
    default: throw new Error(`Unknown: ${name}`);
  }
}

describe("FindingExplorer", () => {
  it("renders heading", async () => {
    const P = await loadPage("FindingExplorer");
    renderPage(<P />);
    expect(screen.getByText("Finding Explorer")).toBeInTheDocument();
  });
  it("calls useFindings", async () => {
    const P = await loadPage("FindingExplorer");
    renderPage(<P />);
    expect(mocks.useFindings).toHaveBeenCalled();
  });
});

describe("CodeScanning", () => {
  it("renders heading", async () => {
    const P = await loadPage("CodeScanning");
    renderPage(<P />);
    expect(screen.getByText("Code Scanning")).toBeInTheDocument();
  });
});

describe("IaCScanning", () => {
  it("renders heading", async () => {
    const P = await loadPage("IaCScanning");
    renderPage(<P />);
    expect(screen.getByText("IaC Scanning")).toBeInTheDocument();
  });
});

describe("CloudPosture", () => {
  it("renders heading", async () => {
    const P = await loadPage("CloudPosture");
    renderPage(<P />);
    expect(screen.getByText("Cloud Posture")).toBeInTheDocument();
  });
});

describe("ContainerSecurity", () => {
  it("renders heading", async () => {
    const P = await loadPage("ContainerSecurity");
    renderPage(<P />);
    expect(screen.getByText("Container Security")).toBeInTheDocument();
  });
});

describe("SBOMInventory", () => {
  it("renders heading", async () => {
    const P = await loadPage("SBOMInventory");
    renderPage(<P />);
    expect(await screen.findByText("XBOM — Extended Bill of Materials")).toBeInTheDocument();
  });
});

describe("AttackPaths", () => {
  it("renders heading", async () => {
    const P = await loadPage("AttackPaths");
    renderPage(<P />);
    expect(await screen.findByRole("heading", { name: /Attack Paths/i })).toBeInTheDocument();
  });
});

describe("ThreatFeeds", () => {
  it("renders heading", async () => {
    const P = await loadPage("ThreatFeeds");
    renderPage(<P />);
    expect(screen.getByText("Threat Feeds")).toBeInTheDocument();
  });
});

describe("CorrelationEngine", () => {
  it("renders heading", async () => {
    const P = await loadPage("CorrelationEngine");
    renderPage(<P />);
    expect(screen.getByText("Correlation Engine")).toBeInTheDocument();
  });
});

describe("DataFabric", () => {
  it("renders heading", async () => {
    const P = await loadPage("DataFabric");
    renderPage(<P />);
    expect(screen.getByText("Data Fabric")).toBeInTheDocument();
  });
});
