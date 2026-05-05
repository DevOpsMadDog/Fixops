/**
 * Validate screens — smoke tests.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import { renderPage, mockQueryResult, mockMutationResult } from "./test-utils";

const mocks: Record<string, any> = {
  useMpteStatus: vi.fn(),
  useMpteStats: vi.fn(),
  useMpteResults: vi.fn(),
  useMpteRequests: vi.fn(),
  useRunMpteScan: vi.fn(),
  useFailDrills: vi.fn(),
  useFailReadiness: vi.fn(),
  useFailHistory: vi.fn(),
  useFailScenarios: vi.fn(),
  useInjectFail: vi.fn(),
  usePlaybooks: vi.fn(),
  useFindings: vi.fn(),
  useKnowledgeGraph: vi.fn(),
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
  mocks.useMpteStatus.mockReturnValue(mockQueryResult({ status: "ready", version: "1.0" }));
  mocks.useMpteStats.mockReturnValue(mockQueryResult({ total_scans: 0, total_vulns: 0 }));
  mocks.useMpteResults.mockReturnValue(mockQueryResult({ results: [] }));
  mocks.useMpteRequests.mockReturnValue(mockQueryResult({ requests: [] }));
  mocks.useRunMpteScan.mockReturnValue(mockMutationResult());
  mocks.useFailDrills.mockReturnValue(mockQueryResult({ drills: [] }));
  mocks.useFailReadiness.mockReturnValue(mockQueryResult({ score: 85, checks: [] }));
  mocks.useFailHistory.mockReturnValue(mockQueryResult({ history: [] }));
  mocks.useFailScenarios.mockReturnValue(mockQueryResult({ scenarios: [] }));
  mocks.useInjectFail.mockReturnValue(mockMutationResult());
  mocks.usePlaybooks.mockReturnValue(mockQueryResult({ playbooks: [] }));
  mocks.useFindings.mockReturnValue(mockQueryResult({ findings: [], total: 0 }));
  mocks.useKnowledgeGraph.mockReturnValue(mockQueryResult({ nodes: [], edges: [] }));
});

async function loadPage(name: string) {
  switch (name) {
    case "AttackSimulation": return (await import("@/pages/validate/AttackSimulation")).default;
    case "Reachability": return (await import("@/pages/validate/Reachability")).default;
    default: throw new Error(`Unknown: ${name}`);
  }
}

describe("AttackSimulation", () => {
  it("renders heading", async () => {
    const P = await loadPage("AttackSimulation");
    renderPage(<P />);
    expect(screen.getByText("Attack Simulation")).toBeInTheDocument();
  });
});

describe("Reachability", () => {
  it("renders heading", async () => {
    const P = await loadPage("Reachability");
    renderPage(<P />);
    expect(screen.getByText(/Reachability/i)).toBeInTheDocument();
  });
});
