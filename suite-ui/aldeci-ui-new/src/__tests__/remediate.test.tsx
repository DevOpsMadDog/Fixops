/**
 * Remediate screens — smoke tests.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import { renderPage, mockQueryResult, mockMutationResult } from "./test-utils";

const mocks: Record<string, any> = {
  useRemediationTasks: vi.fn(),
  useUsers: vi.fn(),
  useTeams: vi.fn(),
  useAutofix: vi.fn(),
  useFindings: vi.fn(),
  useWorkflowRules: vi.fn(),
  useIntegrations: vi.fn(),
  useCases: vi.fn(),
  useTriageCase: vi.fn(),
  useSyncIntegration: vi.fn(),
  useTestIntegration: vi.fn(),
  useConfigureIntegration: vi.fn(),
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
  mocks.useRemediationTasks.mockReturnValue(mockQueryResult({ tasks: [], total: 0 }));
  mocks.useUsers.mockReturnValue(mockQueryResult({ items: [] }));
  mocks.useTeams.mockReturnValue(mockQueryResult({ teams: [] }));
  mocks.useAutofix.mockReturnValue(mockQueryResult({ fixes: [] }));
  mocks.useFindings.mockReturnValue(mockQueryResult({ findings: [], total: 0 }));
  mocks.useWorkflowRules.mockReturnValue(mockQueryResult({ rules: [] }));
  mocks.useIntegrations.mockReturnValue(mockQueryResult({ integrations: [] }));
  mocks.useCases.mockReturnValue(mockQueryResult({ cases: [] }));
  mocks.useTriageCase.mockReturnValue(mockMutationResult());
  mocks.useSyncIntegration.mockReturnValue(mockMutationResult());
  mocks.useTestIntegration.mockReturnValue(mockMutationResult());
  mocks.useConfigureIntegration.mockReturnValue(mockMutationResult());
});

async function loadPage(name: string) {
  switch (name) {
    case "Collaboration": return (await import("@/pages/remediate/Collaboration")).default;
    case "ExposureCases": return (await import("@/pages/remediate/ExposureCases")).default;
    case "TicketIntegration": return (await import("@/pages/remediate/TicketIntegration")).default;
    default: throw new Error(`Unknown: ${name}`);
  }
}

describe("Collaboration", () => {
  it("renders heading", async () => {
    const P = await loadPage("Collaboration");
    renderPage(<P />);
    expect(screen.getByRole("heading", { name: /War Room/i })).toBeInTheDocument();
  });
});

describe("ExposureCases", () => {
  it("renders heading", async () => {
    const P = await loadPage("ExposureCases");
    renderPage(<P />);
    expect(screen.getByText("Exposure Cases")).toBeInTheDocument();
  });
});

describe("TicketIntegration", () => {
  it("renders heading", async () => {
    const P = await loadPage("TicketIntegration");
    renderPage(<P />);
    expect(screen.getByText("Ticket Integration")).toBeInTheDocument();
  });
});
