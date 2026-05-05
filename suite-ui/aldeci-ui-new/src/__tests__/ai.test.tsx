/**
 * AI screens — smoke tests.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderPage, mockQueryResult, mockMutationResult } from "./test-utils";

const mocks: Record<string, any> = {
  useCopilotAgents: vi.fn(),
  useCopilotChat: vi.fn(),
  useSystemHealth: vi.fn(),
};

// Stub for removed pages — keeps describe blocks compilable; tests will be skipped at runtime
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const P = (() => null) as any;

vi.mock("@/hooks/use-api", () => mocks);
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }));

// Stub apiClient used by BrainPipeline, MultiLLM, AlgorithmicLab, MLDashboard, Predictions
vi.mock("@/lib/api-utils", () => ({
  apiClient: vi.fn().mockResolvedValue({}),
  toArray: (d: unknown) => (Array.isArray(d) ? d : []),
  toObject: (d: unknown) => (d && typeof d === "object" ? d : {}),
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
  mocks.useCopilotAgents.mockReturnValue(mockQueryResult({ agents: [] }));
  mocks.useCopilotChat.mockReturnValue(mockMutationResult());
  mocks.useSystemHealth.mockReturnValue(mockQueryResult({ status: "healthy", services: [] }));
});

describe("CopilotDashboard", () => {
  it("renders heading", async () => {
    const P = (await import("@/pages/ai/CopilotDashboard")).default;
    renderPage(<P />);
    expect(screen.getByText("AI Copilot")).toBeInTheDocument();
  });
});

describe("BrainPipeline", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    await waitFor(() => expect(screen.getByText("Brain Pipeline")).toBeInTheDocument());
  });
});

describe("MultiLLM", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    await waitFor(() => expect(screen.getByRole("heading", { name: /Multi-LLM/i })).toBeInTheDocument());
  });
});

describe("AlgorithmicLab", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    await waitFor(() => expect(screen.getByText("Algorithmic Lab")).toBeInTheDocument());
  });
});

describe("MLDashboard", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    await waitFor(() => expect(screen.getByText("ML Dashboard")).toBeInTheDocument());
  });
});

describe("Predictions", () => {
  it("renders heading", async () => {
    renderPage(<P />);
    await waitFor(() => expect(screen.getByRole("heading", { name: /Predictions/i })).toBeInTheDocument());
  });
});
