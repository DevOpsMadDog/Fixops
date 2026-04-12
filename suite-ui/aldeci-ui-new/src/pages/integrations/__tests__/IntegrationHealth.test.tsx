/**
 * Integration Health — component tests (OPS badge)
 *
 * IntegrationHealth uses only local mock data (no API hooks).
 * All renders are synchronous after framer-motion stubs.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen } from "@testing-library/react";
import { renderPage } from "@/__tests__/test-utils";

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

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }));

// ── Stub setInterval / clearInterval to avoid timer leaks ──
beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

async function loadIntegrationHealth() {
  return (await import("@/pages/integrations/IntegrationHealth")).default;
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

describe("IntegrationHealth", () => {
  it("renders without crashing", async () => {
    const Page = await loadIntegrationHealth();
    const { container } = renderPage(<Page />);
    expect(container.firstChild).toBeTruthy();
  });

  it("shows the Integration Health heading", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    expect(screen.getByText("Integration Health")).toBeInTheDocument();
  });

  it("shows the OPS badge", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    expect(screen.getByText("OPS")).toBeInTheDocument();
  });

  it("shows the Total KPI card", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    expect(screen.getByText("Total")).toBeInTheDocument();
  });

  it("shows the Healthy KPI card", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    expect(screen.getByText("Healthy")).toBeInTheDocument();
  });

  it("shows the Degraded KPI card", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    expect(screen.getByText("Degraded")).toBeInTheDocument();
  });

  it("shows the Down KPI card", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    expect(screen.getByText("Down")).toBeInTheDocument();
  });

  it("shows the Avg Uptime KPI card", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    expect(screen.getByText("Avg Uptime")).toBeInTheDocument();
  });

  it("shows the Avg Response KPI card", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    expect(screen.getByText("Avg Response")).toBeInTheDocument();
  });

  it("renders a known integration card — Trivy", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    expect(screen.getByText("Trivy")).toBeInTheDocument();
  });

  it("renders a known integration card — Semgrep", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    expect(screen.getByText("Semgrep")).toBeInTheDocument();
  });

  it("renders at least one HEALTHY status badge", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    const healthyBadges = screen.getAllByText("HEALTHY");
    expect(healthyBadges.length).toBeGreaterThan(0);
  });

  it("renders at least one DEGRADED status badge", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    const degradedBadges = screen.getAllByText("DEGRADED");
    expect(degradedBadges.length).toBeGreaterThan(0);
  });
});
