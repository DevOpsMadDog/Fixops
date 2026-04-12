/**
 * Attack Surface Management — component tests (CTEM badge)
 *
 * AttackSurface uses only local mock data (no API hooks).
 * All renders are synchronous after framer-motion stubs.
 */
import { describe, it, expect, vi } from "vitest";
import { screen, fireEvent } from "@testing-library/react";
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

async function loadAttackSurface() {
  return (await import("@/pages/attack-surface/AttackSurface")).default;
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

describe("AttackSurface", () => {
  it("renders without crashing", async () => {
    const Page = await loadAttackSurface();
    const { container } = renderPage(<Page />);
    expect(container.firstChild).toBeTruthy();
  });

  it("shows the Attack Surface heading", async () => {
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("Attack Surface")).toBeInTheDocument();
  });

  it("shows the CTEM badge", async () => {
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("CTEM")).toBeInTheDocument();
  });

  it("shows the Total Assets KPI card", async () => {
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("Total Assets")).toBeInTheDocument();
  });

  it("shows the Internet-Exposed KPI card", async () => {
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("Internet-Exposed")).toBeInTheDocument();
  });

  it("shows the High-Risk Paths KPI card", async () => {
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("High-Risk Paths")).toBeInTheDocument();
  });

  it("renders a known asset from mock data in the table", async () => {
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getAllByText("api-gateway-prod.aldeci.io").length).toBeGreaterThan(0);
  });

  it("renders the asset search input", async () => {
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByPlaceholderText("Search assets, tags, owners…")).toBeInTheDocument();
  });

  it("renders the Type filter select", async () => {
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("Type")).toBeInTheDocument();
  });

  it("renders the Exposure filter select", async () => {
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("Exposure")).toBeInTheDocument();
  });

  it("renders the Risk filter select", async () => {
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("Risk")).toBeInTheDocument();
  });

  it("filters assets when search text matches a known asset", async () => {
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    const search = screen.getByPlaceholderText("Search assets, tags, owners…");
    fireEvent.change(search, { target: { value: "api-gateway-prod" } });
    expect(screen.getAllByText("api-gateway-prod.aldeci.io").length).toBeGreaterThan(0);
  });
});
