/**
 * Developer Security Portal — component tests (P10 Persona)
 *
 * DeveloperPortal uses only local mock data (no API hooks).
 * All renders are synchronous after framer-motion / recharts stubs.
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

async function loadDeveloperPortal() {
  return (await import("@/pages/developer/DeveloperPortal")).default;
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

describe("DeveloperPortal", () => {
  it("renders without crashing", async () => {
    const Page = await loadDeveloperPortal();
    const { container } = renderPage(<Page />);
    expect(container.firstChild).toBeTruthy();
  });

  it("shows the Developer Security Portal heading", async () => {
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Developer Security Portal")).toBeInTheDocument();
  });

  it("shows the P10 persona badge", async () => {
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("P10")).toBeInTheDocument();
  });

  it("shows the Findings Fixed KPI card", async () => {
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Findings Fixed")).toBeInTheDocument();
  });

  it("shows the Avg Fix Time KPI card", async () => {
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Avg Fix Time")).toBeInTheDocument();
  });

  it("shows the Repos Owned KPI card", async () => {
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Repos Owned")).toBeInTheDocument();
  });

  it("shows the Security Score KPI card", async () => {
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Security Score")).toBeInTheDocument();
  });

  it("renders a known repo from mock data in the table", async () => {
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getAllByText("aldeci/api-gateway").length).toBeGreaterThan(0);
  });

  it("renders another known repo from mock data", async () => {
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getAllByText("aldeci/infra-terraform").length).toBeGreaterThan(0);
  });

  it("renders the severity filter select", async () => {
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Severity")).toBeInTheDocument();
  });

  it("renders the Repository filter select", async () => {
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Repository")).toBeInTheDocument();
  });

  it("renders at least one finding title in the findings table", async () => {
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    // First finding: "Hardcoded AWS secret key in connector config"
    expect(screen.getByText(/Hardcoded AWS secret key/i)).toBeInTheDocument();
  });
});
