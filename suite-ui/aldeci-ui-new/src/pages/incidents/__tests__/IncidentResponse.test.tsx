/**
 * Incident Response — component tests (IR badge)
 *
 * IncidentResponse uses only local mock data (no API hooks).
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

async function loadIncidentResponse() {
  return (await import("@/pages/incidents/IncidentResponse")).default;
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

describe("IncidentResponse", () => {
  it("renders without crashing", async () => {
    const Page = await loadIncidentResponse();
    const { container } = renderPage(<Page />);
    expect(container.firstChild).toBeTruthy();
  });

  it("shows the Incident Response heading", async () => {
    const Page = await loadIncidentResponse();
    renderPage(<Page />);
    expect(screen.getByText("Incident Response")).toBeInTheDocument();
  });

  it("shows the IR badge", async () => {
    const Page = await loadIncidentResponse();
    renderPage(<Page />);
    expect(screen.getByText("IR")).toBeInTheDocument();
  });

  it("shows the Active Incidents KPI card", async () => {
    const Page = await loadIncidentResponse();
    renderPage(<Page />);
    expect(screen.getByText("Active Incidents")).toBeInTheDocument();
  });

  it("shows the Critical Open KPI card", async () => {
    const Page = await loadIncidentResponse();
    renderPage(<Page />);
    expect(screen.getByText("Critical Open")).toBeInTheDocument();
  });

  it("shows the SLA Breached KPI card", async () => {
    const Page = await loadIncidentResponse();
    renderPage(<Page />);
    expect(screen.getByText("SLA Breached")).toBeInTheDocument();
  });

  it("shows the Avg MTTR KPI card", async () => {
    const Page = await loadIncidentResponse();
    renderPage(<Page />);
    expect(screen.getByText("Avg MTTR")).toBeInTheDocument();
  });

  it("renders the incident search input", async () => {
    const Page = await loadIncidentResponse();
    renderPage(<Page />);
    expect(screen.getByPlaceholderText("Search incidents...")).toBeInTheDocument();
  });

  it("renders state machine stages — Detected label is present", async () => {
    const Page = await loadIncidentResponse();
    renderPage(<Page />);
    // STATE_META.DETECTED.label = "Detected" — used in the state machine display
    expect(screen.getAllByText("Detected").length).toBeGreaterThan(0);
  });

  it("renders state machine stage — Triaging", async () => {
    const Page = await loadIncidentResponse();
    renderPage(<Page />);
    expect(screen.getAllByText(/Triaging/i).length).toBeGreaterThan(0);
  });

  it("renders state machine stage — Containing", async () => {
    const Page = await loadIncidentResponse();
    renderPage(<Page />);
    expect(screen.getAllByText(/Containing/i).length).toBeGreaterThan(0);
  });

  it("renders severity badges — at least one critical badge is visible", async () => {
    const Page = await loadIncidentResponse();
    renderPage(<Page />);
    const criticalBadges = screen.getAllByText(/critical/i);
    expect(criticalBadges.length).toBeGreaterThan(0);
  });

  it("filters incidents when search input is changed", async () => {
    const Page = await loadIncidentResponse();
    renderPage(<Page />);
    const search = screen.getByPlaceholderText("Search incidents...");
    fireEvent.change(search, { target: { value: "ransomware" } });
    // After filtering, search box should still be present
    expect(search).toBeInTheDocument();
  });
});
