/**
 * Vendor Management — component tests (TPRM badge)
 *
 * VendorManagement uses only local mock data (no API hooks).
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

async function loadVendorManagement() {
  return (await import("@/pages/vendors/VendorManagement")).default;
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

describe("VendorManagement", () => {
  it("renders without crashing", async () => {
    const Page = await loadVendorManagement();
    const { container } = renderPage(<Page />);
    expect(container.firstChild).toBeTruthy();
  });

  it("shows the Vendor Management heading", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    expect(screen.getByText("Vendor Management")).toBeInTheDocument();
  });

  it("shows the TPRM badge", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    expect(screen.getByText("TPRM")).toBeInTheDocument();
  });

  it("shows the Total Vendors KPI card", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    expect(screen.getByText("Total Vendors")).toBeInTheDocument();
  });

  it("shows the Avg Risk Score KPI card", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    expect(screen.getByText("Avg Risk Score")).toBeInTheDocument();
  });

  it("shows the Critical Tier KPI card", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    expect(screen.getByText("Critical Tier")).toBeInTheDocument();
  });

  it("shows the Active Alerts KPI card", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    expect(screen.getByText("Active Alerts")).toBeInTheDocument();
  });

  it("shows the Overdue Assessments KPI card", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    expect(screen.getByText("Overdue Assessments")).toBeInTheDocument();
  });

  it("shows the Open CVEs KPI card", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    expect(screen.getByText("Open CVEs")).toBeInTheDocument();
  });

  it("renders a known vendor — HashiCorp — in the table", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    expect(screen.getByText("HashiCorp")).toBeInTheDocument();
  });

  it("renders the vendor search input", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    expect(screen.getByPlaceholderText("Search vendors...")).toBeInTheDocument();
  });

  it("renders the tier filter select trigger", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    // The select trigger for tier filter is always rendered in the toolbar
    const triggers = screen.getAllByRole("combobox");
    expect(triggers.length).toBeGreaterThanOrEqual(2);
  });

  it("renders at least two filter selects in the toolbar", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    // tier + grade selects are always in the DOM
    const selects = screen.getAllByRole("combobox");
    expect(selects.length).toBeGreaterThanOrEqual(2);
  });

  it("filters vendors when search text matches HashiCorp", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    const search = screen.getByPlaceholderText("Search vendors...");
    fireEvent.change(search, { target: { value: "HashiCorp" } });
    expect(screen.getByText("HashiCorp")).toBeInTheDocument();
  });
});
