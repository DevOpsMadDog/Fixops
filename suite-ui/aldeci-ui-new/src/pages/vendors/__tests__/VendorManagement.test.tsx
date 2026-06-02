/**
 * Vendor Management — component tests (TPRM badge)
 *
 * VendorManagement fetches from /api/v1/vendors via raw fetch() in a useEffect.
 * Tests stub global.fetch to control API responses.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, fireEvent, waitFor } from "@testing-library/react";
import { renderPage } from "@/__tests__/test-utils";

// PATTERN-A: localStorage stub — component calls localStorage.getItem in API_HEADERS()
Object.defineProperty(window, "localStorage", {
  value: { getItem: () => null, setItem: () => {}, removeItem: () => {}, clear: () => {} },
  writable: true,
});

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

  // PATTERN-B: honest-empty — component now fetches real API; no hardcoded vendors exist.
  it("does not render hardcoded vendor names (honest-empty when API is empty)", async () => {
    const Page = await loadVendorManagement();
    renderPage(<Page />);
    expect(screen.queryByText("HashiCorp")).not.toBeInTheDocument();
  });

  // PATTERN-B: real-data — seed a vendor through fetch stub, verify it renders.
  it("renders a vendor returned by the API", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        vendors: [
          {
            id: "VND-TEST-001",
            name: "Acme Security",
            description: "acmesecurity.io",
            tier: "high",
            current_score: 82,
            service_category: "Infrastructure",
            updated_at: new Date().toISOString(),
            contract_end: new Date(Date.now() + 90 * 86400000).toISOString(),
          },
        ],
      }),
    } as unknown as Response);

    const Page = await loadVendorManagement();
    renderPage(<Page />);
    await waitFor(() => expect(screen.getByText("Acme Security")).toBeInTheDocument());
    fetchSpy.mockRestore();
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

  // PATTERN-B: real-data filter — seed a vendor then confirm search filters correctly.
  it("filters vendors when search text matches a real vendor name", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        vendors: [
          {
            id: "VND-TEST-002",
            name: "CloudGuard Inc",
            description: "cloudguard.io",
            tier: "critical",
            current_score: 55,
            service_category: "Cloud Security",
            updated_at: new Date().toISOString(),
          },
          {
            id: "VND-TEST-003",
            name: "SecureBase",
            description: "securebase.com",
            tier: "medium",
            current_score: 75,
            service_category: "Compliance",
            updated_at: new Date().toISOString(),
          },
        ],
      }),
    } as unknown as Response);

    const Page = await loadVendorManagement();
    renderPage(<Page />);
    await waitFor(() => expect(screen.getByText("CloudGuard Inc")).toBeInTheDocument());

    const search = screen.getByPlaceholderText("Search vendors...");
    fireEvent.change(search, { target: { value: "CloudGuard" } });
    expect(screen.getByText("CloudGuard Inc")).toBeInTheDocument();
    expect(screen.queryByText("SecureBase")).not.toBeInTheDocument();

    fetchSpy.mockRestore();
  });
});
