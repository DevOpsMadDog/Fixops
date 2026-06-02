/**
 * Attack Surface Management — component tests (CTEM badge)
 *
 * AttackSurface fetches assets from /api/v1/asm/assets via fetch().
 * getStoredAuthToken() / getStoredOrgId() read window.localStorage —
 * stub it here so the useEffect doesn't throw before reaching fetch().
 * Tests mock global.fetch so the component can render real-shaped data.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { screen, fireEvent, waitFor, act } from "@testing-library/react";
import { renderPage } from "@/__tests__/test-utils";

// ── Stub localStorage BEFORE any module import touches it ──
// getStoredAuthToken() calls window.localStorage.getItem() which throws
// in jsdom if localStorage is not a real Storage. Stub it so the
// useEffect's try/catch doesn't swallow the fetch call.
Object.defineProperty(window, "localStorage", {
  value: {
    getItem: vi.fn().mockReturnValue(null),
    setItem: vi.fn(),
    removeItem: vi.fn(),
    clear: vi.fn(),
    length: 0,
    key: vi.fn().mockReturnValue(null),
  },
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

// ── Seeded asset — real API shape that mapApiAsset() understands ──
const SEEDED_ASSET = {
  id: "AST-001",
  value: "prod-api-gateway.example.io",
  asset_type: "api",
  status: "internet",
  risk_score: 72,
  cve_count: 3,
  last_seen: new Date().toISOString(),
  owner: "platform-team",
  tags: ["api", "internet-facing"],
};

function makeFetchOk(body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: () => Promise.resolve(body),
  } as any);
}

function makeFetchFail() {
  return vi.fn().mockResolvedValue({
    ok: false,
    status: 401,
    json: () => Promise.resolve({}),
  } as any);
}

async function loadAttackSurface() {
  return (await import("@/pages/attack-surface/AttackSurface")).default;
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

describe("AttackSurface", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders without crashing", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadAttackSurface();
    const { container } = renderPage(<Page />);
    expect(container.firstChild).toBeTruthy();
  });

  it("shows the Attack Surface heading", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("Attack Surface")).toBeInTheDocument();
  });

  it("shows the CTEM badge", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("CTEM")).toBeInTheDocument();
  });

  it("shows the Total Assets KPI card", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("Total Assets")).toBeInTheDocument();
  });

  it("shows the Internet-Exposed KPI card", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("Internet-Exposed")).toBeInTheDocument();
  });

  it("shows the High-Risk Paths KPI card", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("High-Risk Paths")).toBeInTheDocument();
  });

  // ── Real-data test: seeded asset renders in table ──
  it("renders a seeded asset from API data in the table", async () => {
    vi.stubGlobal("fetch", makeFetchOk([SEEDED_ASSET]));
    const Page = await loadAttackSurface();
    await act(async () => { renderPage(<Page />); });
    await waitFor(() => {
      expect(screen.getAllByText("prod-api-gateway.example.io").length).toBeGreaterThan(0);
    }, { timeout: 3000 });
  });

  // ── Honest-empty test: old hardcoded name is gone when API fails ──
  it("does not render stale hardcoded asset names when API is empty", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadAttackSurface();
    await act(async () => { renderPage(<Page />); });
    await waitFor(() => {
      expect(screen.queryByText("api-gateway-prod.aldeci.io")).not.toBeInTheDocument();
    });
  });

  it("renders the asset search input", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByPlaceholderText("Search assets, tags, owners…")).toBeInTheDocument();
  });

  it("renders the Type filter select", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("Type")).toBeInTheDocument();
  });

  it("renders the Exposure filter select", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("Exposure")).toBeInTheDocument();
  });

  it("renders the Risk filter select", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadAttackSurface();
    renderPage(<Page />);
    expect(screen.getByText("Risk")).toBeInTheDocument();
  });

  // ── Search filter test: seed an asset, search for it, verify it appears ──
  it("filters assets when search text matches a seeded asset", async () => {
    vi.stubGlobal("fetch", makeFetchOk([SEEDED_ASSET]));
    const Page = await loadAttackSurface();
    await act(async () => { renderPage(<Page />); });
    // Wait for seeded asset to appear after fetch resolves
    await waitFor(() => {
      expect(screen.getAllByText("prod-api-gateway.example.io").length).toBeGreaterThan(0);
    }, { timeout: 3000 });
    const search = screen.getByPlaceholderText("Search assets, tags, owners…");
    fireEvent.change(search, { target: { value: "prod-api-gateway" } });
    expect(screen.getAllByText("prod-api-gateway.example.io").length).toBeGreaterThan(0);
  });
});
