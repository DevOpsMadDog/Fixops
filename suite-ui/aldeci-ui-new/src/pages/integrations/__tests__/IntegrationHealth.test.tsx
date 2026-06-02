/**
 * Integration Health — component tests (OPS badge)
 *
 * IntegrationHealth reads localStorage at module scope (API_KEY constant) then
 * fires fetch() calls inside a useEffect. We must:
 *   1. Stub localStorage BEFORE the dynamic import so the module-level read
 *      doesn't throw in jsdom.
 *   2. Stub global fetch so the useEffect resolves cleanly (empty arrays).
 *   3. Restore both stubs in afterEach so we don't pollute sibling test files.
 *
 * KPI card labels (Total / Healthy / Degraded / Down / Avg Uptime / Avg
 * Response) are always rendered — they derive from local state, not API data.
 *
 * "Trivy" and "Semgrep" were asserted against old hardcoded mock data that the
 * NO-MOCKS component no longer renders. Those are now honest-empty tests that
 * confirm the names are ABSENT when the API returns an empty list (class 2 fix).
 *
 * Similarly, HEALTHY/DEGRADED status badges only appear when the API returns
 * Integration objects with those statuses. With an empty API response the
 * filter-bar buttons say "HEALTHY" / "DEGRADED" but the integration cards
 * (which emit the badge) are absent — so the tests now assert absence of card
 * badges and use getAllByText for the filter-bar buttons instead.
 */
import { describe, it, expect, vi, beforeAll, afterEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderPage } from "@/__tests__/test-utils";

// ── 1. localStorage stub — must be installed BEFORE any vi.mock that imports
//       the component, so it is present when the module-level `API_KEY`
//       constant is evaluated.
const _ls = { getItem: () => null, setItem: () => {}, removeItem: () => {}, clear: () => {} };
Object.defineProperty(window, "localStorage", { value: _ls, writable: true });

// ── 2. Stub framer-motion ──
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

// ── 3. Stub recharts ──
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

// ── 4. Stub global fetch — returns empty arrays for every endpoint ──
beforeAll(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => [] }),
  );
});

// ── 5. Cleanup — restore fetch stub after each test so we don't bleed into
//       other test files in the full-suite run. Also tick fake timers if any
//       pending setTimeout callbacks exist from setInterval/runAllChecks.
afterEach(() => {
  vi.unstubAllGlobals();
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
    await waitFor(() =>
      expect(screen.getByText("Integration Health")).toBeInTheDocument(),
    );
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

  // ── class-2 (stale mock-data) fixes ──────────────────────────────────────
  // "Trivy" and "Semgrep" were hardcoded in the old mock-data era. The
  // NO-MOCKS component fetches from the real API; with an empty response the
  // names are absent. Assert that explicitly rather than asserting presence.

  it("does not render a hardcoded 'Trivy' card when API returns empty (honest-empty)", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    await waitFor(() =>
      expect(screen.queryByText("Trivy")).not.toBeInTheDocument(),
    );
  });

  it("does not render a hardcoded 'Semgrep' card when API returns empty (honest-empty)", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    await waitFor(() =>
      expect(screen.queryByText("Semgrep")).not.toBeInTheDocument(),
    );
  });

  // The filter-bar renders "HEALTHY" and "DEGRADED" buttons regardless of API
  // data. Integration-card status badges (the same text inside a card) only
  // appear when the API returns Integration objects — with empty API response
  // those card badges are absent.

  it("renders HEALTHY filter button in the status filter bar", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    // The filter bar always renders the HEALTHY button text
    const matches = screen.getAllByText("HEALTHY");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("renders DEGRADED filter button in the status filter bar", async () => {
    const Page = await loadIntegrationHealth();
    renderPage(<Page />);
    // The filter bar always renders the DEGRADED button text
    const matches = screen.getAllByText("DEGRADED");
    expect(matches.length).toBeGreaterThan(0);
  });
});
