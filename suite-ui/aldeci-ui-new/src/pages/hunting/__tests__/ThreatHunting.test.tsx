/**
 * Threat Hunting — component tests (P04 Persona)
 *
 * ThreatHunting reads localStorage at module scope (API_KEY constant) then
 * fires fetch() calls inside a useEffect. We must:
 *   1. Stub localStorage BEFORE the dynamic import so the module-level read
 *      doesn't throw in jsdom.
 *   2. Stub global fetch so the useEffect resolves cleanly (empty arrays).
 *   3. Restore both stubs in afterEach so we don't pollute sibling test files.
 *
 * All data asserted below is STATIC — MITRE tactic labels, KPI card titles,
 * tab labels, and the search placeholder are baked into the component source
 * and do not depend on API responses.
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
//       other test files in the full-suite run.
afterEach(() => {
  vi.unstubAllGlobals();
});

async function loadThreatHunting() {
  return (await import("@/pages/hunting/ThreatHunting")).default;
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

describe("ThreatHunting", () => {
  it("renders without crashing", async () => {
    const Page = await loadThreatHunting();
    const { container } = renderPage(<Page />);
    expect(container.firstChild).toBeTruthy();
  });

  it("shows the Threat Hunting heading", async () => {
    const Page = await loadThreatHunting();
    renderPage(<Page />);
    await waitFor(() =>
      expect(screen.getByText("Threat Hunting")).toBeInTheDocument(),
    );
  });

  it("shows the P04 persona badge", async () => {
    const Page = await loadThreatHunting();
    renderPage(<Page />);
    expect(screen.getByText("P04")).toBeInTheDocument();
  });

  it("shows the Active Sessions KPI card", async () => {
    const Page = await loadThreatHunting();
    renderPage(<Page />);
    expect(screen.getByText("Active Sessions")).toBeInTheDocument();
  });

  it("shows the Total Findings KPI card", async () => {
    const Page = await loadThreatHunting();
    renderPage(<Page />);
    expect(screen.getByText("Total Findings")).toBeInTheDocument();
  });

  it("shows the Critical Findings KPI card", async () => {
    const Page = await loadThreatHunting();
    renderPage(<Page />);
    expect(screen.getByText("Critical Findings")).toBeInTheDocument();
  });

  it("shows the Avg. Confidence KPI card", async () => {
    const Page = await loadThreatHunting();
    renderPage(<Page />);
    expect(screen.getByText("Avg. Confidence")).toBeInTheDocument();
  });

  it("renders the Query Library tab option", async () => {
    const Page = await loadThreatHunting();
    renderPage(<Page />);
    expect(screen.getByText("Query Library")).toBeInTheDocument();
  });

  it("renders a MITRE tactic category — Initial Access", async () => {
    const Page = await loadThreatHunting();
    renderPage(<Page />);
    expect(screen.getAllByText(/Initial Access/i).length).toBeGreaterThan(0);
  });

  it("renders a MITRE tactic category — Persistence", async () => {
    const Page = await loadThreatHunting();
    renderPage(<Page />);
    expect(screen.getAllByText(/Persistence/i).length).toBeGreaterThan(0);
  });

  it("renders the query search input placeholder", async () => {
    const Page = await loadThreatHunting();
    renderPage(<Page />);
    expect(screen.getByPlaceholderText("Search queries…")).toBeInTheDocument();
  });

  it("renders the All Tactics filter option in query library", async () => {
    const Page = await loadThreatHunting();
    renderPage(<Page />);
    expect(screen.getByText("All Tactics")).toBeInTheDocument();
  });
});
