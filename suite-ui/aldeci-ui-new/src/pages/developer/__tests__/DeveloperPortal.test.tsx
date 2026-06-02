/**
 * Developer Security Portal — component tests (P10 Persona)
 *
 * DeveloperPortal calls window.localStorage.getItem at module-level and
 * fetches repos+findings from /api/v1/developer-portal/* via fetch().
 * We stub localStorage before the module is imported, and mock fetch
 * per-test to control the data the component receives.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderPage } from "@/__tests__/test-utils";

// ── Stub localStorage BEFORE any module import touches it ──
// DeveloperPortal.tsx reads localStorage.getItem at the top level (line 35).
// jsdom provides localStorage but vitest's test runner may not wire it as
// a real Storage — stub it here so the module-level read doesn't throw.
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

// ── Seeded data — real API shapes the component's .map() understands ──
const SEEDED_REPOS = [
  {
    id: "r-1",
    name: "myorg/real-api-service",
    language: "TypeScript",
    grade: "B",
    findings: 5,
    last_scan: new Date().toISOString(),
    trend: "down",
    trend_delta: 2,
    branch: "main",
  },
  {
    id: "r-2",
    name: "myorg/infra-modules",
    language: "HCL",
    grade: "C",
    findings: 12,
    last_scan: new Date().toISOString(),
    trend: "flat",
    trend_delta: 0,
    branch: "main",
  },
];

const SEEDED_FINDINGS = [
  {
    id: "FND-001",
    severity: "critical",
    title: "SQL injection in query builder",
    repo: "myorg/real-api-service",
    type: "sast",
    fix_available: true,
    age: 3,
  },
  {
    id: "FND-002",
    severity: "high",
    title: "Exposed S3 bucket policy",
    repo: "myorg/infra-modules",
    type: "iac",
    fix_available: false,
    age: 7,
  },
];

function makeFetchOk(repos: unknown, findings: unknown) {
  let callCount = 0;
  return vi.fn().mockImplementation(() => {
    callCount++;
    const body = callCount === 1 ? repos : findings;
    return Promise.resolve({
      ok: true,
      status: 200,
      json: () => Promise.resolve(body),
    } as any);
  });
}

function makeFetchFail() {
  return vi.fn().mockResolvedValue({
    ok: false,
    status: 401,
    json: () => Promise.resolve({}),
  } as any);
}

async function loadDeveloperPortal() {
  return (await import("@/pages/developer/DeveloperPortal")).default;
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

describe("DeveloperPortal", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders without crashing", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadDeveloperPortal();
    const { container } = renderPage(<Page />);
    expect(container.firstChild).toBeTruthy();
  });

  it("shows the Developer Security Portal heading", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Developer Security Portal")).toBeInTheDocument();
  });

  it("shows the P10 persona badge", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("P10")).toBeInTheDocument();
  });

  it("shows the Findings Fixed KPI card", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Findings Fixed")).toBeInTheDocument();
  });

  it("shows the Avg Fix Time KPI card", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Avg Fix Time")).toBeInTheDocument();
  });

  it("shows the Repos Owned KPI card", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Repos Owned")).toBeInTheDocument();
  });

  it("shows the Security Score KPI card", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Security Score")).toBeInTheDocument();
  });

  // ── Real-data test: seeded repos render in the repos table ──
  it("renders seeded repo names from API data in the table", async () => {
    vi.stubGlobal("fetch", makeFetchOk(SEEDED_REPOS, SEEDED_FINDINGS));
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    await waitFor(() => {
      expect(screen.getAllByText("myorg/real-api-service").length).toBeGreaterThan(0);
      expect(screen.getAllByText("myorg/infra-modules").length).toBeGreaterThan(0);
    });
  });

  // ── Honest-empty test: old hardcoded repo names are gone when API is empty ──
  it("does not render stale hardcoded repo names when API is empty", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    await waitFor(() => {
      expect(screen.queryByText("aldeci/api-gateway")).not.toBeInTheDocument();
      expect(screen.queryByText("aldeci/infra-terraform")).not.toBeInTheDocument();
    });
  });

  it("renders the severity filter select", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Severity")).toBeInTheDocument();
  });

  it("renders the Repository filter select", async () => {
    vi.stubGlobal("fetch", makeFetchFail());
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    expect(screen.getByText("Repository")).toBeInTheDocument();
  });

  // ── Real-data test: seeded finding title renders in findings table ──
  it("renders a seeded finding title from API data in the findings table", async () => {
    vi.stubGlobal("fetch", makeFetchOk(SEEDED_REPOS, SEEDED_FINDINGS));
    const Page = await loadDeveloperPortal();
    renderPage(<Page />);
    await waitFor(() => {
      expect(screen.getByText(/SQL injection in query builder/i)).toBeInTheDocument();
    });
  });
});
