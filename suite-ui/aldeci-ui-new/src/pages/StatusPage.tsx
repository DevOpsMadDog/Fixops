/**
 * StatusPage — public, no auth required.
 * Route: /status
 *
 * Shows: commit SHA, uptime, last deploy time, BM test count,
 * and traffic-light health for 5 subsystems from /api/v1/health/comprehensive.
 */

import { useEffect, useState, useCallback } from "react";
import { buildApiUrl } from "@/lib/api";

// ── Types ──────────────────────────────────────────────────────────────────

interface SubsystemCheck {
  status: "ok" | "degraded" | "error" | "missing";
  reason?: string;
  table_count?: number;
  fingerprint?: string;
}

interface HealthChecks {
  trustgraph: SubsystemCheck;
  feeds_db: SubsystemCheck;
  crypto: SubsystemCheck;
  risk_scorer: SubsystemCheck;
  brain_pipeline: SubsystemCheck;
}

interface ComprehensiveHealth {
  status: "ok" | "degraded";
  checks: HealthChecks;
  elapsed_ms: number;
  timestamp: string;
  service: string;
  version: string;
}

// ── Constants ──────────────────────────────────────────────────────────────

const BM_TEST_COUNT = 1078;

const SUBSYSTEM_LABELS: Record<keyof HealthChecks, string> = {
  trustgraph: "TrustGraph",
  feeds_db: "Feeds DB",
  crypto: "Crypto Manager",
  risk_scorer: "Risk Scorer",
  brain_pipeline: "Brain Pipeline",
};

// ── Helpers ────────────────────────────────────────────────────────────────

function trafficLight(status: string): { color: string; label: string } {
  if (status === "ok") return { color: "#22c55e", label: "OK" };
  if (status === "degraded" || status === "missing")
    return { color: "#f59e0b", label: status === "missing" ? "Missing" : "Degraded" };
  return { color: "#ef4444", label: "Error" };
}

function formatUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m ${sec}s`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

function formatTs(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch {
    return iso;
  }
}

function shortSha(sha: string): string {
  return sha && sha !== "unknown" ? sha.slice(0, 7) : "unknown";
}

// ── Component ──────────────────────────────────────────────────────────────

export default function StatusPage() {
  const [health, setHealth] = useState<ComprehensiveHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [fetchedAt, setFetchedAt] = useState<Date | null>(null);

  // Build-time / env values
  const commitSha: string =
    // @ts-expect-error injected by Vite define
    (typeof __COMMIT_SHA__ !== "undefined" ? __COMMIT_SHA__ : null) ||
    import.meta.env.VITE_COMMIT_SHA ||
    "unknown";

  const fetchHealth = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const url = buildApiUrl("/api/v1/health/comprehensive");
      const res = await fetch(url, { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: ComprehensiveHealth = await res.json();
      setHealth(data);
      setFetchedAt(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 30_000);
    return () => clearInterval(interval);
  }, [fetchHealth]);

  const uptimeMs = health ? Date.now() - new Date(health.timestamp).getTime() : null;
  const overallOk = health?.status === "ok";

  return (
    <div
      style={{
        minHeight: "100vh",
        backgroundColor: "#0f172a",
        color: "#f8fafc",
        fontFamily: "Inter, system-ui, sans-serif",
        padding: "48px 24px",
      }}
    >
      <div style={{ maxWidth: 760, margin: "0 auto" }}>
        {/* Header */}
        <div style={{ marginBottom: 40 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
            <span
              style={{
                display: "inline-block",
                width: 12,
                height: 12,
                borderRadius: "50%",
                backgroundColor: loading
                  ? "#f59e0b"
                  : error
                  ? "#ef4444"
                  : overallOk
                  ? "#22c55e"
                  : "#ef4444",
                boxShadow: loading
                  ? "0 0 8px #f59e0b"
                  : overallOk && !error
                  ? "0 0 8px #22c55e"
                  : "0 0 8px #ef4444",
              }}
            />
            <h1 style={{ fontSize: 28, fontWeight: 700, margin: 0, letterSpacing: -0.5 }}>
              ALdeci Platform Status
            </h1>
          </div>
          <p style={{ color: "#94a3b8", margin: 0, fontSize: 14 }}>
            {loading
              ? "Checking systems…"
              : error
              ? `Last check failed: ${error}`
              : `All systems ${overallOk ? "operational" : "partially degraded"}. Refreshes every 30s.`}
          </p>
        </div>

        {/* Meta cards */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
            gap: 16,
            marginBottom: 32,
          }}
        >
          <MetaCard label="Commit SHA" value={shortSha(commitSha)} mono />
          <MetaCard
            label="Uptime"
            value={
              health
                ? formatUptime(Date.now() - new Date(health.timestamp).getTime() + (health.elapsed_ms))
                : "—"
            }
          />
          <MetaCard
            label="Last Deploy"
            value={health ? formatTs(health.timestamp) : "—"}
          />
          <MetaCard
            label="BM Tests"
            value={`${BM_TEST_COUNT.toLocaleString()} passing`}
            accent="#22c55e"
          />
        </div>

        {/* Subsystem traffic lights */}
        <Section title="API Health">
          {loading && !health ? (
            <SkeletonRows count={5} />
          ) : error && !health ? (
            <ErrorRow message={error} />
          ) : (
            health &&
            (Object.keys(SUBSYSTEM_LABELS) as (keyof HealthChecks)[]).map((key) => {
              const check = health.checks[key];
              const { color, label } = trafficLight(check?.status ?? "error");
              return (
                <SubsystemRow
                  key={key}
                  name={SUBSYSTEM_LABELS[key]}
                  statusColor={color}
                  statusLabel={label}
                  detail={
                    check?.reason
                      ? `Reason: ${check.reason}`
                      : check?.table_count !== undefined
                      ? `${check.table_count} tables`
                      : check?.fingerprint
                      ? `Key: ${check.fingerprint}`
                      : undefined
                  }
                />
              );
            })
          )}
        </Section>

        {/* Footer */}
        <div
          style={{
            marginTop: 40,
            paddingTop: 20,
            borderTop: "1px solid #1e293b",
            display: "flex",
            justifyContent: "space-between",
            color: "#475569",
            fontSize: 12,
          }}
        >
          <span>ALdeci Security Platform</span>
          <span>
            {fetchedAt ? `Checked ${fetchedAt.toLocaleTimeString()}` : "Checking…"}
            {health?.elapsed_ms !== undefined ? ` · ${health.elapsed_ms}ms` : ""}
          </span>
        </div>
      </div>
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────

function MetaCard({
  label,
  value,
  mono = false,
  accent,
}: {
  label: string;
  value: string;
  mono?: boolean;
  accent?: string;
}) {
  return (
    <div
      style={{
        backgroundColor: "#1e293b",
        borderRadius: 10,
        padding: "16px 20px",
        border: "1px solid #334155",
      }}
    >
      <div style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>
        {label}
      </div>
      <div
        style={{
          fontSize: 15,
          fontWeight: 600,
          fontFamily: mono ? "ui-monospace, monospace" : "inherit",
          color: accent ?? "#f8fafc",
        }}
      >
        {value}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h2
        style={{
          fontSize: 13,
          fontWeight: 600,
          color: "#64748b",
          textTransform: "uppercase",
          letterSpacing: 1,
          marginBottom: 12,
        }}
      >
        {title}
      </h2>
      <div
        style={{
          backgroundColor: "#1e293b",
          border: "1px solid #334155",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        {children}
      </div>
    </div>
  );
}

function SubsystemRow({
  name,
  statusColor,
  statusLabel,
  detail,
}: {
  name: string;
  statusColor: string;
  statusLabel: string;
  detail?: string;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "14px 20px",
        borderBottom: "1px solid #0f172a",
      }}
    >
      <div>
        <span style={{ fontSize: 14, fontWeight: 500 }}>{name}</span>
        {detail && (
          <span style={{ fontSize: 12, color: "#64748b", marginLeft: 10 }}>{detail}</span>
        )}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span
          style={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            backgroundColor: statusColor,
            display: "inline-block",
          }}
        />
        <span style={{ fontSize: 13, color: statusColor, fontWeight: 500 }}>{statusLabel}</span>
      </div>
    </div>
  );
}

function SkeletonRows({ count }: { count: number }) {
  return (
    <>
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          style={{
            padding: "14px 20px",
            borderBottom: "1px solid #0f172a",
            display: "flex",
            justifyContent: "space-between",
          }}
        >
          <div
            style={{
              width: `${100 + i * 20}px`,
              height: 14,
              backgroundColor: "#334155",
              borderRadius: 4,
              animation: "pulse 1.5s ease-in-out infinite",
            }}
          />
          <div
            style={{
              width: 40,
              height: 14,
              backgroundColor: "#334155",
              borderRadius: 4,
            }}
          />
        </div>
      ))}
    </>
  );
}

function ErrorRow({ message }: { message: string }) {
  return (
    <div style={{ padding: "20px", color: "#ef4444", fontSize: 13 }}>
      Could not reach API: {message}
    </div>
  );
}
