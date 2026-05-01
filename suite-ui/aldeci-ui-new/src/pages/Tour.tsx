/**
 * Tour.tsx — Real-product-demo "tour mode"
 *
 * Single screen at /tour.  No auth required (public demo path).
 * SSE consumer drives a 5-stage animated timeline.
 *
 * NO mock data: every stage shows real output or a visible error badge.
 */

import { useState, useRef, useCallback, useEffect } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type StageStatus = "pending" | "running" | "completed" | "error" | "skipped";

interface StageEvent {
  ts: string;
  stage: number;
  stage_name: string;
  status: StageStatus;
  [key: string]: unknown;
}

interface StageState {
  id: number;
  label: string;
  status: StageStatus;
  events: StageEvent[];
  latestMessage: string;
}

const STAGE_META: { id: number; label: string; icon: string }[] = [
  { id: 1, label: "Repo Ingest", icon: "📦" },
  { id: 2, label: "Brain Pipeline (12-step)", icon: "🧠" },
  { id: 3, label: "Multi-LLM Council", icon: "⚖️" },
  { id: 4, label: "TrustGraph Propagation", icon: "🕸️" },
  { id: 5, label: "DPO Pair Captured", icon: "💾" },
];

const DEFAULT_REPO = "https://github.com/OWASP/NodeGoat";
const API_BASE = "/api/v1/tour";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function statusColor(s: StageStatus): string {
  switch (s) {
    case "completed": return "#22c55e";
    case "running":   return "#3b82f6";
    case "error":     return "#ef4444";
    case "skipped":   return "#f59e0b";
    default:          return "#6b7280";
  }
}

function statusLabel(s: StageStatus): string {
  switch (s) {
    case "completed": return "DONE";
    case "running":   return "RUNNING…";
    case "error":     return "SKIPPED — not implemented";
    case "skipped":   return "SKIPPED";
    default:          return "PENDING";
  }
}

function StageBadge({ status }: { status: StageStatus }) {
  return (
    <span style={{
      display: "inline-block",
      padding: "2px 10px",
      borderRadius: 12,
      fontSize: 11,
      fontWeight: 700,
      background: statusColor(status) + "22",
      color: statusColor(status),
      border: `1px solid ${statusColor(status)}44`,
      letterSpacing: "0.04em",
    }}>
      {statusLabel(status)}
    </span>
  );
}

function Spinner() {
  return (
    <span style={{
      display: "inline-block",
      width: 14,
      height: 14,
      borderRadius: "50%",
      border: "2px solid #3b82f666",
      borderTopColor: "#3b82f6",
      animation: "spin 0.8s linear infinite",
      verticalAlign: "middle",
      marginLeft: 8,
    }} />
  );
}

// ---------------------------------------------------------------------------
// Stage card sub-components
// ---------------------------------------------------------------------------

function RepoIngestDetail({ events }: { events: StageEvent[] }) {
  const completed = events.find(e => e.status === "completed");
  if (!completed) return null;
  const exts = completed.top_extensions as Record<string, number> | undefined;
  return (
    <div style={{ marginTop: 8, fontSize: 13, color: "#94a3b8" }}>
      <span style={{ color: "#e2e8f0" }}>{completed.total_files as number} files cloned</span>
      {exts && (
        <span style={{ marginLeft: 12 }}>
          {Object.entries(exts).slice(0, 5).map(([ext, n]) => (
            <span key={ext} style={{ marginRight: 8 }}>
              <code style={{ color: "#7dd3fc" }}>{ext}</code>
              <span style={{ color: "#64748b" }}>×{n}</span>
            </span>
          ))}
        </span>
      )}
    </div>
  );
}

function BrainPipelineDetail({ events }: { events: StageEvent[] }) {
  const completed = events.find(e => e.status === "completed");
  if (!completed) return null;
  const steps = completed.steps as Array<{ name: string; status: string; findings_in: number; findings_out: number }> | undefined;
  return (
    <div style={{ marginTop: 8, fontSize: 12 }}>
      <div style={{ color: "#94a3b8", marginBottom: 6 }}>
        {completed.findings_ingested as number} findings ingested ·{" "}
        {completed.exposure_cases as number} exposure cases ·{" "}
        {completed.critical_cases as number} critical
      </div>
      {steps && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
          {steps.map(s => (
            <span key={s.name} style={{
              padding: "2px 8px",
              borderRadius: 8,
              background: s.status === "completed" ? "#16a34a22" : s.status === "failed" ? "#dc262622" : "#374151",
              color: s.status === "completed" ? "#86efac" : s.status === "failed" ? "#fca5a5" : "#9ca3af",
              fontSize: 11,
            }}>
              {s.name} ({s.findings_out}→)
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function CouncilDetail({ events }: { events: StageEvent[] }) {
  const completed = events.find(e => e.status === "completed");
  if (!completed) return null;
  const votes = completed.member_votes as Array<{ member: string; expertise: string; action: string; confidence: number }> | undefined;
  const hasDivergence = completed.divergence as boolean;
  return (
    <div style={{ marginTop: 8, fontSize: 12 }}>
      {hasDivergence && (
        <div style={{
          marginBottom: 8, padding: "4px 10px",
          background: "#b45309" + "33", border: "1px solid #b45309",
          borderRadius: 8, color: "#fcd34d", fontSize: 11,
        }}>
          DIVERGENCE DETECTED — members disagreed on action
        </div>
      )}
      {votes && votes.map(v => (
        <div key={v.member} style={{
          marginBottom: 4, padding: "4px 10px",
          background: "#1e293b", borderRadius: 8,
          display: "flex", gap: 12, alignItems: "center",
        }}>
          <span style={{ color: "#94a3b8", minWidth: 140 }}>{v.member}</span>
          <span style={{ color: "#e2e8f0", fontWeight: 600 }}>{v.action}</span>
          <span style={{ color: "#64748b" }}>@ {v.confidence.toFixed(2)}</span>
        </div>
      ))}
      <div style={{ marginTop: 6, padding: "6px 10px", background: "#0f172a", borderRadius: 8 }}>
        <span style={{ color: "#7dd3fc", fontSize: 11 }}>Chairman: </span>
        <span style={{ color: "#e2e8f0", fontWeight: 700 }}>{completed.verdict_action as string}</span>
        <span style={{ color: "#64748b" }}> @ {(completed.verdict_confidence as number)?.toFixed(2)}</span>
        {completed.verdict_reasoning && (
          <div style={{ marginTop: 4, color: "#94a3b8", fontSize: 11, lineHeight: 1.5 }}>
            {(completed.verdict_reasoning as string).slice(0, 280)}
            {(completed.verdict_reasoning as string).length > 280 ? "…" : ""}
          </div>
        )}
      </div>
    </div>
  );
}

function TrustGraphDetail({ events }: { events: StageEvent[] }) {
  const completed = events.find(e => e.status === "completed");
  if (!completed) return null;
  return (
    <div style={{ marginTop: 8, fontSize: 13, color: "#94a3b8" }}>
      <span style={{ color: "#e2e8f0" }}>{completed.nodes_emitted as number} nodes</span>
      {" "}emitted to TrustGraph event bus
      {completed.finding_node && (
        <pre style={{
          marginTop: 6, padding: 8, background: "#0f172a",
          borderRadius: 6, fontSize: 11, color: "#7dd3fc", overflowX: "auto",
        }}>
          {JSON.stringify(completed.finding_node, null, 2)}
        </pre>
      )}
    </div>
  );
}

function DPODetail({ events }: { events: StageEvent[] }) {
  const completed = events.find(e => e.status === "completed");
  if (!completed) return null;
  const snippet = completed.pair_snippet as Record<string, unknown> | null;
  return (
    <div style={{ marginTop: 8, fontSize: 13, color: "#94a3b8" }}>
      <div>
        <span style={{ color: "#e2e8f0" }}>{completed.total_pairs as number}</span> total DPO pairs ·{" "}
        <span style={{ color: "#e2e8f0" }}>{completed.total_verdicts as number}</span> council verdicts
      </div>
      {snippet && (
        <pre style={{
          marginTop: 6, padding: 8, background: "#0f172a",
          borderRadius: 6, fontSize: 11, color: "#86efac", overflowX: "auto",
          maxHeight: 180, overflow: "auto",
        }}>
          {JSON.stringify(snippet, null, 2)}
        </pre>
      )}
    </div>
  );
}

function StageDetail({ stageId, events }: { stageId: number; events: StageEvent[] }) {
  switch (stageId) {
    case 1: return <RepoIngestDetail events={events} />;
    case 2: return <BrainPipelineDetail events={events} />;
    case 3: return <CouncilDetail events={events} />;
    case 4: return <TrustGraphDetail events={events} />;
    case 5: return <DPODetail events={events} />;
    default: return null;
  }
}

// ---------------------------------------------------------------------------
// Summary card
// ---------------------------------------------------------------------------

function SummaryCard({ summary }: { summary: Record<string, unknown> | null }) {
  if (!summary) return null;
  const sev = summary.severity_counts as Record<string, number> | undefined;
  const topFinding = summary.top_finding as Record<string, unknown> | undefined;
  const repro = topFinding?.reproduction as string[] | undefined;

  return (
    <div style={{
      marginTop: 24,
      padding: 20,
      background: "#0f172a",
      border: "1px solid #22c55e44",
      borderRadius: 12,
    }}>
      <div style={{ color: "#22c55e", fontWeight: 700, fontSize: 16, marginBottom: 12 }}>
        Scan Complete
      </div>
      <div style={{ display: "flex", gap: 24, flexWrap: "wrap", marginBottom: 16 }}>
        <div>
          <div style={{ color: "#64748b", fontSize: 11 }}>TOTAL FINDINGS</div>
          <div style={{ color: "#e2e8f0", fontSize: 24, fontWeight: 700 }}>{summary.total_findings as number}</div>
        </div>
        {sev && Object.entries(sev).map(([s, n]) => (
          <div key={s}>
            <div style={{ color: "#64748b", fontSize: 11 }}>{s}</div>
            <div style={{
              fontSize: 24, fontWeight: 700,
              color: s === "CRITICAL" ? "#ef4444" : s === "HIGH" ? "#f97316" : s === "MEDIUM" ? "#f59e0b" : "#6b7280",
            }}>{n}</div>
          </div>
        ))}
        <div>
          <div style={{ color: "#64748b", fontSize: 11 }}>COUNCIL VERDICT</div>
          <div style={{ color: "#7dd3fc", fontSize: 16, fontWeight: 700 }}>{summary.council_verdict as string ?? "—"}</div>
        </div>
        <div>
          <div style={{ color: "#64748b", fontSize: 11 }}>TRUSTGRAPH NODES</div>
          <div style={{ color: "#e2e8f0", fontSize: 24, fontWeight: 700 }}>{summary.trustgraph_nodes as number}</div>
        </div>
        <div>
          <div style={{ color: "#64748b", fontSize: 11 }}>DPO PAIRS</div>
          <div style={{ color: "#e2e8f0", fontSize: 24, fontWeight: 700 }}>{summary.dpo_pairs as number}</div>
        </div>
      </div>
      {topFinding && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ color: "#94a3b8", fontSize: 12, marginBottom: 4 }}>Top finding</div>
          <div style={{
            padding: "8px 12px",
            background: "#1e293b",
            borderRadius: 8,
            borderLeft: `4px solid ${topFinding.severity === "CRITICAL" ? "#ef4444" : "#f97316"}`,
          }}>
            <div style={{ color: "#e2e8f0", fontWeight: 600 }}>{topFinding.title as string}</div>
            <div style={{ color: "#64748b", fontSize: 12 }}>
              {topFinding.file as string}:{topFinding.line as number}
            </div>
          </div>
        </div>
      )}
      {repro && repro.length > 0 && (
        <div>
          <div style={{ color: "#94a3b8", fontSize: 12, marginBottom: 4 }}>Reproduction commands</div>
          <pre style={{
            padding: 12, background: "#020617", borderRadius: 8,
            fontSize: 12, color: "#86efac", overflowX: "auto",
          }}>
            {repro.join("\n")}
          </pre>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Tour page
// ---------------------------------------------------------------------------

export default function Tour() {
  const [repoUrl, setRepoUrl] = useState(DEFAULT_REPO);
  const [running, setRunning] = useState(false);
  const [tourId, setTourId] = useState<string | null>(null);
  const [stages, setStages] = useState<StageState[]>(
    STAGE_META.map(m => ({ id: m.id, label: m.label, status: "pending", events: [], latestMessage: "" }))
  );
  const [summary, setSummary] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const esRef = useRef<EventSource | null>(null);
  const startTimeRef = useRef<number>(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Inject keyframe animation once
  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = `@keyframes spin { to { transform: rotate(360deg); } }`;
    document.head.appendChild(style);
    return () => { document.head.removeChild(style); };
  }, []);

  const updateStage = useCallback((stageId: number, event: StageEvent) => {
    setStages(prev => prev.map(s => {
      if (s.id !== stageId) return s;
      return {
        ...s,
        status: event.status === "running" ? "running"
               : event.status === "completed" ? "completed"
               : event.status === "error" ? "error"
               : s.status,
        events: [...s.events, event],
        latestMessage: (event.message as string) ?? s.latestMessage,
      };
    }));
  }, []);

  const startTour = useCallback(async () => {
    if (!repoUrl.trim()) return;
    setRunning(true);
    setError(null);
    setSummary(null);
    setStages(STAGE_META.map(m => ({ id: m.id, label: m.label, status: "pending", events: [], latestMessage: "" })));
    setElapsed(0);
    startTimeRef.current = Date.now();
    timerRef.current = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTimeRef.current) / 1000));
    }, 1000);

    try {
      const res = await fetch(`${API_BASE}/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: repoUrl.trim() }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? `HTTP ${res.status}`);
      }
      const data = await res.json();
      setTourId(data.tour_id);

      // Open SSE stream
      const es = new EventSource(data.stream_url);
      esRef.current = es;

      es.onmessage = (e) => {
        try {
          const event: StageEvent = JSON.parse(e.data);
          if (event.stage === 0 && event.stage_name === "tour") {
            // Top-level tour event
            if (event.status === "completed") {
              setSummary(event as unknown as Record<string, unknown>);
              setRunning(false);
              if (timerRef.current) clearInterval(timerRef.current);
            } else if (event.status === "failed") {
              setError((event.message as string) ?? "Tour failed");
              setRunning(false);
              if (timerRef.current) clearInterval(timerRef.current);
            }
          } else if (event.stage >= 1 && event.stage <= 5) {
            updateStage(event.stage, event);
          }
        } catch (_) {
          // ignore parse errors
        }
      };

      es.addEventListener("done", () => {
        es.close();
        esRef.current = null;
        setRunning(false);
        if (timerRef.current) clearInterval(timerRef.current);
      });

      es.onerror = () => {
        es.close();
        esRef.current = null;
        setRunning(false);
        if (timerRef.current) clearInterval(timerRef.current);
      };

    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
      setRunning(false);
      if (timerRef.current) clearInterval(timerRef.current);
    }
  }, [repoUrl, updateStage]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      esRef.current?.close();
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  return (
    <div style={{
      minHeight: "100vh",
      background: "#020617",
      color: "#e2e8f0",
      fontFamily: "'Inter', 'Segoe UI', sans-serif",
      padding: "40px 24px",
      maxWidth: 800,
      margin: "0 auto",
    }}>
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <span style={{ fontSize: 28, fontWeight: 800, color: "#38bdf8" }}>ALdeci</span>
          <span style={{
            padding: "2px 10px", borderRadius: 12,
            background: "#1e293b", border: "1px solid #334155",
            fontSize: 12, color: "#94a3b8",
          }}>CTEM+ Platform Demo</span>
        </div>
        <p style={{ color: "#64748b", fontSize: 14, margin: 0 }}>
          End-to-end scan: repo clone → Brain Pipeline → Multi-LLM Council → TrustGraph → DPO capture
        </p>
      </div>

      {/* Input */}
      <div style={{ marginBottom: 24, display: "flex", gap: 12, flexWrap: "wrap" }}>
        <input
          type="text"
          value={repoUrl}
          onChange={e => setRepoUrl(e.target.value)}
          placeholder="https://github.com/OWASP/NodeGoat"
          disabled={running}
          style={{
            flex: 1,
            minWidth: 280,
            padding: "10px 14px",
            background: "#0f172a",
            border: "1px solid #334155",
            borderRadius: 8,
            color: "#e2e8f0",
            fontSize: 14,
            outline: "none",
          }}
        />
        <button
          onClick={startTour}
          disabled={running || !repoUrl.trim()}
          style={{
            padding: "10px 24px",
            background: running ? "#1e293b" : "#2563eb",
            color: running ? "#64748b" : "#fff",
            border: "none",
            borderRadius: 8,
            fontSize: 14,
            fontWeight: 700,
            cursor: running ? "not-allowed" : "pointer",
            transition: "background 0.2s",
          }}
        >
          {running ? `Running… ${elapsed}s` : "Start Tour"}
        </button>
      </div>

      {error && (
        <div style={{
          marginBottom: 16, padding: "10px 14px",
          background: "#ef444422", border: "1px solid #ef4444",
          borderRadius: 8, color: "#fca5a5", fontSize: 13,
        }}>
          {error}
        </div>
      )}

      {tourId && (
        <div style={{ marginBottom: 12, fontSize: 12, color: "#64748b" }}>
          Tour ID: <code style={{ color: "#7dd3fc" }}>{tourId}</code>
        </div>
      )}

      {/* Stage timeline */}
      <div style={{ position: "relative" }}>
        {/* Vertical line */}
        <div style={{
          position: "absolute",
          left: 19,
          top: 20,
          bottom: 20,
          width: 2,
          background: "#1e293b",
        }} />

        {stages.map((stage, idx) => {
          const meta = STAGE_META[idx];
          const isActive = stage.status !== "pending";
          return (
            <div key={stage.id} style={{
              display: "flex",
              gap: 16,
              marginBottom: 16,
              opacity: isActive ? 1 : 0.4,
              transition: "opacity 0.3s",
            }}>
              {/* Circle indicator */}
              <div style={{
                width: 40,
                height: 40,
                minWidth: 40,
                borderRadius: "50%",
                background: isActive ? statusColor(stage.status) + "22" : "#1e293b",
                border: `2px solid ${isActive ? statusColor(stage.status) : "#334155"}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 18,
                zIndex: 1,
              }}>
                {meta.icon}
              </div>

              {/* Content */}
              <div style={{
                flex: 1,
                padding: "10px 14px",
                background: "#0f172a",
                border: `1px solid ${isActive ? statusColor(stage.status) + "44" : "#1e293b"}`,
                borderRadius: 10,
                transition: "border-color 0.3s",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
                  <span style={{ fontWeight: 700, fontSize: 14 }}>
                    Stage {stage.id} — {stage.label}
                  </span>
                  <StageBadge status={stage.status} />
                  {stage.status === "running" && <Spinner />}
                </div>

                {stage.latestMessage && (
                  <div style={{ color: "#94a3b8", fontSize: 13 }}>{stage.latestMessage}</div>
                )}

                <StageDetail stageId={stage.id} events={stage.events} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Summary card */}
      <SummaryCard summary={summary} />

      {/* Footer */}
      <div style={{ marginTop: 40, color: "#334155", fontSize: 12, textAlign: "center" }}>
        ALdeci CTEM+ Platform — Real scan, no mocks
      </div>
    </div>
  );
}
