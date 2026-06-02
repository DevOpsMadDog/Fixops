/**
 * api-client.ts — Typed ALDECI API client.
 *
 * ALDECIClient wraps fetch with:
 *   - configurable base URL + API key
 *   - X-API-Key / Bearer auth header injection
 *   - Automatic retry on 5xx / network errors (exponential back-off)
 *   - Typed response interfaces per endpoint group
 *   - Graceful error normalisation (ApiError)
 *
 * Usage:
 *   import { aldeciClient } from "@/lib/api-client";
 *   const findings = await aldeciClient.getFindings({ severity: "critical" });
 */

import {
  API_BASE_URL,
  API_KEY,
  DEFAULT_ORG_ID,
  REQUEST_TIMEOUT_MS,
  MAX_RETRIES,
  RETRY_BASE_DELAY_MS,
} from "@/lib/api-config";

// ─────────────────────────────────────────────────────────────────────────────
// Response type interfaces
// ─────────────────────────────────────────────────────────────────────────────

export interface Finding {
  id: string;
  finding_id?: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: string;
  cve?: string;
  cve_id?: string;
  source?: string;
  scanner?: string;
  created_at?: string;
  updated_at?: string;
  [key: string]: unknown;
}

export interface FindingsResponse {
  findings: Finding[];
  items: Finding[];
  total: number;
  page?: number;
  limit?: number;
}

export interface PostureScore {
  score: number;
  grade?: string;
  trend?: "improving" | "degrading" | "stable";
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  last_updated?: string;
  top_risks?: PostureRisk[];
  [key: string]: unknown;
}

export interface PostureRisk {
  id: string;
  title: string;
  severity: string;
  score?: number;
  [key: string]: unknown;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  version?: string;
  status: "compliant" | "non_compliant" | "partial" | "unknown";
  score?: number;
  controls_total?: number;
  controls_passed?: number;
  controls_failed?: number;
  last_assessed?: string;
  [key: string]: unknown;
}

export interface ComplianceStatus {
  frameworks: ComplianceFramework[];
  overall_score?: number;
  last_updated?: string;
  [key: string]: unknown;
}

export interface SLAMetrics {
  total_findings: number;
  within_sla: number;
  breached: number;
  at_risk: number;
  compliance_rate?: number;
  by_severity?: Record<string, SLASeverityBand>;
  breaches?: SLABreach[];
  [key: string]: unknown;
}

export interface SLASeverityBand {
  target_days: number;
  within: number;
  breached: number;
  [key: string]: unknown;
}

export interface SLABreach {
  finding_id: string;
  title?: string;
  severity: string;
  days_overdue: number;
  [key: string]: unknown;
}

export interface AttackSurfaceData {
  assets?: AttackSurfaceAsset[];
  nodes?: AttackSurfaceAsset[];
  attack_paths?: AttackPath[];
  risk_score?: number;
  exposed_count?: number;
  [key: string]: unknown;
}

export interface AttackSurfaceAsset {
  id: string;
  name?: string;
  type?: string;
  risk?: string;
  exposure?: string;
  [key: string]: unknown;
}

export interface AttackPath {
  id: string;
  source?: string;
  target?: string;
  steps?: number;
  likelihood?: string;
  [key: string]: unknown;
}

export interface Incident {
  id: string;
  title: string;
  severity: string;
  status: string;
  created_at?: string;
  updated_at?: string;
  assigned_to?: string;
  [key: string]: unknown;
}

export interface IncidentsResponse {
  incidents?: Incident[];
  items?: Incident[];
  cases?: Incident[];
  total?: number;
  [key: string]: unknown;
}

export interface Vendor {
  id: string;
  name: string;
  category?: string;
  risk_score?: number;
  status?: string;
  last_reviewed?: string;
  [key: string]: unknown;
}

export interface VendorsResponse {
  vendors?: Vendor[];
  items?: Vendor[];
  total?: number;
  [key: string]: unknown;
}

export interface IntegrationHealth {
  id: string;
  name: string;
  type?: string;
  status: "healthy" | "degraded" | "down" | "unknown";
  last_sync?: string;
  error?: string;
  [key: string]: unknown;
}

export interface IntegrationHealthResponse {
  integrations?: IntegrationHealth[];
  items?: IntegrationHealth[];
  total?: number;
  healthy?: number;
  degraded?: number;
  down?: number;
  [key: string]: unknown;
}

export interface DashboardMetrics {
  total_findings?: number;
  critical_findings?: number;
  open_findings?: number;
  resolved_findings?: number;
  posture_score?: number;
  compliance_rate?: number;
  sla_compliance?: number;
  mean_time_to_remediate?: number;
  active_threats?: number;
  [key: string]: unknown;
}

export interface ThreatHuntSession {
  id: string;
  name?: string;
  status: string;
  hypothesis?: string;
  started_at?: string;
  completed_at?: string;
  findings_count?: number;
  [key: string]: unknown;
}

export interface ThreatHuntingResponse {
  sessions?: ThreatHuntSession[];
  items?: ThreatHuntSession[];
  total?: number;
  [key: string]: unknown;
}

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly detail?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ALDECIClient
// ─────────────────────────────────────────────────────────────────────────────

export class ALDECIClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(baseUrl = API_BASE_URL, apiKey = API_KEY) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
  }

  // ── Auth helpers ──────────────────────────────────────────────────────────

  /** Reads the stored auth token (API key or JWT) from localStorage at call time. */
  private resolveToken(): string {
    if (typeof window !== "undefined") {
      const stored = window.localStorage.getItem("aldeci.authToken")?.trim();
      if (stored) return stored;
    }
    return this.apiKey;
  }

  private buildHeaders(): HeadersInit {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    const token = this.resolveToken();
    if (token) {
      const strategy =
        typeof window !== "undefined"
          ? window.localStorage.getItem("aldeci.authStrategy") ?? "token"
          : "token";

      if (strategy === "jwt") {
        headers["Authorization"] = token.toLowerCase().startsWith("bearer ")
          ? token
          : `Bearer ${token}`;
      } else {
        headers["X-API-Key"] = token;
      }
    }

    const orgId =
      (typeof window !== "undefined"
        ? window.localStorage.getItem("aldeci.orgId")?.trim()
        : null) ?? DEFAULT_ORG_ID;
    if (orgId) {
      headers["X-Org-ID"] = orgId;
    }

    return headers;
  }

  // ── Core fetch with retry ─────────────────────────────────────────────────

  private async request<T>(
    path: string,
    options: RequestInit = {},
    attempt = 0,
  ): Promise<T> {
    const url = `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    let response: Response;
    try {
      response = await fetch(url, {
        ...options,
        headers: {
          ...this.buildHeaders(),
          ...(options.headers ?? {}),
        },
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timeoutId);
      // Network / abort error — retry if budget allows
      if (attempt < MAX_RETRIES) {
        await this.delay(RETRY_BASE_DELAY_MS * 2 ** attempt);
        return this.request<T>(path, options, attempt + 1);
      }
      throw new ApiError(0, `Network error: ${(err as Error).message}`);
    } finally {
      clearTimeout(timeoutId);
    }

    // 401 / 403 — do not retry, redirect to login
    if (response.status === 401 || response.status === 403) {
      if (response.status === 401 && typeof window !== "undefined") {
        window.location.hash = "#/login";
      }
      throw new ApiError(response.status, `Auth error: ${response.status}`);
    }

    // 429 rate-limit — retry with back-off
    if (response.status === 429 && attempt < MAX_RETRIES) {
      const retryAfter = Number(response.headers.get("Retry-After") ?? 1);
      await this.delay(retryAfter * 1_000);
      return this.request<T>(path, options, attempt + 1);
    }

    // 5xx — retry with exponential back-off
    if (response.status >= 500 && attempt < MAX_RETRIES) {
      await this.delay(RETRY_BASE_DELAY_MS * 2 ** attempt);
      return this.request<T>(path, options, attempt + 1);
    }

    if (!response.ok) {
      let detail: unknown;
      try {
        detail = await response.json();
      } catch {
        detail = await response.text().catch(() => undefined);
      }
      throw new ApiError(response.status, `HTTP ${response.status}`, detail);
    }

    // 204 No Content
    if (response.status === 204) {
      return undefined as unknown as T;
    }

    return response.json() as Promise<T>;
  }

  private get<T>(path: string, params?: Record<string, string | number | boolean | undefined>): Promise<T> {
    let url = path;
    if (params) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== null) qs.set(k, String(v));
      }
      const qsStr = qs.toString();
      if (qsStr) url = `${path}?${qsStr}`;
    }
    return this.request<T>(url, { method: "GET" });
  }

  private post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>(path, {
      method: "POST",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public API methods
  // ─────────────────────────────────────────────────────────────────────────

  /** List findings, optionally filtered. */
  getFindings(
    filters?: Record<string, string | number | boolean | undefined>,
  ): Promise<FindingsResponse> {
    return this.get<FindingsResponse>("/api/v1/analytics/findings", filters);
  }

  /** Current security posture score and top risks. */
  getPostureScore(): Promise<PostureScore> {
    return this.get<Record<string, unknown>>("/api/v1/posture-score/current").then(
      (d) => ({ ...d, score: (d.overall_score as number) ?? 0 } as PostureScore),
    );
  }

  /** Compliance status across all frameworks. */
  getComplianceStatus(): Promise<ComplianceStatus> {
    return this.get<ComplianceStatus>("/api/v1/compliance-engine/status");
  }

  /** SLA metrics — breaches, at-risk, compliance rate. */
  getSLAStatus(): Promise<SLAMetrics> {
    return this.get<SLAMetrics>("/api/v1/sla/dashboard");
  }

  /** Attack surface assets and attack paths. */
  getAttackSurface(): Promise<AttackSurfaceData> {
    return this.get<AttackSurfaceData>("/api/v1/graph/attack-paths");
  }

  /** Active incidents / cases. */
  getIncidents(
    params?: Record<string, string | number | boolean | undefined>,
  ): Promise<IncidentsResponse> {
    return this.get<IncidentsResponse>("/api/v1/cases", params);
  }

  /** Third-party vendor list. */
  getVendors(
    params?: Record<string, string | number | boolean | undefined>,
  ): Promise<VendorsResponse> {
    return this.get<VendorsResponse>("/api/v1/integrations", params);
  }

  /** Integration health status for all connected tools. */
  getIntegrationHealth(): Promise<IntegrationHealthResponse> {
    return this.get<IntegrationHealthResponse>("/api/v1/integrations/health");
  }

  /** High-level dashboard metrics (overview). */
  getMetrics(): Promise<DashboardMetrics> {
    return this.get<DashboardMetrics>("/api/v1/analytics/dashboard/overview");
  }

  /** Threat hunting sessions. */
  getThreatHunting(
    params?: Record<string, string | number | boolean | undefined>,
  ): Promise<ThreatHuntingResponse> {
    return this.get<ThreatHuntingResponse>("/api/v1/feeds", params);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Singleton instance — ready to import anywhere
// ─────────────────────────────────────────────────────────────────────────────

/** Pre-configured singleton ALDECI client. Import and use directly. */
export const aldeciClient = new ALDECIClient();
