/**
 * Audit Log Viewer — Immutable audit trail for compliance, forensics, and access review
 *
 * Design:
 * - Header: "Audit Log" with subtitle
 * - Anomaly highlights (3 alert cards)
 * - KPI row: Events Today, Failed Auth Attempts, Config Changes, Policy Violations
 * - Filter bar: date range, event type, severity, search, export
 * - Audit events table (20 rows, paginated)
 * - Event detail slide-in panel on row click
 *
 * API: GET /api/v1/audit/events?limit=20 — falls back to mock data.
 */

import { useState, useCallback, useMemo, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Shield,
  Search,
  Download,
  ChevronRight,
  ChevronLeft,
  Clock,
  User,
  Terminal,
  Database,
  Settings,
  Lock,
  Eye,
  X,
  Activity,
  AlertCircle,
  Info,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type Severity = "critical" | "high" | "medium" | "low" | "info";
type EventType =
  | "authentication"
  | "authorization"
  | "configuration"
  | "data_access"
  | "admin_action";
type Result = "success" | "failure";

interface AuditEvent {
  id: string;
  timestamp: string;
  severity: Severity;
  event_type: EventType;
  actor: string;
  action: string;
  resource: string;
  result: Result;
  ip_address: string;
  // detail fields
  request_id: string;
  session_id: string;
  user_agent: string;
  request_body: string;
  response_status: number;
  geo_location: string;
  previous_value?: string;
  new_value?: string;
}

interface AnomalyAlert {
  id: string;
  level: "critical" | "warning";
  message: string;
  detail: string;
  time: string;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_EVENTS: AuditEvent[] = [
  {
    id: "EVT-001",
    timestamp: "2026-04-16T08:14:32Z",
    severity: "info",
    event_type: "authentication",
    actor: "devopsadmin",
    action: "LOGIN",
    resource: "/api/v1/auth/login",
    result: "success",
    ip_address: "10.0.1.5",
    request_id: "req-a1b2c3d4",
    session_id: "ses-x9y8z7w6",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/124.0",
    request_body: '{"username": "devopsadmin", "password": "[REDACTED]"}',
    response_status: 200,
    geo_location: "US / New York",
  },
  {
    id: "EVT-002",
    timestamp: "2026-04-16T08:17:45Z",
    severity: "info",
    event_type: "admin_action",
    actor: "devopsadmin",
    action: "API_KEY_CREATE",
    resource: "/api/v1/api-keys",
    result: "success",
    ip_address: "10.0.1.5",
    request_id: "req-b2c3d4e5",
    session_id: "ses-x9y8z7w6",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/124.0",
    request_body: '{"name": "ci-service-account", "scope": "read:findings"}',
    response_status: 201,
    geo_location: "US / New York",
    new_value: "Key: ak_live_ci-service-account (scope: read:findings)",
  },
  {
    id: "EVT-003",
    timestamp: "2026-04-16T08:22:11Z",
    severity: "critical",
    event_type: "authentication",
    actor: "unknown",
    action: "LOGIN_FAILED",
    resource: "/api/v1/auth/login",
    result: "failure",
    ip_address: "185.220.101.47",
    request_id: "req-c3d4e5f6",
    session_id: "ses-none",
    user_agent: "python-requests/2.28.0",
    request_body: '{"username": "admin", "password": "[REDACTED]"}',
    response_status: 401,
    geo_location: "DE / Frankfurt (Tor Exit Node)",
  },
  {
    id: "EVT-004",
    timestamp: "2026-04-16T08:22:13Z",
    severity: "critical",
    event_type: "authentication",
    actor: "unknown",
    action: "LOGIN_FAILED",
    resource: "/api/v1/auth/login",
    result: "failure",
    ip_address: "185.220.101.47",
    request_id: "req-c3d4e5f7",
    session_id: "ses-none",
    user_agent: "python-requests/2.28.0",
    request_body: '{"username": "root", "password": "[REDACTED]"}',
    response_status: 401,
    geo_location: "DE / Frankfurt (Tor Exit Node)",
  },
  {
    id: "EVT-005",
    timestamp: "2026-04-16T08:22:15Z",
    severity: "critical",
    event_type: "authentication",
    actor: "unknown",
    action: "LOGIN_FAILED",
    resource: "/api/v1/auth/login",
    result: "failure",
    ip_address: "185.220.101.47",
    request_id: "req-c3d4e5f8",
    session_id: "ses-none",
    user_agent: "python-requests/2.28.0",
    request_body: '{"username": "administrator", "password": "[REDACTED]"}',
    response_status: 401,
    geo_location: "DE / Frankfurt (Tor Exit Node)",
  },
  {
    id: "EVT-006",
    timestamp: "2026-04-16T08:31:07Z",
    severity: "high",
    event_type: "configuration",
    actor: "alice@corp.com",
    action: "POLICY_UPDATE",
    resource: "/api/v1/policies/rate-limit",
    result: "success",
    ip_address: "10.0.2.14",
    request_id: "req-d4e5f6g7",
    session_id: "ses-p1q2r3s4",
    user_agent: "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0",
    request_body: '{"threshold": 5000, "window_seconds": 60}',
    response_status: 200,
    geo_location: "US / Chicago",
    previous_value: "threshold: 1000, window_seconds: 60",
    new_value: "threshold: 5000, window_seconds: 60",
  },
  {
    id: "EVT-007",
    timestamp: "2026-04-16T02:47:33Z",
    severity: "critical",
    event_type: "admin_action",
    actor: "bob@corp.com",
    action: "ROLE_ESCALATION",
    resource: "/api/v1/users/charlie@corp.com/roles",
    result: "success",
    ip_address: "10.0.3.88",
    request_id: "req-e5f6g7h8",
    session_id: "ses-t5u6v7w8",
    user_agent: "curl/7.88.1",
    request_body: '{"role": "admin", "reason": "temporary coverage"}',
    response_status: 200,
    geo_location: "US / Seattle",
    previous_value: "role: viewer",
    new_value: "role: admin",
  },
  {
    id: "EVT-008",
    timestamp: "2026-04-16T09:05:52Z",
    severity: "high",
    event_type: "data_access",
    actor: "carol@corp.com",
    action: "DATA_EXPORT",
    resource: "/api/v1/findings/export",
    result: "success",
    ip_address: "10.0.4.22",
    request_id: "req-f6g7h8i9",
    session_id: "ses-y1z2a3b4",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/124.0",
    request_body: '{"format": "csv", "filters": {"severity": "all"}}',
    response_status: 200,
    geo_location: "US / Austin",
    new_value: "Exported 50MB — 42,318 findings",
  },
  {
    id: "EVT-009",
    timestamp: "2026-04-16T09:12:19Z",
    severity: "info",
    event_type: "admin_action",
    actor: "scim-provisioner",
    action: "USER_PROVISION",
    resource: "/scim/v2/Users",
    result: "success",
    ip_address: "10.0.0.5",
    request_id: "req-g7h8i9j0",
    session_id: "ses-c5d6e7f8",
    user_agent: "Okta SCIM 2.0 Provisioner/1.0",
    request_body:
      '{"userName": "alice@corp.com", "displayName": "Alice Smith", "active": true}',
    response_status: 201,
    geo_location: "US / Internal",
    new_value: "User alice@corp.com created (active: true)",
  },
  {
    id: "EVT-010",
    timestamp: "2026-04-16T09:18:44Z",
    severity: "high",
    event_type: "configuration",
    actor: "devopsadmin",
    action: "SSO_CONFIG_MODIFIED",
    resource: "/api/v1/sso/providers/okta",
    result: "success",
    ip_address: "10.0.1.5",
    request_id: "req-h8i9j0k1",
    session_id: "ses-x9y8z7w6",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/124.0",
    request_body:
      '{"entity_id": "https://corp.okta.com", "metadata_url": "https://corp.okta.com/app/metadata"}',
    response_status: 200,
    geo_location: "US / New York",
    previous_value: "entity_id: https://corp-old.okta.com",
    new_value: "entity_id: https://corp.okta.com",
  },
  {
    id: "EVT-011",
    timestamp: "2026-04-16T09:25:03Z",
    severity: "medium",
    event_type: "configuration",
    actor: "alice@corp.com",
    action: "WEBHOOK_ADDED",
    resource: "/api/v1/webhooks",
    result: "success",
    ip_address: "10.0.2.14",
    request_id: "req-i9j0k1l2",
    session_id: "ses-p1q2r3s4",
    user_agent: "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0",
    request_body:
      '{"url": "https://hooks.slack.com/services/T00/B00/abc123", "events": ["finding.critical"]}',
    response_status: 201,
    geo_location: "US / Chicago",
    new_value: "Webhook: hooks.slack.com (events: finding.critical)",
  },
  {
    id: "EVT-012",
    timestamp: "2026-04-16T09:33:27Z",
    severity: "info",
    event_type: "admin_action",
    actor: "devopsadmin",
    action: "SCAN_TRIGGERED",
    resource: "/api/v1/cve/scan",
    result: "success",
    ip_address: "10.0.1.5",
    request_id: "req-j0k1l2m3",
    session_id: "ses-x9y8z7w6",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/124.0",
    request_body: '{"target": "all", "severity_threshold": "medium"}',
    response_status: 202,
    geo_location: "US / New York",
  },
  {
    id: "EVT-013",
    timestamp: "2026-04-16T09:41:55Z",
    severity: "medium",
    event_type: "authorization",
    actor: "dave@corp.com",
    action: "ACCESS_DENIED",
    resource: "/api/v1/admin/users",
    result: "failure",
    ip_address: "10.0.5.17",
    request_id: "req-k1l2m3n4",
    session_id: "ses-g9h0i1j2",
    user_agent: "Mozilla/5.0 (Linux x86_64) Chrome/124.0",
    request_body: "{}",
    response_status: 403,
    geo_location: "US / Denver",
  },
  {
    id: "EVT-014",
    timestamp: "2026-04-16T09:47:12Z",
    severity: "info",
    event_type: "data_access",
    actor: "carol@corp.com",
    action: "REPORT_GENERATED",
    resource: "/api/v1/reports/compliance",
    result: "success",
    ip_address: "10.0.4.22",
    request_id: "req-l2m3n4o5",
    session_id: "ses-y1z2a3b4",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/124.0",
    request_body: '{"framework": "SOC2", "period": "2026-Q1"}',
    response_status: 200,
    geo_location: "US / Austin",
  },
  {
    id: "EVT-015",
    timestamp: "2026-04-16T10:02:38Z",
    severity: "medium",
    event_type: "configuration",
    actor: "devopsadmin",
    action: "RATE_LIMIT_UPDATED",
    resource: "/api/v1/policies/api-rate-limit",
    result: "success",
    ip_address: "10.0.1.5",
    request_id: "req-m3n4o5p6",
    session_id: "ses-x9y8z7w6",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/124.0",
    request_body: '{"tier": "enterprise", "limit": 10000}',
    response_status: 200,
    geo_location: "US / New York",
    previous_value: "limit: 5000",
    new_value: "limit: 10000",
  },
  {
    id: "EVT-016",
    timestamp: "2026-04-16T10:15:04Z",
    severity: "high",
    event_type: "admin_action",
    actor: "devopsadmin",
    action: "USER_SUSPENDED",
    resource: "/api/v1/users/mallory@corp.com",
    result: "success",
    ip_address: "10.0.1.5",
    request_id: "req-n4o5p6q7",
    session_id: "ses-x9y8z7w6",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/124.0",
    request_body: '{"reason": "suspicious activity detected by insider threat engine"}',
    response_status: 200,
    geo_location: "US / New York",
    previous_value: "status: active",
    new_value: "status: suspended",
  },
  {
    id: "EVT-017",
    timestamp: "2026-04-16T10:22:51Z",
    severity: "info",
    event_type: "data_access",
    actor: "alice@corp.com",
    action: "ASSET_INVENTORY_EXPORT",
    resource: "/api/v1/assets/export",
    result: "success",
    ip_address: "10.0.2.14",
    request_id: "req-o5p6q7r8",
    session_id: "ses-p1q2r3s4",
    user_agent: "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0",
    request_body: '{"format": "json", "include_risk_scores": true}',
    response_status: 200,
    geo_location: "US / Chicago",
  },
  {
    id: "EVT-018",
    timestamp: "2026-04-16T10:31:17Z",
    severity: "medium",
    event_type: "authorization",
    actor: "scim-provisioner",
    action: "PERMISSION_GRANTED",
    resource: "/api/v1/rbac/permissions",
    result: "success",
    ip_address: "10.0.0.5",
    request_id: "req-p6q7r8s9",
    session_id: "ses-c5d6e7f8",
    user_agent: "Okta SCIM 2.0 Provisioner/1.0",
    request_body:
      '{"user": "alice@corp.com", "permission": "read:findings,write:remediation"}',
    response_status: 200,
    geo_location: "US / Internal",
    new_value: "Permissions: read:findings, write:remediation",
  },
  {
    id: "EVT-019",
    timestamp: "2026-04-16T10:45:09Z",
    severity: "low",
    event_type: "authentication",
    actor: "bob@corp.com",
    action: "SESSION_REFRESH",
    resource: "/api/v1/auth/refresh",
    result: "success",
    ip_address: "10.0.3.88",
    request_id: "req-q7r8s9t0",
    session_id: "ses-t5u6v7w8",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0",
    request_body: '{"grant_type": "refresh_token"}',
    response_status: 200,
    geo_location: "US / Seattle",
  },
  {
    id: "EVT-020",
    timestamp: "2026-04-16T10:58:33Z",
    severity: "info",
    event_type: "admin_action",
    actor: "devopsadmin",
    action: "BACKUP_TRIGGERED",
    resource: "/api/v1/admin/backup",
    result: "success",
    ip_address: "10.0.1.5",
    request_id: "req-r8s9t0u1",
    session_id: "ses-x9y8z7w6",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/124.0",
    request_body: '{"target": "all_databases", "compress": true}',
    response_status: 202,
    geo_location: "US / New York",
  },
];

const ANOMALY_ALERTS: AnomalyAlert[] = [
  {
    id: "ANO-001",
    level: "critical",
    message: "Brute-force attack detected",
    detail:
      "5 failed login attempts from 185.220.101.47 (Tor exit node) within 2 minutes",
    time: "08:22 UTC",
  },
  {
    id: "ANO-002",
    level: "critical",
    message: "Admin action outside business hours",
    detail:
      "Role escalation performed by bob@corp.com at 02:47 UTC — outside normal 08:00-18:00 window",
    time: "02:47 UTC",
  },
  {
    id: "ANO-003",
    level: "warning",
    message: "Abnormal data export volume",
    detail:
      "carol@corp.com exported 50MB — 10x larger than 30-day baseline of 4.8MB",
    time: "09:05 UTC",
  },
];

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

const SEVERITY_BADGE: Record<
  Severity,
  "critical" | "high" | "medium" | "low" | "secondary"
> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "secondary",
};

const EVENT_TYPE_LABEL: Record<EventType, string> = {
  authentication: "Authentication",
  authorization: "Authorization",
  configuration: "Configuration",
  data_access: "Data Access",
  admin_action: "Admin Action",
};

const EVENT_TYPE_ICON: Record<EventType, typeof Shield> = {
  authentication: Lock,
  authorization: Shield,
  configuration: Settings,
  data_access: Database,
  admin_action: Terminal,
};

function formatTimestamp(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleString("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

// ══════════════════════════════════════════════════════════════
// Event Detail Panel
// ══════════════════════════════════════════════════════════════

interface EventDetailPanelProps {
  event: AuditEvent | null;
  onClose: () => void;
}

function EventDetailPanel({ event, onClose }: EventDetailPanelProps) {
  return (
    <AnimatePresence>
      {event && (
        <>
          {/* Backdrop */}
          <motion.div
            key="backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/40 z-40"
            onClick={onClose}
          />
          {/* Slide-in panel */}
          <motion.div
            key="panel"
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", damping: 28, stiffness: 300 }}
            className="fixed right-0 top-0 h-full w-full max-w-lg bg-slate-900 border-l border-slate-700 z-50 overflow-y-auto"
          >
            {/* Panel header */}
            <div className="sticky top-0 bg-slate-900 border-b border-slate-700 px-5 py-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Eye className="w-5 h-5 text-blue-400" />
                <div>
                  <h2 className="text-base font-semibold text-white">
                    Event Detail
                  </h2>
                  <p className="text-xs text-gray-500 font-mono">{event.id}</p>
                </div>
              </div>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Panel content */}
            <div className="p-5 space-y-5">
              {/* Summary */}
              <div className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
                <Badge
                  variant={SEVERITY_BADGE[event.severity]}
                  className="text-[10px] uppercase shrink-0"
                >
                  {event.severity}
                </Badge>
                <div>
                  <p className="text-sm font-medium text-white">
                    {event.action}
                  </p>
                  <p className="text-xs text-gray-400">
                    {formatTimestamp(event.timestamp)}
                  </p>
                </div>
                <div className="ml-auto">
                  <span
                    className={cn(
                      "text-xs font-semibold px-2 py-1 rounded",
                      event.result === "success"
                        ? "bg-green-600/20 text-green-400"
                        : "bg-red-600/20 text-red-400"
                    )}
                  >
                    {event.result.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Fields */}
              {[
                { label: "Request ID", value: event.request_id },
                { label: "Session ID", value: event.session_id },
                { label: "Actor", value: event.actor },
                { label: "IP Address", value: event.ip_address },
                { label: "Geo Location", value: event.geo_location },
                { label: "Resource", value: event.resource },
                {
                  label: "Event Type",
                  value: EVENT_TYPE_LABEL[event.event_type],
                },
                {
                  label: "Response Status",
                  value: String(event.response_status),
                },
              ].map(({ label, value }) => (
                <div key={label} className="flex gap-3">
                  <span className="text-xs text-gray-500 w-36 shrink-0 pt-0.5">
                    {label}
                  </span>
                  <span className="text-xs text-gray-200 font-mono break-all">
                    {value}
                  </span>
                </div>
              ))}

              {/* User Agent */}
              <div className="flex gap-3">
                <span className="text-xs text-gray-500 w-36 shrink-0 pt-0.5">
                  User Agent
                </span>
                <span className="text-xs text-gray-200 font-mono break-all">
                  {event.user_agent}
                </span>
              </div>

              {/* Request Body */}
              <div>
                <p className="text-xs text-gray-500 mb-2">Request Body</p>
                <pre className="bg-slate-800 rounded p-3 text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap break-all">
                  {event.request_body}
                </pre>
              </div>

              {/* Config change diff */}
              {(event.previous_value || event.new_value) && (
                <div className="space-y-2">
                  <p className="text-xs text-gray-500">Change Diff</p>
                  {event.previous_value && (
                    <div className="bg-red-900/20 border border-red-700/30 rounded p-3">
                      <p className="text-[10px] text-red-400 mb-1 uppercase font-semibold">
                        Previous
                      </p>
                      <p className="text-xs font-mono text-red-300">
                        {event.previous_value}
                      </p>
                    </div>
                  )}
                  {event.new_value && (
                    <div className="bg-green-900/20 border border-green-700/30 rounded p-3">
                      <p className="text-[10px] text-green-400 mb-1 uppercase font-semibold">
                        New
                      </p>
                      <p className="text-xs font-mono text-green-300">
                        {event.new_value}
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Full JSON */}
              <div>
                <p className="text-xs text-gray-500 mb-2">Full Event JSON</p>
                <pre className="bg-slate-800 rounded p-3 text-xs font-mono text-gray-400 overflow-x-auto whitespace-pre-wrap break-all">
                  {JSON.stringify(event, null, 2)}
                </pre>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}

// ══════════════════════════════════════════════════════════════
// Main Page
// ══════════════════════════════════════════════════════════════

const PAGE_SIZE = 20;

export default function AuditLogPage() {
  const [dateRange, setDateRange] = useState("Last 24h");
  const [eventTypeFilter, setEventTypeFilter] = useState<"all" | EventType>(
    "all"
  );
  const [severityFilter, setSeverityFilter] = useState<"all" | Severity>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [currentPage, setCurrentPage] = useState(1);

  // Fetch events
  const { data: events = MOCK_EVENTS } = useQuery<AuditEvent[]>({
    queryKey: ["audit-events", dateRange, eventTypeFilter, severityFilter],
    queryFn: async () => {
      try {
        const params = new URLSearchParams({ limit: "100" });
        if (eventTypeFilter !== "all") params.set("event_type", eventTypeFilter);
        const res = await fetch(
          `${API_BASE}/api/v1/audit/logs?${params.toString()}`,
          { headers: { "X-API-Key": import.meta.env.VITE_API_KEY || "dev-key" } }
        );
        if (!res.ok) throw new Error("API unavailable");
        const data = await res.json();
        // Router returns { items: [...], total, limit, offset }
        return Array.isArray(data) ? data : (data.items ?? MOCK_EVENTS);
      } catch {
        return MOCK_EVENTS;
      }
    },
  });

  // Live stats from /api/v1/audit/user-activity for KPI enrichment
  const [liveStats, setLiveStats] = useState<any>(null);
  useEffect(() => {
    Promise.allSettled([
      fetch(`${API_BASE}/api/v1/audit/logs?limit=1000`, {
        headers: { "X-API-Key": import.meta.env.VITE_API_KEY || "dev-key" },
      }).then((r) => (r.ok ? r.json() : null)),
    ]).then(([logsRes]) => {
      if (logsRes.status === "fulfilled" && logsRes.value) {
        const data = logsRes.value;
        const items = Array.isArray(data) ? data : (data.items ?? []);
        setLiveStats({
          eventsTotal: data.total ?? items.length,
          failedAuth: items.filter((e: any) => e.event_type === "authentication" && (e.result === "failure" || e.action?.includes("FAIL"))).length,
          configChanges: items.filter((e: any) => e.event_type === "configuration").length,
          policyViolations: items.filter((e: any) => e.event_type === "policy_change" || e.action?.includes("POLICY")).length,
        });
      }
    });
  }, []);

  // Filter + search
  const filtered = useMemo(() => {
    const q = searchQuery.toLowerCase();
    return events.filter((e) => {
      if (eventTypeFilter !== "all" && e.event_type !== eventTypeFilter)
        return false;
      if (severityFilter !== "all" && e.severity !== severityFilter)
        return false;
      if (
        q &&
        !e.actor.toLowerCase().includes(q) &&
        !e.action.toLowerCase().includes(q) &&
        !e.resource.toLowerCase().includes(q) &&
        !e.ip_address.includes(q)
      )
        return false;
      return true;
    });
  }, [events, eventTypeFilter, severityFilter, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE
  );

  const handleExportCSV = useCallback(() => {
    const headers = [
      "ID",
      "Timestamp",
      "Severity",
      "Event Type",
      "Actor",
      "Action",
      "Resource",
      "Result",
      "IP Address",
    ];
    const rows = filtered.map((e) =>
      [
        e.id,
        e.timestamp,
        e.severity,
        e.event_type,
        e.actor,
        e.action,
        e.resource,
        e.result,
        e.ip_address,
      ].join(",")
    );
    const csv = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-log-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [filtered]);

  // KPI derivation — prefer live stats, fall back to mock-derived counts
  const kpis = {
    eventsToday: liveStats?.eventsTotal ?? 12847,
    failedAuth: liveStats?.failedAuth ?? (filtered.filter(
      (e) => e.event_type === "authentication" && e.result === "failure"
    ).length || 23),
    configChanges: liveStats?.configChanges ?? (filtered.filter(
      (e) => e.event_type === "configuration"
    ).length || 7),
    policyViolations: liveStats?.policyViolations ?? 3,
  };

  return (
    <div className="space-y-6 pb-8">
      {/* Page Header */}
      <PageHeader
        title="Audit Log"
        description="Immutable audit trail for compliance, forensics, and access review"
      />

      {/* Anomaly Highlights */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {ANOMALY_ALERTS.map((alert) => (
          <motion.div
            key={alert.id}
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            className={cn(
              "rounded-lg border p-4 flex gap-3",
              alert.level === "critical"
                ? "bg-red-900/10 border-red-700/40"
                : "bg-yellow-900/10 border-yellow-700/40"
            )}
          >
            <div className="shrink-0 mt-0.5">
              {alert.level === "critical" ? (
                <AlertCircle className="w-4 h-4 text-red-400" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-yellow-400" />
              )}
            </div>
            <div className="min-w-0">
              <p
                className={cn(
                  "text-sm font-semibold",
                  alert.level === "critical"
                    ? "text-red-300"
                    : "text-yellow-300"
                )}
              >
                {alert.message}
              </p>
              <p className="text-xs text-gray-400 mt-0.5">{alert.detail}</p>
              <p className="text-[10px] text-gray-500 mt-1 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {alert.time}
              </p>
            </div>
          </motion.div>
        ))}
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Events Today"
          value={kpis.eventsToday.toLocaleString()}
          icon={Activity}
          valueClassName="text-blue-400"
          trend="flat"
        />
        <KpiCard
          title="Failed Auth Attempts"
          value={kpis.failedAuth}
          icon={XCircle}
          valueClassName="text-red-400"
          trend="negative"
        />
        <KpiCard
          title="Config Changes"
          value={kpis.configChanges}
          icon={Settings}
          valueClassName="text-yellow-400"
          trend="flat"
        />
        <KpiCard
          title="Policy Violations"
          value={kpis.policyViolations}
          icon={AlertTriangle}
          valueClassName="text-orange-400"
          trend={kpis.policyViolations > 0 ? "negative" : "positive"}
        />
      </div>

      {/* Filter Bar */}
      <Card className="border-slate-700/50">
        <CardContent className="py-4">
          <div className="flex flex-wrap gap-3 items-center">
            {/* Date range */}
            <div className="flex items-center gap-2 bg-slate-800 border border-slate-700 rounded px-3 py-2 min-w-[140px]">
              <Clock className="w-4 h-4 text-gray-500 shrink-0" />
              <input
                type="text"
                value={dateRange}
                onChange={(e) => setDateRange(e.target.value)}
                className="bg-transparent text-sm text-white outline-none w-full"
                placeholder="Last 24h"
              />
            </div>

            {/* Event Type */}
            <select
              value={eventTypeFilter}
              onChange={(e) => {
                setEventTypeFilter(e.target.value as "all" | EventType);
                setCurrentPage(1);
              }}
              className="bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm text-white outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="all">All Event Types</option>
              <option value="authentication">Authentication</option>
              <option value="authorization">Authorization</option>
              <option value="configuration">Configuration</option>
              <option value="data_access">Data Access</option>
              <option value="admin_action">Admin Action</option>
            </select>

            {/* Severity */}
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value as "all" | Severity);
                setCurrentPage(1);
              }}
              className="bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm text-white outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>

            {/* Search */}
            <div className="flex items-center gap-2 bg-slate-800 border border-slate-700 rounded px-3 py-2 flex-1 min-w-[220px]">
              <Search className="w-4 h-4 text-gray-500 shrink-0" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
                placeholder="Search by user, action, resource..."
                className="bg-transparent text-sm text-white outline-none w-full placeholder-gray-500"
              />
            </div>

            {/* Export */}
            <Button
              onClick={handleExportCSV}
              variant="outline"
              className="border-slate-600 text-gray-300 hover:bg-slate-700 flex items-center gap-2 shrink-0"
            >
              <Download className="w-4 h-4" />
              Export CSV
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Events Table */}
      <Card className="border-slate-700/50">
        <CardHeader className="border-b border-slate-700/50 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-5 h-5 text-blue-400" />
              <CardTitle className="text-base">Audit Events</CardTitle>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-gray-500">
                {filtered.length} event{filtered.length !== 1 ? "s" : ""}
              </span>
              <Badge
                variant="secondary"
                className="bg-blue-600/20 text-blue-400 border-blue-600/30"
              >
                Page {currentPage} / {totalPages}
              </Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-slate-700/50 hover:bg-transparent">
                  <TableHead className="text-gray-400 text-xs w-40">
                    Timestamp
                  </TableHead>
                  <TableHead className="text-gray-400 text-xs w-24">
                    Severity
                  </TableHead>
                  <TableHead className="text-gray-400 text-xs w-32">
                    Event Type
                  </TableHead>
                  <TableHead className="text-gray-400 text-xs">Actor</TableHead>
                  <TableHead className="text-gray-400 text-xs">Action</TableHead>
                  <TableHead className="text-gray-400 text-xs max-w-[180px]">
                    Resource
                  </TableHead>
                  <TableHead className="text-gray-400 text-xs w-24">
                    Result
                  </TableHead>
                  <TableHead className="text-gray-400 text-xs w-32">
                    IP Address
                  </TableHead>
                  <TableHead className="text-gray-400 text-xs w-20 text-center">
                    Details
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginated.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={9}
                      className="text-center py-12 text-gray-500"
                    >
                      <Info className="w-8 h-8 mx-auto mb-2 opacity-30" />
                      No events match the current filters
                    </TableCell>
                  </TableRow>
                ) : (
                  paginated.map((event) => {
                    const TypeIcon = EVENT_TYPE_ICON[event.event_type];
                    return (
                      <motion.tr
                        key={event.id}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className={cn(
                          "border-slate-700/30 transition-colors cursor-pointer",
                          selectedEvent?.id === event.id
                            ? "bg-blue-900/20"
                            : "hover:bg-slate-800/40"
                        )}
                        onClick={() =>
                          setSelectedEvent(
                            selectedEvent?.id === event.id ? null : event
                          )
                        }
                      >
                        <TableCell className="text-xs font-mono text-gray-400 py-3">
                          {formatTimestamp(event.timestamp)}
                        </TableCell>
                        <TableCell className="py-3">
                          <Badge
                            variant={SEVERITY_BADGE[event.severity]}
                            className="text-[10px] uppercase"
                          >
                            {event.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="py-3">
                          <div className="flex items-center gap-1.5 text-xs text-gray-300">
                            <TypeIcon className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                            <span className="truncate">
                              {EVENT_TYPE_LABEL[event.event_type]}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="py-3">
                          <div className="flex items-center gap-1.5 text-xs">
                            <User className="w-3 h-3 text-gray-500 shrink-0" />
                            <span className="text-gray-200 truncate max-w-[120px]">
                              {event.actor}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="text-xs font-mono text-blue-400 py-3">
                          {event.action}
                        </TableCell>
                        <TableCell
                          className="text-xs text-gray-400 py-3 max-w-[180px] truncate font-mono"
                          title={event.resource}
                        >
                          {event.resource}
                        </TableCell>
                        <TableCell className="py-3">
                          <span
                            className={cn(
                              "text-xs font-semibold flex items-center gap-1",
                              event.result === "success"
                                ? "text-green-400"
                                : "text-red-400"
                            )}
                          >
                            {event.result === "success" ? (
                              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                            ) : (
                              <XCircle className="w-3.5 h-3.5 shrink-0" />
                            )}
                            {event.result === "success" ? "Success" : "Failure"}
                          </span>
                        </TableCell>
                        <TableCell className="text-xs font-mono text-gray-400 py-3">
                          {event.ip_address}
                        </TableCell>
                        <TableCell className="py-3 text-center">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedEvent(
                                selectedEvent?.id === event.id ? null : event
                              );
                            }}
                            className="text-gray-500 hover:text-blue-400 transition-colors"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </TableCell>
                      </motion.tr>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700/50">
              <span className="text-xs text-gray-500">
                Showing {(currentPage - 1) * PAGE_SIZE + 1}–
                {Math.min(currentPage * PAGE_SIZE, filtered.length)} of{" "}
                {filtered.length}
              </span>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  className="border-slate-600 h-7 px-2"
                  disabled={currentPage === 1}
                  onClick={() => setCurrentPage((p) => p - 1)}
                >
                  <ChevronLeft className="w-4 h-4" />
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="border-slate-600 h-7 px-2"
                  disabled={currentPage === totalPages}
                  onClick={() => setCurrentPage((p) => p + 1)}
                >
                  <ChevronRight className="w-4 h-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Event Detail Panel */}
      <EventDetailPanel
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  );
}
