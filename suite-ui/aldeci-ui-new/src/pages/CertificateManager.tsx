/**
 * Certificate Manager
 *
 * TLS/SSL certificate inventory, expiry tracking, and weak config detection.
 * Route: /certificates
 *
 * API: /api/v1/certificates — falls back to mock data on failure.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Search,
  RefreshCw,
  Lock,
  AlertCircle,
  Calendar,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = import.meta.env.VITE_API_KEY || "dev-key";
const ORG = "default";

async function apiFetch(path: string) {
  const res = await fetch(`${API}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

interface CertRecord {
  id: string;
  domain: string;
  issuer: string;
  not_after: string;
  not_before: string;
  algorithm: string;
  key_size: number;
  san_list: string[];
  wildcard: boolean;
  self_signed: boolean;
}

interface CertStats {
  total: number;
  expired: number;
  expiring_soon: number;
  healthy: number;
  by_issuer: Record<string, number>;
  avg_validity_days: number;
}

interface ExpiryAlerts {
  expired: CertRecord[];
  expiring_7d: CertRecord[];
  expiring_30d: CertRecord[];
  expiring_90d: CertRecord[];
}

interface CheckResult {
  domain: string;
  reachable: boolean;
  subject?: string;
  issuer?: string;
  not_after?: string;
  days_remaining?: number;
  algorithm?: string;
  tls_version?: string;
  san_list?: string[];
  wildcard?: boolean;
  error?: string;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_STATS: CertStats = {
  total: 47,
  expired: 2,
  expiring_soon: 8,
  healthy: 37,
  by_issuer: {
    "Let's Encrypt": 28,
    DigiCert: 11,
    Sectigo: 5,
    "Self-Signed": 3,
  },
  avg_validity_days: 82,
};

const MOCK_CERTS: CertRecord[] = [
  {
    id: "1",
    domain: "api.aldeci.io",
    issuer: "Let's Encrypt",
    not_before: "2026-01-15T00:00:00Z",
    not_after: "2026-04-15T00:00:00Z",
    algorithm: "sha256WithRSAEncryption",
    key_size: 2048,
    san_list: ["api.aldeci.io", "*.aldeci.io"],
    wildcard: true,
    self_signed: false,
  },
  {
    id: "2",
    domain: "app.aldeci.io",
    issuer: "DigiCert",
    not_before: "2025-06-01T00:00:00Z",
    not_after: "2026-06-01T00:00:00Z",
    algorithm: "sha256WithRSAEncryption",
    key_size: 4096,
    san_list: ["app.aldeci.io"],
    wildcard: false,
    self_signed: false,
  },
  {
    id: "3",
    domain: "legacy.internal",
    issuer: "legacy.internal",
    not_before: "2024-01-01T00:00:00Z",
    not_after: "2026-01-01T00:00:00Z",
    algorithm: "sha1WithRSAEncryption",
    key_size: 1024,
    san_list: [],
    wildcard: false,
    self_signed: true,
  },
  {
    id: "4",
    domain: "old-service.corp",
    issuer: "Sectigo",
    not_before: "2025-01-01T00:00:00Z",
    not_after: "2026-04-20T00:00:00Z",
    algorithm: "sha256WithRSAEncryption",
    key_size: 2048,
    san_list: ["old-service.corp"],
    wildcard: false,
    self_signed: false,
  },
  {
    id: "5",
    domain: "expired-svc.corp",
    issuer: "DigiCert",
    not_before: "2024-01-01T00:00:00Z",
    not_after: "2025-12-01T00:00:00Z",
    algorithm: "sha256WithRSAEncryption",
    key_size: 2048,
    san_list: ["expired-svc.corp"],
    wildcard: false,
    self_signed: false,
  },
];

const MOCK_WEAK: CertRecord[] = [
  { ...MOCK_CERTS[2], id: "3" },
];

const MOCK_ALERTS: ExpiryAlerts = {
  expired: [MOCK_CERTS[4]],
  expiring_7d: [MOCK_CERTS[0]],
  expiring_30d: [MOCK_CERTS[3]],
  expiring_90d: [],
};

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

function daysUntil(isoDate: string): number {
  const exp = new Date(isoDate).getTime();
  const now = Date.now();
  return Math.floor((exp - now) / 86400000);
}

function expiryLabel(isoDate: string): { label: string; color: string } {
  const days = daysUntil(isoDate);
  if (days < 0) return { label: "Expired", color: "text-red-400" };
  if (days <= 7) return { label: `${days}d`, color: "text-red-400" };
  if (days <= 30) return { label: `${days}d`, color: "text-amber-400" };
  if (days <= 90) return { label: `${days}d`, color: "text-yellow-400" };
  return { label: `${days}d`, color: "text-emerald-400" };
}

function statusBadge(cert: CertRecord) {
  const days = daysUntil(cert.not_after);
  if (days < 0) return <Badge variant="destructive">Expired</Badge>;
  if (days <= 7) return <Badge className="bg-red-900/60 text-red-300 border-red-700">Critical</Badge>;
  if (days <= 30) return <Badge className="bg-amber-900/60 text-amber-300 border-amber-700">Warning</Badge>;
  return <Badge className="bg-emerald-900/60 text-emerald-300 border-emerald-700">Healthy</Badge>;
}

// ═══════════════════════════════════════════════════════════
// KPI Card
// ═══════════════════════════════════════════════════════════

function KPICard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: number | string;
  icon: React.ElementType;
  color: string;
}) {
  return (
    <Card className="bg-slate-900/60 border-slate-700/50">
      <CardContent className="p-4 flex items-center gap-4">
        <div className={cn("p-2 rounded-lg", color)}>
          <Icon className="w-5 h-5" />
        </div>
        <div>
          <p className="text-2xl font-bold text-white">{value}</p>
          <p className="text-xs text-slate-400">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Domain Check Panel
// ═══════════════════════════════════════════════════════════

function DomainCheckPanel() {
  const [domain, setDomain] = useState("");
  const [result, setResult] = useState<CheckResult | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleCheck() {
    if (!domain.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const resp = await fetch(`${API}/api/v1/certificates/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
        body: JSON.stringify({ domain: domain.trim(), port: 443, timeout: 5 }),
      });
      const data = await resp.json();
      setResult(data);
    } catch {
      setResult({
        domain: domain.trim(),
        reachable: false,
        error: "Failed to reach API",
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="bg-slate-900/60 border-slate-700/50">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <Search className="w-4 h-4 text-blue-400" />
          Check Domain
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex gap-2">
          <Input
            placeholder="e.g. google.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleCheck()}
            className="bg-slate-800 border-slate-600 text-white placeholder:text-slate-500 text-sm"
          />
          <Button
            onClick={handleCheck}
            disabled={loading || !domain.trim()}
            size="sm"
            className="bg-blue-600 hover:bg-blue-700 text-white shrink-0"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : "Check"}
          </Button>
        </div>

        {result && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="rounded-md border border-slate-700 bg-slate-800/50 p-3 space-y-2 text-sm"
          >
            {!result.reachable ? (
              <div className="flex items-center gap-2 text-red-400">
                <XCircle className="w-4 h-4" />
                <span>{result.error || "Unreachable"}</span>
              </div>
            ) : (
              <>
                <div className="flex items-center gap-2 text-emerald-400">
                  <CheckCircle className="w-4 h-4" />
                  <span className="font-semibold">{result.domain}</span>
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-slate-300">
                  {result.issuer && (
                    <>
                      <span className="text-slate-500">Issuer</span>
                      <span className="truncate">{result.issuer}</span>
                    </>
                  )}
                  {result.not_after && (
                    <>
                      <span className="text-slate-500">Expires</span>
                      <span className={expiryLabel(result.not_after).color}>
                        {new Date(result.not_after).toLocaleDateString()} ({result.days_remaining}d)
                      </span>
                    </>
                  )}
                  {result.algorithm && (
                    <>
                      <span className="text-slate-500">Algorithm</span>
                      <span>{result.algorithm}</span>
                    </>
                  )}
                  {result.tls_version && (
                    <>
                      <span className="text-slate-500">TLS</span>
                      <span>{result.tls_version}</span>
                    </>
                  )}
                  {result.wildcard !== undefined && (
                    <>
                      <span className="text-slate-500">Wildcard</span>
                      <span>{result.wildcard ? "Yes" : "No"}</span>
                    </>
                  )}
                </div>
                {result.san_list && result.san_list.length > 0 && (
                  <div className="text-xs text-slate-400 pt-1">
                    SANs: {result.san_list.slice(0, 4).join(", ")}
                    {result.san_list.length > 4 && ` +${result.san_list.length - 4} more`}
                  </div>
                )}
              </>
            )}
          </motion.div>
        )}
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function CertificateManagerPage() {
  const [filter, setFilter] = useState("");

  const { data: stats = MOCK_STATS } = useQuery<CertStats>({
    queryKey: ["cert-stats", ORG],
    queryFn: () => apiFetch(`/api/v1/certificates/stats?org_id=${ORG}`),
    staleTime: 30_000,
    retry: false,
  });

  const { data: certs = MOCK_CERTS } = useQuery<CertRecord[]>({
    queryKey: ["certs-list", ORG],
    queryFn: async () => {
      const data = await apiFetch(`/api/v1/certificates/?org_id=${ORG}`);
      return Array.isArray(data) ? data : (data.items ?? data.certificates ?? MOCK_CERTS);
    },
    staleTime: 30_000,
    retry: false,
  });

  const { data: weakCerts = MOCK_WEAK } = useQuery<CertRecord[]>({
    queryKey: ["certs-weak", ORG],
    queryFn: async () => {
      const data = await apiFetch(`/api/v1/certificates/weak?org_id=${ORG}`);
      return Array.isArray(data) ? data : (data.items ?? data.certificates ?? MOCK_WEAK);
    },
    staleTime: 60_000,
    retry: false,
  });

  const { data: alerts = MOCK_ALERTS } = useQuery<ExpiryAlerts>({
    queryKey: ["certs-alerts", ORG],
    queryFn: () => apiFetch(`/api/v1/certificates/alerts/expiry?org_id=${ORG}`),
    staleTime: 30_000,
    retry: false,
  });

  const filtered = certs.filter(
    (c) =>
      !filter ||
      c.domain.toLowerCase().includes(filter.toLowerCase()) ||
      c.issuer.toLowerCase().includes(filter.toLowerCase()),
  );

  const urgentCerts = [
    ...alerts.expired,
    ...alerts.expiring_7d,
    ...alerts.expiring_30d,
  ].slice(0, 6);

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Certificate Manager"
        description="TLS/SSL certificate inventory, expiry tracking, and weak config detection"
        icon={<Lock className="w-5 h-5 text-blue-400" />}
      />

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KPICard
          label="Total Certificates"
          value={stats.total}
          icon={Shield}
          color="bg-blue-900/40 text-blue-400"
        />
        <KPICard
          label="Expired"
          value={stats.expired}
          icon={XCircle}
          color="bg-red-900/40 text-red-400"
        />
        <KPICard
          label="Expiring (30d)"
          value={stats.expiring_soon}
          icon={AlertTriangle}
          color="bg-amber-900/40 text-amber-400"
        />
        <KPICard
          label="Healthy"
          value={stats.healthy}
          icon={CheckCircle}
          color="bg-emerald-900/40 text-emerald-400"
        />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Left column: expiry timeline + weak certs */}
        <div className="xl:col-span-1 flex flex-col gap-4">
          {/* Expiry timeline */}
          <Card className="bg-slate-900/60 border-slate-700/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Calendar className="w-4 h-4 text-amber-400" />
                Expiry Timeline
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <ScrollArea className="h-56">
                {urgentCerts.length === 0 ? (
                  <p className="text-slate-400 text-xs px-4 py-3">No urgent expirations</p>
                ) : (
                  urgentCerts.map((cert) => {
                    const { label, color } = expiryLabel(cert.not_after);
                    return (
                      <div
                        key={cert.id}
                        className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800 last:border-0 hover:bg-slate-800/40 transition-colors"
                      >
                        <div className="min-w-0">
                          <p className="text-xs font-medium text-slate-200 truncate">{cert.domain}</p>
                          <p className="text-xs text-slate-500 truncate">{cert.issuer}</p>
                        </div>
                        <div className={cn("text-xs font-bold shrink-0 ml-2", color)}>
                          {label}
                        </div>
                      </div>
                    );
                  })
                )}
              </ScrollArea>
            </CardContent>
          </Card>

          {/* Weak certs */}
          <Card className="bg-slate-900/60 border-slate-700/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-red-400" />
                Weak Configurations
                {weakCerts.length > 0 && (
                  <Badge variant="destructive" className="ml-auto text-xs">
                    {weakCerts.length}
                  </Badge>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <ScrollArea className="h-48">
                {weakCerts.length === 0 ? (
                  <div className="flex items-center gap-2 px-4 py-3 text-emerald-400 text-xs">
                    <CheckCircle className="w-4 h-4" />
                    No weak certificates detected
                  </div>
                ) : (
                  weakCerts.map((cert) => (
                    <div
                      key={cert.id}
                      className="px-4 py-2.5 border-b border-slate-800 last:border-0 space-y-0.5"
                    >
                      <p className="text-xs font-medium text-red-300 truncate">{cert.domain}</p>
                      <p className="text-xs text-slate-500">
                        {cert.algorithm || "Unknown algorithm"} ·{" "}
                        {cert.key_size > 0 ? `${cert.key_size}-bit` : "unknown key size"}
                        {cert.self_signed && " · Self-signed"}
                      </p>
                    </div>
                  ))
                )}
              </ScrollArea>
            </CardContent>
          </Card>

          {/* Domain check */}
          <DomainCheckPanel />
        </div>

        {/* Right column: certificate table */}
        <div className="xl:col-span-2">
          <Card className="bg-slate-900/60 border-slate-700/50 h-full">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between gap-3">
                <CardTitle className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Clock className="w-4 h-4 text-blue-400" />
                  Certificate Inventory
                  <Badge className="bg-slate-700 text-slate-300 text-xs">{certs.length}</Badge>
                </CardTitle>
                <div className="relative w-48">
                  <Search className="absolute left-2.5 top-2 w-3.5 h-3.5 text-slate-500" />
                  <Input
                    placeholder="Filter domain / issuer..."
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    className="pl-8 h-7 text-xs bg-slate-800 border-slate-600 text-white placeholder:text-slate-500"
                  />
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-800">
                      <th className="text-left px-4 py-2.5 text-slate-400 font-medium">Domain</th>
                      <th className="text-left px-4 py-2.5 text-slate-400 font-medium">Issuer</th>
                      <th className="text-left px-4 py-2.5 text-slate-400 font-medium">Expires</th>
                      <th className="text-left px-4 py-2.5 text-slate-400 font-medium">Algorithm</th>
                      <th className="text-left px-4 py-2.5 text-slate-400 font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-4 py-6 text-center text-slate-500">
                          No certificates match filter
                        </td>
                      </tr>
                    ) : (
                      filtered.map((cert) => {
                        const { label, color } = expiryLabel(cert.not_after);
                        return (
                          <tr
                            key={cert.id}
                            className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors"
                          >
                            <td className="px-4 py-2.5">
                              <div className="flex items-center gap-1.5">
                                {cert.wildcard && (
                                  <span className="text-blue-400 text-xs">*</span>
                                )}
                                <span className="text-slate-200 font-medium truncate max-w-[160px]">
                                  {cert.domain}
                                </span>
                              </div>
                            </td>
                            <td className="px-4 py-2.5 text-slate-400 truncate max-w-[120px]">
                              {cert.issuer || "—"}
                            </td>
                            <td className={cn("px-4 py-2.5 font-semibold", color)}>
                              {label}
                            </td>
                            <td className="px-4 py-2.5 text-slate-400 truncate max-w-[140px]">
                              {cert.algorithm
                                ? cert.algorithm.replace("WithRSAEncryption", "")
                                : "—"}
                              {cert.key_size > 0 && (
                                <span className="text-slate-500"> ({cert.key_size})</span>
                              )}
                            </td>
                            <td className="px-4 py-2.5">{statusBadge(cert)}</td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
