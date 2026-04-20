/**
 * Secrets Rotation Tracker
 *
 * Secrets lifecycle management dashboard with rotation schedule, inventory, and audit log.
 * Route: /secrets-rotation
 *
 * Features:
 *   1. Alert banner for overdue secrets
 *   2. Top KPIs: Total Tracked, Overdue, Due This Week, Compliant %
 *   3. Secrets Inventory table with status badges
 *   4. Rotation Calendar showing next 30 days
 *   5. Rotation History audit log
 *   6. Filters by status (All, Overdue, Due This Week, Compliant)
 *
 * API: GET /api/v1/secrets-rotation/list — fallback to mock data on failure
 */

import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle,
  Key,
  Shield,
  Clock,
  CheckCircle2,
  XCircle,
  Calendar,
  History,
  Plus,
  X,
  ChevronRight,
  AlertCircle,
  Lock,
  FileText,
  User,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type SecretType = "api_key" | "certificate" | "password" | "token";
type SecretStatus = "compliant" | "due_soon" | "overdue" | "unknown";

interface Secret {
  id: string;
  name: string;
  type: SecretType;
  service: string;
  last_rotated: string;
  next_rotation: string;
  status: SecretStatus;
  days_until_due: number;
  owner?: string;
}

interface RotationHistoryEvent {
  id: string;
  secret_name: string;
  rotated_by: string;
  rotated_at: string;
  old_expiry: string;
  new_expiry: string;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_SECRETS: Secret[] = [
  { id: "s1", name: "AWS Root Key", type: "api_key", service: "AWS", last_rotated: "2025-10-15", next_rotation: "2026-04-10", status: "overdue", days_until_due: -4, owner: "infra-team" },
  { id: "s2", name: "GitHub PAT", type: "token", service: "GitHub", last_rotated: "2026-02-01", next_rotation: "2026-05-15", status: "due_soon", days_until_due: 31, owner: "devops-team" },
  { id: "s3", name: "Okta Client Secret", type: "api_key", service: "Okta", last_rotated: "2026-01-20", next_rotation: "2026-07-20", status: "compliant", days_until_due: 97, owner: "security-team" },
  { id: "s4", name: "Slack Bot Token", type: "token", service: "Slack", last_rotated: "2025-11-10", next_rotation: "2026-04-12", status: "overdue", days_until_due: -2, owner: "platform-team" },
  { id: "s5", name: "Production DB Password", type: "password", service: "PostgreSQL", last_rotated: "2026-03-01", next_rotation: "2026-06-01", status: "due_soon", days_until_due: 48, owner: "dba-team" },
  { id: "s6", name: "TLS Certificate", type: "certificate", service: "Let's Encrypt", last_rotated: "2025-12-20", next_rotation: "2026-04-20", status: "due_soon", days_until_due: 6, owner: "infra-team" },
  { id: "s7", name: "JWT Signing Key", type: "api_key", service: "Internal Auth", last_rotated: "2026-02-10", next_rotation: "2026-08-10", status: "compliant", days_until_due: 118, owner: "security-team" },
  { id: "s8", name: "OpenAI API Key", type: "api_key", service: "OpenAI", last_rotated: "2026-01-05", next_rotation: "2026-07-05", status: "compliant", days_until_due: 82, owner: "ai-team" },
  { id: "s9", name: "Stripe API Key", type: "api_key", service: "Stripe", last_rotated: "2025-09-14", next_rotation: "2026-04-14", status: "overdue", days_until_due: 0, owner: "billing-team" },
  { id: "s10", name: "Admin SSH Key", type: "api_key", service: "Infrastructure", last_rotated: "2026-02-28", next_rotation: "2026-05-28", status: "due_soon", days_until_due: 44, owner: "sre-team" },
];

const MOCK_HISTORY: RotationHistoryEvent[] = [
  { id: "h1", secret_name: "TLS Certificate", rotated_by: "john.doe", rotated_at: "2025-12-20T14:32:00Z", old_expiry: "2025-12-20", new_expiry: "2026-04-20" },
  { id: "h2", secret_name: "Okta Client Secret", rotated_by: "alice.smith", rotated_at: "2026-01-20T09:15:00Z", old_expiry: "2026-01-20", new_expiry: "2026-07-20" },
  { id: "h3", secret_name: "JWT Signing Key", rotated_by: "bob.johnson", rotated_at: "2026-02-10T11:45:00Z", old_expiry: "2026-02-10", new_expiry: "2026-08-10" },
  { id: "h4", secret_name: "OpenAI API Key", rotated_by: "charlie.brown", rotated_at: "2026-01-05T16:20:00Z", old_expiry: "2026-01-05", new_expiry: "2026-07-05" },
  { id: "h5", secret_name: "Admin SSH Key", rotated_by: "diana.prince", rotated_at: "2026-02-28T13:10:00Z", old_expiry: "2026-02-28", new_expiry: "2026-05-28" },
];

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

const TYPE_CONFIG: Record<SecretType, { label: string; icon: typeof Key; color: string }> = {
  api_key:    { label: "API Key",       icon: Key,       color: "text-cyan-400 bg-cyan-500/10" },
  certificate: { label: "Certificate",  icon: Lock,      color: "text-purple-400 bg-purple-500/10" },
  password:   { label: "Password",      icon: Shield,    color: "text-orange-400 bg-orange-500/10" },
  token:      { label: "Token",         icon: Zap,       color: "text-blue-400 bg-blue-500/10" },
};

function statusColor(status: SecretStatus): string {
  if (status === "overdue")   return "text-red-400 bg-red-500/10 border-red-500/20";
  if (status === "due_soon")  return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";
  if (status === "compliant") return "text-green-400 bg-green-500/10 border-green-500/20";
  return "text-gray-400 bg-gray-500/10 border-gray-500/20";
}

function statusLabel(status: SecretStatus): string {
  if (status === "overdue")   return "Overdue";
  if (status === "due_soon")  return "Due Soon";
  if (status === "compliant") return "Compliant";
  return "Unknown";
}

function statusIcon(status: SecretStatus) {
  if (status === "overdue")   return XCircle;
  if (status === "due_soon")  return AlertCircle;
  if (status === "compliant") return CheckCircle2;
  return AlertTriangle;
}

// ═══════════════════════════════════════════════════════════
// Rotation Calendar
// ═══════════════════════════════════════════════════════════

function RotationCalendar({ secrets }: { secrets: Secret[] }) {
  const today = new Date();
  const days: (Date | null)[] = [];
  const firstDay = new Date(today.getFullYear(), today.getMonth(), 1);
  const lastDay = new Date(today.getFullYear(), today.getMonth() + 1, 0);
  const startDate = new Date(firstDay);
  startDate.setDate(startDate.getDate() - firstDay.getDay());

  for (let i = 0; i < 42; i++) {
    const d = new Date(startDate);
    d.setDate(d.getDate() + i);
    if (d.getMonth() === today.getMonth()) {
      days.push(d);
    } else if (i === 0 || i > 35) {
      days.push(null);
    }
  }

  const dueDates = new Set(
    secrets
      .filter((s) => s.status === "overdue" || s.status === "due_soon")
      .map((s) => new Date(s.next_rotation).toDateString())
  );

  return (
    <Card className="border border-border">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Calendar className="w-4 h-4 text-purple-400" />
          Next 30 Days
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-7 gap-2">
          {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map((d) => (
            <div key={d} className="text-center text-xs font-medium text-muted-foreground py-1">
              {d}
            </div>
          ))}
          {days.map((day, i) => (
            <div
              key={i}
              className={cn(
                "aspect-square flex items-center justify-center text-xs rounded border",
                day === null
                  ? "border-transparent"
                  : dueDates.has(day.toDateString())
                  ? "border-red-500/30 bg-red-500/10 text-red-400 font-semibold"
                  : "border-border text-muted-foreground hover:border-primary/30"
              )}
            >
              {day?.getDate()}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Secret Row
// ═══════════════════════════════════════════════════════════

function SecretRow({
  secret,
  index,
}: {
  secret: Secret;
  index: number;
}) {
  const TypeIcon = TYPE_CONFIG[secret.type].icon;
  const StatusIcon = statusIcon(secret.status);

  return (
    <motion.tr
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.03, duration: 0.25 }}
      className={cn(
        "border-b border-border/50 hover:bg-accent/30 transition-colors",
        secret.status === "overdue" && "bg-red-500/5"
      )}
    >
      <td className="py-3 px-4">
        <div className="flex items-center gap-2.5">
          <div className={cn("rounded p-1", TYPE_CONFIG[secret.type].color)}>
            <TypeIcon className="w-3.5 h-3.5" />
          </div>
          <span className="text-sm font-medium font-mono">{secret.name}</span>
        </div>
      </td>
      <td className="py-3 px-4">
        <span className="text-xs text-muted-foreground">{TYPE_CONFIG[secret.type].label}</span>
      </td>
      <td className="py-3 px-4">
        <span className="text-xs text-muted-foreground">{secret.service}</span>
      </td>
      <td className="py-3 px-4 text-xs text-muted-foreground">
        {secret.last_rotated}
      </td>
      <td className="py-3 px-4 text-xs text-muted-foreground">
        {secret.next_rotation}
      </td>
      <td className="py-3 px-4">
        <div className="flex items-center gap-2">
          <StatusIcon className="w-4 h-4" />
          <Badge className={cn("text-xs border", statusColor(secret.status))}>
            {statusLabel(secret.status)}
          </Badge>
          {secret.days_until_due >= 0 && (
            <span className="text-xs text-muted-foreground">
              ({secret.days_until_due}d)
            </span>
          )}
          {secret.days_until_due < 0 && (
            <span className="text-xs text-red-400 font-semibold">
              {Math.abs(secret.days_until_due)}d overdue
            </span>
          )}
        </div>
      </td>
    </motion.tr>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function SecretsRotation() {
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const { data: secrets } = useQuery<Secret[]>({
    queryKey: ["secrets-rotation"],
    queryFn: async () => {
      const res = await fetch(`${API}/api/v1/secrets-rotation/?org_id=default`);
      if (!res.ok) throw new Error("secrets api unavailable");
      return res.json();
    },
    retry: 1,
    staleTime: 60_000,
    initialData: MOCK_SECRETS,
  });

  const filtered = useMemo(() => {
    if (!secrets) return [];
    return secrets.filter((s) => {
      if (statusFilter === "overdue") return s.status === "overdue";
      if (statusFilter === "due_soon") return s.status === "due_soon";
      if (statusFilter === "compliant") return s.status === "compliant";
      return true;
    });
  }, [secrets, statusFilter]);

  const totalSecrets = secrets?.length ?? 0;
  const overdueCount = secrets?.filter((s) => s.status === "overdue").length ?? 0;
  const dueSoonCount = secrets?.filter((s) => s.status === "due_soon").length ?? 0;
  const compliantCount = secrets?.filter((s) => s.status === "compliant").length ?? 0;
  const compliantPercent = totalSecrets > 0 ? Math.round((compliantCount / totalSecrets) * 100) : 0;

  const hasOverdue = overdueCount > 0;

  return (
    <div className="flex flex-col gap-6 p-6 h-full">
      {/* Header */}
      <PageHeader
        title="Secrets Rotation Tracker"
        description="API keys, certificates, and credential lifecycle management"
        badge="SECRETS"
      />

      {/* Alert banner */}
      <AnimatePresence>
        {hasOverdue && (
          <motion.div
            initial={{ opacity: 0, y: -12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -12 }}
            className="flex items-start gap-3 px-4 py-3 rounded-lg border border-red-500/30 bg-red-500/5"
          >
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div className="min-w-0">
              <p className="text-sm font-semibold text-red-400">
                {overdueCount} secret{overdueCount === 1 ? "" : "s"} overdue for rotation
              </p>
              <p className="text-xs text-red-300/70 mt-0.5">
                Rotate these secrets immediately to maintain security compliance
              </p>
            </div>
            <Button
              size="sm"
              variant="ghost"
              className="h-6 w-6 p-0 shrink-0 ml-auto"
              onClick={() => setStatusFilter("overdue")}
            >
              <ChevronRight className="w-4 h-4" />
            </Button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Total Secrets" value={totalSecrets} icon={Lock} />
        <KpiCard
          title="Overdue Rotation"
          value={overdueCount}
          icon={AlertTriangle}
          trend={overdueCount > 0 ? "up" : "down"}
          trendLabel={overdueCount > 0 ? "Needs attention" : "None"}
        />
        <KpiCard
          title="Due This Week"
          value={dueSoonCount}
          icon={Clock}
          trend="flat"
          trendLabel="Monitor closely"
        />
        <KpiCard
          title="Compliant"
          value={`${compliantPercent}%`}
          icon={CheckCircle2}
          trend={compliantPercent === 100 ? "up" : "flat"}
          trendLabel={compliantPercent === 100 ? "All in order" : "Some need rotation"}
        />
      </div>

      {/* Main content grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1 min-h-0">
        {/* Left: Inventory table */}
        <div className="lg:col-span-2 flex flex-col min-h-0">
          <div className="flex flex-col flex-1 overflow-hidden rounded-lg border border-border bg-card min-h-0">
            {/* Filter bar */}
            <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
              <span className="text-xs text-muted-foreground font-medium uppercase tracking-wide">Filter:</span>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="h-8 w-40 text-xs">
                  <SelectValue placeholder="All Secrets" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Secrets</SelectItem>
                  <SelectItem value="overdue">Overdue</SelectItem>
                  <SelectItem value="due_soon">Due This Week</SelectItem>
                  <SelectItem value="compliant">Compliant</SelectItem>
                </SelectContent>
              </Select>
              <span className="text-xs text-muted-foreground ml-auto">
                {filtered.length} of {totalSecrets} secrets
              </span>
              <Button size="sm" className="ml-2 h-8 px-3 gap-1.5 text-xs">
                <Plus className="w-3.5 h-3.5" />
                Add Secret
              </Button>
            </div>

            {/* Table */}
            <ScrollArea className="flex-1">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-xs text-muted-foreground sticky top-0 bg-card z-10">
                    <th className="py-2.5 px-4 text-left font-medium">Name</th>
                    <th className="py-2.5 px-4 text-left font-medium">Type</th>
                    <th className="py-2.5 px-4 text-left font-medium">Service</th>
                    <th className="py-2.5 px-4 text-left font-medium">Last Rotated</th>
                    <th className="py-2.5 px-4 text-left font-medium">Next Rotation</th>
                    <th className="py-2.5 px-4 text-left font-medium">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-16 text-center text-sm text-muted-foreground">
                        No secrets match the selected filter
                      </td>
                    </tr>
                  ) : (
                    filtered.map((secret, i) => (
                      <SecretRow key={secret.id} secret={secret} index={i} />
                    ))
                  )}
                </tbody>
              </table>
            </ScrollArea>
          </div>
        </div>

        {/* Right: Calendar + History */}
        <div className="flex flex-col gap-6 min-h-0">
          {/* Rotation Calendar */}
          <RotationCalendar secrets={secrets ?? []} />

          {/* Rotation History */}
          <Card className="border border-border flex-1 flex flex-col min-h-0 overflow-hidden">
            <CardHeader className="pb-3 shrink-0">
              <CardTitle className="text-sm flex items-center gap-2">
                <History className="w-4 h-4 text-blue-400" />
                Rotation History
              </CardTitle>
            </CardHeader>
            <CardContent className="flex-1 min-h-0 p-0">
              <ScrollArea className="h-full">
                <div className="space-y-3 p-4">
                  {MOCK_HISTORY.map((event, i) => (
                    <motion.div
                      key={event.id}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.05, duration: 0.2 }}
                      className="flex flex-col gap-1.5 pb-3 border-b border-border/50 last:border-0 last:pb-0"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-xs font-semibold text-foreground">{event.secret_name}</p>
                        <span className="text-[10px] text-muted-foreground shrink-0">
                          {new Date(event.rotated_at).toLocaleDateString()}
                        </span>
                      </div>
                      <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                        <User className="w-3 h-3" />
                        {event.rotated_by}
                      </div>
                      <div className="text-[11px] text-muted-foreground">
                        <span className="text-gray-500">{event.old_expiry}</span>
                        <span className="mx-1.5 text-gray-600">→</span>
                        <span className="text-green-400">{event.new_expiry}</span>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
