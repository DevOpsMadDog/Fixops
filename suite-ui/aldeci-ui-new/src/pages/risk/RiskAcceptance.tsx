/**
 * Risk Acceptance — Governance ledger for accepted risks
 *
 * Persona targets: CISO (P20), Security Manager, Compliance Officer (P07)
 * Aesthetic: Industrial risk ledger — amber/orange on deep slate, tabular density,
 *            expiration cells shift green → amber → red as deadline approaches.
 *
 * Route: /risk-acceptance
 */

import { useState, useMemo, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldAlert,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  PlusCircle,
  ChevronDown,
  ChevronUp,
  MessageSquare,
  CalendarClock,
  User,
  FileText,
  Search,
  Filter,
  RefreshCw,
  Inbox,
  ThumbsUp,
  ThumbsDown,
  Ban,
  Info,
  Building2,
  Layers,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type RiskSeverity = "critical" | "high" | "medium" | "low";
type AcceptanceStatus = "pending" | "accepted" | "rejected" | "expired";

interface CompensatingControl {
  id: string;
  description: string;
}

interface Comment {
  id: string;
  author: string;
  role: string;
  body: string;
  at: Date;
}

interface RiskAcceptanceRecord {
  id: string;
  finding_id: string;
  title: string;
  severity: RiskSeverity;
  status: AcceptanceStatus;
  requester: string;
  requester_role: string;
  approver?: string;
  submitted_at: Date;
  reviewed_at?: Date;
  expiration: Date;
  justification: string;
  compensating_controls: CompensatingControl[];
  comments: Comment[];
  asset: string;
  framework_ref?: string;
}

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

const now = new Date();
const daysAgo  = (d: number) => new Date(now.getTime() - d * 86_400_000);
const daysFrom = (d: number) => new Date(now.getTime() + d * 86_400_000);

function daysUntil(date: Date): number {
  return Math.ceil((date.getTime() - now.getTime()) / 86_400_000);
}

function formatDate(d: Date): string {
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function expirationClass(date: Date, status: AcceptanceStatus): string {
  if (status === "expired" || status === "rejected") return "text-red-400";
  if (status === "pending") return "text-muted-foreground";
  const days = daysUntil(date);
  if (days <= 7)  return "text-red-400 font-semibold";
  if (days <= 30) return "text-amber-400";
  return "text-green-400";
}

function expirationLabel(date: Date, status: AcceptanceStatus): string {
  if (status === "expired") return "Expired";
  if (status === "rejected") return "N/A";
  const days = daysUntil(date);
  if (days < 0)  return `Expired ${Math.abs(days)}d ago`;
  if (days === 0) return "Expires today";
  if (days === 1) return "1 day left";
  return `${days}d left`;
}

const SEVERITY_CONFIG: Record<RiskSeverity, { label: string; color: string; bg: string }> = {
  critical: { label: "Critical", color: "text-red-400",    bg: "bg-red-500/10 border border-red-500/20" },
  high:     { label: "High",     color: "text-orange-400", bg: "bg-orange-500/10 border border-orange-500/20" },
  medium:   { label: "Medium",   color: "text-amber-400",  bg: "bg-amber-500/10 border border-amber-500/20" },
  low:      { label: "Low",      color: "text-green-400",  bg: "bg-green-500/10 border border-green-500/20" },
};

const STATUS_CONFIG: Record<AcceptanceStatus, { label: string; icon: React.ElementType; color: string }> = {
  pending:  { label: "Pending",  icon: Clock,       color: "text-amber-400" },
  accepted: { label: "Accepted", icon: CheckCircle2, color: "text-green-400" },
  rejected: { label: "Rejected", icon: XCircle,      color: "text-red-400" },
  expired:  { label: "Expired",  icon: Ban,          color: "text-muted-foreground" },
};

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_RECORDS: RiskAcceptanceRecord[] = [
  {
    id: "RA-0024",
    finding_id: "FND-1892",
    title: "End-of-life OpenSSL 1.1.x in payment-service base image",
    severity: "high",
    status: "pending",
    requester: "Jordan Lee",
    requester_role: "Security Engineer",
    submitted_at: daysAgo(2),
    expiration: daysFrom(88),
    justification:
      "Upgrade blocked by third-party PCI-certified library vendor dependency. Vendor roadmap commits to updated build by Q3. Runtime firewall WAF rules and strict egress controls reduce exploitability to near-zero in current environment.",
    compensating_controls: [
      { id: "CC-1", description: "WAF rule blocking known OpenSSL 1.1 exploit payloads (Cloudflare rule set 001-A)" },
      { id: "CC-2", description: "Egress allow-list restricts outbound connections to 4 approved endpoints" },
      { id: "CC-3", description: "Quarterly penetration test in scope — last clean result 2026-02-14" },
    ],
    comments: [
      { id: "c1", author: "Alex Morgan", role: "CISO", body: "Compensating controls look reasonable. Need sign-off from compliance before I approve.", at: daysAgo(1) },
    ],
    asset: "payment-service:v4.1.0",
    framework_ref: "PCI-DSS 4.0 §6.3.3",
  },
  {
    id: "RA-0023",
    finding_id: "FND-1847",
    title: "Publicly writable S3 bucket: aldeci-reports-staging",
    severity: "medium",
    status: "pending",
    requester: "Sam Rivera",
    requester_role: "DevOps Lead",
    submitted_at: daysAgo(5),
    expiration: daysFrom(25),
    justification:
      "Staging bucket only — no PII or production data. Automated nightly cleanup job removes all objects after 24h. Bucket is referenced by external integration test harness that cannot authenticate.",
    compensating_controls: [
      { id: "CC-1", description: "CloudTrail logging on all S3 API calls with SIEM alerting on abnormal access" },
      { id: "CC-2", description: "Nightly Lambda job hard-deletes all objects. Retention > 24h is impossible." },
    ],
    comments: [],
    asset: "aws::s3::aldeci-reports-staging",
    framework_ref: "SOC 2 CC6.1",
  },
  {
    id: "RA-0022",
    finding_id: "FND-1821",
    title: "Missing HSTS header on internal admin portal (port 8443)",
    severity: "low",
    status: "accepted",
    requester: "Taylor Kim",
    requester_role: "Security Analyst",
    approver: "Alex Morgan",
    submitted_at: daysAgo(30),
    reviewed_at: daysAgo(28),
    expiration: daysFrom(62),
    justification:
      "Admin portal is internal-only, accessible exclusively over VPN. No internet exposure. HSTS on internal TLS is deferred to network-layer enforcement via mTLS at the Istio ingress.",
    compensating_controls: [
      { id: "CC-1", description: "mTLS enforced at Istio service mesh level — all admin traffic mutual-authenticated" },
      { id: "CC-2", description: "VPN required — zero public ingress route exists to port 8443" },
    ],
    comments: [
      { id: "c1", author: "Alex Morgan", role: "CISO", body: "Approved. mTLS at mesh layer is sufficient compensating control. Re-evaluate if admin portal scope changes.", at: daysAgo(28) },
    ],
    asset: "internal-admin:8443",
    framework_ref: "NIST CSF PR.PT-3",
  },
  {
    id: "RA-0021",
    finding_id: "FND-1798",
    title: "CVE-2023-44487 (HTTP/2 Rapid Reset) — nginx 1.24 in edge-proxy",
    severity: "high",
    status: "accepted",
    requester: "Jordan Lee",
    requester_role: "Security Engineer",
    approver: "Alex Morgan",
    submitted_at: daysAgo(90),
    reviewed_at: daysAgo(88),
    expiration: daysFrom(5),
    justification:
      "Mitigation applied via nginx config (limit_req, worker_connections, keepalive_requests capped). Full version upgrade requires kernel module rebuild scheduled for maintenance window 2026-04-18.",
    compensating_controls: [
      { id: "CC-1", description: "nginx rate-limit: 100 req/s burst, keepalive_requests capped at 50" },
      { id: "CC-2", description: "Cloudflare HTTP/2 Rapid Reset mitigation rule active upstream" },
    ],
    comments: [
      { id: "c1", author: "Alex Morgan", role: "CISO", body: "Time-boxed acceptance until maintenance window. Expires 2026-04-17.", at: daysAgo(88) },
    ],
    asset: "edge-proxy:nginx-1.24",
    framework_ref: "CVE-2023-44487",
  },
  {
    id: "RA-0020",
    finding_id: "FND-1703",
    title: "Weak TLS 1.0/1.1 ciphers in legacy billing API",
    severity: "medium",
    status: "expired",
    requester: "Chris Park",
    requester_role: "Backend Engineer",
    approver: "Alex Morgan",
    submitted_at: daysAgo(200),
    reviewed_at: daysAgo(198),
    expiration: daysAgo(15),
    justification:
      "Billing API client (third-party POS system) does not support TLS 1.2. Acceptance granted for 180 days while vendor migrates.",
    compensating_controls: [
      { id: "CC-1", description: "Connection limited to single vendor IP via allowlist" },
    ],
    comments: [
      { id: "c1", author: "Alex Morgan", role: "CISO", body: "Approved with strict vendor SLA. Auto-expires 2026-03-28 — no renewal without re-submission.", at: daysAgo(198) },
      { id: "c2", author: "System", role: "Automation", body: "Acceptance expired. Finding FND-1703 status reset to OPEN.", at: daysAgo(15) },
    ],
    asset: "billing-api:v2.0-legacy",
    framework_ref: "PCI-DSS 4.0 §4.2.1",
  },
  {
    id: "RA-0019",
    finding_id: "FND-1677",
    title: "Default admin credentials in RabbitMQ management console",
    severity: "critical",
    status: "rejected",
    requester: "Dana Walsh",
    requester_role: "Junior DevOps",
    submitted_at: daysAgo(60),
    reviewed_at: daysAgo(59),
    expiration: daysFrom(0),
    justification:
      "RabbitMQ management UI only accessible from internal network. Requested temporary acceptance while team schedules rotation.",
    compensating_controls: [],
    comments: [
      { id: "c1", author: "Alex Morgan", role: "CISO", body: "Rejected. Default credentials are never acceptable even on internal services. Rotate immediately — this takes 10 minutes. No compensating controls provided.", at: daysAgo(59) },
    ],
    asset: "rabbitmq:management-console",
  },
];

// ═══════════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════════

function SeverityBadge({ severity }: { severity: RiskSeverity }) {
  const cfg = SEVERITY_CONFIG[severity];
  return (
    <span className={cn("inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide", cfg.color, cfg.bg)}>
      {cfg.label}
    </span>
  );
}

function StatusChip({ status }: { status: AcceptanceStatus }) {
  const cfg = STATUS_CONFIG[status];
  const Icon = cfg.icon;
  return (
    <span className={cn("inline-flex items-center gap-1 text-xs font-medium", cfg.color)}>
      <Icon className="h-3.5 w-3.5" />
      {cfg.label}
    </span>
  );
}

// ═══════════════════════════════════════════════════════════
// New Request Form
// ═══════════════════════════════════════════════════════════

interface NewRequestFormProps {
  onSubmit: (record: Omit<RiskAcceptanceRecord, "id" | "status" | "submitted_at" | "comments">) => void;
  onCancel: () => void;
}

function NewRequestForm({ onSubmit, onCancel }: NewRequestFormProps) {
  const [form, setForm] = useState({
    finding_id: "",
    title: "",
    severity: "medium" as RiskSeverity,
    asset: "",
    justification: "",
    controls: [""],
    expiration_days: "90",
    framework_ref: "",
  });

  const set = (key: string, val: string) => setForm((f) => ({ ...f, [key]: val }));

  const addControl = () => setForm((f) => ({ ...f, controls: [...f.controls, ""] }));
  const setControl = (i: number, val: string) =>
    setForm((f) => {
      const c = [...f.controls];
      c[i] = val;
      return { ...f, controls: c };
    });
  const removeControl = (i: number) =>
    setForm((f) => ({ ...f, controls: f.controls.filter((_, idx) => idx !== i) }));

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      finding_id: form.finding_id,
      title: form.title,
      severity: form.severity,
      asset: form.asset,
      justification: form.justification,
      compensating_controls: form.controls
        .filter(Boolean)
        .map((d, i) => ({ id: `CC-${i + 1}`, description: d })),
      expiration: daysFrom(parseInt(form.expiration_days, 10) || 90),
      requester: "You",
      requester_role: "Security Engineer",
      framework_ref: form.framework_ref || undefined,
    });
  };

  const labelCls = "text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5 block";
  const inputCls = "bg-card border-border text-sm";

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className={labelCls}>Finding ID</label>
          <Input className={inputCls} placeholder="FND-XXXX" value={form.finding_id} onChange={(e) => set("finding_id", e.target.value)} required />
        </div>
        <div>
          <label className={labelCls}>Severity</label>
          <Select value={form.severity} onValueChange={(v) => set("severity", v)}>
            <SelectTrigger className={inputCls}><SelectValue /></SelectTrigger>
            <SelectContent>
              {(["critical", "high", "medium", "low"] as RiskSeverity[]).map((s) => (
                <SelectItem key={s} value={s}>{SEVERITY_CONFIG[s].label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div>
        <label className={labelCls}>Finding Title</label>
        <Input className={inputCls} placeholder="Brief description of the finding" value={form.title} onChange={(e) => set("title", e.target.value)} required />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className={labelCls}>Affected Asset</label>
          <Input className={inputCls} placeholder="service:version or arn::" value={form.asset} onChange={(e) => set("asset", e.target.value)} required />
        </div>
        <div>
          <label className={labelCls}>Framework Reference</label>
          <Input className={inputCls} placeholder="e.g. SOC 2 CC6.1, PCI-DSS 4.0" value={form.framework_ref} onChange={(e) => set("framework_ref", e.target.value)} />
        </div>
      </div>

      <div>
        <label className={labelCls}>Business Justification</label>
        <Textarea
          className={cn(inputCls, "min-h-[100px] resize-none")}
          placeholder="Why must this risk be accepted rather than remediated? Include timeline, business impact of remediation, and any external dependencies."
          value={form.justification}
          onChange={(e) => set("justification", e.target.value)}
          required
        />
      </div>

      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label className={cn(labelCls, "mb-0")}>Compensating Controls</label>
          <Button type="button" variant="ghost" size="sm" className="h-6 text-xs gap-1 text-muted-foreground hover:text-foreground" onClick={addControl}>
            <PlusCircle className="h-3 w-3" /> Add
          </Button>
        </div>
        <div className="space-y-2">
          {form.controls.map((ctrl, i) => (
            <div key={i} className="flex gap-2">
              <Input
                className={cn(inputCls, "flex-1")}
                placeholder={`Control ${i + 1}: describe the mitigating measure`}
                value={ctrl}
                onChange={(e) => setControl(i, e.target.value)}
              />
              {form.controls.length > 1 && (
                <Button type="button" variant="ghost" size="icon" className="h-9 w-9 shrink-0 text-muted-foreground hover:text-red-400" onClick={() => removeControl(i)}>
                  <XCircle className="h-4 w-4" />
                </Button>
              )}
            </div>
          ))}
        </div>
      </div>

      <div>
        <label className={labelCls}>Acceptance Duration</label>
        <Select value={form.expiration_days} onValueChange={(v) => set("expiration_days", v)}>
          <SelectTrigger className={inputCls}><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="30">30 days</SelectItem>
            <SelectItem value="60">60 days</SelectItem>
            <SelectItem value="90">90 days (default)</SelectItem>
            <SelectItem value="180">180 days</SelectItem>
            <SelectItem value="365">1 year (requires CISO approval)</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="flex justify-end gap-2 pt-2 border-t border-border">
        <Button type="button" variant="outline" onClick={onCancel}>Cancel</Button>
        <Button type="submit" className="bg-amber-500 hover:bg-amber-400 text-black font-semibold">
          Submit for Approval
        </Button>
      </div>
    </form>
  );
}

// ═══════════════════════════════════════════════════════════
// Detail / Approval Dialog
// ═══════════════════════════════════════════════════════════

interface DetailDialogProps {
  record: RiskAcceptanceRecord;
  onClose: () => void;
  onApprove: (id: string, comment: string) => void;
  onReject: (id: string, comment: string) => void;
}

function DetailDialog({ record, onClose, onApprove, onReject }: DetailDialogProps) {
  const [comment, setComment] = useState("");
  const isPending = record.status === "pending";

  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="max-w-2xl bg-card border-border">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-3 text-base">
            <span className="font-mono text-xs text-muted-foreground bg-muted px-2 py-1 rounded">{record.id}</span>
            <span className="flex-1 truncate">{record.title}</span>
            <SeverityBadge severity={record.severity} />
          </DialogTitle>
        </DialogHeader>

        <ScrollArea className="max-h-[70vh] pr-2">
          <div className="space-y-5 pb-2">
            {/* Meta row */}
            <div className="grid grid-cols-3 gap-3 text-xs">
              {[
                { icon: User,        label: "Requester", value: `${record.requester} · ${record.requester_role}` },
                { icon: FileText,    label: "Finding",   value: record.finding_id },
                { icon: Building2,   label: "Asset",     value: record.asset },
                { icon: CalendarClock, label: "Submitted", value: formatDate(record.submitted_at) },
                { icon: Clock,       label: "Expires",   value: formatDate(record.expiration) },
                { icon: Layers,      label: "Framework", value: record.framework_ref ?? "—" },
              ].map(({ icon: Icon, label, value }) => (
                <div key={label} className="flex flex-col gap-1 rounded-lg bg-muted/40 px-3 py-2">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                    <Icon className="h-3 w-3" />{label}
                  </div>
                  <span className="font-medium text-foreground truncate" title={value}>{value}</span>
                </div>
              ))}
            </div>

            {/* Status */}
            <div className="flex items-center gap-2">
              <StatusChip status={record.status} />
              {record.approver && (
                <span className="text-xs text-muted-foreground">— reviewed by {record.approver} on {formatDate(record.reviewed_at!)}</span>
              )}
            </div>

            <Separator />

            {/* Justification */}
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Business Justification</p>
              <p className="text-sm leading-relaxed text-foreground/90">{record.justification}</p>
            </div>

            {/* Compensating Controls */}
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                Compensating Controls ({record.compensating_controls.length})
              </p>
              {record.compensating_controls.length === 0 ? (
                <p className="text-xs text-red-400 flex items-center gap-1.5">
                  <AlertTriangle className="h-3.5 w-3.5" /> No compensating controls provided
                </p>
              ) : (
                <ul className="space-y-2">
                  {record.compensating_controls.map((cc) => (
                    <li key={cc.id} className="flex items-start gap-2.5 text-sm">
                      <CheckCircle2 className="h-3.5 w-3.5 mt-0.5 shrink-0 text-green-400" />
                      <span className="text-foreground/80">{cc.description}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Comments */}
            {record.comments.length > 0 && (
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                  Comments ({record.comments.length})
                </p>
                <div className="space-y-3">
                  {record.comments.map((c) => (
                    <div key={c.id} className="rounded-lg bg-muted/40 p-3 space-y-1">
                      <div className="flex items-center gap-2 text-xs">
                        <span className="font-medium text-foreground">{c.author}</span>
                        <span className="text-muted-foreground">· {c.role}</span>
                        <span className="ml-auto text-muted-foreground">{formatDate(c.at)}</span>
                      </div>
                      <p className="text-sm text-foreground/80">{c.body}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Approval actions */}
            {isPending && (
              <>
                <Separator />
                <div className="space-y-3">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Reviewer Decision</p>
                  <Textarea
                    className="bg-background border-border text-sm min-h-[72px] resize-none"
                    placeholder="Add a comment (required for rejection, optional for approval)..."
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                  />
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      className="flex-1 border-red-500/40 text-red-400 hover:bg-red-500/10 hover:text-red-300 gap-2"
                      onClick={() => { onReject(record.id, comment); onClose(); }}
                      disabled={!comment.trim()}
                    >
                      <ThumbsDown className="h-4 w-4" /> Reject
                    </Button>
                    <Button
                      className="flex-1 bg-green-600 hover:bg-green-500 text-white gap-2"
                      onClick={() => { onApprove(record.id, comment); onClose(); }}
                    >
                      <ThumbsUp className="h-4 w-4" /> Approve
                    </Button>
                  </div>
                </div>
              </>
            )}
          </div>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════
// Accepted Risks Table Row
// ═══════════════════════════════════════════════════════════

function AcceptedRow({ record, onClick }: { record: RiskAcceptanceRecord; onClick: () => void }) {
  const days = daysUntil(record.expiration);
  const expCls = expirationClass(record.expiration, record.status);
  const expLbl = expirationLabel(record.expiration, record.status);

  return (
    <motion.tr
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      className="border-b border-border/50 hover:bg-muted/20 cursor-pointer transition-colors"
      onClick={onClick}
    >
      <td className="px-4 py-3">
        <span className="font-mono text-xs text-muted-foreground">{record.id}</span>
      </td>
      <td className="px-4 py-3 max-w-[300px]">
        <p className="text-sm font-medium truncate">{record.title}</p>
        <p className="text-xs text-muted-foreground truncate mt-0.5">{record.asset}</p>
      </td>
      <td className="px-4 py-3"><SeverityBadge severity={record.severity} /></td>
      <td className="px-4 py-3"><StatusChip status={record.status} /></td>
      <td className="px-4 py-3">
        <div className={cn("text-xs font-medium tabular-nums", expCls)}>
          {expLbl}
        </div>
        <div className="text-[10px] text-muted-foreground mt-0.5">{formatDate(record.expiration)}</div>
        {record.status === "accepted" && days > 0 && days <= 30 && (
          <div className="mt-1 h-1 w-20 rounded-full bg-muted overflow-hidden">
            <div
              className={cn("h-full rounded-full transition-all", days <= 7 ? "bg-red-500" : "bg-amber-500")}
              style={{ width: `${Math.max(4, (days / 90) * 100)}%` }}
            />
          </div>
        )}
      </td>
      <td className="px-4 py-3">
        <span className="text-xs text-muted-foreground">{record.approver ?? "—"}</span>
      </td>
      <td className="px-4 py-3">
        <span className="text-xs text-muted-foreground">{record.framework_ref ?? "—"}</span>
      </td>
    </motion.tr>
  );
}

// ═══════════════════════════════════════════════════════════
// Pending Approval Card
// ═══════════════════════════════════════════════════════════

function PendingCard({ record, onClick }: { record: RiskAcceptanceRecord; onClick: () => void }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-lg border border-border bg-card hover:border-amber-500/30 transition-colors"
    >
      <div className="flex items-start gap-4 p-4">
        <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-amber-500/10">
          <Inbox className="h-4 w-4 text-amber-400" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs text-muted-foreground">{record.id}</span>
            <span className="text-xs text-muted-foreground">·</span>
            <span className="text-xs text-muted-foreground">{record.finding_id}</span>
            <SeverityBadge severity={record.severity} />
            {record.framework_ref && (
              <span className="text-[10px] text-muted-foreground border border-border rounded px-1.5 py-0.5">{record.framework_ref}</span>
            )}
          </div>
          <p className="text-sm font-semibold mt-1 leading-snug">{record.title}</p>
          <p className="text-xs text-muted-foreground mt-1">{record.asset}</p>
          <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
            <span className="flex items-center gap-1"><User className="h-3 w-3" />{record.requester}</span>
            <span className="flex items-center gap-1"><Clock className="h-3 w-3" />Submitted {formatDate(record.submitted_at)}</span>
            <span className="flex items-center gap-1"><CalendarClock className="h-3 w-3" />Expires in {Math.round((record.expiration.getTime() - now.getTime()) / 86_400_000)}d if accepted</span>
            {record.comments.length > 0 && (
              <span className="flex items-center gap-1"><MessageSquare className="h-3 w-3" />{record.comments.length}</span>
            )}
          </div>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-xs gap-1 text-muted-foreground"
            onClick={(e) => { e.stopPropagation(); setExpanded(!expanded); }}
          >
            {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            {expanded ? "Less" : "Preview"}
          </Button>
          <Button
            size="sm"
            className="h-7 text-xs bg-amber-500 hover:bg-amber-400 text-black font-semibold gap-1"
            onClick={onClick}
          >
            Review
          </Button>
        </div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="border-t border-border px-4 py-3 space-y-3">
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold mb-1">Justification</p>
                <p className="text-xs text-foreground/80 leading-relaxed line-clamp-3">{record.justification}</p>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold mb-1">
                  Compensating Controls ({record.compensating_controls.length})
                </p>
                {record.compensating_controls.length === 0 ? (
                  <p className="text-xs text-red-400 flex items-center gap-1"><AlertTriangle className="h-3 w-3" />None provided</p>
                ) : (
                  <ul className="space-y-1">
                    {record.compensating_controls.slice(0, 2).map((cc) => (
                      <li key={cc.id} className="flex items-start gap-2 text-xs text-foreground/70">
                        <CheckCircle2 className="h-3 w-3 mt-0.5 shrink-0 text-green-400" />
                        {cc.description}
                      </li>
                    ))}
                    {record.compensating_controls.length > 2 && (
                      <li className="text-xs text-muted-foreground">+{record.compensating_controls.length - 2} more — open to review all</li>
                    )}
                  </ul>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function RiskAcceptance() {
  const [records, setRecords] = useState<RiskAcceptanceRecord[]>(MOCK_RECORDS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"pending" | "ledger">("pending");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedRecord, setSelectedRecord] = useState<RiskAcceptanceRecord | null>(null);
  const [showNewForm, setShowNewForm] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  // Fetch records from the real API, fall back to MOCK_RECORDS on failure
  useEffect(() => {
    let cancelled = false;
    async function fetchRecords() {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch("/api/v1/risk-acceptance?org_id=default");
        if (!res.ok) throw new Error(`API ${res.status}`);
        const data = await res.json();
        if (!cancelled && Array.isArray(data) && data.length > 0) {
          const mapped: RiskAcceptanceRecord[] = data.map((r: Record<string, unknown>, idx: number) => ({
            id: String(r.id ?? `RA-${String(idx + 1).padStart(4, "0")}`),
            finding_id: String(r.finding_id ?? ""),
            title: String(r.justification ?? r.finding_id ?? "Risk Acceptance"),
            severity: (String(r.priority ?? "medium").toLowerCase()) as RiskSeverity,
            status: (String(r.status ?? "pending").toLowerCase()) as AcceptanceStatus,
            requester: String(r.requested_by ?? "Unknown"),
            requester_role: String(r.requester_role ?? "Security Engineer"),
            approver: r.approved_by ? String(r.approved_by) : undefined,
            submitted_at: new Date(String(r.created_at ?? new Date().toISOString())),
            reviewed_at: r.reviewed_at ? new Date(String(r.reviewed_at)) : undefined,
            expiration: new Date(String(r.expires_at ?? daysFrom(90).toISOString())),
            justification: String(r.business_reason ?? r.justification ?? ""),
            compensating_controls: String(r.compensating_controls ?? "")
              .split("\n")
              .filter(Boolean)
              .map((desc: string, ci: number) => ({ id: `CC-${ci + 1}`, description: desc })),
            comments: Array.isArray(r.comments) ? (r.comments as Comment[]) : [],
            asset: String(r.asset ?? r.finding_id ?? ""),
            framework_ref: r.framework_ref ? String(r.framework_ref) : undefined,
          }));
          setRecords(mapped);
        } else if (!cancelled) {
          // Empty API response -- keep mock data as fallback
          setRecords(MOCK_RECORDS);
        }
      } catch {
        if (!cancelled) {
          setError("Could not load records from API -- showing cached data");
          setRecords(MOCK_RECORDS);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchRecords();
    return () => { cancelled = true; };
  }, [lastRefreshed]);

  // Derived stats
  const stats = useMemo(() => {
    const total     = records.length;
    const pending   = records.filter((r) => r.status === "pending").length;
    const accepted  = records.filter((r) => r.status === "accepted").length;
    const expired   = records.filter((r) => r.status === "expired").length;
    const expiringSoon = records.filter(
      (r) => r.status === "accepted" && daysUntil(r.expiration) <= 30
    ).length;
    return { total, pending, accepted, expired, expiringSoon };
  }, [records]);

  const filtered = useMemo(() => {
    return records.filter((r) => {
      const matchSearch =
        !search ||
        r.title.toLowerCase().includes(search.toLowerCase()) ||
        r.id.toLowerCase().includes(search.toLowerCase()) ||
        r.finding_id.toLowerCase().includes(search.toLowerCase()) ||
        r.asset.toLowerCase().includes(search.toLowerCase());
      const matchSeverity = severityFilter === "all" || r.severity === severityFilter;
      const matchStatus   = statusFilter === "all" || r.status === statusFilter;
      return matchSearch && matchSeverity && matchStatus;
    });
  }, [records, search, severityFilter, statusFilter]);

  const pendingRecords = filtered.filter((r) => r.status === "pending");
  const ledgerRecords  = filtered.filter((r) => r.status !== "pending");

  const handleApprove = useCallback((id: string, comment: string) => {
    setRecords((rs) =>
      rs.map((r) =>
        r.id === id
          ? {
              ...r,
              status: "accepted" as const,
              approver: "Alex Morgan",
              reviewed_at: new Date(),
              comments: comment
                ? [...r.comments, { id: `c${Date.now()}`, author: "Alex Morgan", role: "CISO", body: comment, at: new Date() }]
                : r.comments,
            }
          : r
      )
    );
  }, []);

  const handleReject = useCallback((id: string, comment: string) => {
    setRecords((rs) =>
      rs.map((r) =>
        r.id === id
          ? {
              ...r,
              status: "rejected" as const,
              approver: "Alex Morgan",
              reviewed_at: new Date(),
              comments: [...r.comments, { id: `c${Date.now()}`, author: "Alex Morgan", role: "CISO", body: comment, at: new Date() }],
            }
          : r
      )
    );
  }, []);

  const handleNewSubmit = useCallback(
    (data: Omit<RiskAcceptanceRecord, "id" | "status" | "submitted_at" | "comments">) => {
      const newRecord: RiskAcceptanceRecord = {
        ...data,
        id: `RA-${String(records.length + 25).padStart(4, "0")}`,
        status: "pending",
        submitted_at: new Date(),
        comments: [],
      };
      setRecords((rs) => [newRecord, ...rs]);
      setShowNewForm(false);
      setActiveTab("pending");
    },
    [records.length]
  );

  const tabs: { key: "pending" | "ledger"; label: string; count?: number }[] = [
    { key: "pending", label: "Pending Approvals", count: pendingRecords.length },
    { key: "ledger",  label: "Accepted Risk Ledger" },
  ];

  return (
    <TooltipProvider delayDuration={300}>
      <div className="space-y-6">
        {/* Header */}
        <PageHeader
          title="Risk Acceptance"
          description="Governance ledger for formally accepted security risks. All acceptances require business justification, compensating controls, and a fixed expiration."
          badge="GRC"
          actions={
            <Button
              className="bg-amber-500 hover:bg-amber-400 text-black font-semibold gap-2"
              onClick={() => setShowNewForm(true)}
            >
              <PlusCircle className="h-4 w-4" />
              New Request
            </Button>
          }
        />

        {/* KPI strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <KpiCard
            title="Pending Approvals"
            value={stats.pending}
            icon={Inbox}         trend={stats.pending > 0 ? "down" : "flat"}
            trendLabel={stats.pending > 0 ? "Awaiting reviewer" : "Queue clear"}
          />
          <KpiCard
            title="Active Acceptances"
            value={stats.accepted}
            icon={CheckCircle2}         trend="flat"
            trendLabel="Currently in force"
          />
          <KpiCard
            title="Expiring ≤ 30 Days"
            value={stats.expiringSoon}
            icon={CalendarClock}         trend={stats.expiringSoon > 0 ? "down" : "flat"}
            trendLabel={stats.expiringSoon > 0 ? "Renewal required" : "None imminent"}
          />
          <KpiCard
            title="Expired / Rejected"
            value={stats.expired + records.filter((r) => r.status === "rejected").length}
            icon={Ban}         trend="flat"
            trendLabel="Historical"
          />
        </div>

        {/* Expiring soon banner */}
        {stats.expiringSoon > 0 && (
          <motion.div
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3"
          >
            <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
            <p className="text-sm text-amber-300">
              <span className="font-semibold">{stats.expiringSoon} acceptance{stats.expiringSoon > 1 ? "s" : ""}</span> expire within 30 days.
              Review and renew or close the associated findings before expiration resets them to open status.
            </p>
          </motion.div>
        )}

        {/* Loading / Error / Empty states */}
        {loading && (
          <div className="flex items-center justify-center py-8 text-muted-foreground gap-2">
            <RefreshCw className="h-4 w-4 animate-spin" />
            <span className="text-sm">Loading risk acceptance records from API...</span>
          </div>
        )}
        {error && (
          <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-2 text-sm text-amber-300">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            {error}
          </div>
        )}
        {!loading && !error && records.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Inbox className="h-8 w-8 opacity-20 mb-2" />
            <p className="text-sm">No risk acceptance records found.</p>
          </div>
        )}

        {/* Toolbar */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              className="pl-9 h-8 text-xs bg-card border-border"
              placeholder="Search by ID, title, asset…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="h-8 w-[130px] text-xs bg-card border-border">
              <Filter className="h-3 w-3 mr-1 text-muted-foreground" />
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities</SelectItem>
              {(["critical", "high", "medium", "low"] as RiskSeverity[]).map((s) => (
                <SelectItem key={s} value={s}>{SEVERITY_CONFIG[s].label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="h-8 w-[130px] text-xs bg-card border-border">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Statuses</SelectItem>
              {(["pending", "accepted", "rejected", "expired"] as AcceptanceStatus[]).map((s) => (
                <SelectItem key={s} value={s}>{STATUS_CONFIG[s].label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-muted-foreground hover:text-foreground"
                onClick={() => setLastRefreshed(new Date())}
              >
                <RefreshCw className="h-3.5 w-3.5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              Last refreshed {lastRefreshed.toLocaleTimeString()}
            </TooltipContent>
          </Tooltip>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-border">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={cn(
                "flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px",
                activeTab === tab.key
                  ? "border-amber-500 text-amber-400"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              )}
            >
              {tab.label}
              {tab.count !== undefined && (
                <span className={cn(
                  "rounded-full px-1.5 py-0.5 text-[10px] font-bold",
                  activeTab === tab.key ? "bg-amber-500/20 text-amber-300" : "bg-muted text-muted-foreground"
                )}>
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <AnimatePresence mode="wait">
          {activeTab === "pending" ? (
            <motion.div
              key="pending"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
              className="space-y-3"
            >
              {pendingRecords.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-center">
                  <CheckCircle2 className="h-10 w-10 text-green-400/40 mb-3" />
                  <p className="text-sm font-medium text-muted-foreground">No pending approvals</p>
                  <p className="text-xs text-muted-foreground/60 mt-1">All risk acceptance requests have been reviewed.</p>
                </div>
              ) : (
                pendingRecords.map((r) => (
                  <PendingCard key={r.id} record={r} onClick={() => setSelectedRecord(r)} />
                ))
              )}
            </motion.div>
          ) : (
            <motion.div
              key="ledger"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
            >
              <Card className="overflow-hidden">
                <ScrollArea>
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border bg-muted/30">
                        {["ID", "Finding / Asset", "Severity", "Status", "Expiration", "Approved By", "Framework"].map((h) => (
                          <th key={h} className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground whitespace-nowrap">
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {ledgerRecords.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="px-4 py-12 text-center text-sm text-muted-foreground">
                            No records match the current filters.
                          </td>
                        </tr>
                      ) : (
                        ledgerRecords.map((r) => (
                          <AcceptedRow key={r.id} record={r} onClick={() => setSelectedRecord(r)} />
                        ))
                      )}
                    </tbody>
                  </table>
                </ScrollArea>
                <div className="border-t border-border px-4 py-2.5 flex items-center justify-between">
                  <p className="text-xs text-muted-foreground">{ledgerRecords.length} records</p>
                  <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                    <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full bg-green-400" /> &gt;30d</span>
                    <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full bg-amber-400" /> ≤30d</span>
                    <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full bg-red-400" /> ≤7d / expired</span>
                  </div>
                </div>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Detail / Approval dialog */}
      {selectedRecord && (
        <DetailDialog
          record={selectedRecord}
          onClose={() => setSelectedRecord(null)}
          onApprove={handleApprove}
          onReject={handleReject}
        />
      )}

      {/* New request dialog */}
      <Dialog open={showNewForm} onOpenChange={setShowNewForm}>
        <DialogContent className="max-w-2xl bg-card border-border">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <ShieldAlert className="h-4 w-4 text-amber-400" />
              New Risk Acceptance Request
            </DialogTitle>
          </DialogHeader>
          <ScrollArea className="max-h-[80vh] pr-2">
            <NewRequestForm onSubmit={handleNewSubmit} onCancel={() => setShowNewForm(false)} />
          </ScrollArea>
        </DialogContent>
      </Dialog>
    </TooltipProvider>
  );
}
