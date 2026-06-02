/**
 * Risk Acceptance — Governance ledger for accepted risks
 *
 * Data source: GET /api/v1/risk-acceptance?org_id=default
 *   Returns [] when empty — renders honest EmptyState, NO mock fallback.
 *
 * API fields: id, finding_id, justification, priority, status, requested_by,
 *   approved_by, created_at, expires_at, business_reason, compensating_controls,
 *   asset, framework_ref
 *
 * Persona targets: CISO (P20), Security Manager, Compliance Officer (P07)
 * Route: /risk-acceptance
 */

import { useState, useMemo, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldAlert, Clock, CheckCircle2, XCircle, AlertTriangle, PlusCircle,
  ChevronDown, ChevronUp, MessageSquare, CalendarClock, User, FileText,
  Search, Filter, RefreshCw, Inbox, ThumbsUp, ThumbsDown, Ban,
  Building2, Layers,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { EmptyState } from "@/components/shared/EmptyState";
import api, { buildApiUrl, getStoredAuthToken, getStoredAuthStrategy, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

// ═══════════════════════════════════════════════════════════
// Shared array guard (mirrors the helper used across codebase)
// ═══════════════════════════════════════════════════════════

const arr = (v: any): any[] => (Array.isArray(v) ? v : []);

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type RiskSeverity = "critical" | "high" | "medium" | "low";
type AcceptanceStatus = "pending" | "accepted" | "rejected" | "expired";

interface CompensatingControl {
  id: string;
  description: string;
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
  asset: string;
  framework_ref?: string;
}

// Raw API shape
interface ApiAcceptance {
  id: string;
  finding_id?: string;
  justification?: string;
  priority?: string;
  status?: string;
  requested_by?: string;
  approved_by?: string;
  created_at?: string;
  expires_at?: string;
  business_reason?: string;
  compensating_controls?: string;
  asset?: string;
  framework_ref?: string;
  requester_role?: string;
  reviewed_at?: string;
  title?: string;
  severity?: string;
}

// ═══════════════════════════════════════════════════════════
// Auth headers
// ═══════════════════════════════════════════════════════════

function apiHeaders(): Record<string, string> {
  const token = getStoredAuthToken();
  const strategy = getStoredAuthStrategy();
  const orgId = getStoredOrgId();
  const h: Record<string, string> = { "Content-Type": "application/json", "X-Org-ID": orgId };
  if (token) {
    if (strategy === "jwt") {
      h.Authorization = token.toLowerCase().startsWith("bearer ") ? token : `Bearer ${token}`;
    } else {
      h["X-API-Key"] = token;
    }
  }
  return h;
}

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

const now = new Date();

function daysFrom(d: number): Date {
  return new Date(now.getTime() + d * 86_400_000);
}

function daysUntil(date: Date): number {
  return Math.ceil((date.getTime() - Date.now()) / 86_400_000);
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

function mapApiRecord(r: ApiAcceptance, idx: number): RiskAcceptanceRecord {
  const rawSeverity = (r.priority ?? r.severity ?? "medium").toLowerCase();
  const severity: RiskSeverity = ["critical", "high", "medium", "low"].includes(rawSeverity)
    ? rawSeverity as RiskSeverity : "medium";

  const rawStatus = (r.status ?? "pending").toLowerCase();
  const status: AcceptanceStatus = ["pending", "accepted", "rejected", "expired"].includes(rawStatus)
    ? rawStatus as AcceptanceStatus : "pending";

  const rawControls = r.compensating_controls ?? "";
  const controls: CompensatingControl[] = typeof rawControls === "string"
    ? rawControls.split("\n").filter(Boolean).map((desc, ci) => ({ id: `CC-${ci + 1}`, description: desc }))
    : Array.isArray(rawControls)
      ? (rawControls as { id?: string; description: string }[]).map((c, ci) => ({ id: c.id ?? `CC-${ci + 1}`, description: c.description }))
      : [];

  return {
    id: String(r.id ?? `RA-${String(idx + 1).padStart(4, "0")}`),
    finding_id: String(r.finding_id ?? ""),
    title: String(r.title ?? r.justification ?? r.business_reason ?? r.finding_id ?? "Risk Acceptance"),
    severity,
    status,
    requester: String(r.requested_by ?? "Unknown"),
    requester_role: String(r.requester_role ?? "Security Engineer"),
    approver: r.approved_by ? String(r.approved_by) : undefined,
    submitted_at: new Date(String(r.created_at ?? new Date().toISOString())),
    reviewed_at: r.reviewed_at ? new Date(String(r.reviewed_at)) : undefined,
    expiration: new Date(String(r.expires_at ?? daysFrom(90).toISOString())),
    justification: String(r.business_reason ?? r.justification ?? ""),
    compensating_controls: controls,
    asset: String(r.asset ?? r.finding_id ?? ""),
    framework_ref: r.framework_ref ? String(r.framework_ref) : undefined,
  };
}

// ═══════════════════════════════════════════════════════════
// Config
// ═══════════════════════════════════════════════════════════

const SEVERITY_CONFIG: Record<RiskSeverity, { label: string; color: string; bg: string }> = {
  critical: { label: "Critical", color: "text-red-400",    bg: "bg-red-500/10 border border-red-500/20" },
  high:     { label: "High",     color: "text-orange-400", bg: "bg-orange-500/10 border border-orange-500/20" },
  medium:   { label: "Medium",   color: "text-amber-400",  bg: "bg-amber-500/10 border border-amber-500/20" },
  low:      { label: "Low",      color: "text-green-400",  bg: "bg-green-500/10 border border-green-500/20" },
};

const STATUS_CONFIG: Record<AcceptanceStatus, { label: string; icon: React.ElementType; color: string }> = {
  pending:  { label: "Pending",  icon: Clock,       color: "text-amber-400" },
  accepted: { label: "Accepted", icon: CheckCircle2, color: "text-green-400" },
  rejected: { label: "Rejected", icon: XCircle,     color: "text-red-400" },
  expired:  { label: "Expired",  icon: Ban,         color: "text-muted-foreground" },
};

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
      <Icon className="h-3.5 w-3.5" />{cfg.label}
    </span>
  );
}

// ═══════════════════════════════════════════════════════════
// New Request Form
// ═══════════════════════════════════════════════════════════

interface NewRequestFormProps {
  onSubmit: (data: Omit<RiskAcceptanceRecord, "id" | "status" | "submitted_at">) => void;
  onCancel: () => void;
}

function NewRequestForm({ onSubmit, onCancel }: NewRequestFormProps) {
  const [form, setForm] = useState({
    finding_id: "", title: "", severity: "medium" as RiskSeverity,
    asset: "", justification: "", controls: [""], expiration_days: "90", framework_ref: "",
  });

  const set = (key: string, val: string) => setForm((f) => ({ ...f, [key]: val }));
  const addControl = () => setForm((f) => ({ ...f, controls: [...f.controls, ""] }));
  const setControl = (i: number, val: string) => setForm((f) => { const c = [...f.controls]; c[i] = val; return { ...f, controls: c }; });
  const removeControl = (i: number) => setForm((f) => ({ ...f, controls: f.controls.filter((_, idx) => idx !== i) }));

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      finding_id: form.finding_id, title: form.title, severity: form.severity, asset: form.asset,
      justification: form.justification,
      compensating_controls: form.controls.filter(Boolean).map((d, i) => ({ id: `CC-${i + 1}`, description: d })),
      expiration: daysFrom(parseInt(form.expiration_days, 10) || 90),
      requester: "You", requester_role: "Security Engineer",
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
            <SelectContent>{(["critical", "high", "medium", "low"] as RiskSeverity[]).map((s) => (<SelectItem key={s} value={s}>{SEVERITY_CONFIG[s].label}</SelectItem>))}</SelectContent>
          </Select>
        </div>
      </div>
      <div>
        <label className={labelCls}>Finding Title</label>
        <Input className={inputCls} placeholder="Brief description" value={form.title} onChange={(e) => set("title", e.target.value)} required />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className={labelCls}>Affected Asset</label>
          <Input className={inputCls} placeholder="service:version" value={form.asset} onChange={(e) => set("asset", e.target.value)} required />
        </div>
        <div>
          <label className={labelCls}>Framework Reference</label>
          <Input className={inputCls} placeholder="e.g. SOC 2 CC6.1" value={form.framework_ref} onChange={(e) => set("framework_ref", e.target.value)} />
        </div>
      </div>
      <div>
        <label className={labelCls}>Business Justification</label>
        <Textarea className={cn(inputCls, "min-h-[100px] resize-none")} placeholder="Why must this risk be accepted?" value={form.justification} onChange={(e) => set("justification", e.target.value)} required />
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
              <Input className={cn(inputCls, "flex-1")} placeholder={`Control ${i + 1}`} value={ctrl} onChange={(e) => setControl(i, e.target.value)} />
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
            <SelectItem value="365">1 year</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="flex justify-end gap-2 pt-2 border-t border-border">
        <Button type="button" variant="outline" onClick={onCancel}>Cancel</Button>
        <Button type="submit" className="bg-amber-500 hover:bg-amber-400 text-black font-semibold">Submit for Approval</Button>
      </div>
    </form>
  );
}

// ═══════════════════════════════════════════════════════════
// Detail Dialog
// ═══════════════════════════════════════════════════════════

function DetailDialog({ record, onClose, onApprove, onReject }: {
  record: RiskAcceptanceRecord; onClose: () => void;
  onApprove: (id: string, comment: string) => void;
  onReject: (id: string, comment: string) => void;
}) {
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
            <div className="grid grid-cols-3 gap-3 text-xs">
              {[
                { icon: User,          label: "Requester", value: `${record.requester} · ${record.requester_role}` },
                { icon: FileText,      label: "Finding",   value: record.finding_id || "—" },
                { icon: Building2,     label: "Asset",     value: record.asset || "—" },
                { icon: CalendarClock, label: "Submitted", value: formatDate(record.submitted_at) },
                { icon: Clock,         label: "Expires",   value: formatDate(record.expiration) },
                { icon: Layers,        label: "Framework", value: record.framework_ref ?? "—" },
              ].map(({ icon: Icon, label, value }) => (
                <div key={label} className="flex flex-col gap-1 rounded-lg bg-muted/40 px-3 py-2">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground"><Icon className="h-3 w-3" />{label}</div>
                  <span className="font-medium text-foreground truncate" title={value}>{value}</span>
                </div>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <StatusChip status={record.status} />
              {record.approver && <span className="text-xs text-muted-foreground">— reviewed by {record.approver}{record.reviewed_at ? ` on ${formatDate(record.reviewed_at)}` : ""}</span>}
            </div>
            <Separator />
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Business Justification</p>
              <p className="text-sm leading-relaxed text-foreground/90">{record.justification || "No justification provided."}</p>
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Compensating Controls ({record.compensating_controls.length})</p>
              {record.compensating_controls.length === 0 ? (
                <p className="text-xs text-red-400 flex items-center gap-1.5"><AlertTriangle className="h-3.5 w-3.5" /> No compensating controls provided</p>
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
            {isPending && (
              <>
                <Separator />
                <div className="space-y-3">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Reviewer Decision</p>
                  <Textarea className="bg-background border-border text-sm min-h-[72px] resize-none" placeholder="Add a comment (required for rejection)..." value={comment} onChange={(e) => setComment(e.target.value)} />
                  <div className="flex gap-2">
                    <Button variant="outline" className="flex-1 border-red-500/40 text-red-400 hover:bg-red-500/10 gap-2"
                      onClick={() => { onReject(record.id, comment); onClose(); }} disabled={!comment.trim()}>
                      <ThumbsDown className="h-4 w-4" /> Reject
                    </Button>
                    <Button className="flex-1 bg-green-600 hover:bg-green-500 text-white gap-2" onClick={() => { onApprove(record.id, comment); onClose(); }}>
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
// Row and Card sub-components
// ═══════════════════════════════════════════════════════════

function AcceptedRow({ record, onClick }: { record: RiskAcceptanceRecord; onClick: () => void }) {
  const expCls = expirationClass(record.expiration, record.status);
  const expLbl = expirationLabel(record.expiration, record.status);
  const days = daysUntil(record.expiration);
  return (
    <motion.tr initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }}
      className="border-b border-border/50 hover:bg-muted/20 cursor-pointer transition-colors" onClick={onClick}>
      <td className="px-4 py-3"><span className="font-mono text-xs text-muted-foreground">{record.id}</span></td>
      <td className="px-4 py-3 max-w-[300px]">
        <p className="text-sm font-medium truncate">{record.title}</p>
        <p className="text-xs text-muted-foreground truncate mt-0.5">{record.asset}</p>
      </td>
      <td className="px-4 py-3"><SeverityBadge severity={record.severity} /></td>
      <td className="px-4 py-3"><StatusChip status={record.status} /></td>
      <td className="px-4 py-3">
        <div className={cn("text-xs font-medium tabular-nums", expCls)}>{expLbl}</div>
        <div className="text-[10px] text-muted-foreground mt-0.5">{formatDate(record.expiration)}</div>
        {record.status === "accepted" && days > 0 && days <= 30 && (
          <div className="mt-1 h-1 w-20 rounded-full bg-muted overflow-hidden">
            <div className={cn("h-full rounded-full transition-all", days <= 7 ? "bg-red-500" : "bg-amber-500")} style={{ width: `${Math.max(4, (days / 90) * 100)}%` }} />
          </div>
        )}
      </td>
      <td className="px-4 py-3"><span className="text-xs text-muted-foreground">{record.approver ?? "—"}</span></td>
      <td className="px-4 py-3"><span className="text-xs text-muted-foreground">{record.framework_ref ?? "—"}</span></td>
    </motion.tr>
  );
}

function PendingCard({ record, onClick }: { record: RiskAcceptanceRecord; onClick: () => void }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="rounded-lg border border-border bg-card hover:border-amber-500/30 transition-colors">
      <div className="flex items-start gap-4 p-4">
        <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-amber-500/10">
          <Inbox className="h-4 w-4 text-amber-400" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs text-muted-foreground">{record.id}</span>
            {record.finding_id && <span className="text-xs text-muted-foreground">· {record.finding_id}</span>}
            <SeverityBadge severity={record.severity} />
            {record.framework_ref && <span className="text-[10px] text-muted-foreground border border-border rounded px-1.5 py-0.5">{record.framework_ref}</span>}
          </div>
          <p className="text-sm font-semibold mt-1 leading-snug">{record.title}</p>
          <p className="text-xs text-muted-foreground mt-1">{record.asset || "—"}</p>
          <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
            <span className="flex items-center gap-1"><User className="h-3 w-3" />{record.requester}</span>
            <span className="flex items-center gap-1"><Clock className="h-3 w-3" />Submitted {formatDate(record.submitted_at)}</span>
            <span className="flex items-center gap-1"><CalendarClock className="h-3 w-3" />Expires in {daysUntil(record.expiration)}d if accepted</span>
          </div>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button variant="ghost" size="sm" className="h-7 text-xs gap-1 text-muted-foreground" onClick={(e) => { e.stopPropagation(); setExpanded(!expanded); }}>
            {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            {expanded ? "Less" : "Preview"}
          </Button>
          <Button size="sm" className="h-7 text-xs bg-amber-500 hover:bg-amber-400 text-black font-semibold gap-1" onClick={onClick}>Review</Button>
        </div>
      </div>
      <AnimatePresence>
        {expanded && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }} className="overflow-hidden">
            <div className="border-t border-border px-4 py-3 space-y-3">
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold mb-1">Justification</p>
                <p className="text-xs text-foreground/80 leading-relaxed line-clamp-3">{record.justification || "No justification provided."}</p>
              </div>
              {record.compensating_controls.length > 0 && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold mb-1">Compensating Controls ({record.compensating_controls.length})</p>
                  <ul className="space-y-1">
                    {record.compensating_controls.slice(0, 2).map((cc) => (
                      <li key={cc.id} className="flex items-start gap-2 text-xs text-foreground/70">
                        <CheckCircle2 className="h-3 w-3 mt-0.5 shrink-0 text-green-400" />{cc.description}
                      </li>
                    ))}
                    {record.compensating_controls.length > 2 && <li className="text-xs text-muted-foreground">+{record.compensating_controls.length - 2} more</li>}
                  </ul>
                </div>
              )}
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
  const orgId = getStoredOrgId();
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<"pending" | "ledger">("pending");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedRecord, setSelectedRecord] = useState<RiskAcceptanceRecord | null>(null);
  const [showNewForm, setShowNewForm] = useState(false);
  // optimistic local overrides (approve/reject/new)
  const [localOverrides, setLocalOverrides] = useState<Map<string, Partial<RiskAcceptanceRecord>>>(new Map());
  const [localNew, setLocalNew] = useState<RiskAcceptanceRecord[]>([]);

  const { data: apiRecords, isLoading, isError, refetch, dataUpdatedAt } = useQuery<RiskAcceptanceRecord[]>({
    queryKey: ["risk-acceptance", orgId],
    queryFn: async () => {
      const url = buildApiUrl("/api/v1/risk-acceptance", { org_id: orgId });
      const res = await api.get<ApiAcceptance[]>(url);
      const arr = Array.isArray(res.data) ? res.data : [];
      return arr.map((r, i) => mapApiRecord(r, i));
    },
    refetchInterval: 120_000,
    staleTime: 60_000,
  });

  // Merge API records with local overrides
  const records: RiskAcceptanceRecord[] = useMemo(() => {
    const base = (arr(apiRecords ?? []) as RiskAcceptanceRecord[]).map((r) => {
      const override = localOverrides.get(r.id);
      return override ? { ...r, ...override } : r;
    });
    return [...localNew, ...base];
  }, [apiRecords, localOverrides, localNew]);

  const stats = useMemo(() => {
    const pending = records.filter((r) => r.status === "pending").length;
    const accepted = records.filter((r) => r.status === "accepted").length;
    const expired = records.filter((r) => r.status === "expired").length;
    const expiringSoon = records.filter((r) => r.status === "accepted" && daysUntil(r.expiration) <= 30).length;
    return { total: records.length, pending, accepted, expired, expiringSoon };
  }, [records]);

  const filtered = useMemo(() => records.filter((r) => {
    const matchSearch = !search || r.title.toLowerCase().includes(search.toLowerCase()) ||
      r.id.toLowerCase().includes(search.toLowerCase()) ||
      r.finding_id.toLowerCase().includes(search.toLowerCase()) ||
      r.asset.toLowerCase().includes(search.toLowerCase());
    const matchSeverity = severityFilter === "all" || r.severity === severityFilter;
    const matchStatus = statusFilter === "all" || r.status === statusFilter;
    return matchSearch && matchSeverity && matchStatus;
  }), [records, search, severityFilter, statusFilter]);

  const pendingRecords = filtered.filter((r) => r.status === "pending");
  const ledgerRecords = filtered.filter((r) => r.status !== "pending");

  const handleApprove = useCallback((id: string, _comment: string) => {
    setLocalOverrides((m) => new Map(m).set(id, { status: "accepted", approver: "You", reviewed_at: new Date() }));
  }, []);

  const handleReject = useCallback((id: string, _comment: string) => {
    setLocalOverrides((m) => new Map(m).set(id, { status: "rejected", approver: "You", reviewed_at: new Date() }));
  }, []);

  const handleNewSubmit = useCallback((data: Omit<RiskAcceptanceRecord, "id" | "status" | "submitted_at">) => {
    const newRecord: RiskAcceptanceRecord = {
      ...data,
      id: `RA-LOCAL-${Date.now()}`,
      status: "pending",
      submitted_at: new Date(),
    };
    setLocalNew((prev) => [newRecord, ...prev]);
    setShowNewForm(false);
    setActiveTab("pending");
  }, []);

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load risk acceptance records" onRetry={refetch} />;

  const tabs: { key: "pending" | "ledger"; label: string; count?: number }[] = [
    { key: "pending", label: "Pending Approvals", count: pendingRecords.length },
    { key: "ledger",  label: "Accepted Risk Ledger" },
  ];

  return (
    <TooltipProvider delayDuration={300}>
      <div className="space-y-6">
        <PageHeader
          title="Risk Acceptance"
          description="Governance ledger for formally accepted security risks. All acceptances require business justification, compensating controls, and a fixed expiration."
          badge="GRC"
          actions={
            <Button className="bg-amber-500 hover:bg-amber-400 text-black font-semibold gap-2" onClick={() => setShowNewForm(true)}>
              <PlusCircle className="h-4 w-4" />New Request
            </Button>
          }
        />

        {/* KPI strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <KpiCard title="Pending Approvals" value={stats.pending} icon={Inbox} trend={stats.pending > 0 ? "down" : "flat"} trendLabel={stats.pending > 0 ? "Awaiting reviewer" : "Queue clear"} />
          <KpiCard title="Active Acceptances" value={stats.accepted} icon={CheckCircle2} trend="flat" trendLabel="Currently in force" />
          <KpiCard title="Expiring ≤ 30 Days" value={stats.expiringSoon} icon={CalendarClock} trend={stats.expiringSoon > 0 ? "down" : "flat"} trendLabel={stats.expiringSoon > 0 ? "Renewal required" : "None imminent"} />
          <KpiCard title="Expired / Rejected" value={stats.expired + records.filter((r) => r.status === "rejected").length} icon={Ban} trend="flat" trendLabel="Historical" />
        </div>

        {/* Expiring soon banner */}
        {stats.expiringSoon > 0 && (
          <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} className="flex items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3">
            <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
            <p className="text-sm text-amber-300">
              <span className="font-semibold">{stats.expiringSoon} acceptance{stats.expiringSoon > 1 ? "s" : ""}</span> expire within 30 days. Review and renew before expiration resets them to open status.
            </p>
          </motion.div>
        )}

        {/* Toolbar */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input className="pl-9 h-8 text-xs bg-card border-border" placeholder="Search by ID, title, asset…" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="h-8 w-[130px] text-xs bg-card border-border">
              <Filter className="h-3 w-3 mr-1 text-muted-foreground" /><SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities</SelectItem>
              {(["critical", "high", "medium", "low"] as RiskSeverity[]).map((s) => (<SelectItem key={s} value={s}>{SEVERITY_CONFIG[s].label}</SelectItem>))}
            </SelectContent>
          </Select>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="h-8 w-[130px] text-xs bg-card border-border"><SelectValue placeholder="Status" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Statuses</SelectItem>
              {(["pending", "accepted", "rejected", "expired"] as AcceptanceStatus[]).map((s) => (<SelectItem key={s} value={s}>{STATUS_CONFIG[s].label}</SelectItem>))}
            </SelectContent>
          </Select>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8 text-muted-foreground hover:text-foreground" onClick={() => refetch()}>
                <RefreshCw className="h-3.5 w-3.5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Refreshed {new Date(dataUpdatedAt).toLocaleTimeString()}</TooltipContent>
          </Tooltip>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-border">
          {tabs.map((tab) => (
            <button key={tab.key} onClick={() => setActiveTab(tab.key)}
              className={cn("flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px",
                activeTab === tab.key ? "border-amber-500 text-amber-400" : "border-transparent text-muted-foreground hover:text-foreground")}>
              {tab.label}
              {tab.count !== undefined && (
                <span className={cn("rounded-full px-1.5 py-0.5 text-[10px] font-bold",
                  activeTab === tab.key ? "bg-amber-500/20 text-amber-300" : "bg-muted text-muted-foreground")}>
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <AnimatePresence mode="wait">
          {activeTab === "pending" ? (
            <motion.div key="pending" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.15 }} className="space-y-3">
              {pendingRecords.length === 0 ? (
                <EmptyState icon={CheckCircle2} title="No pending approvals" description="All risk acceptance requests have been reviewed, or no requests have been submitted yet." />
              ) : (
                pendingRecords.map((r) => <PendingCard key={r.id} record={r} onClick={() => setSelectedRecord(r)} />)
              )}
            </motion.div>
          ) : (
            <motion.div key="ledger" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.15 }}>
              <Card className="overflow-hidden">
                <ScrollArea>
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border bg-muted/30">
                        {["ID", "Finding / Asset", "Severity", "Status", "Expiration", "Approved By", "Framework"].map((h) => (
                          <th key={h} className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground whitespace-nowrap">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {ledgerRecords.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="px-4 py-12 text-center text-sm text-muted-foreground">
                            No accepted/rejected/expired records found.
                          </td>
                        </tr>
                      ) : (
                        ledgerRecords.map((r) => <AcceptedRow key={r.id} record={r} onClick={() => setSelectedRecord(r)} />)
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

      {/* Detail dialog */}
      {selectedRecord && (
        <DetailDialog record={selectedRecord} onClose={() => setSelectedRecord(null)} onApprove={handleApprove} onReject={handleReject} />
      )}

      {/* New request dialog */}
      <Dialog open={showNewForm} onOpenChange={setShowNewForm}>
        <DialogContent className="max-w-2xl bg-card border-border">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <ShieldAlert className="h-4 w-4 text-amber-400" />New Risk Acceptance Request
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
