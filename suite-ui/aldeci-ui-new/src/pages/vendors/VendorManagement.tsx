/**
 * Vendor Management — Third-Party Risk & SBOM Linkage
 *
 * Designed for security teams managing supply-chain exposure.
 * Dark-first, information-dense, grade glyphs for instant risk scanning.
 * Vendor scores rendered as A-F grades with chromatic halo — wall-display readable.
 *
 * Route: /vendors
 */

import { useState, useMemo, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Building2,
  Plus,
  Search,
  Filter,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  Minus,
  Package,
  Globe,
  Calendar,
  Clock,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  BarChart3,
  X,
  CheckCircle2,
  Bell,
  BellOff,
  Link2,
  ArrowUpRight,
  ArrowDownRight,
  Info,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type VendorTier = "critical" | "high" | "medium" | "low";
type RiskGrade = "A" | "B" | "C" | "D" | "F";
type RiskTrend = "improving" | "degrading" | "stable" | "flat";
type AssessmentStatus = "passed" | "failed" | "partial" | "pending";

interface SBOMComponent {
  name: string;
  version: string;
  license: string;
  cves: number;
  path: string;
}

interface AssessmentRecord {
  id: string;
  date: Date;
  score: number;
  grade: RiskGrade;
  assessor: string;
  status: AssessmentStatus;
  findings: number;
  critical: number;
  notes: string;
}

interface RiskAlert {
  id: string;
  date: Date;
  type: "score_drop" | "new_cve" | "breach_reported" | "cert_expiry" | "tier_change";
  message: string;
  severity: "critical" | "high" | "medium";
  dismissed: boolean;
}

interface Vendor {
  id: string;
  name: string;
  domain: string;
  tier: VendorTier;
  grade: RiskGrade;
  score: number; // 0-100
  trend: RiskTrend;
  trendDelta: number; // points change over 30d
  lastAssessed: Date;
  nextAssessment: Date;
  contactEmail: string;
  category: string;
  components: SBOMComponent[];
  assessmentHistory: AssessmentRecord[];
  alerts: RiskAlert[];
  certifications: string[];
  slaBreaches: number;
  criticalFindings: number;
  totalFindings: number;
  notes: string;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const now = new Date();
const daysAgo = (d: number) => new Date(now.getTime() - d * 86_400_000);
const daysFrom = (d: number) => new Date(now.getTime() + d * 86_400_000);


// ═══════════════════════════════════════════════════════════
// Grade rendering — the signature design element
// ═══════════════════════════════════════════════════════════

const GRADE_CONFIG: Record<RiskGrade, { color: string; bg: string; ring: string; label: string }> = {
  A: { color: "text-emerald-400", bg: "bg-emerald-500/10", ring: "ring-emerald-500/30", label: "Excellent" },
  B: { color: "text-sky-400",     bg: "bg-sky-500/10",     ring: "ring-sky-500/30",     label: "Good" },
  C: { color: "text-amber-400",   bg: "bg-amber-500/10",   ring: "ring-amber-500/30",   label: "Fair" },
  D: { color: "text-orange-400",  bg: "bg-orange-500/10",  ring: "ring-orange-500/30",  label: "Poor" },
  F: { color: "text-red-400",     bg: "bg-red-500/10",     ring: "ring-red-500/30",     label: "Critical" },
};

const TIER_CONFIG: Record<VendorTier, { label: string; badgeVariant: "critical" | "high" | "medium" | "low" }> = {
  critical: { label: "Critical", badgeVariant: "critical" },
  high:     { label: "High",     badgeVariant: "high" },
  medium:   { label: "Medium",   badgeVariant: "medium" },
  low:      { label: "Low",      badgeVariant: "low" },
};

const ALERT_TYPE_LABELS: Record<RiskAlert["type"], string> = {
  score_drop:      "Score Change",
  new_cve:         "New CVE",
  breach_reported: "Breach Report",
  cert_expiry:     "Cert Expiry",
  tier_change:     "Tier Change",
};

function GradeBadge({ grade, size = "md" }: { grade: RiskGrade; size?: "sm" | "md" | "lg" }) {
  const cfg = GRADE_CONFIG[grade];
  const sizeClass = size === "lg"
    ? "h-14 w-14 text-3xl ring-2"
    : size === "sm"
    ? "h-7 w-7 text-base ring-1"
    : "h-10 w-10 text-xl ring-1";
  return (
    <div
      className={cn(
        "flex items-center justify-center rounded-lg font-mono font-bold shrink-0",
        sizeClass,
        cfg.color,
        cfg.bg,
        cfg.ring
      )}
    >
      {grade}
    </div>
  );
}

function TrendIndicator({ trend, delta }: { trend: RiskTrend; delta: number }) {
  if (trend === "improving") return (
    <span className="flex items-center gap-0.5 text-xs text-emerald-400 font-medium">
      <ArrowUpRight className="h-3 w-3" />+{delta}
    </span>
  );
  if (trend === "degrading") return (
    <span className="flex items-center gap-0.5 text-xs text-red-400 font-medium">
      <ArrowDownRight className="h-3 w-3" />{delta}
    </span>
  );
  return (
    <span className="flex items-center gap-0.5 text-xs text-muted-foreground">
      <Minus className="h-3 w-3" />0
    </span>
  );
}

function ScoreBar({ score }: { score: number }) {
  const grade: RiskGrade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 45 ? "D" : "F";
  const cfg = GRADE_CONFIG[grade];
  const barColor = grade === "A" ? "bg-emerald-500" : grade === "B" ? "bg-sky-500" : grade === "C" ? "bg-amber-500" : grade === "D" ? "bg-orange-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
        <motion.div
          className={cn("h-full rounded-full", barColor)}
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.6, ease: "easeOut" }}
        />
      </div>
      <span className={cn("text-xs font-mono font-medium w-6 text-right", cfg.color)}>{score}</span>
    </div>
  );
}

function formatDate(d: Date) {
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}
function daysUntil(d: Date) {
  return Math.ceil((d.getTime() - now.getTime()) / 86_400_000);
}

// ═══════════════════════════════════════════════════════════
// Add Vendor Form
// ═══════════════════════════════════════════════════════════

interface AddVendorFormProps {
  onClose: () => void;
  onAdd: (v: Partial<Vendor>) => void;
}

function AddVendorForm({ onClose, onAdd }: AddVendorFormProps) {
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [tier, setTier] = useState<VendorTier>("medium");
  const [category, setCategory] = useState("");
  const [contact, setContact] = useState("");
  const [notes, setNotes] = useState("");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim() || !domain.trim()) return;
    onAdd({ name, domain, tier, category, contactEmail: contact, notes });
    onClose();
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <Label htmlFor="vnd-name">Vendor Name <span className="text-red-400">*</span></Label>
          <Input id="vnd-name" placeholder="e.g. HashiCorp" value={name} onChange={e => setName(e.target.value)} required />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="vnd-domain">Domain <span className="text-red-400">*</span></Label>
          <Input id="vnd-domain" placeholder="e.g. hashicorp.com" value={domain} onChange={e => setDomain(e.target.value)} required />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <Label>Risk Tier</Label>
          <Select value={tier} onValueChange={v => setTier(v as VendorTier)}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="vnd-cat">Category</Label>
          <Input id="vnd-cat" placeholder="e.g. Infrastructure" value={category} onChange={e => setCategory(e.target.value)} />
        </div>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="vnd-contact">Security Contact Email</Label>
        <Input id="vnd-contact" type="email" placeholder="security@vendor.com" value={contact} onChange={e => setContact(e.target.value)} />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="vnd-notes">Notes</Label>
        <textarea
          id="vnd-notes"
          rows={3}
          placeholder="Integration context, scope, known concerns..."
          value={notes}
          onChange={e => setNotes(e.target.value)}
          className="w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-none"
        />
      </div>
      <div className="flex justify-end gap-2 pt-2">
        <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
        <Button type="submit" disabled={!name.trim() || !domain.trim()}>Add Vendor</Button>
      </div>
    </form>
  );
}

// ═══════════════════════════════════════════════════════════
// Assessment History Panel
// ═══════════════════════════════════════════════════════════

const STATUS_CONFIG: Record<AssessmentStatus, { label: string; color: string }> = {
  passed:  { label: "Passed",  color: "text-emerald-400" },
  failed:  { label: "Failed",  color: "text-red-400" },
  partial: { label: "Partial", color: "text-amber-400" },
  pending: { label: "Pending", color: "text-muted-foreground" },
};

function AssessmentPanel({ vendor }: { vendor: Vendor }) {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <GradeBadge grade={vendor.grade} size="lg" />
        <div>
          <div className="text-lg font-bold">{vendor.name}</div>
          <div className="text-sm text-muted-foreground">{vendor.domain}</div>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-xs text-muted-foreground">Risk score:</span>
            <span className={cn("text-sm font-mono font-bold", GRADE_CONFIG[vendor.grade].color)}>{vendor.score}/100</span>
            <TrendIndicator trend={vendor.trend} delta={vendor.trendDelta} />
          </div>
        </div>
      </div>

      <Separator />

      {/* Active alerts */}
      {vendor.alerts.filter(a => !a.dismissed).length > 0 && (
        <div className="space-y-2">
          <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Active Alerts</div>
          {vendor.alerts.filter(a => !a.dismissed).map(alert => (
            <div
              key={alert.id}
              className={cn(
                "rounded-lg border p-3 text-xs",
                alert.severity === "critical" ? "border-red-500/30 bg-red-500/5" :
                alert.severity === "high"     ? "border-orange-500/30 bg-orange-500/5" :
                                                "border-yellow-500/30 bg-yellow-500/5"
              )}
            >
              <div className="flex items-start gap-2">
                <Bell className={cn("h-3.5 w-3.5 mt-0.5 shrink-0", alert.severity === "critical" ? "text-red-400" : alert.severity === "high" ? "text-orange-400" : "text-yellow-400")} />
                <div>
                  <span className="font-medium">{ALERT_TYPE_LABELS[alert.type]}</span>
                  <span className="text-muted-foreground"> — {formatDate(alert.date)}</span>
                  <p className="text-muted-foreground mt-0.5">{alert.message}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Score trend chart (simplified bars) */}
      <div className="space-y-2">
        <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Score History</div>
        <div className="flex items-end gap-1.5 h-12">
          {[...vendor.assessmentHistory].reverse().map((a, i) => {
            const heightPct = `${a.score}%`;
            const cfg = GRADE_CONFIG[a.grade];
            const barColor = a.grade === "A" ? "bg-emerald-500" : a.grade === "B" ? "bg-sky-500" : a.grade === "C" ? "bg-amber-500" : a.grade === "D" ? "bg-orange-500" : "bg-red-500";
            return (
              <TooltipProvider key={a.id}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="flex-1 flex flex-col items-center gap-1">
                      <motion.div
                        className={cn("w-full rounded-sm", barColor)}
                        style={{ height: heightPct }}
                        initial={{ scaleY: 0 }}
                        animate={{ scaleY: 1 }}
                        transition={{ delay: i * 0.08, duration: 0.4 }}
                      />
                    </div>
                  </TooltipTrigger>
                  <TooltipContent side="top" className="text-xs">
                    <div className="font-medium">{a.grade} — {a.score}/100</div>
                    <div className="text-muted-foreground">{formatDate(a.date)}</div>
                    <div className={STATUS_CONFIG[a.status].color}>{STATUS_CONFIG[a.status].label} · {a.findings} findings</div>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            );
          })}
        </div>
      </div>

      {/* Assessment records */}
      <div className="space-y-2">
        <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Assessment Records</div>
        <div className="space-y-2">
          {vendor.assessmentHistory.map((a, i) => (
            <motion.div
              key={a.id}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.05 }}
              className="rounded-lg border border-border bg-card/50 p-3 space-y-2"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <GradeBadge grade={a.grade} size="sm" />
                  <div>
                    <span className="text-xs font-mono text-muted-foreground">{a.id}</span>
                    <div className="text-xs font-medium">{formatDate(a.date)}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className={cn("text-xs font-medium", STATUS_CONFIG[a.status].color)}>
                    {STATUS_CONFIG[a.status].label}
                  </div>
                  <div className="text-xs text-muted-foreground">{a.findings} findings · {a.critical} critical</div>
                </div>
              </div>
              {a.notes && (
                <p className="text-xs text-muted-foreground border-t border-border pt-2">{a.notes}</p>
              )}
              <div className="text-xs text-muted-foreground">Assessor: {a.assessor}</div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* SBOM Components */}
      {vendor.components.length > 0 && (
        <div className="space-y-2">
          <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
            <Package className="h-3.5 w-3.5" />
            SBOM Components ({vendor.components.length})
          </div>
          <div className="space-y-1.5">
            {vendor.components.map((c, i) => (
              <div key={i} className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-xs">
                <div className="flex items-center gap-2 min-w-0">
                  <code className="font-mono font-medium truncate">{c.name}</code>
                  <span className="text-muted-foreground shrink-0">{c.version}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-muted-foreground">{c.license}</span>
                  {c.cves > 0 ? (
                    <Badge variant="critical">{c.cves} CVE{c.cves > 1 ? "s" : ""}</Badge>
                  ) : (
                    <Badge variant="success">Clean</Badge>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Vendor Table Row
// ═══════════════════════════════════════════════════════════

interface VendorRowProps {
  vendor: Vendor;
  selected: boolean;
  onSelect: () => void;
  index: number;
}

function VendorRow({ vendor, selected, onSelect, index }: VendorRowProps) {
  const activeAlerts = vendor.alerts.filter(a => !a.dismissed);
  const nextDays = daysUntil(vendor.nextAssessment);
  const overdueAssessment = nextDays < 0;
  const dueSoon = nextDays >= 0 && nextDays <= 14;

  return (
    <motion.tr
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04 }}
      onClick={onSelect}
      className={cn(
        "border-b border-border cursor-pointer transition-colors group",
        selected
          ? "bg-primary/5 hover:bg-primary/8"
          : "hover:bg-muted/30"
      )}
    >
      {/* Grade */}
      <td className="px-4 py-3 w-14">
        <GradeBadge grade={vendor.grade} size="md" />
      </td>

      {/* Name + domain */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-medium text-sm">{vendor.name}</span>
              {activeAlerts.length > 0 && (
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-red-500/15 text-red-400 text-[10px] font-bold">
                  {activeAlerts.length}
                </span>
              )}
            </div>
            <div className="flex items-center gap-1 text-xs text-muted-foreground mt-0.5">
              <Globe className="h-3 w-3" />
              {vendor.domain}
            </div>
          </div>
        </div>
      </td>

      {/* Category */}
      <td className="px-4 py-3 hidden lg:table-cell">
        <span className="text-xs text-muted-foreground">{vendor.category}</span>
      </td>

      {/* Score bar */}
      <td className="px-4 py-3 w-36">
        <ScoreBar score={vendor.score} />
        <div className="flex justify-between mt-1">
          <TrendIndicator trend={vendor.trend} delta={vendor.trendDelta} />
          <span className="text-[10px] text-muted-foreground">30d</span>
        </div>
      </td>

      {/* Tier */}
      <td className="px-4 py-3 w-24">
        <Badge variant={TIER_CONFIG[vendor.tier].badgeVariant}>
          {TIER_CONFIG[vendor.tier].label}
        </Badge>
      </td>

      {/* Last assessed */}
      <td className="px-4 py-3 w-32 hidden md:table-cell">
        <div className="text-xs">{formatDate(vendor.lastAssessed)}</div>
        <div className={cn(
          "text-[10px] mt-0.5",
          overdueAssessment ? "text-red-400" : dueSoon ? "text-amber-400" : "text-muted-foreground"
        )}>
          {overdueAssessment
            ? `Overdue ${Math.abs(nextDays)}d`
            : dueSoon
            ? `Due in ${nextDays}d`
            : `Next: ${formatDate(vendor.nextAssessment)}`}
        </div>
      </td>

      {/* Components */}
      <td className="px-4 py-3 w-24 hidden xl:table-cell">
        <div className="flex items-center gap-1.5">
          <Package className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs">{vendor.components.length}</span>
          {vendor.components.some(c => c.cves > 0) && (
            <Badge variant="critical" className="text-[10px] px-1 py-0">
              {vendor.components.reduce((s, c) => s + c.cves, 0)} CVE
            </Badge>
          )}
        </div>
      </td>

      {/* Findings */}
      <td className="px-4 py-3 w-24 hidden xl:table-cell">
        <div className="text-xs">
          {vendor.criticalFindings > 0 && (
            <span className="text-red-400 font-medium">{vendor.criticalFindings} crit</span>
          )}
          {vendor.criticalFindings > 0 && vendor.totalFindings > vendor.criticalFindings && (
            <span className="text-muted-foreground"> · </span>
          )}
          <span className="text-muted-foreground">{vendor.totalFindings} total</span>
        </div>
      </td>

      {/* Actions */}
      <td className="px-4 py-3 w-10">
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity"
          onClick={(e) => { e.stopPropagation(); window.open(`https://${vendor.domain}`, "_blank"); }}
        >
          <ExternalLink className="h-3.5 w-3.5" />
        </Button>
      </td>
    </motion.tr>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// API helpers
// ═══════════════════════════════════════════════════════════

const API_HEADERS = () => ({
  "Content-Type": "application/json",
  "X-API-Key": localStorage.getItem("apiKey") || "",
});

function scoreToGrade(score: number): RiskGrade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 45) return "D";
  return "F";
}

function tierToVendorTier(tier: string | null | undefined): VendorTier {
  const t = (tier || "medium").toLowerCase();
  if (t === "critical") return "critical";
  if (t === "high") return "high";
  if (t === "low") return "low";
  return "medium";
}

/** Map backend VendorResponse → frontend Vendor shape. */
function apiVendorToVendor(v: Record<string, any>): Vendor {
  const score = typeof v.current_score === "number" ? Math.round(v.current_score) : 60;
  const grade = scoreToGrade(score);
  const tier = tierToVendorTier(v.tier);
  return {
    id: v.id || `VND-${Date.now()}`,
    name: v.name || "Unknown",
    domain: v.description || v.name?.toLowerCase().replace(/\s+/g, "") + ".com" || "vendor.com",
    tier,
    grade,
    score,
    trend: "stable",
    trendDelta: 0,
    lastAssessed: v.updated_at ? new Date(v.updated_at) : new Date(0),
    nextAssessment: v.contract_end ? new Date(v.contract_end) : daysFrom(90),
    contactEmail: "",
    category: v.service_category || "Unknown",
    components: [],
    assessmentHistory: [],
    alerts: [],
    certifications: [],
    slaBreaches: 0,
    criticalFindings: 0,
    totalFindings: 0,
    notes: v.description || "",
  };
}

export default function VendorManagement() {
  const [vendors, setVendors] = useState<Vendor[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedVendor, setSelectedVendor] = useState<Vendor | null>(null);
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [search, setSearch] = useState("");
  const [filterTier, setFilterTier] = useState<"all" | VendorTier>("all");
  const [filterGrade, setFilterGrade] = useState<"all" | RiskGrade>("all");
  const [sortBy, setSortBy] = useState<"score" | "name" | "tier" | "assessed">("score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const fetchVendors = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/v1/vendors", { headers: API_HEADERS() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const list: Record<string, any>[] = data.vendors ?? data ?? [];
      if (Array.isArray(list)) {
        setVendors(list.map(apiVendorToVendor));
      }
    } catch (err: any) {
      console.warn("VendorManagement: API fetch failed:", err.message);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchVendors();
  }, [fetchVendors]);

  const filtered = useMemo(() => {
    let v = vendors.filter(vnd => {
      const q = search.toLowerCase();
      if (q && !vnd.name.toLowerCase().includes(q) && !vnd.domain.toLowerCase().includes(q) && !vnd.category.toLowerCase().includes(q)) return false;
      if (filterTier !== "all" && vnd.tier !== filterTier) return false;
      if (filterGrade !== "all" && vnd.grade !== filterGrade) return false;
      return true;
    });

    v = [...v].sort((a, b) => {
      let cmp = 0;
      if (sortBy === "score") cmp = a.score - b.score;
      else if (sortBy === "name") cmp = a.name.localeCompare(b.name);
      else if (sortBy === "tier") {
        const order: VendorTier[] = ["critical", "high", "medium", "low"];
        cmp = order.indexOf(a.tier) - order.indexOf(b.tier);
      } else if (sortBy === "assessed") cmp = a.lastAssessed.getTime() - b.lastAssessed.getTime();
      return sortDir === "asc" ? cmp : -cmp;
    });

    return v;
  }, [vendors, search, filterTier, filterGrade, sortBy, sortDir]);

  function toggleSort(col: typeof sortBy) {
    if (sortBy === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortBy(col); setSortDir("asc"); }
  }

  function SortIcon({ col }: { col: typeof sortBy }) {
    if (sortBy !== col) return <Minus className="h-3 w-3 text-muted-foreground/40" />;
    return sortDir === "asc" ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />;
  }

  function handleAddVendor(partial: Partial<Vendor>) {
    const newVendor: Vendor = {
      id: `VND-${String(vendors.length + 1).padStart(3, "0")}`,
      name: partial.name ?? "New Vendor",
      domain: partial.domain ?? "vendor.com",
      tier: partial.tier ?? "medium",
      grade: "C",
      score: 60,
      trend: "flat",
      trendDelta: 0,
      lastAssessed: new Date(0),
      nextAssessment: daysFrom(30),
      contactEmail: partial.contactEmail ?? "",
      category: partial.category ?? "Unknown",
      components: [],
      assessmentHistory: [],
      alerts: [
        {
          id: `ALR-NEW-${Date.now()}`,
          date: new Date(),
          type: "tier_change",
          message: "Vendor added — initial assessment required",
          severity: "medium",
          dismissed: false,
        },
      ],
      certifications: [],
      slaBreaches: 0,
      criticalFindings: 0,
      totalFindings: 0,
      notes: partial.notes ?? "",
    };
    setVendors(v => [newVendor, ...v]);
  }

  // KPI aggregates
  const totalVendors = vendors.length;
  const criticalTierCount = vendors.filter(v => v.tier === "critical").length;
  const activeAlertCount = vendors.reduce((s, v) => s + v.alerts.filter(a => !a.dismissed).length, 0);
  const avgScore = Math.round(vendors.reduce((s, v) => s + v.score, 0) / vendors.length);
  const overdueCount = vendors.filter(v => daysUntil(v.nextAssessment) < 0).length;
  const totalCVEs = vendors.reduce((s, v) => s + v.components.reduce((cs, c) => cs + c.cves, 0), 0);

  return (
    <TooltipProvider>
      <div className="space-y-6">
        {/* Header */}
        <PageHeader
          title="Vendor Management"
          description="Third-party risk tracking, SBOM component linkage, and assessment history across your supply chain."
          badge="TPRM"
          actions={
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" className="gap-1.5" onClick={fetchVendors} disabled={loading}>
                <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
                Refresh
              </Button>
              <Button onClick={() => setShowAddDialog(true)} size="sm" className="gap-1.5">
                <Plus className="h-4 w-4" />
                Add Vendor
              </Button>
            </div>
          }
        />

        {/* KPI row */}
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
          <KpiCard
            title="Total Vendors"
            value={totalVendors}
            icon={Building2}
            description="Under management"
          />
          <KpiCard
            title="Avg Risk Score"
            value={`${avgScore}/100`}
            icon={BarChart3}         trend={avgScore >= 75 ? "up" : avgScore >= 55 ? "flat" : "down"}
            trendLabel={avgScore >= 75 ? "Acceptable posture" : avgScore >= 55 ? "Needs attention" : "High exposure"}
          />
          <KpiCard
            title="Critical Tier"
            value={criticalTierCount}
            icon={ShieldAlert}
            description="Vendors in critical tier"
          />
          <KpiCard
            title="Active Alerts"
            value={activeAlertCount}
            icon={Bell}         trend={activeAlertCount === 0 ? "up" : "down"}
            trendLabel={activeAlertCount === 0 ? "All clear" : "Require attention"}
          />
          <KpiCard
            title="Overdue Assessments"
            value={overdueCount}
            icon={Clock}         trend={overdueCount === 0 ? "up" : "down"}
            trendLabel={overdueCount === 0 ? "All current" : "Past due date"}
          />
          <KpiCard
            title="Open CVEs"
            value={totalCVEs}
            icon={ShieldX}         trend={totalCVEs === 0 ? "up" : "down"}
            trendLabel={totalCVEs === 0 ? "No CVEs" : "In SBOM components"}
          />
        </div>

        {/* Loading / error banners */}
        {loading && (
          <div className="flex items-center justify-center gap-2 py-4 text-sm text-muted-foreground">
            <RefreshCw className="h-4 w-4 animate-spin" />
            Loading vendors from API...
          </div>
        )}
        {error && !loading && (
          <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm text-amber-300">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>API unavailable ({error}) — showing fallback data.</span>
          </div>
        )}

        {/* Alert strip — undismissed high/critical alerts */}
        {activeAlertCount > 0 && (() => {
          const urgentAlerts = vendors
            .flatMap(v => v.alerts.filter(a => !a.dismissed && (a.severity === "critical" || a.severity === "high")).map(a => ({ ...a, vendorName: v.name })))
            .sort((a, b) => b.date.getTime() - a.date.getTime())
            .slice(0, 3);
          return urgentAlerts.length > 0 ? (
            <div className="space-y-2">
              {urgentAlerts.map(alert => (
                <motion.div
                  key={alert.id}
                  initial={{ opacity: 0, y: -4 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={cn(
                    "flex items-start gap-3 rounded-lg border px-4 py-3 text-sm",
                    alert.severity === "critical"
                      ? "border-red-500/40 bg-red-500/5 text-red-300"
                      : "border-orange-500/40 bg-orange-500/5 text-orange-300"
                  )}
                >
                  <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <span className="font-medium">{alert.vendorName}</span>
                    {" — "}
                    <span>{alert.message}</span>
                  </div>
                  <span className="text-xs opacity-60 shrink-0">{formatDate(alert.date)}</span>
                </motion.div>
              ))}
            </div>
          ) : null;
        })()}

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-48 max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder="Search vendors..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-9 h-8 text-sm"
            />
          </div>
          <Select value={filterTier} onValueChange={v => setFilterTier(v as typeof filterTier)}>
            <SelectTrigger className="h-8 w-36 text-sm">
              <SelectValue placeholder="All tiers" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Tiers</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
          <Select value={filterGrade} onValueChange={v => setFilterGrade(v as typeof filterGrade)}>
            <SelectTrigger className="h-8 w-36 text-sm">
              <SelectValue placeholder="All grades" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Grades</SelectItem>
              <SelectItem value="A">A — Excellent</SelectItem>
              <SelectItem value="B">B — Good</SelectItem>
              <SelectItem value="C">C — Fair</SelectItem>
              <SelectItem value="D">D — Poor</SelectItem>
              <SelectItem value="F">F — Critical</SelectItem>
            </SelectContent>
          </Select>
          <span className="text-xs text-muted-foreground ml-auto">
            {filtered.length} of {vendors.length} vendors
          </span>
        </div>

        {/* Main table + detail panel layout */}
        <div className="flex gap-5 items-start">
          {/* Table */}
          <Card className={cn("flex-1 min-w-0 overflow-hidden", selectedVendor && "xl:max-w-[calc(100%-400px-20px)]")}>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/20">
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground w-14">Grade</th>
                    <th className="px-4 py-3 text-left">
                      <button onClick={() => toggleSort("name")} className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors">
                        Vendor <SortIcon col="name" />
                      </button>
                    </th>
                    <th className="px-4 py-3 text-left hidden lg:table-cell text-xs font-medium text-muted-foreground">Category</th>
                    <th className="px-4 py-3 text-left w-36">
                      <button onClick={() => toggleSort("score")} className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors">
                        Score <SortIcon col="score" />
                      </button>
                    </th>
                    <th className="px-4 py-3 text-left w-24">
                      <button onClick={() => toggleSort("tier")} className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors">
                        Tier <SortIcon col="tier" />
                      </button>
                    </th>
                    <th className="px-4 py-3 text-left w-32 hidden md:table-cell">
                      <button onClick={() => toggleSort("assessed")} className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors">
                        Assessed <SortIcon col="assessed" />
                      </button>
                    </th>
                    <th className="px-4 py-3 text-left w-24 hidden xl:table-cell text-xs font-medium text-muted-foreground">Components</th>
                    <th className="px-4 py-3 text-left w-24 hidden xl:table-cell text-xs font-medium text-muted-foreground">Findings</th>
                    <th className="w-10" />
                  </tr>
                </thead>
                <tbody>
                  <AnimatePresence>
                    {filtered.length === 0 ? (
                      <tr>
                        <td colSpan={9} className="px-4 py-16 text-center text-muted-foreground text-sm">
                          No vendors match your filters.
                        </td>
                      </tr>
                    ) : (
                      filtered.map((vendor, i) => (
                        <VendorRow
                          key={vendor.id}
                          vendor={vendor}
                          selected={selectedVendor?.id === vendor.id}
                          onSelect={() => setSelectedVendor(prev => prev?.id === vendor.id ? null : vendor)}
                          index={i}
                        />
                      ))
                    )}
                  </AnimatePresence>
                </tbody>
              </table>
            </div>
          </Card>

          {/* Detail panel */}
          <AnimatePresence>
            {selectedVendor && (
              <motion.div
                key={selectedVendor.id}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
                className="w-[390px] shrink-0 hidden xl:block"
              >
                <Card className="sticky top-20">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm font-semibold">Vendor Detail</CardTitle>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => setSelectedVendor(null)}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[calc(100vh-260px)]">
                      <AssessmentPanel vendor={selectedVendor} />
                    </ScrollArea>
                  </CardContent>
                </Card>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Mobile detail drawer */}
        <Dialog
          open={!!selectedVendor}
          onOpenChange={open => { if (!open) setSelectedVendor(null); }}
        >
          <DialogContent className="xl:hidden max-w-lg">
            <DialogHeader>
              <DialogTitle className="text-sm">Vendor Detail</DialogTitle>
            </DialogHeader>
            {selectedVendor && (
              <ScrollArea className="max-h-[70vh]">
                <AssessmentPanel vendor={selectedVendor} />
              </ScrollArea>
            )}
          </DialogContent>
        </Dialog>

        {/* Add Vendor dialog */}
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>Add Vendor</DialogTitle>
            </DialogHeader>
            <AddVendorForm onClose={() => setShowAddDialog(false)} onAdd={handleAddVendor} />
          </DialogContent>
        </Dialog>
      </div>
    </TooltipProvider>
  );
}
