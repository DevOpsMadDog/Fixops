/**
 * SBOM Management — Software Bill of Materials Command Center
 *
 * Full lifecycle: import, inspect, diff, license compliance, vuln mapping.
 * Designed for AppSec leads, supply chain security engineers, and compliance officers.
 *
 * Aesthetic: industrial-dark data terminal — charcoal/slate, amber license warnings,
 * teal for safe, red for vulns. Component tree uses monospace density.
 * Diff view: newspaper-column split with surgical red/green line decoration.
 *
 * Route: /sbom
 */

import { useState, useMemo, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Package,
  Upload,
  GitCompare,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ChevronRight,
  ChevronDown,
  Search,
  Filter,
  Download,
  Clock,
  Shield,
  FileCode2,
  Layers,
  Plus,
  Minus,
  RefreshCw,
  ExternalLink,
  Info,
  ArrowLeftRight,
  FileJson,
  FileText,
  Scale,
  Cpu,
  Globe,
  Lock,
  Unlock,
  AlertCircle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type SBOMFormat = "CycloneDX" | "SPDX";
type LicenseRisk = "critical" | "high" | "medium" | "low" | "none";
type ComponentStatus = "added" | "removed" | "changed" | "unchanged";

interface VulnRef {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  cvss: number;
  description: string;
}

interface Component {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  license: string;
  licenseRisk: LicenseRisk;
  vulns: VulnRef[];
  children?: Component[];
  supplier?: string;
  hash?: string;
  isTransitive: boolean;
}

interface SBOMEntry {
  id: string;
  project: string;
  version: string;
  format: SBOMFormat;
  componentCount: number;
  vulnCount: number;
  criticalVulns: number;
  licenseRisks: number;
  importedAt: Date;
  generatedAt: Date;
  environment: "production" | "staging" | "development";
  components: Component[];
}

interface DiffComponent {
  name: string;
  oldVersion?: string;
  newVersion?: string;
  status: ComponentStatus;
  licenseChange?: { from: string; to: string };
  vulnChange?: { added: number; removed: number };
}

// ═══════════════════════════════════════════════════════════
// Mock Data
// ═══════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════
// Utility helpers
// ═══════════════════════════════════════════════════════════

function formatDate(d: Date) {
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function formatDateShort(d: Date) {
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

const LICENSE_RISK_META: Record<LicenseRisk, { label: string; className: string }> = {
  critical: { label: "COPYLEFT", className: "bg-red-500/15 text-red-400 border-red-500/30" },
  high: { label: "RESTRICTIVE", className: "bg-orange-500/15 text-orange-400 border-orange-500/30" },
  medium: { label: "NOTICE", className: "bg-amber-500/15 text-amber-400 border-amber-500/30" },
  low: { label: "PERMISSIVE", className: "bg-blue-500/15 text-blue-400 border-blue-500/30" },
  none: { label: "CLEAN", className: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30" },
};

const SEVERITY_META = {
  critical: { className: "bg-red-500/15 text-red-400 border-red-500/30", dot: "bg-red-400" },
  high: { className: "bg-orange-500/15 text-orange-400 border-orange-500/30", dot: "bg-orange-400" },
  medium: { className: "bg-amber-500/15 text-amber-400 border-amber-500/30", dot: "bg-amber-400" },
  low: { className: "bg-blue-500/15 text-blue-400 border-blue-500/30", dot: "bg-blue-400" },
};

const ENV_META = {
  production: { label: "PROD", className: "bg-red-500/15 text-red-400" },
  staging: { label: "STG", className: "bg-amber-500/15 text-amber-400" },
  development: { label: "DEV", className: "bg-blue-500/15 text-blue-400" },
};

const ECOSYSTEM_ICONS: Record<string, string> = {
  npm: "⬡",
  maven: "▲",
  pypi: "⬢",
  system: "◈",
  go: "◉",
  cargo: "◆",
};

// ═══════════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════════

function LicenseBadge({ risk, license }: { risk: LicenseRisk; license: string }) {
  const meta = LICENSE_RISK_META[risk];
  return (
    <div className="flex items-center gap-1.5">
      <span className={cn("inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-mono font-bold border", meta.className)}>
        {meta.label}
      </span>
      <span className="text-xs text-muted-foreground font-mono">{license}</span>
    </div>
  );
}

function SeverityDot({ severity }: { severity: "critical" | "high" | "medium" | "low" }) {
  return <span className={cn("inline-block h-2 w-2 rounded-full shrink-0", SEVERITY_META[severity].dot)} />;
}

function VulnBadge({ count, severity }: { count: number; severity: "critical" | "high" | "medium" | "low" }) {
  if (count === 0) return null;
  return (
    <span className={cn("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold border", SEVERITY_META[severity].className)}>
      <SeverityDot severity={severity} />
      {count}
    </span>
  );
}

// ── Component Tree Node ──
function ComponentNode({ comp, depth = 0, searchTerm }: { comp: Component; depth?: number; searchTerm: string }) {
  const [expanded, setExpanded] = useState(depth === 0);
  const hasChildren = comp.children && comp.children.length > 0;
  const totalVulns = comp.vulns.length;
  const criticalVulns = comp.vulns.filter((v) => v.severity === "critical").length;
  const highVulns = comp.vulns.filter((v) => v.severity === "high").length;
  const [selectedVuln, setSelectedVuln] = useState<VulnRef | null>(null);

  const nameMatch = searchTerm && comp.name.toLowerCase().includes(searchTerm.toLowerCase());

  return (
    <div className={cn("font-mono text-xs", depth > 0 && "ml-5 border-l border-border/50 pl-3")}>
      <div
        className={cn(
          "flex items-center gap-2 py-1.5 px-2 rounded-md group cursor-pointer hover:bg-muted/30 transition-colors",
          nameMatch && "bg-amber-500/10 border border-amber-500/20",
        )}
        onClick={() => hasChildren && setExpanded(!expanded)}
      >
        {/* Expand toggle */}
        <span className="shrink-0 w-3">
          {hasChildren ? (
            expanded ? <ChevronDown className="h-3 w-3 text-muted-foreground" /> : <ChevronRight className="h-3 w-3 text-muted-foreground" />
          ) : <span className="h-3 w-3 inline-block" />}
        </span>

        {/* Ecosystem icon */}
        <span className="text-muted-foreground text-[11px] shrink-0 w-3">
          {ECOSYSTEM_ICONS[comp.ecosystem] ?? "◇"}
        </span>

        {/* Name + version */}
        <span className={cn("font-semibold", nameMatch ? "text-amber-300" : "text-foreground")}>
          {comp.name}
        </span>
        <span className="text-muted-foreground/60">@</span>
        <span className="text-primary/80">{comp.version}</span>

        {/* Transitive indicator */}
        {comp.isTransitive && (
          <span className="text-[9px] text-muted-foreground/50 border border-border rounded px-1">DEP</span>
        )}

        {/* License */}
        <span className="ml-auto shrink-0">
          <LicenseBadge risk={comp.licenseRisk} license={comp.license} />
        </span>

        {/* Vulns */}
        <div className="flex gap-1 shrink-0">
          {criticalVulns > 0 && <VulnBadge count={criticalVulns} severity="critical" />}
          {highVulns > 0 && <VulnBadge count={highVulns} severity="high" />}
          {totalVulns - criticalVulns - highVulns > 0 && (
            <VulnBadge count={totalVulns - criticalVulns - highVulns} severity="medium" />
          )}
        </div>
      </div>

      {/* Vuln detail rows */}
      {comp.vulns.length > 0 && (
        <div className={cn("ml-8 space-y-0.5 mb-1", depth > 0 && "ml-5")}>
          {comp.vulns.map((v) => (
            <button
              key={v.id}
              onClick={() => setSelectedVuln(selectedVuln?.id === v.id ? null : v)}
              className="flex items-center gap-2 w-full text-left px-2 py-1 rounded hover:bg-muted/20 transition-colors"
            >
              <SeverityDot severity={v.severity} />
              <span className={cn("font-mono text-[10px] font-bold", SEVERITY_META[v.severity].className.split(" ").filter(c => c.startsWith("text-")).join(" "))}>
                {v.id}
              </span>
              <span className="text-[10px] text-muted-foreground truncate">{v.description}</span>
              <span className="ml-auto text-[10px] text-muted-foreground shrink-0">CVSS {v.cvss}</span>
            </button>
          ))}
          <AnimatePresence>
            {selectedVuln && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden"
              >
                <div className="ml-4 p-2.5 rounded-md bg-card border border-border/60 text-[10px] space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-foreground">{selectedVuln.id}</span>
                    <span className={cn("rounded px-1.5 py-0.5 font-bold border", SEVERITY_META[selectedVuln.severity].className)}>
                      {selectedVuln.severity.toUpperCase()}
                    </span>
                    <span className="ml-auto text-muted-foreground">CVSS {selectedVuln.cvss}/10</span>
                  </div>
                  <p className="text-muted-foreground leading-relaxed">{selectedVuln.description}</p>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${selectedVuln.id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-primary hover:underline"
                  >
                    <ExternalLink className="h-2.5 w-2.5" /> NVD Entry
                  </a>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* Children */}
      <AnimatePresence initial={false}>
        {expanded && hasChildren && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden"
          >
            {comp.children!.map((child) => (
              <ComponentNode key={child.id} comp={child} depth={depth + 1} searchTerm={searchTerm} />
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ── License Compliance Pie Chart ──
function LicensePieChart({ components }: { components: Component[] }) {
  const allComps = useMemo(() => {
    const flatten = (c: Component[]): Component[] =>
      c.flatMap((comp) => [comp, ...(comp.children ? flatten(comp.children) : [])]);
    return flatten(components);
  }, [components]);

  const data = useMemo(() => {
    const counts: Record<LicenseRisk, number> = { none: 0, low: 0, medium: 0, high: 0, critical: 0 };
    allComps.forEach((c) => counts[c.licenseRisk]++);
    return [
      { name: "Clean (MIT/Apache)", value: counts.none, color: "#10b981" },
      { name: "Permissive", value: counts.low, color: "#3b82f6" },
      { name: "Notice Required", value: counts.medium, color: "#f59e0b" },
      { name: "Restrictive", value: counts.high, color: "#f97316" },
      { name: "Copyleft Risk", value: counts.critical, color: "#ef4444" },
    ].filter((d) => d.value > 0);
  }, [allComps]);

  const total = allComps.length;

  return (
    <div className="h-[260px]">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="40%"
            cy="50%"
            innerRadius={60}
            outerRadius={90}
            paddingAngle={3}
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={index} fill={entry.color} opacity={0.85} />
            ))}
          </Pie>
          <RechartsTooltip
            contentStyle={{
              background: "oklch(0.17 0.01 250)",
              border: "1px solid oklch(0.25 0.01 250)",
              borderRadius: "8px",
              fontSize: "11px",
              fontFamily: "JetBrains Mono, monospace",
            }}
            formatter={(value: number, name: string) => [
              `${value} (${total > 0 ? ((value / total) * 100).toFixed(1) : "0.0"}%)`,
              name,
            ]}
          />
          <Legend
            layout="vertical"
            verticalAlign="middle"
            align="right"
            iconType="circle"
            iconSize={8}
            formatter={(value) => <span style={{ fontSize: 11, color: "oklch(0.60 0.01 250)" }}>{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Diff Line ──
function DiffLine({ item }: { item: DiffComponent }) {
  const isAdded = item.status === "added";
  const isRemoved = item.status === "removed";
  const isChanged = item.status === "changed";

  return (
    <div
      className={cn(
        "flex items-center gap-3 px-3 py-2 border-b border-border/30 font-mono text-xs group transition-colors",
        isAdded && "bg-emerald-500/5 hover:bg-emerald-500/10",
        isRemoved && "bg-red-500/5 hover:bg-red-500/10",
        isChanged && "bg-amber-500/5 hover:bg-amber-500/10",
        item.status === "unchanged" && "hover:bg-muted/20 opacity-60",
      )}
    >
      {/* Status glyph */}
      <span className={cn(
        "shrink-0 w-4 h-4 rounded-sm flex items-center justify-center text-[10px] font-bold",
        isAdded && "bg-emerald-500/20 text-emerald-400",
        isRemoved && "bg-red-500/20 text-red-400",
        isChanged && "bg-amber-500/20 text-amber-400",
        item.status === "unchanged" && "bg-muted/30 text-muted-foreground",
      )}>
        {isAdded ? "+" : isRemoved ? "−" : isChanged ? "~" : "·"}
      </span>

      {/* Package name */}
      <span className={cn(
        "font-semibold w-44 truncate",
        isAdded && "text-emerald-300",
        isRemoved && "text-red-300 line-through decoration-red-500/50",
        isChanged && "text-amber-200",
        item.status === "unchanged" && "text-muted-foreground",
      )}>
        {item.name}
      </span>

      {/* Version columns */}
      <div className="flex items-center gap-1 w-48">
        {item.oldVersion ? (
          <span className={cn("text-muted-foreground", isRemoved && "text-red-400/70")}>{item.oldVersion}</span>
        ) : (
          <span className="text-muted-foreground/30">—</span>
        )}
        {(isChanged || isAdded) && item.oldVersion && item.newVersion && (
          <ArrowLeftRight className="h-3 w-3 text-muted-foreground/40 shrink-0" />
        )}
        {item.newVersion ? (
          <span className={cn("", isAdded && "text-emerald-400", isChanged && "text-amber-300")}>{item.newVersion}</span>
        ) : (
          <span className="text-muted-foreground/30">—</span>
        )}
      </div>

      {/* License change */}
      {item.licenseChange && (
        <div className="flex items-center gap-1 ml-2">
          <Scale className="h-3 w-3 text-muted-foreground/60 shrink-0" />
          <span className="text-red-400/70 line-through text-[10px]">{item.licenseChange.from}</span>
          <ChevronRight className="h-2.5 w-2.5 text-muted-foreground/40" />
          <span className={cn("text-[10px]", item.licenseChange.to.includes("GPL") ? "text-orange-400" : "text-muted-foreground")}>
            {item.licenseChange.to}
          </span>
        </div>
      )}

      {/* Vuln change */}
      {item.vulnChange && (item.vulnChange.added > 0 || item.vulnChange.removed > 0) && (
        <div className="flex items-center gap-1.5 ml-auto shrink-0">
          {item.vulnChange.added > 0 && (
            <span className="text-[10px] text-red-400 flex items-center gap-0.5">
              <Plus className="h-2.5 w-2.5" />{item.vulnChange.added} vuln
            </span>
          )}
          {item.vulnChange.removed > 0 && (
            <span className="text-[10px] text-emerald-400 flex items-center gap-0.5">
              <Minus className="h-2.5 w-2.5" />{item.vulnChange.removed} fixed
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ── Import SBOM Modal ──
function ImportSBOMModal({ onClose }: { onClose: () => void }) {
  const [dragging, setDragging] = useState(false);
  const [file, setFile] = useState<string | null>(null);
  const [format, setFormat] = useState<SBOMFormat>("CycloneDX");

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0, y: 8 }}
        animate={{ scale: 1, opacity: 1, y: 0 }}
        exit={{ scale: 0.95, opacity: 0, y: 8 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        className="bg-card border border-border rounded-xl shadow-xl w-full max-w-lg p-6 space-y-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold">Import SBOM</h2>
            <p className="text-xs text-muted-foreground mt-0.5">CycloneDX JSON/XML or SPDX JSON/TV</p>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="h-8 w-8 p-0">
            <XCircle className="h-4 w-4" />
          </Button>
        </div>

        <Separator />

        {/* Drop zone */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            const f = e.dataTransfer.files[0];
            if (f) setFile(f.name);
          }}
          className={cn(
            "border-2 border-dashed rounded-lg p-8 text-center transition-colors cursor-pointer",
            dragging ? "border-primary bg-primary/5" : "border-border hover:border-primary/50 hover:bg-muted/20",
            file && "border-emerald-500/50 bg-emerald-500/5",
          )}
          onClick={() => {
            // Simulate file selection
            setFile("bom-api-gateway-v2.5.0.json");
          }}
        >
          {file ? (
            <div className="space-y-2">
              <CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto" />
              <p className="text-sm font-medium text-emerald-300">{file}</p>
              <p className="text-xs text-muted-foreground">Ready to import</p>
            </div>
          ) : (
            <div className="space-y-2">
              <Upload className="h-8 w-8 text-muted-foreground mx-auto" />
              <p className="text-sm text-muted-foreground">Drop SBOM file here or click to browse</p>
              <p className="text-xs text-muted-foreground/60">.json · .xml · .tv</p>
            </div>
          )}
        </div>

        {/* Format selection */}
        <div className="grid grid-cols-2 gap-3">
          {(["CycloneDX", "SPDX"] as SBOMFormat[]).map((f) => (
            <button
              key={f}
              onClick={() => setFormat(f)}
              className={cn(
                "flex items-center gap-2.5 rounded-lg px-4 py-3 border text-sm font-medium transition-colors",
                format === f
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:border-primary/40 hover:text-foreground",
              )}
            >
              {f === "CycloneDX" ? <FileJson className="h-4 w-4" /> : <FileText className="h-4 w-4" />}
              {f}
            </button>
          ))}
        </div>

        {/* Metadata */}
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground font-medium">Project</label>
            <Input placeholder="e.g. api-gateway" className="h-8 text-xs" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground font-medium">Version tag</label>
            <Input placeholder="e.g. v2.5.0" className="h-8 text-xs" />
          </div>
        </div>

        <div className="flex gap-2 justify-end">
          <Button variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          <Button size="sm" disabled={!file} onClick={onClose} className="gap-1.5">
            <Upload className="h-3.5 w-3.5" />
            Import SBOM
          </Button>
        </div>
      </motion.div>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// API helpers
// ═══════════════════════════════════════════════════════════

const SBOM_API_HEADERS = () => ({
  "Content-Type": "application/json",
  "X-API-Key": localStorage.getItem("apiKey") || "",
});

/** Map a backend project row into the SBOMEntry shape. */
function apiProjectToSBOM(p: Record<string, any>, idx: number): SBOMEntry {
  return {
    id: `sbom-api-${idx}`,
    project: p.project_name || p.name || "unknown",
    version: p.version_tag || p.version || "v1.0",
    format: (p.format as SBOMFormat) || "CycloneDX",
    componentCount: p.component_count ?? p.components ?? 0,
    vulnCount: p.vuln_count ?? p.vulns ?? 0,
    criticalVulns: p.critical_vulns ?? p.critical_count ?? 0,
    licenseRisks: p.license_risks ?? 0,
    importedAt: p.last_export ? new Date(p.last_export) : p.imported_at ? new Date(p.imported_at) : new Date(),
    generatedAt: p.generated_at ? new Date(p.generated_at) : new Date(),
    environment: (p.environment as SBOMEntry["environment"]) || "production",
    components: [],
  };
}

export default function SBOMManagement() {
  const [sboms, setSboms] = useState<SBOMEntry[]>([]);
  const [diffComponents, setDiffComponents] = useState<DiffComponent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [formatFilter, setFormatFilter] = useState<"all" | SBOMFormat>("all");
  const [envFilter, setEnvFilter] = useState<"all" | "production" | "staging" | "development">("all");
  const [selectedSBOM, setSelectedSBOM] = useState<SBOMEntry | null>(null);
  const [detailTab, setDetailTab] = useState("tree");
  const [componentSearch, setComponentSearch] = useState("");
  const [showImport, setShowImport] = useState(false);

  // Diff state
  const [diffLeft, setDiffLeft] = useState<string>("sbom-006");
  const [diffRight, setDiffRight] = useState<string>("sbom-001");
  const [diffFilter, setDiffFilter] = useState<"all" | ComponentStatus>("all");

  const fetchSBOMs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/v1/sbom-export/projects?org_id=default", {
        headers: SBOM_API_HEADERS(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const list: Record<string, any>[] = Array.isArray(data) ? data : data.projects ?? [];
      if (list.length > 0) {
        const mapped = list.map(apiProjectToSBOM);
        setSboms(mapped);
        // Update diff selectors to reference new IDs
        if (mapped.length >= 2) {
          setDiffLeft(mapped[mapped.length - 1].id);
          setDiffRight(mapped[0].id);
        }
      }
    } catch (err: any) {
      console.warn("SBOMManagement: API fetch failed:", err.message);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSBOMs();
    fetch("/api/v1/sbom-export/diff?org_id=default", { headers: SBOM_API_HEADERS() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => {
        const items = Array.isArray(d) ? d : (d?.components ?? d?.diff ?? []);
        if (items.length > 0) setDiffComponents(items);
      })
      .catch(() => { /* leave empty */ });
  }, [fetchSBOMs]);

  // Load real components when an SBOM is selected and has no components yet
  useEffect(() => {
    if (!selectedSBOM || selectedSBOM.components.length > 0) return;
    let cancelled = false;
    (async () => {
      try {
        // Try to fetch assets and their components for this project
        const res = await fetch(
          `/api/v1/sbom/assets?org_id=default`,
          { headers: SBOM_API_HEADERS() },
        );
        if (!res.ok) return;
        const assets: any[] = await res.json();
        // Find asset matching this project name
        const asset = assets.find(
          (a: any) => (a.name || "").toLowerCase() === selectedSBOM.project.toLowerCase(),
        );
        if (!asset) return;
        const compRes = await fetch(
          `/api/v1/sbom/assets/${asset.id}/components?org_id=default`,
          { headers: SBOM_API_HEADERS() },
        );
        if (!compRes.ok) return;
        const comps: any[] = await compRes.json();
        if (cancelled || !Array.isArray(comps) || comps.length === 0) return;
        const mapped: Component[] = comps.map((c: any, i: number) => ({
          id: c.id || `comp-${i}`,
          name: c.name || c.component_name || "unknown",
          version: c.version || c.component_version || "0.0.0",
          ecosystem: c.ecosystem || "npm",
          license: c.license || "Unknown",
          licenseRisk: (c.license_risk as LicenseRisk) || "none",
          vulns: Array.isArray(c.vulns)
            ? c.vulns.map((v: any) => ({
                id: v.cve_id || v.id || "CVE-0000",
                severity: v.severity || "medium",
                cvss: v.cvss_score ?? v.cvss ?? 0,
                description: v.description || "",
              }))
            : [],
          isTransitive: c.is_transitive ?? false,
          supplier: c.supplier || undefined,
          hash: c.hash_sha256 || undefined,
        }));
        setSboms((prev) =>
          prev.map((s) =>
            s.id === selectedSBOM.id ? { ...s, components: mapped } : s,
          ),
        );
        setSelectedSBOM((prev) =>
          prev && prev.id === selectedSBOM.id ? { ...prev, components: mapped } : prev,
        );
      } catch {
        // Silently fall back to mock components if API fails
      }
    })();
    return () => { cancelled = true; };
  }, [selectedSBOM?.id]);

  const filtered = useMemo(() => {
    return sboms.filter((s) => {
      const matchSearch = !search || s.project.toLowerCase().includes(search.toLowerCase()) || s.version.includes(search);
      const matchFormat = formatFilter === "all" || s.format === formatFilter;
      const matchEnv = envFilter === "all" || s.environment === envFilter;
      return matchSearch && matchFormat && matchEnv;
    });
  }, [sboms, search, formatFilter, envFilter]);

  const kpis = useMemo(() => {
    const total = sboms.length;
    const totalComponents = sboms.reduce((a, s) => a + s.componentCount, 0);
    const totalVulns = sboms.reduce((a, s) => a + s.vulnCount, 0);
    const criticals = sboms.reduce((a, s) => a + s.criticalVulns, 0);
    const licenseRisks = sboms.reduce((a, s) => a + s.licenseRisks, 0);
    return { total, totalComponents, totalVulns, criticals, licenseRisks };
  }, [sboms]);

  const filteredDiff = useMemo(() => {
    if (diffFilter === "all") return diffComponents;
    return diffComponents.filter((d) => d.status === diffFilter);
  }, [diffFilter, diffComponents]);

  const diffStats = useMemo(() => ({
    added:     diffComponents.filter((d) => d.status === "added").length,
    removed:   diffComponents.filter((d) => d.status === "removed").length,
    changed:   diffComponents.filter((d) => d.status === "changed").length,
    unchanged: diffComponents.filter((d) => d.status === "unchanged").length,
  }), [diffComponents]);

  const leftSBOM = sboms.find((s) => s.id === diffLeft);
  const rightSBOM = sboms.find((s) => s.id === diffRight);

  return (
    <TooltipProvider>
      <div className="space-y-6">
        {/* Header */}
        <PageHeader
          title="SBOM Management"
          description="Software Bill of Materials lifecycle — import, inspect, diff, and enforce license & vulnerability policy."
          badge="SUPPLY CHAIN"
          actions={
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" className="gap-1.5" onClick={fetchSBOMs} disabled={loading}>
                <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
                Refresh
              </Button>
              <Button variant="outline" size="sm" className="gap-1.5">
                <Download className="h-3.5 w-3.5" />
                Export All
              </Button>
              <Button size="sm" className="gap-1.5" onClick={() => setShowImport(true)}>
                <Upload className="h-3.5 w-3.5" />
                Import SBOM
              </Button>
            </div>
          }
        />

        {/* KPIs */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
          <KpiCard
            title="SBOM Files"
            value={kpis.total}
            icon={Package}
            description="Across all projects"
          />
          <KpiCard
            title="Total Components"
            value={kpis.totalComponents.toLocaleString()}
            icon={Layers}
            description="Unique packages tracked"
          />
          <KpiCard
            title="Vulnerabilities"
            value={kpis.totalVulns}
            icon={Shield}         trend="down"
            trendLabel="↓ 8% since last week"
          />
          <KpiCard
            title="Critical CVEs"
            value={kpis.criticals}
            icon={AlertTriangle}
            className={kpis.criticals > 0 ? "border-red-500/30" : ""}
            trend={kpis.criticals > 0 ? "down" : "flat"}
            trendLabel={kpis.criticals > 0 ? "Needs attention" : "Clean"}
          />
          <KpiCard
            title="License Risks"
            value={kpis.licenseRisks}
            icon={Scale}
            description="Copyleft / restrictive"
          />
        </div>

        {/* Loading / error banners */}
        {loading && (
          <div className="flex items-center justify-center gap-2 py-4 text-sm text-muted-foreground">
            <RefreshCw className="h-4 w-4 animate-spin" />
            Loading SBOMs from API...
          </div>
        )}
        {error && !loading && (
          <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm text-amber-300">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>API unavailable ({error}) — showing fallback data.</span>
          </div>
        )}

        {/* Main content tabs */}
        <Tabs defaultValue="inventory">
          <TabsList className="mb-4">
            <TabsTrigger value="inventory">
              <Package className="h-3.5 w-3.5 mr-1.5" />
              Inventory
            </TabsTrigger>
            <TabsTrigger value="detail" disabled={!selectedSBOM}>
              <FileCode2 className="h-3.5 w-3.5 mr-1.5" />
              Detail View
            </TabsTrigger>
            <TabsTrigger value="diff">
              <GitCompare className="h-3.5 w-3.5 mr-1.5" />
              Diff View
            </TabsTrigger>
          </TabsList>

          {/* ── Inventory Tab ── */}
          <TabsContent value="inventory" className="space-y-4">
            {/* Filters */}
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[200px] max-w-sm">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search project or version..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-8 h-8 text-xs"
                />
              </div>
              <div className="flex items-center gap-2">
                <Filter className="h-3.5 w-3.5 text-muted-foreground" />
                {(["all", "CycloneDX", "SPDX"] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setFormatFilter(f)}
                    className={cn(
                      "rounded-md px-3 py-1 text-xs font-medium border transition-colors",
                      formatFilter === f
                        ? "bg-primary/10 border-primary/40 text-primary"
                        : "border-border text-muted-foreground hover:border-primary/30 hover:text-foreground",
                    )}
                  >
                    {f === "all" ? "All Formats" : f}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-2 ml-auto">
                {(["all", "production", "staging", "development"] as const).map((e) => (
                  <button
                    key={e}
                    onClick={() => setEnvFilter(e)}
                    className={cn(
                      "rounded-md px-3 py-1 text-xs font-medium border transition-colors",
                      envFilter === e
                        ? "bg-primary/10 border-primary/40 text-primary"
                        : "border-border text-muted-foreground hover:border-primary/30 hover:text-foreground",
                    )}
                  >
                    {e === "all" ? "All Envs" : e.charAt(0).toUpperCase() + e.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            {/* Table */}
            <Card className="overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-muted/30">
                      <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Project</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Format</th>
                      <th className="text-right px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Components</th>
                      <th className="text-right px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Vulns</th>
                      <th className="text-right px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">License Risks</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Environment</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Imported</th>
                      <th className="px-4 py-3" />
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.length === 0 && (
                      <tr>
                        <td colSpan={8} className="px-4 py-12 text-center text-sm text-muted-foreground">
                          No SBOMs match your filters
                        </td>
                      </tr>
                    )}
                    {filtered.map((sbom, i) => (
                      <motion.tr
                        key={sbom.id}
                        initial={{ opacity: 0, x: -4 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.03, duration: 0.2 }}
                        className={cn(
                          "border-b border-border/50 group transition-colors cursor-pointer",
                          selectedSBOM?.id === sbom.id
                            ? "bg-primary/5 border-primary/20"
                            : "hover:bg-muted/30",
                        )}
                        onClick={() => setSelectedSBOM(sbom)}
                      >
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="h-7 w-7 rounded-md bg-primary/10 flex items-center justify-center shrink-0">
                              <Package className="h-3.5 w-3.5 text-primary" />
                            </div>
                            <div>
                              <div className="font-medium text-foreground">{sbom.project}</div>
                              <div className="text-xs text-muted-foreground font-mono">{sbom.version}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={cn(
                            "inline-flex items-center gap-1.5 rounded px-2 py-1 text-xs font-mono font-bold border",
                            sbom.format === "CycloneDX"
                              ? "bg-blue-500/10 text-blue-400 border-blue-500/20"
                              : "bg-violet-500/10 text-violet-400 border-violet-500/20",
                          )}>
                            {sbom.format === "CycloneDX" ? <FileJson className="h-3 w-3" /> : <FileText className="h-3 w-3" />}
                            {sbom.format}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right font-mono text-sm font-semibold">
                          {sbom.componentCount.toLocaleString()}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            {sbom.criticalVulns > 0 && (
                              <span className="font-mono text-xs font-bold text-red-400">
                                {sbom.criticalVulns}C
                              </span>
                            )}
                            <span className="font-mono text-sm font-semibold text-foreground">
                              {sbom.vulnCount}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            {sbom.licenseRisks > 0 ? (
                              <span className="font-mono text-sm font-semibold text-amber-400">{sbom.licenseRisks}</span>
                            ) : (
                              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={cn("rounded px-2 py-0.5 text-[10px] font-bold uppercase", ENV_META[sbom.environment].className)}>
                            {ENV_META[sbom.environment].label}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                            <Clock className="h-3 w-3" />
                            {formatDate(sbom.importedAt)}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-7 w-7 p-0"
                                  onClick={(e) => { e.stopPropagation(); setSelectedSBOM(sbom); }}
                                >
                                  <FileCode2 className="h-3.5 w-3.5" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>View detail</TooltipContent>
                            </Tooltip>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button variant="ghost" size="sm" className="h-7 w-7 p-0">
                                  <Download className="h-3.5 w-3.5" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>Download</TooltipContent>
                            </Tooltip>
                          </div>
                        </td>
                      </motion.tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>

            <p className="text-xs text-muted-foreground">
              Showing {filtered.length} of {sboms.length} SBOMs · Click a row to inspect components
            </p>
          </TabsContent>

          {/* ── Detail Tab ── */}
          <TabsContent value="detail" className="space-y-4">
            {selectedSBOM ? (
              <>
                {/* Detail header */}
                <Card className="p-4">
                  <div className="flex flex-wrap items-center gap-4">
                    <div className="flex items-center gap-3">
                      <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                        <Package className="h-5 w-5 text-primary" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h2 className="text-lg font-bold">{selectedSBOM.project}</h2>
                          <span className="font-mono text-sm text-muted-foreground">{selectedSBOM.version}</span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-bold", ENV_META[selectedSBOM.environment].className)}>
                            {ENV_META[selectedSBOM.environment].label}
                          </span>
                          <span className="text-xs text-muted-foreground">
                            Generated {formatDate(selectedSBOM.generatedAt)} · Imported {formatDate(selectedSBOM.importedAt)}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="ml-auto flex items-center gap-6">
                      <div className="text-center">
                        <div className="text-2xl font-bold font-mono">{selectedSBOM.componentCount}</div>
                        <div className="text-[10px] text-muted-foreground uppercase tracking-wide">Components</div>
                      </div>
                      <Separator orientation="vertical" className="h-10" />
                      <div className="text-center">
                        <div className={cn("text-2xl font-bold font-mono", selectedSBOM.vulnCount > 0 ? "text-orange-400" : "text-emerald-400")}>
                          {selectedSBOM.vulnCount}
                        </div>
                        <div className="text-[10px] text-muted-foreground uppercase tracking-wide">Vulns</div>
                      </div>
                      <Separator orientation="vertical" className="h-10" />
                      <div className="text-center">
                        <div className={cn("text-2xl font-bold font-mono", selectedSBOM.criticalVulns > 0 ? "text-red-400" : "text-emerald-400")}>
                          {selectedSBOM.criticalVulns}
                        </div>
                        <div className="text-[10px] text-muted-foreground uppercase tracking-wide">Critical</div>
                      </div>
                      <Separator orientation="vertical" className="h-10" />
                      <div className="text-center">
                        <div className={cn("text-2xl font-bold font-mono", selectedSBOM.licenseRisks > 0 ? "text-amber-400" : "text-emerald-400")}>
                          {selectedSBOM.licenseRisks}
                        </div>
                        <div className="text-[10px] text-muted-foreground uppercase tracking-wide">License Risks</div>
                      </div>
                    </div>
                  </div>
                </Card>

                {/* Detail sub-tabs */}
                <Tabs value={detailTab} onValueChange={setDetailTab}>
                  <TabsList>
                    <TabsTrigger value="tree">
                      <Layers className="h-3.5 w-3.5 mr-1.5" />
                      Component Tree
                    </TabsTrigger>
                    <TabsTrigger value="vulns">
                      <Shield className="h-3.5 w-3.5 mr-1.5" />
                      Vulnerability Map
                    </TabsTrigger>
                    <TabsTrigger value="licenses">
                      <Scale className="h-3.5 w-3.5 mr-1.5" />
                      License Compliance
                    </TabsTrigger>
                  </TabsList>

                  {/* Component Tree */}
                  <TabsContent value="tree" className="mt-4">
                    <Card>
                      <CardHeader className="pb-3 flex flex-row items-center gap-3">
                        <CardTitle className="text-sm">Component Tree</CardTitle>
                        <div className="relative ml-auto w-56">
                          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
                          <Input
                            placeholder="Search components..."
                            value={componentSearch}
                            onChange={(e) => setComponentSearch(e.target.value)}
                            className="pl-7 h-7 text-xs"
                          />
                        </div>
                      </CardHeader>
                      <CardContent className="p-0">
                        <ScrollArea className="h-[480px]">
                          <div className="p-4 space-y-0.5">
                            {selectedSBOM.components.map((comp) => (
                              <ComponentNode key={comp.id} comp={comp} searchTerm={componentSearch} />
                            ))}
                          </div>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  </TabsContent>

                  {/* Vulnerability Map */}
                  <TabsContent value="vulns" className="mt-4">
                    <div className="space-y-3">
                      {selectedSBOM.components.flatMap((c) => {
                        const flat = [c, ...(c.children ?? [])];
                        return flat.flatMap((comp) =>
                          comp.vulns.map((v) => ({ comp, vuln: v }))
                        );
                      }).sort((a, b) => b.vuln.cvss - a.vuln.cvss).map(({ comp, vuln }) => (
                        <motion.div
                          key={`${comp.id}-${vuln.id}`}
                          initial={{ opacity: 0, y: 4 }}
                          animate={{ opacity: 1, y: 0 }}
                          className={cn(
                            "rounded-lg border p-4 space-y-2",
                            vuln.severity === "critical" && "border-red-500/30 bg-red-500/5",
                            vuln.severity === "high" && "border-orange-500/30 bg-orange-500/5",
                            vuln.severity === "medium" && "border-amber-500/30 bg-amber-500/5",
                            vuln.severity === "low" && "border-blue-500/30 bg-blue-500/5",
                          )}
                        >
                          <div className="flex items-center gap-3">
                            <SeverityDot severity={vuln.severity} />
                            <span className="font-mono font-bold text-sm">{vuln.id}</span>
                            <span className={cn("rounded px-2 py-0.5 text-[10px] font-bold border uppercase", SEVERITY_META[vuln.severity].className)}>
                              {vuln.severity}
                            </span>
                            <span className="ml-auto font-mono text-sm font-bold">CVSS {vuln.cvss}</span>
                          </div>
                          <p className="text-sm text-muted-foreground">{vuln.description}</p>
                          <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <Package className="h-3 w-3" />
                            <span className="font-mono">{comp.name}@{comp.version}</span>
                            <span className="ml-auto">
                              <Progress value={(vuln.cvss / 10) * 100} className="w-24 h-1.5" />
                            </span>
                          </div>
                        </motion.div>
                      ))}
                      {selectedSBOM.components.every((c) => c.vulns.length === 0 && (!c.children || c.children.every((ch) => ch.vulns.length === 0))) && (
                        <div className="text-center py-12 space-y-2">
                          <CheckCircle2 className="h-10 w-10 text-emerald-400 mx-auto" />
                          <p className="text-sm font-medium text-emerald-300">No vulnerabilities found</p>
                          <p className="text-xs text-muted-foreground">This SBOM is clean</p>
                        </div>
                      )}
                    </div>
                  </TabsContent>

                  {/* License Compliance */}
                  <TabsContent value="licenses" className="mt-4">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <Card className="p-4">
                        <CardTitle className="text-sm mb-4">License Distribution</CardTitle>
                        <LicensePieChart components={selectedSBOM.components} />
                      </Card>
                      <Card className="p-4">
                        <CardTitle className="text-sm mb-4">Risk Breakdown</CardTitle>
                        <div className="space-y-3">
                          {Object.entries(LICENSE_RISK_META).map(([risk, meta]) => {
                            const flat = (comps: Component[]): Component[] =>
                              comps.flatMap((c) => [c, ...(c.children ? flat(c.children) : [])]);
                            const count = flat(selectedSBOM.components).filter((c) => c.licenseRisk === risk).length;
                            if (count === 0) return null;
                            return (
                              <div key={risk} className="space-y-1.5">
                                <div className="flex items-center justify-between">
                                  <span className={cn("inline-flex items-center rounded px-2 py-0.5 text-[10px] font-mono font-bold border", meta.className)}>
                                    {meta.label}
                                  </span>
                                  <span className="text-xs font-mono font-semibold">{count}</span>
                                </div>
                                <Progress
                                  value={(count / selectedSBOM.componentCount) * 100}
                                  className="h-1.5"
                                />
                              </div>
                            );
                          })}
                        </div>
                        <Separator className="my-4" />
                        <div className="space-y-2">
                          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Policy Status</p>
                          {selectedSBOM.licenseRisks > 0 ? (
                            <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
                              <AlertCircle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                              <div className="text-xs text-amber-300">
                                <p className="font-semibold">Policy violation detected</p>
                                <p className="text-amber-400/70 mt-0.5">{selectedSBOM.licenseRisks} components require legal review before distribution.</p>
                              </div>
                            </div>
                          ) : (
                            <div className="flex items-center gap-2 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                              <span className="text-xs text-emerald-300 font-semibold">All licenses compliant</span>
                            </div>
                          )}
                        </div>
                      </Card>
                    </div>
                  </TabsContent>
                </Tabs>
              </>
            ) : (
              <div className="text-center py-20 space-y-3">
                <FileCode2 className="h-12 w-12 text-muted-foreground/40 mx-auto" />
                <p className="text-sm text-muted-foreground">Select an SBOM from the Inventory tab to inspect</p>
              </div>
            )}
          </TabsContent>

          {/* ── Diff Tab ── */}
          <TabsContent value="diff" className="space-y-4">
            {/* Diff selector */}
            <Card className="p-4">
              <div className="flex flex-wrap items-center gap-4">
                <div className="flex items-center gap-3 flex-1 min-w-[280px]">
                  <div className="flex-1 space-y-1">
                    <label className="text-[10px] text-muted-foreground uppercase tracking-wide font-medium">Base (older)</label>
                    <div className="flex flex-col gap-1">
                      {sboms.map((s) => (
                        <label key={s.id} className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="radio"
                            name="diff-left"
                            value={s.id}
                            checked={diffLeft === s.id}
                            onChange={() => setDiffLeft(s.id)}
                            className="accent-primary"
                          />
                          <span className={cn("text-xs font-mono", diffLeft === s.id ? "text-foreground font-semibold" : "text-muted-foreground")}>
                            {s.project} {s.version}
                            <span className="text-[10px] ml-1.5 opacity-60">{formatDateShort(s.importedAt)}</span>
                          </span>
                        </label>
                      ))}
                    </div>
                  </div>

                  <div className="flex flex-col items-center gap-1">
                    <ArrowLeftRight className="h-5 w-5 text-muted-foreground" />
                    <span className="text-[10px] text-muted-foreground">vs</span>
                  </div>

                  <div className="flex-1 space-y-1">
                    <label className="text-[10px] text-muted-foreground uppercase tracking-wide font-medium">Target (newer)</label>
                    <div className="flex flex-col gap-1">
                      {sboms.map((s) => (
                        <label key={s.id} className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="radio"
                            name="diff-right"
                            value={s.id}
                            checked={diffRight === s.id}
                            onChange={() => setDiffRight(s.id)}
                            className="accent-primary"
                          />
                          <span className={cn("text-xs font-mono", diffRight === s.id ? "text-foreground font-semibold" : "text-muted-foreground")}>
                            {s.project} {s.version}
                            <span className="text-[10px] ml-1.5 opacity-60">{formatDateShort(s.importedAt)}</span>
                          </span>
                        </label>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Diff stats */}
                <div className="flex items-center gap-4 shrink-0 ml-auto">
                  <div className="text-center">
                    <div className="text-xl font-bold font-mono text-emerald-400">+{diffStats.added}</div>
                    <div className="text-[10px] text-muted-foreground uppercase">Added</div>
                  </div>
                  <div className="text-center">
                    <div className="text-xl font-bold font-mono text-red-400">-{diffStats.removed}</div>
                    <div className="text-[10px] text-muted-foreground uppercase">Removed</div>
                  </div>
                  <div className="text-center">
                    <div className="text-xl font-bold font-mono text-amber-400">~{diffStats.changed}</div>
                    <div className="text-[10px] text-muted-foreground uppercase">Changed</div>
                  </div>
                  <div className="text-center">
                    <div className="text-xl font-bold font-mono text-muted-foreground">{diffStats.unchanged}</div>
                    <div className="text-[10px] text-muted-foreground uppercase">Same</div>
                  </div>
                </div>
              </div>
            </Card>

            {/* Diff viewer */}
            <Card className="overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/20">
                <div className="flex items-center gap-3">
                  <GitCompare className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm font-medium">
                    {leftSBOM ? `${leftSBOM.project} ${leftSBOM.version}` : "—"}
                    <span className="text-muted-foreground mx-2">→</span>
                    {rightSBOM ? `${rightSBOM.project} ${rightSBOM.version}` : "—"}
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  {(["all", "added", "removed", "changed", "unchanged"] as const).map((f) => (
                    <button
                      key={f}
                      onClick={() => setDiffFilter(f)}
                      className={cn(
                        "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                        diffFilter === f
                          ? f === "added" ? "bg-emerald-500/20 text-emerald-300"
                            : f === "removed" ? "bg-red-500/20 text-red-300"
                            : f === "changed" ? "bg-amber-500/20 text-amber-300"
                            : "bg-primary/10 text-primary"
                          : "text-muted-foreground hover:text-foreground hover:bg-muted/40",
                      )}
                    >
                      {f.charAt(0).toUpperCase() + f.slice(1)}
                    </button>
                  ))}
                </div>
              </div>

              {/* Column headers */}
              <div className="grid grid-cols-[1rem_1fr_1fr_1fr] gap-x-3 px-3 py-2 border-b border-border/30 bg-muted/10 font-mono text-[10px] text-muted-foreground uppercase tracking-wider">
                <span />
                <span>Package</span>
                <span>Version (base → target)</span>
                <span>Notes</span>
              </div>

              <ScrollArea className="h-[500px]">
                <div>
                  {filteredDiff.map((item, i) => (
                    <motion.div
                      key={item.name}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.015 }}
                    >
                      <DiffLine item={item} />
                    </motion.div>
                  ))}
                </div>
              </ScrollArea>

              <div className="px-4 py-3 border-t border-border/30 flex items-center justify-between text-xs text-muted-foreground bg-muted/10">
                <span>
                  {filteredDiff.length} of {diffComponents.length} components shown
                </span>
                <Button variant="outline" size="sm" className="h-7 text-xs gap-1.5">
                  <Download className="h-3 w-3" />
                  Export Diff Report
                </Button>
              </div>
            </Card>
          </TabsContent>
        </Tabs>
      </div>

      {/* Import modal */}
      <AnimatePresence>
        {showImport && <ImportSBOMModal onClose={() => setShowImport(false)} />}
      </AnimatePresence>
    </TooltipProvider>
  );
}
