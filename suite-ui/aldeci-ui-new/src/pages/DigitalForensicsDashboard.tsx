/**
 * DigitalForensicsDashboard — Case management, evidence chain of custody, and analysis
 *
 * Route: /digital-forensics
 * Sections:
 *   1. KPIs: Open Cases, Evidence Items, Analyses Completed, Avg Case Duration
 *   2. Case table (10 rows)
 *   3. Evidence list for top case (8 items)
 *   4. Analysis results (5 cards)
 *   5. Chain of custody table (6 entries)
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { FolderOpen, Database, FlaskConical, Clock, RefreshCw, Shield, FileText, ChevronRight } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const CASES = [
  { id: "DF-2024-001", title: "Ransomware deployment on prod-db cluster", type: "ransom",      priority: "Critical", analyst: "K. Torres",   status: "active",    days: 4,  evidence: 12 },
  { id: "DF-2024-002", title: "Insider exfiltration via USB devices",     type: "insider",     priority: "High",     analyst: "M. Patel",    status: "analysis",  days: 7,  evidence: 8  },
  { id: "DF-2024-003", title: "Supply chain compromise in node_modules",  type: "malware",     priority: "Critical", analyst: "S. Kim",      status: "active",    days: 2,  evidence: 6  },
  { id: "DF-2024-004", title: "Business email compromise — finance dept", type: "fraud",       priority: "High",     analyst: "J. Rivera",   status: "analysis",  days: 9,  evidence: 5  },
  { id: "DF-2024-005", title: "Customer PII exfil from API endpoint",     type: "data_breach", priority: "Critical", analyst: "L. Chen",     status: "reporting", days: 14, evidence: 17 },
  { id: "DF-2024-006", title: "Crypto-jacking on Kubernetes workers",     type: "malware",     priority: "Medium",   analyst: "D. Nguyen",   status: "active",    days: 3,  evidence: 4  },
  { id: "DF-2024-007", title: "Credential stuffing campaign against SSO", type: "data_breach", priority: "High",     analyst: "K. Torres",   status: "closed",    days: 22, evidence: 9  },
  { id: "DF-2024-008", title: "Rogue admin account creation via SCIM",   type: "insider",     priority: "Medium",   analyst: "M. Patel",    status: "analysis",  days: 6,  evidence: 3  },
  { id: "DF-2024-009", title: "Phishing-based lateral movement",          type: "malware",     priority: "High",     analyst: "S. Kim",      status: "active",    days: 1,  evidence: 2  },
  { id: "DF-2024-010", title: "Card skimmer JS injection on checkout",    type: "fraud",       priority: "Critical", analyst: "J. Rivera",   status: "analysis",  days: 5,  evidence: 7  },
];

const EVIDENCE = [
  { type: "memory_dump",    filename: "prod-db-01_mem_dump_20260416.bin", size: "32.4 GB", hash: "a3f4c9d1...", collected_by: "K. Torres", collected_at: "2026-04-16 02:14" },
  { type: "disk_image",     filename: "prod-db-01_sda_full.dd",           size: "500 GB",  hash: "7e2a1b8f...", collected_by: "K. Torres", collected_at: "2026-04-16 02:31" },
  { type: "pcap",           filename: "net_capture_16apr_0200_0600.pcap", size: "14.7 GB", hash: "c9d3e8a2...", collected_by: "SIEM Auto", collected_at: "2026-04-16 06:00" },
  { type: "log_file",       filename: "auth_svc_prod_20260416.log",       size: "1.2 GB",  hash: "f1b7d4e9...", collected_by: "SIEM Auto", collected_at: "2026-04-16 06:01" },
  { type: "malware_sample", filename: "ransom_dropper_x64.elf",           size: "284 KB",  hash: "88c5a3f2...", collected_by: "K. Torres", collected_at: "2026-04-16 03:47" },
  { type: "log_file",       filename: "k8s_audit_log_20260416.jsonl",     size: "3.1 GB",  hash: "2d9e7c4b...", collected_by: "SIEM Auto", collected_at: "2026-04-16 06:02" },
  { type: "memory_dump",    filename: "worker-node-07_mem_20260416.bin",  size: "16.0 GB", hash: "b4a2f6d8...", collected_by: "S. Kim",    collected_at: "2026-04-16 04:22" },
  { type: "pcap",           filename: "c2_comm_trace_20260416.pcap",      size: "892 MB",  hash: "e7c1d3a9...", collected_by: "K. Torres", collected_at: "2026-04-16 05:10" },
];

const ANALYSES = [
  { type: "static",  iocs: 14, tool: "YARA + Radare2",     analyst: "K. Torres", date: "2026-04-16 08:30", findings: "Confirmed double-encrypted ransomware payload with persistence via systemd unit" },
  { type: "dynamic", iocs: 22, tool: "Cuckoo Sandbox v3",  analyst: "M. Patel",  date: "2026-04-16 09:15", findings: "C2 beaconing every 90s to 185.220.101.x, exfil over port 443 with custom TLS" },
  { type: "network", iocs: 8,  tool: "Zeek + Suricata",    analyst: "S. Kim",    date: "2026-04-16 10:00", findings: "Lateral movement via RDP relay; 3 pivot hosts identified in 192.168.10.0/24" },
  { type: "timeline",iocs: 31, tool: "Timesketch",          analyst: "J. Rivera", date: "2026-04-16 11:30", findings: "Initial access 72h before detonation; dwell time 3 days with staged exfil" },
  { type: "memory",  iocs: 19, tool: "Volatility 3",        analyst: "L. Chen",   date: "2026-04-16 12:45", findings: "Injected shellcode in LSASS; credential harvester active since 2026-04-13 18:22" },
];

const CUSTODY_CHAIN = [
  { action: "collected",   actor: "K. Torres",   ts: "2026-04-16 02:31", notes: "Forensic image taken with FTK Imager; write-blocker verified" },
  { action: "transferred", actor: "K. Torres",   ts: "2026-04-16 02:55", notes: "Transferred to encrypted evidence storage via SCP" },
  { action: "analyzed",    actor: "S. Kim",      ts: "2026-04-16 04:22", notes: "Memory analysis with Volatility 3; hash verified pre-analysis" },
  { action: "stored",      actor: "SIEM System", ts: "2026-04-16 06:00", notes: "Replicated to cold storage; SHA-256 checksum logged" },
  { action: "transferred", actor: "J. Rivera",   ts: "2026-04-16 09:00", notes: "Copy provided to legal team for preservation hold" },
  { action: "analyzed",    actor: "L. Chen",     ts: "2026-04-16 12:45", notes: "Final analysis sign-off; chain of custody integrity confirmed" },
];

// ── Helpers ────────────────────────────────────────────────────

function CaseTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    malware:     "border-red-500/30 text-red-400 bg-red-500/10",
    data_breach: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    insider:     "border-purple-500/30 text-purple-400 bg-purple-500/10",
    fraud:       "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    ransom:      "border-red-600/30 text-red-300 bg-red-600/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{type}</Badge>;
}

function PriorityBadge({ p }: { p: string }) {
  const map: Record<string, string> = {
    Critical: "border-red-500/30 text-red-400 bg-red-500/10",
    High:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    Medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    Low:      "border-border text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border", map[p] ?? "border-border text-muted-foreground")}>{p}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    analysis:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
    reporting: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    closed:    "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[status] ?? "border-border text-muted-foreground")}>{status}</Badge>;
}

function EvidenceTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    memory_dump:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    pcap:           "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    log_file:       "border-green-500/30 text-green-400 bg-green-500/10",
    disk_image:     "border-purple-500/30 text-purple-400 bg-purple-500/10",
    malware_sample: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{type.replace(/_/g, " ")}</Badge>;
}

function AnalysisTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    static:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    dynamic:  "border-orange-500/30 text-orange-400 bg-orange-500/10",
    network:  "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    timeline: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    memory:   "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{type}</Badge>;
}

function CustodyActionBadge({ action }: { action: string }) {
  const map: Record<string, string> = {
    collected:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    transferred: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    analyzed:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    stored:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[action] ?? "border-border text-muted-foreground")}>{action}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function DigitalForensicsDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [selectedCase, setSelectedCase] = useState("DF-2024-001");
  const [liveData, setLiveData] = useState<Record<string, any> | null>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/digital-forensics/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/digital-forensics/cases?org_id=${ORG_ID}&limit=20`),
    ]).then(([statsResult, casesResult]) => {
      const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
      const cases = casesResult.status === "fulfilled" ? casesResult.value : null;
      if (stats || cases) {
        setLiveData({ stats, cases });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const liveCases = liveData?.cases?.items ?? liveData?.cases ?? CASES;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Digital Forensics"
        description="Case management, evidence chain of custody, and analysis"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Open Cases"           value={liveData?.stats?.open_cases ?? liveData?.stats?.total_open ?? 8}      icon={FolderOpen}   trend="up"   className="border-blue-500/20" />
        <KpiCard title="Evidence Items"       value={liveData?.stats?.total_evidence ?? liveData?.stats?.evidence_count ?? 47} icon={Database}  trend="up"   />
        <KpiCard title="Analyses Completed"   value={liveData?.stats?.analyses_completed ?? liveData?.stats?.closed_cases ?? 23} icon={FlaskConical} trend="up" className="border-green-500/20" />
        <KpiCard title="Avg Case Duration"    value={liveData?.stats?.avg_case_duration_days != null ? `${liveData.stats.avg_case_duration_days}d` : "12.4d"} icon={Clock} trend="down" />
      </div>

      {/* Case Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <FolderOpen className="h-4 w-4 text-blue-400" />
            Active Cases
          </CardTitle>
          <CardDescription className="text-xs">Click a row to view evidence and analysis for that case</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Case ID</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Priority</TableHead>
                  <TableHead className="text-[11px] h-8">Analyst</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Days</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Evidence</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {liveCases.map((c: any) => (
                  <TableRow
                    key={c.id}
                    className={cn("hover:bg-muted/30 cursor-pointer", selectedCase === c.id && "bg-primary/5 border-l-2 border-l-primary")}
                    onClick={() => setSelectedCase(c.id)}
                  >
                    <TableCell className="text-xs font-mono py-2.5">{c.id}</TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[200px] truncate">{c.title}</TableCell>
                    <TableCell className="py-2.5"><CaseTypeBadge type={c.type} /></TableCell>
                    <TableCell className="py-2.5"><PriorityBadge p={c.priority} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{c.analyst}</TableCell>
                    <TableCell className="py-2.5"><StatusBadge status={c.status} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-right tabular-nums text-muted-foreground">{c.days}</TableCell>
                    <TableCell className="text-xs py-2.5 text-right tabular-nums font-medium">{c.evidence}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Open</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Evidence List + Chain of Custody */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Evidence list */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Database className="h-4 w-4 text-purple-400" />
                Evidence — {selectedCase}
              </CardTitle>
              <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">
                {EVIDENCE.length} items
              </Badge>
            </div>
            <CardDescription className="text-xs">Collected evidence with integrity hashes</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Filename</TableHead>
                  <TableHead className="text-[11px] h-8">Size</TableHead>
                  <TableHead className="text-[11px] h-8">Hash</TableHead>
                  <TableHead className="text-[11px] h-8">Collected</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {EVIDENCE.map((e, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2"><EvidenceTypeBadge type={e.type} /></TableCell>
                    <TableCell className="text-xs py-2 max-w-[120px] truncate font-mono text-muted-foreground">{e.filename}</TableCell>
                    <TableCell className="text-xs py-2 tabular-nums text-muted-foreground">{e.size}</TableCell>
                    <TableCell className="text-xs py-2 font-mono text-muted-foreground">{e.hash}</TableCell>
                    <TableCell className="text-xs py-2 text-muted-foreground">{e.collected_by}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Chain of custody */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-green-400" />
              Chain of Custody
            </CardTitle>
            <CardDescription className="text-xs">Audit trail for selected evidence item</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Action</TableHead>
                  <TableHead className="text-[11px] h-8">Actor</TableHead>
                  <TableHead className="text-[11px] h-8">Timestamp</TableHead>
                  <TableHead className="text-[11px] h-8">Notes</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {CUSTODY_CHAIN.map((entry, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2"><CustodyActionBadge action={entry.action} /></TableCell>
                    <TableCell className="text-xs py-2 text-muted-foreground">{entry.actor}</TableCell>
                    <TableCell className="text-xs py-2 tabular-nums text-muted-foreground">{entry.ts}</TableCell>
                    <TableCell className="text-xs py-2 max-w-[160px] truncate text-muted-foreground">{entry.notes}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {/* Analysis Results */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <FlaskConical className="h-4 w-4 text-orange-400" />
            Analysis Results
          </CardTitle>
          <CardDescription className="text-xs">Completed forensic analyses for case {selectedCase}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {ANALYSES.map((a) => (
              <div key={a.type} className="rounded-lg border border-border bg-muted/10 p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <AnalysisTypeBadge type={a.type} />
                  <span className="text-[10px] text-muted-foreground">{a.date}</span>
                </div>
                <div className="flex items-center gap-2">
                  <FileText className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                  <span className="text-[11px] text-muted-foreground">{a.tool}</span>
                </div>
                <p className="text-[11px] text-muted-foreground leading-relaxed line-clamp-2">{a.findings}</p>
                <div className="flex items-center justify-between pt-1">
                  <span className="text-[11px] text-muted-foreground">
                    <span className="font-semibold text-foreground">{a.iocs}</span> IOCs — {a.analyst}
                  </span>
                  <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] gap-1">
                    View <ChevronRight className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
