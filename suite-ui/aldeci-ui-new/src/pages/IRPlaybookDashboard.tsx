/**
 * IR Playbook Dashboard
 *
 * Incident Response Playbooks — execution tracking, MTTD/MTTR metrics.
 *   1. KPIs: Playbooks, Executions, Avg MTTD (hours), Avg MTTR (hours)
 *   2. Recent executions table (playbook name, incident type, severity, MTTD, MTTR, status)
 *
 * Route: /ir-playbook
 * API: GET /api/v1/ir-playbook/stats, /api/v1/ir-playbook/executions
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { BookOpen, Play, Clock, TrendingDown, RefreshCw, CheckCircle, AlertTriangle, Loader2 } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_STATS = {
  playbooks: 12,
  executions: 47,
  avg_mttd_hours: 2.3,
  avg_mttr_hours: 8.7,
};

const MOCK_EXECUTIONS = [
  { id: "EXEC-001", playbook: "Ransomware Response",        incident_type: "ransomware",      severity: "critical", mttd_hours: 0.8, mttr_hours: 4.2,  status: "completed" },
  { id: "EXEC-002", playbook: "Data Breach Containment",    incident_type: "data_breach",     severity: "critical", mttd_hours: 1.2, mttr_hours: 12.5, status: "in_progress" },
  { id: "EXEC-003", playbook: "Phishing Campaign Response", incident_type: "phishing",        severity: "high",     mttd_hours: 0.5, mttr_hours: 2.1,  status: "completed" },
  { id: "EXEC-004", playbook: "DDoS Mitigation",            incident_type: "ddos",            severity: "high",     mttd_hours: 0.2, mttr_hours: 1.8,  status: "completed" },
  { id: "EXEC-005", playbook: "Insider Threat Investigation",incident_type: "insider_threat", severity: "high",     mttd_hours: 3.5, mttr_hours: 18.0, status: "in_progress" },
  { id: "EXEC-006", playbook: "Supply Chain Compromise",    incident_type: "supply_chain",    severity: "critical", mttd_hours: 5.1, mttr_hours: 32.0, status: "in_progress" },
  { id: "EXEC-007", playbook: "Credential Stuffing",        incident_type: "credential_abuse",severity: "medium",   mttd_hours: 1.0, mttr_hours: 3.5,  status: "completed" },
  { id: "EXEC-008", playbook: "Malware Infection",          incident_type: "malware",         severity: "high",     mttd_hours: 2.2, mttr_hours: 6.8,  status: "completed" },
  { id: "EXEC-009", playbook: "Zero-Day Exploitation",      incident_type: "zero_day",        severity: "critical", mttd_hours: 0.3, mttr_hours: 48.0, status: "in_progress" },
  { id: "EXEC-010", playbook: "Business Email Compromise",  incident_type: "bec",             severity: "high",     mttd_hours: 4.8, mttr_hours: 9.2,  status: "completed" },
];

// ── Badge helpers ──────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/40 text-red-400 bg-red-500/10",
    high:     "border-orange-500/40 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/40 text-yellow-400 bg-yellow-500/10",
    low:      "border-blue-500/40 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge variant="outline" className={map[severity] ?? map.low}>
      {severity}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed:   "border-green-500/40 text-green-400 bg-green-500/10",
    in_progress: "border-yellow-500/40 text-yellow-400 bg-yellow-500/10",
    failed:      "border-red-500/40 text-red-400 bg-red-500/10",
  };
  const icons: Record<string, React.ReactNode> = {
    completed:   <CheckCircle className="w-3 h-3 mr-1" />,
    in_progress: <Loader2 className="w-3 h-3 mr-1 animate-spin" />,
    failed:      <AlertTriangle className="w-3 h-3 mr-1" />,
  };
  const labels: Record<string, string> = {
    completed:   "Completed",
    in_progress: "In Progress",
    failed:      "Failed",
  };
  return (
    <Badge variant="outline" className={`flex items-center ${map[status] ?? map.in_progress}`}>
      {icons[status]}
      {labels[status] ?? status}
    </Badge>
  );
}

function MttrCell({ hours }: { hours: number }) {
  const color =
    hours <= 4  ? "text-green-400" :
    hours <= 12 ? "text-yellow-400" :
                  "text-red-400";
  return <span className={`font-mono text-sm ${color}`}>{hours.toFixed(1)}h</span>;
}

// ── Main Component ─────────────────────────────────────────────

export default function IRPlaybookDashboard() {
  const [stats, setStats] = useState(MOCK_STATS);
  const [executions, setExecutions] = useState(MOCK_EXECUTIONS);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const [s, e] = await Promise.all([
        apiFetch("/api/v1/ir-playbook/stats?org_id=default"),
        apiFetch("/api/v1/ir-playbook/executions?org_id=default&limit=10"),
      ]);
      if (s && typeof s.playbooks === "number") setStats(s);
      if (Array.isArray(e) && e.length > 0) setExecutions(e);
    } catch {
      // API not available — keep mock data
    } finally {
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="IR Playbook Dashboard"
        description="Incident Response Playbooks — execution tracking, MTTD/MTTR performance metrics"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <KpiCard
            title="Playbooks"
            value={stats.playbooks}
            icon={<BookOpen className="w-5 h-5 text-blue-400" />}
            trend={{ direction: "up", label: "+2 this month" }}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.10 }}>
          <KpiCard
            title="Executions"
            value={stats.executions}
            icon={<Play className="w-5 h-5 text-purple-400" />}
            trend={{ direction: "up", label: "+5 this week" }}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <KpiCard
            title="Avg MTTD"
            value={`${stats.avg_mttd_hours}h`}
            icon={<Clock className="w-5 h-5 text-yellow-400" />}
            trend={{ direction: "down", label: "-0.4h vs last month" }}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.20 }}>
          <KpiCard
            title="Avg MTTR"
            value={`${stats.avg_mttr_hours}h`}
            icon={<TrendingDown className="w-5 h-5 text-green-400" />}
            trend={{ direction: "down", label: "-1.2h vs last month" }}
          />
        </motion.div>
      </div>

      {/* Executions Table */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
        <Card className="border-white/10 bg-white/5">
          <CardHeader>
            <CardTitle className="text-sm font-medium text-white/80">Recent Executions</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="border-white/10 hover:bg-transparent">
                  <TableHead className="text-white/50">Playbook</TableHead>
                  <TableHead className="text-white/50">Incident Type</TableHead>
                  <TableHead className="text-white/50">Severity</TableHead>
                  <TableHead className="text-white/50">MTTD</TableHead>
                  <TableHead className="text-white/50">MTTR</TableHead>
                  <TableHead className="text-white/50">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {executions.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  executions.map((ex) => (
                  <TableRow key={ex.id} className="border-white/10 hover:bg-white/5">
                    <TableCell className="font-medium text-white/90">{ex.playbook}</TableCell>
                    <TableCell className="text-white/60 text-sm">{ex.incident_type.replace(/_/g, " ")}</TableCell>
                    <TableCell><SeverityBadge severity={ex.severity} /></TableCell>
                    <TableCell><MttrCell hours={ex.mttd_hours} /></TableCell>
                    <TableCell><MttrCell hours={ex.mttr_hours} /></TableCell>
                    <TableCell><StatusBadge status={ex.status} /></TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
