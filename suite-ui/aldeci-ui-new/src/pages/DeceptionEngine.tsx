/**
 * Deception Engine Dashboard
 *
 * Honeypot and canary token monitoring:
 *   1. KPIs: Active Honeypots, Canary Tokens Deployed, Triggered This Week, Unique Attacker IPs
 *   2. Alert Feed: Recent deception triggers (red-accented)
 *   3. Honeypot Status grid: 12 honeypots with type, status, interactions
 *   4. Canary Tokens table: 10 tokens with trigger status
 *   5. Attacker Profile cards: per unique attacker IP
 *   6. Deploy New Decoy panel (placeholder)
 *
 * Route: /deception
 * API: GET /api/v1/deception/honeypots, /api/v1/deception/canary-tokens, /api/v1/deception/alerts
 */

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle,
  Shield,
  MapPin,
  Clock,
  Globe,
  Activity,
  Eye,
  X,
  ChevronRight,
  Wifi,
  Server,
  Database,
  Folder,
  Cloud,
  Monitor,
  Plus,
  FileText,
  Key,
  Link,
  Image,
  Terminal,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type TriggerType = "honeypot_access" | "canary_opened" | "credential_used";
type HoneypotType = "windows_server" | "linux_ssh" | "fake_database" | "web_app" | "file_share" | "cloud_storage";
type HoneypotStatus = "active" | "maintenance";
type CanaryType = "dns" | "word_doc" | "pdf" | "url" | "aws_key" | "image" | "csv";

interface DeceptionAlert {
  id: string;
  timestamp: string;
  trigger_type: TriggerType;
  attacker_ip: string;
  geo: string;
  geo_flag: string;
  asset_triggered: string;
  severity: "critical";
}

interface Honeypot {
  id: string;
  name: string;
  type: HoneypotType;
  last_triggered: string | null;
  interactions_count: number;
  status: HoneypotStatus;
  ip: string;
}

interface CanaryToken {
  id: string;
  token_name: string;
  type: CanaryType;
  deployed_to: string;
  created_date: string;
  triggered: boolean;
  triggered_timestamp: string | null;
  triggered_by_ip: string | null;
}

interface AttackerProfile {
  ip: string;
  geo: string;
  geo_flag: string;
  city: string;
  first_seen: string;
  interactions: number;
  techniques: string[];
  threat_score: number;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_ALERTS: DeceptionAlert[] = [
  {
    id: "DEC-001",
    timestamp: "2026-04-16 08:14",
    trigger_type: "credential_used",
    attacker_ip: "185.220.101.42",
    geo: "RU",
    geo_flag: "🇷🇺",
    asset_triggered: "AWS Prod Keys Backup.txt",
    severity: "critical",
  },
  {
    id: "DEC-002",
    timestamp: "2026-04-15 23:47",
    trigger_type: "honeypot_access",
    attacker_ip: "194.165.16.88",
    geo: "NL",
    geo_flag: "🇳🇱",
    asset_triggered: "HP-WinSrv-DC01 (Windows Server)",
    severity: "critical",
  },
  {
    id: "DEC-003",
    timestamp: "2026-04-15 19:22",
    trigger_type: "canary_opened",
    attacker_ip: "45.33.32.156",
    geo: "US",
    geo_flag: "🇺🇸",
    asset_triggered: "Finance Q4 Budget — copy.docx",
    severity: "critical",
  },
  {
    id: "DEC-004",
    timestamp: "2026-04-15 14:05",
    trigger_type: "honeypot_access",
    attacker_ip: "185.220.101.42",
    geo: "RU",
    geo_flag: "🇷🇺",
    asset_triggered: "HP-LinSSH-Prod01 (Linux SSH)",
    severity: "critical",
  },
  {
    id: "DEC-005",
    timestamp: "2026-04-14 21:33",
    trigger_type: "honeypot_access",
    attacker_ip: "194.165.16.88",
    geo: "NL",
    geo_flag: "🇳🇱",
    asset_triggered: "HP-FakeDB-MySQL01 (Fake Database)",
    severity: "critical",
  },
  {
    id: "DEC-006",
    timestamp: "2026-04-14 16:58",
    trigger_type: "canary_opened",
    attacker_ip: "185.220.101.42",
    geo: "RU",
    geo_flag: "🇷🇺",
    asset_triggered: "Employee_Salaries_2026.pdf",
    severity: "critical",
  },
  {
    id: "DEC-007",
    timestamp: "2026-04-14 11:12",
    trigger_type: "honeypot_access",
    attacker_ip: "45.33.32.156",
    geo: "US",
    geo_flag: "🇺🇸",
    asset_triggered: "HP-WebApp-Staging (Web App)",
    severity: "critical",
  },
  {
    id: "DEC-008",
    timestamp: "2026-04-13 09:44",
    trigger_type: "credential_used",
    attacker_ip: "194.165.16.88",
    geo: "NL",
    geo_flag: "🇳🇱",
    asset_triggered: "Backup S3 Access Keys — PROD",
    severity: "critical",
  },
];

const MOCK_HONEYPOTS: Honeypot[] = [
  { id: "HP-001", name: "HP-WinSrv-DC01", type: "windows_server", last_triggered: "2026-04-15 23:47", interactions_count: 14, status: "active", ip: "10.0.250.10" },
  { id: "HP-002", name: "HP-WinSrv-Exchange", type: "windows_server", last_triggered: null, interactions_count: 0, status: "active", ip: "10.0.250.11" },
  { id: "HP-003", name: "HP-LinSSH-Prod01", type: "linux_ssh", last_triggered: "2026-04-15 14:05", interactions_count: 31, status: "active", ip: "10.0.250.20" },
  { id: "HP-004", name: "HP-LinSSH-Dev02", type: "linux_ssh", last_triggered: "2026-04-12 07:19", interactions_count: 7, status: "active", ip: "10.0.250.21" },
  { id: "HP-005", name: "HP-FakeDB-MySQL01", type: "fake_database", last_triggered: "2026-04-14 21:33", interactions_count: 9, status: "active", ip: "10.0.250.30" },
  { id: "HP-006", name: "HP-FakeDB-Postgres", type: "fake_database", last_triggered: null, interactions_count: 0, status: "maintenance", ip: "10.0.250.31" },
  { id: "HP-007", name: "HP-WebApp-Staging", type: "web_app", last_triggered: "2026-04-14 11:12", interactions_count: 22, status: "active", ip: "10.0.250.40" },
  { id: "HP-008", name: "HP-WebApp-AdminPanel", type: "web_app", last_triggered: "2026-04-10 15:30", interactions_count: 5, status: "active", ip: "10.0.250.41" },
  { id: "HP-009", name: "HP-FileShare-Finance", type: "file_share", last_triggered: null, interactions_count: 0, status: "active", ip: "10.0.250.50" },
  { id: "HP-010", name: "HP-FileShare-HR", type: "file_share", last_triggered: "2026-04-11 18:44", interactions_count: 3, status: "active", ip: "10.0.250.51" },
  { id: "HP-011", name: "HP-Cloud-S3Bucket", type: "cloud_storage", last_triggered: "2026-04-13 09:44", interactions_count: 8, status: "active", ip: "cloud" },
  { id: "HP-012", name: "HP-Cloud-AzureBlob", type: "cloud_storage", last_triggered: null, interactions_count: 0, status: "active", ip: "cloud" },
];

const MOCK_CANARY_TOKENS: CanaryToken[] = [
  {
    id: "CT-001",
    token_name: "Finance Q4 Budget.docx",
    type: "word_doc",
    deployed_to: "SharePoint Finance folder",
    created_date: "2026-03-01",
    triggered: false,
    triggered_timestamp: null,
    triggered_by_ip: null,
  },
  {
    id: "CT-002",
    token_name: "AWS Prod Keys Backup.txt",
    type: "aws_key",
    deployed_to: "S3 bucket root",
    created_date: "2026-03-05",
    triggered: true,
    triggered_timestamp: "2026-04-14 09:31",
    triggered_by_ip: "185.220.101.42",
  },
  {
    id: "CT-003",
    token_name: "Customer DB Dump 2026.csv",
    type: "csv",
    deployed_to: "Email attachment sent to vendor",
    created_date: "2026-03-10",
    triggered: false,
    triggered_timestamp: null,
    triggered_by_ip: null,
  },
  {
    id: "CT-004",
    token_name: "Employee_Salaries_2026.pdf",
    type: "pdf",
    deployed_to: "HR shared drive",
    created_date: "2026-03-12",
    triggered: true,
    triggered_timestamp: "2026-04-14 16:58",
    triggered_by_ip: "185.220.101.42",
  },
  {
    id: "CT-005",
    token_name: "backup-credentials.env",
    type: "aws_key",
    deployed_to: "GitHub private repo (honeypot)",
    created_date: "2026-03-15",
    triggered: false,
    triggered_timestamp: null,
    triggered_by_ip: null,
  },
  {
    id: "CT-006",
    token_name: "internal-api-docs.pdf",
    type: "pdf",
    deployed_to: "Confluence public space",
    created_date: "2026-03-18",
    triggered: false,
    triggered_timestamp: null,
    triggered_by_ip: null,
  },
  {
    id: "CT-007",
    token_name: "corp-logo-2026.png",
    type: "image",
    deployed_to: "Marketing shared folder",
    created_date: "2026-03-20",
    triggered: true,
    triggered_timestamp: "2026-04-15 19:22",
    triggered_by_ip: "45.33.32.156",
  },
  {
    id: "CT-008",
    token_name: "https://internal.corp/admin-reset",
    type: "url",
    deployed_to: "Phishing bait email (sent to TI feed)",
    created_date: "2026-03-22",
    triggered: false,
    triggered_timestamp: null,
    triggered_by_ip: null,
  },
  {
    id: "CT-009",
    token_name: "dns-canary.internal.corp",
    type: "dns",
    deployed_to: "Embedded in API response (decoy endpoint)",
    created_date: "2026-03-25",
    triggered: false,
    triggered_timestamp: null,
    triggered_by_ip: null,
  },
  {
    id: "CT-010",
    token_name: "Backup S3 Access Keys — PROD",
    type: "aws_key",
    deployed_to: "Internal wiki (decoy page)",
    created_date: "2026-03-28",
    triggered: true,
    triggered_timestamp: "2026-04-13 09:44",
    triggered_by_ip: "194.165.16.88",
  },
];

const MOCK_ATTACKERS: AttackerProfile[] = [
  {
    ip: "185.220.101.42",
    geo: "RU",
    geo_flag: "🇷🇺",
    city: "Moscow, Russia",
    first_seen: "2026-04-13 09:31",
    interactions: 24,
    techniques: ["SSH brute force", "Credential stuffing", "S3 enumeration", "Port scan"],
    threat_score: 98,
  },
  {
    ip: "194.165.16.88",
    geo: "NL",
    geo_flag: "🇳🇱",
    city: "Amsterdam, Netherlands",
    first_seen: "2026-04-13 09:44",
    interactions: 17,
    techniques: ["Web app crawling", "SQL injection probe", "AWS key abuse", "Port scan"],
    threat_score: 91,
  },
  {
    ip: "45.33.32.156",
    geo: "US",
    geo_flag: "🇺🇸",
    city: "Fremont, CA (Tor exit)",
    first_seen: "2026-04-14 11:12",
    interactions: 9,
    techniques: ["Document exfil probe", "DNS canary trigger", "Directory traversal"],
    threat_score: 74,
  },
];

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

const HONEYPOT_ICONS: Record<HoneypotType, React.ReactNode> = {
  windows_server: <Monitor className="w-5 h-5 text-blue-400" />,
  linux_ssh: <Terminal className="w-5 h-5 text-green-400" />,
  fake_database: <Database className="w-5 h-5 text-purple-400" />,
  web_app: <Globe className="w-5 h-5 text-cyan-400" />,
  file_share: <Folder className="w-5 h-5 text-yellow-400" />,
  cloud_storage: <Cloud className="w-5 h-5 text-sky-400" />,
};

const HONEYPOT_TYPE_LABELS: Record<HoneypotType, string> = {
  windows_server: "Windows Server",
  linux_ssh: "Linux SSH",
  fake_database: "Fake Database",
  web_app: "Web App",
  file_share: "File Share",
  cloud_storage: "Cloud Storage",
};

const CANARY_ICONS: Record<CanaryType, React.ReactNode> = {
  dns: <Wifi className="w-4 h-4 text-cyan-400" />,
  word_doc: <FileText className="w-4 h-4 text-blue-400" />,
  pdf: <FileText className="w-4 h-4 text-red-400" />,
  url: <Link className="w-4 h-4 text-purple-400" />,
  aws_key: <Key className="w-4 h-4 text-yellow-400" />,
  image: <Image className="w-4 h-4 text-pink-400" />,
  csv: <FileText className="w-4 h-4 text-green-400" />,
};

const TRIGGER_LABELS: Record<TriggerType, string> = {
  honeypot_access: "Honeypot Access",
  canary_opened: "Canary Opened",
  credential_used: "Credential Used",
};

const TRIGGER_COLORS: Record<TriggerType, string> = {
  honeypot_access: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  canary_opened: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  credential_used: "bg-red-500/10 text-red-400 border-red-500/30",
};

function threatScoreColor(score: number): string {
  if (score >= 90) return "bg-red-500/20 text-red-400 border-red-500/40";
  if (score >= 70) return "bg-orange-500/20 text-orange-400 border-orange-500/40";
  return "bg-yellow-500/20 text-yellow-400 border-yellow-500/40";
}

// ══════════════════════════════════════════════════════════════
// Deploy Panel (placeholder)
// ══════════════════════════════════════════════════════════════

function DeployPanel({ onClose }: { onClose: () => void }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: 40 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 40 }}
      className="fixed inset-y-0 right-0 z-50 w-96 bg-slate-900 border-l border-slate-700 shadow-2xl flex flex-col"
    >
      <div className="flex items-center justify-between p-6 border-b border-slate-700">
        <h3 className="text-lg font-semibold text-slate-100">Deploy New Decoy</h3>
        <Button variant="ghost" size="icon" onClick={onClose} className="text-slate-400 hover:text-slate-100">
          <X className="w-5 h-5" />
        </Button>
      </div>
      <div className="flex-1 p-6 space-y-5 overflow-y-auto">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">Decoy Type</label>
          <select className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-slate-200 text-sm focus:outline-none focus:border-cyan-500">
            <option>Windows Server Honeypot</option>
            <option>Linux SSH Honeypot</option>
            <option>Fake Database</option>
            <option>Web App Honeypot</option>
            <option>File Share Honeypot</option>
            <option>Cloud Storage Honeypot</option>
            <option>DNS Canary Token</option>
            <option>Word Doc Canary</option>
            <option>PDF Canary</option>
            <option>AWS Key Canary</option>
            <option>URL Canary</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">Placement / Location</label>
          <input
            type="text"
            placeholder="e.g. SharePoint Finance folder, S3 bucket root..."
            className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-slate-200 text-sm placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">Notification Email</label>
          <input
            type="email"
            placeholder="soc-alerts@company.com"
            className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-slate-200 text-sm placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">Alert on Trigger</label>
          <div className="flex gap-4">
            {["Email", "Slack", "PagerDuty"].map((ch) => (
              <label key={ch} className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
                <input type="checkbox" defaultChecked={ch === "Email"} className="accent-cyan-500" />
                {ch}
              </label>
            ))}
          </div>
        </div>
        <div className="pt-2 text-xs text-slate-500 bg-slate-800/50 rounded-lg p-3 border border-slate-700">
          Note: Decoy deployment is a placeholder in this build. Integration with the backend deception engine at{" "}
          <code className="text-cyan-400">/api/v1/deception/deploy</code> is pending.
        </div>
      </div>
      <div className="p-6 border-t border-slate-700 flex gap-3">
        <Button variant="outline" className="flex-1 border-slate-600 text-slate-300" onClick={onClose}>
          Cancel
        </Button>
        <Button className="flex-1 bg-cyan-600 hover:bg-cyan-500 text-white" disabled>
          Deploy (Coming Soon)
        </Button>
      </div>
    </motion.div>
  );
}

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function DeceptionEngine() {
  const [deployOpen, setDeployOpen] = useState(false);

  const triggeredTokens = MOCK_CANARY_TOKENS.filter((t) => t.triggered).length;

  return (
    <div className="min-h-screen bg-slate-900 p-8 space-y-8">
      {/* Deploy panel overlay */}
      <AnimatePresence>
        {deployOpen && <DeployPanel onClose={() => setDeployOpen(false)} />}
      </AnimatePresence>

      {/* Header */}
      <div className="flex items-center justify-between">
        <PageHeader
          title="Deception Engine"
          description="Honeypots, canary tokens, and attacker tracking"
        />
        <Button
          onClick={() => setDeployOpen(true)}
          className="bg-cyan-600 hover:bg-cyan-500 text-white gap-2"
        >
          <Plus className="w-4 h-4" />
          Deploy New Decoy
        </Button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Active Honeypots"
          value={MOCK_HONEYPOTS.filter((h) => h.status === "active").length}
          icon={Server}
          changeLabel="2 cloud, 10 on-prem"
        />
        <KpiCard
          title="Canary Tokens Deployed"
          value={MOCK_CANARY_TOKENS.length + 37}
          icon={Eye}
          changeLabel="across 8 asset types"
        />
        <KpiCard
          title="Triggered This Week"
          value={8}
          icon={AlertTriangle}
          change={60}
          changeLabel="vs last week"
        />
        <KpiCard
          title="Unique Attacker IPs"
          value={MOCK_ATTACKERS.length}
          icon={Globe}
          changeLabel="3 countries"
        />
      </div>

      {/* Alert Feed */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
      >
        <Card className="border-red-500/40 bg-red-500/5">
          <CardHeader className="border-b border-red-500/20">
            <CardTitle className="flex items-center gap-2 text-red-400">
              <AlertTriangle className="w-5 h-5" />
              Deception Trigger Alerts
              <Badge className="ml-auto bg-red-500/20 text-red-400 border-red-500/40 text-xs">
                ALL CRITICAL — Legitimate users never touch decoys
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-slate-700/50">
              {MOCK_ALERTS.map((alert, idx) => (
                <motion.div
                  key={alert.id}
                  initial={{ opacity: 0, x: -4 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.05 + idx * 0.04 }}
                  className="flex items-center gap-4 px-6 py-3 hover:bg-red-500/5 transition-colors"
                >
                  <div className="w-2 h-2 rounded-full bg-red-500 flex-shrink-0 animate-pulse" />
                  <span className="text-xs font-mono text-slate-500 w-32 flex-shrink-0">{alert.timestamp}</span>
                  <Badge className={cn("text-xs border flex-shrink-0", TRIGGER_COLORS[alert.trigger_type])}>
                    {TRIGGER_LABELS[alert.trigger_type]}
                  </Badge>
                  <span className="font-mono text-sm text-slate-300 flex-shrink-0 w-32">{alert.attacker_ip}</span>
                  <span className="text-sm flex-shrink-0">{alert.geo_flag} {alert.geo}</span>
                  <span className="text-sm text-slate-400 flex-1 truncate">
                    <ChevronRight className="w-3 h-3 inline mr-1 text-slate-600" />
                    {alert.asset_triggered}
                  </span>
                  <Badge className="bg-red-500/10 text-red-400 border-red-500/30 text-xs flex-shrink-0">CRITICAL</Badge>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Honeypot Status Grid */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15 }}
      >
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <CardTitle className="flex items-center gap-2">
              <Server className="w-5 h-5 text-cyan-400" />
              Honeypot Status
              <span className="ml-2 text-sm font-normal text-slate-400">12 decoy systems deployed</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
              {MOCK_HONEYPOTS.map((hp, idx) => (
                <motion.div
                  key={hp.id}
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.15 + idx * 0.03 }}
                  className={cn(
                    "p-4 rounded-lg border transition-all",
                    hp.status === "maintenance"
                      ? "border-slate-600 bg-slate-800/30"
                      : hp.last_triggered
                        ? "border-orange-500/30 bg-orange-500/5"
                        : "border-slate-700 bg-slate-800/20"
                  )}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2">
                      {HONEYPOT_ICONS[hp.type]}
                      <span className="text-xs text-slate-400">{HONEYPOT_TYPE_LABELS[hp.type]}</span>
                    </div>
                    <Badge
                      className={cn(
                        "text-xs",
                        hp.status === "active"
                          ? "bg-green-500/10 text-green-400 border-green-500/30"
                          : "bg-slate-600/30 text-slate-400 border-slate-600"
                      )}
                    >
                      {hp.status === "active" ? "Active" : "Maintenance"}
                    </Badge>
                  </div>
                  <h4 className="font-semibold text-slate-200 text-sm mb-1 font-mono">{hp.name}</h4>
                  {hp.ip !== "cloud" && (
                    <p className="text-xs text-slate-500 mb-2 font-mono">{hp.ip}</p>
                  )}
                  <div className="flex items-center justify-between text-xs mt-2">
                    <span className="text-slate-500 flex items-center gap-1">
                      <Activity className="w-3 h-3" />
                      {hp.interactions_count} interactions
                    </span>
                  </div>
                  <div className="mt-2 text-xs">
                    {hp.last_triggered ? (
                      <span className="text-orange-400 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {hp.last_triggered}
                      </span>
                    ) : (
                      <span className="text-slate-500 italic">Never triggered — clean</span>
                    )}
                  </div>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Canary Tokens Table */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.25 }}
      >
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <CardTitle className="flex items-center gap-2">
              <Eye className="w-5 h-5 text-yellow-400" />
              Canary Tokens
              <span className="ml-2 text-sm font-normal text-slate-400">
                {triggeredTokens} triggered / {MOCK_CANARY_TOKENS.length} shown
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader className="bg-slate-800/50 border-b border-slate-700">
                  <TableRow>
                    <TableHead className="text-slate-300">Token Name</TableHead>
                    <TableHead className="text-slate-300">Type</TableHead>
                    <TableHead className="text-slate-300">Deployed To</TableHead>
                    <TableHead className="text-slate-300">Created</TableHead>
                    <TableHead className="text-slate-300 text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {MOCK_CANARY_TOKENS.map((token, idx) => (
                    <motion.tr
                      key={token.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: 0.25 + idx * 0.04 }}
                      className={cn(
                        "border-b border-slate-700/50 transition-colors",
                        token.triggered
                          ? "bg-red-500/5 hover:bg-red-500/10"
                          : "hover:bg-slate-800/30"
                      )}
                    >
                      <TableCell className="text-slate-200 font-medium text-sm">
                        <div className="flex items-center gap-2">
                          {CANARY_ICONS[token.type]}
                          {token.token_name}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className="bg-slate-700/50 text-slate-300 border-slate-600 text-xs uppercase">
                          {token.type.replace("_", " ")}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-slate-400 text-sm max-w-xs truncate">
                        <MapPin className="w-3 h-3 inline mr-1 text-slate-600" />
                        {token.deployed_to}
                      </TableCell>
                      <TableCell className="text-slate-500 text-sm font-mono">{token.created_date}</TableCell>
                      <TableCell className="text-right">
                        {token.triggered ? (
                          <div className="flex flex-col items-end gap-1">
                            <Badge className="bg-red-500/15 text-red-400 border-red-500/40 text-xs">
                              TRIGGERED
                            </Badge>
                            <span className="text-xs font-mono text-red-400/70">
                              {token.triggered_timestamp} by {token.triggered_by_ip}
                            </span>
                          </div>
                        ) : (
                          <Badge className="bg-green-500/10 text-green-400 border-green-500/30 text-xs">
                            Clean
                          </Badge>
                        )}
                      </TableCell>
                    </motion.tr>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Attacker Profiles */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.35 }}
      >
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <CardTitle className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-red-400" />
              Attacker Profiles
              <span className="ml-2 text-sm font-normal text-slate-400">{MOCK_ATTACKERS.length} unique IPs identified</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {MOCK_ATTACKERS.map((attacker, idx) => (
                <motion.div
                  key={attacker.ip}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.35 + idx * 0.07 }}
                  className="p-5 rounded-lg border border-slate-700 bg-slate-800/30 hover:border-red-500/30 transition-all"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-lg">{attacker.geo_flag}</span>
                        <span className="font-mono font-bold text-slate-100">{attacker.ip}</span>
                      </div>
                      <p className="text-xs text-slate-400">{attacker.city}</p>
                    </div>
                    <Badge className={cn("text-xs border font-bold", threatScoreColor(attacker.threat_score))}>
                      {attacker.threat_score} / 100
                    </Badge>
                  </div>

                  <div className="space-y-2 text-xs mb-4">
                    <div className="flex justify-between">
                      <span className="text-slate-500">First seen</span>
                      <span className="text-slate-300 font-mono">{attacker.first_seen}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Interactions</span>
                      <span className="text-slate-300 font-semibold">{attacker.interactions}</span>
                    </div>
                  </div>

                  <div>
                    <p className="text-xs text-slate-500 mb-2">Techniques observed</p>
                    <div className="flex flex-wrap gap-1">
                      {attacker.techniques.map((t) => (
                        <span
                          key={t}
                          className="text-xs px-2 py-0.5 rounded-full bg-slate-700/60 text-slate-300 border border-slate-600"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
