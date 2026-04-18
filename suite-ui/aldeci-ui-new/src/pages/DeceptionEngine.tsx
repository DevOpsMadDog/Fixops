/**
 * Deception Engine — /deception
 * API stubs: GET /api/v1/deception/honeypots, GET /api/v1/deception/canary-tokens
 */
import { useState, useEffect } from "react";
import { AlertTriangle, Shield, Eye, Server, Globe, Activity, Clock, MapPin, Key, FileText, Wifi, Link, Database, Folder, Cloud, Monitor, Terminal } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────
type TriggerType = "honeypot_access" | "canary_opened" | "credential_used";
type HoneypotType = "windows_server" | "linux_ssh" | "fake_database" | "web_app" | "file_share" | "cloud_storage";
type CanaryType = "dns" | "word_doc" | "pdf" | "url" | "aws_key" | "image" | "csv";

// ── Static data ────────────────────────────────────────────────
const ALERTS = [
  { id: "DEC-001", ts: "2026-04-16 08:14", type: "credential_used" as TriggerType, ip: "185.220.101.42", geo: "🇷🇺 RU", asset: "AWS Prod Keys Backup.txt" },
  { id: "DEC-002", ts: "2026-04-15 23:47", type: "honeypot_access" as TriggerType, ip: "194.165.16.88", geo: "🇳🇱 NL", asset: "HP-WinSrv-DC01 (Windows Server)" },
  { id: "DEC-003", ts: "2026-04-15 19:22", type: "canary_opened" as TriggerType, ip: "45.33.32.156", geo: "🇺🇸 US", asset: "Finance Q4 Budget — copy.docx" },
  { id: "DEC-004", ts: "2026-04-15 14:05", type: "honeypot_access" as TriggerType, ip: "185.220.101.42", geo: "🇷🇺 RU", asset: "HP-LinSSH-Prod01 (Linux SSH)" },
  { id: "DEC-005", ts: "2026-04-14 21:33", type: "honeypot_access" as TriggerType, ip: "194.165.16.88", geo: "🇳🇱 NL", asset: "HP-FakeDB-MySQL01 (Fake Database)" },
];

const TRIGGER_BADGE: Record<TriggerType, string> = {
  honeypot_access: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  canary_opened: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  credential_used: "bg-red-500/10 text-red-400 border-red-500/30",
};
const TRIGGER_LABEL: Record<TriggerType, string> = {
  honeypot_access: "Honeypot Access", canary_opened: "Canary Opened", credential_used: "Credential Used",
};

const HP_ICON: Record<HoneypotType, React.ReactNode> = {
  windows_server: <Monitor className="w-4 h-4 text-blue-400" />,
  linux_ssh: <Terminal className="w-4 h-4 text-green-400" />,
  fake_database: <Database className="w-4 h-4 text-purple-400" />,
  web_app: <Globe className="w-4 h-4 text-cyan-400" />,
  file_share: <Folder className="w-4 h-4 text-yellow-400" />,
  cloud_storage: <Cloud className="w-4 h-4 text-sky-400" />,
};
const HP_LABEL: Record<HoneypotType, string> = {
  windows_server: "Windows Server", linux_ssh: "Linux SSH", fake_database: "Fake Database",
  web_app: "Web App", file_share: "File Share", cloud_storage: "Cloud Storage",
};

const HONEYPOTS: { id: string; name: string; type: HoneypotType; last_triggered: string | null; interactions: number; status: "active" | "maintenance" }[] = [
  { id: "HP-001", name: "HP-WinSrv-DC01",       type: "windows_server", last_triggered: "2026-04-15 23:47", interactions: 14, status: "active" },
  { id: "HP-002", name: "HP-WinSrv-Exchange",    type: "windows_server", last_triggered: null,               interactions: 0,  status: "active" },
  { id: "HP-003", name: "HP-LinSSH-Prod01",      type: "linux_ssh",      last_triggered: "2026-04-15 14:05", interactions: 31, status: "active" },
  { id: "HP-004", name: "HP-LinSSH-Dev02",       type: "linux_ssh",      last_triggered: "2026-04-12 07:19", interactions: 7,  status: "active" },
  { id: "HP-005", name: "HP-FakeDB-MySQL01",     type: "fake_database",  last_triggered: "2026-04-14 21:33", interactions: 9,  status: "active" },
  { id: "HP-006", name: "HP-FakeDB-Postgres",    type: "fake_database",  last_triggered: null,               interactions: 0,  status: "maintenance" },
  { id: "HP-007", name: "HP-WebApp-Staging",     type: "web_app",        last_triggered: "2026-04-14 11:12", interactions: 22, status: "active" },
  { id: "HP-008", name: "HP-WebApp-AdminPanel",  type: "web_app",        last_triggered: "2026-04-10 15:30", interactions: 5,  status: "active" },
  { id: "HP-009", name: "HP-FileShare-Finance",  type: "file_share",     last_triggered: null,               interactions: 0,  status: "active" },
  { id: "HP-010", name: "HP-FileShare-HR",       type: "file_share",     last_triggered: "2026-04-11 18:44", interactions: 3,  status: "active" },
  { id: "HP-011", name: "HP-Cloud-S3Bucket",     type: "cloud_storage",  last_triggered: "2026-04-13 09:44", interactions: 8,  status: "active" },
  { id: "HP-012", name: "HP-Cloud-AzureBlob",    type: "cloud_storage",  last_triggered: null,               interactions: 0,  status: "active" },
];

const CANARY_ICON: Record<CanaryType, React.ReactNode> = {
  dns: <Wifi className="w-4 h-4 text-cyan-400" />, word_doc: <FileText className="w-4 h-4 text-blue-400" />,
  pdf: <FileText className="w-4 h-4 text-red-400" />, url: <Link className="w-4 h-4 text-purple-400" />,
  aws_key: <Key className="w-4 h-4 text-yellow-400" />, image: <FileText className="w-4 h-4 text-pink-400" />,
  csv: <FileText className="w-4 h-4 text-green-400" />,
};

const CANARIES: { id: string; name: string; type: CanaryType; location: string; triggered: boolean; ts: string | null; ip: string | null }[] = [
  { id: "CT-001", name: "Finance Q4 Budget.docx",        type: "word_doc", location: "SharePoint Finance",          triggered: false, ts: null,               ip: null },
  { id: "CT-002", name: "AWS Prod Keys Backup.txt",       type: "aws_key",  location: "S3 bucket root",              triggered: true,  ts: "2026-04-14 09:31", ip: "185.220.101.42" },
  { id: "CT-003", name: "Customer DB Dump 2026.csv",      type: "csv",      location: "Email attachment (vendor)",   triggered: false, ts: null,               ip: null },
  { id: "CT-004", name: "Employee_Salaries_2026.pdf",     type: "pdf",      location: "HR shared drive",             triggered: true,  ts: "2026-04-14 16:58", ip: "185.220.101.42" },
  { id: "CT-005", name: "backup-credentials.env",         type: "aws_key",  location: "GitHub honeypot repo",        triggered: false, ts: null,               ip: null },
  { id: "CT-006", name: "internal-api-docs.pdf",          type: "pdf",      location: "Confluence public space",     triggered: false, ts: null,               ip: null },
  { id: "CT-007", name: "corp-logo-2026.png",             type: "image",    location: "Marketing shared folder",     triggered: true,  ts: "2026-04-15 19:22", ip: "45.33.32.156" },
  { id: "CT-008", name: "https://internal.corp/admin",    type: "url",      location: "Phishing bait email",         triggered: false, ts: null,               ip: null },
  { id: "CT-009", name: "dns-canary.internal.corp",       type: "dns",      location: "Decoy API response",          triggered: false, ts: null,               ip: null },
  { id: "CT-010", name: "Backup S3 Access Keys — PROD",   type: "aws_key",  location: "Internal wiki (decoy page)",  triggered: true,  ts: "2026-04-13 09:44", ip: "194.165.16.88" },
];

const ATTACKERS = [
  { ip: "185.220.101.42", geo: "🇷🇺 Moscow, Russia",          first_seen: "2026-04-13 09:31", interactions: 24, score: 98, techniques: ["SSH brute force", "Credential stuffing", "S3 enumeration", "Port scan"] },
  { ip: "194.165.16.88",  geo: "🇳🇱 Amsterdam, Netherlands",   first_seen: "2026-04-13 09:44", interactions: 17, score: 91, techniques: ["Web app crawling", "SQL injection probe", "AWS key abuse"] },
  { ip: "45.33.32.156",   geo: "🇺🇸 Fremont, CA (Tor exit)",   first_seen: "2026-04-14 11:12", interactions: 9,  score: 74, techniques: ["Document exfil probe", "DNS canary trigger", "Directory traversal"] },
];

function scoreColor(s: number) {
  if (s >= 90) return "bg-red-500/20 text-red-400 border-red-500/40";
  if (s >= 70) return "bg-orange-500/20 text-orange-400 border-orange-500/40";
  return "bg-yellow-500/20 text-yellow-400 border-yellow-500/40";
}

// ── Component ──────────────────────────────────────────────────
export default function DeceptionEngine() {
  const [liveData, setLiveData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/deception/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/deception/canaries?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/deception/alerts?org_id=${ORG_ID}&hours=168`),
    ]).then(([statsRes, canariesRes, alertsRes]) => {
      const stats    = statsRes.status    === "fulfilled" ? statsRes.value    : null;
      const canaries = canariesRes.status === "fulfilled" ? canariesRes.value : null;
      const alerts   = alertsRes.status   === "fulfilled" ? alertsRes.value   : null;
      if (stats || canaries || alerts) {
        setLiveData({ stats, canaries, alerts });
      }
    });
  }, []);

  const activeHoneypots = liveData?.stats?.active_honeypots ?? HONEYPOTS.filter((h) => h.status === "active").length;
  const triggeredCanaries = liveData?.stats?.triggered_canaries ?? CANARIES.filter((c) => c.triggered).length;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-900 p-8 space-y-8">
      <PageHeader title="Deception Engine" description="Honeypots, canary tokens, and attacker tracking" />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active Honeypots"    value={activeHoneypots}                                                            icon={Server}        changeLabel="2 cloud, 10 on-prem" />
        <KpiCard title="Canary Tokens"       value={liveData?.stats?.total_canaries ?? liveData?.canaries?.length ?? 47}       icon={Eye}           changeLabel="across 8 asset types" />
        <KpiCard title="Triggered This Week" value={liveData?.stats?.triggered_this_week ?? liveData?.alerts?.length ?? 8}    icon={AlertTriangle} changeLabel="vs last week" />
        <KpiCard title="Unique Attackers"    value={liveData?.stats?.unique_attackers ?? ATTACKERS.length}                     icon={Globe}         changeLabel="3 countries" />
      </div>

      {/* Alert Feed */}
      <Card className="border-red-500/40 bg-red-500/5">
        <CardHeader className="border-b border-red-500/20">
          <CardTitle className="flex items-center gap-2 text-red-400">
            <AlertTriangle className="w-5 h-5" />
            Deception Trigger Alerts
            <Badge className="ml-auto bg-red-500/20 text-red-400 border-red-500/40 text-xs">ALL CRITICAL</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0 divide-y divide-slate-700/50">
          {(liveData?.alerts ?? ALERTS).map((a: any) => (
            <div key={a.id} className="flex items-center gap-4 px-6 py-3 hover:bg-red-500/5 transition-colors">
              <div className="w-2 h-2 rounded-full bg-red-500 flex-shrink-0 animate-pulse" />
              <span className="text-xs font-mono text-slate-500 w-36 flex-shrink-0">{a.ts}</span>
              <Badge className={cn("text-xs border flex-shrink-0", TRIGGER_BADGE[a.type])}>{TRIGGER_LABEL[a.type]}</Badge>
              <span className="font-mono text-sm text-slate-300 w-32 flex-shrink-0">{a.ip}</span>
              <span className="text-sm flex-shrink-0">{a.geo}</span>
              <span className="text-sm text-slate-400 flex-1 truncate">{a.asset}</span>
              <Badge className="bg-red-500/10 text-red-400 border-red-500/30 text-xs flex-shrink-0">CRITICAL</Badge>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Honeypot Grid */}
      <Card className="border-slate-700">
        <CardHeader className="border-b border-slate-700">
          <CardTitle className="flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" /> Honeypot Status
            <span className="ml-2 text-sm font-normal text-slate-400">12 decoy systems</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-6">
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-3">
            {HONEYPOTS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              HONEYPOTS.map((hp) => (
              <div key={hp.id} className={cn("p-4 rounded-lg border", hp.status === "maintenance" ? "border-slate-600 bg-slate-800/30" : hp.last_triggered ? "border-orange-500/30 bg-orange-500/5" : "border-slate-700 bg-slate-800/20")}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-1.5">{HP_ICON[hp.type]}<span className="text-xs text-slate-400">{HP_LABEL[hp.type]}</span></div>
                  <Badge className={cn("text-xs", hp.status === "active" ? "bg-green-500/10 text-green-400 border-green-500/30" : "bg-slate-600/30 text-slate-400 border-slate-600")}>
                    {hp.status === "active" ? "Active" : "Maintenance"}
                  </Badge>
                </div>
                <p className="font-mono text-sm font-semibold text-slate-200 mb-1">{hp.name}</p>
                <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                  <span className="flex items-center gap-1"><Activity className="w-3 h-3" />{hp.interactions} interactions</span>
                </div>
                <div className="text-xs">
                  {hp.last_triggered
                    ? <span className="text-orange-400 flex items-center gap-1"><Clock className="w-3 h-3" />{hp.last_triggered}</span>
                    : <span className="text-slate-500 italic">Never triggered</span>}
                </div>
              </div>
            )))}
          </div>
        </CardContent>
      </Card>

      {/* Canary Tokens */}
      <Card className="border-slate-700">
        <CardHeader className="border-b border-slate-700">
          <CardTitle className="flex items-center gap-2">
            <Eye className="w-5 h-5 text-yellow-400" /> Canary Tokens
            <span className="ml-2 text-sm font-normal text-slate-400">{triggeredCanaries} triggered / {(liveData?.canaries ?? CANARIES).length} shown</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0 overflow-x-auto">
          <Table>
            <TableHeader className="bg-slate-800/50 border-b border-slate-700">
              <TableRow>
                <TableHead className="text-slate-300">Token Name</TableHead>
                <TableHead className="text-slate-300">Type</TableHead>
                <TableHead className="text-slate-300">Location</TableHead>
                <TableHead className="text-slate-300 text-right">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(liveData?.canaries ?? CANARIES).map((c: any) => (
                <TableRow key={c.id} className={cn("border-b border-slate-700/50", c.triggered ? "bg-red-500/5 hover:bg-red-500/10" : "hover:bg-slate-800/30")}>
                  <TableCell className="text-slate-200 font-medium text-sm">
                    <div className="flex items-center gap-2">{CANARY_ICON[c.type]}{c.name}</div>
                  </TableCell>
                  <TableCell>
                    <Badge className="bg-slate-700/50 text-slate-300 border-slate-600 text-xs uppercase">{c.type.replace("_", " ")}</Badge>
                  </TableCell>
                  <TableCell className="text-slate-400 text-sm">
                    <MapPin className="w-3 h-3 inline mr-1 text-slate-600" />{c.location}
                  </TableCell>
                  <TableCell className="text-right">
                    {c.triggered ? (
                      <div className="flex flex-col items-end gap-0.5">
                        <Badge className="bg-red-500/15 text-red-400 border-red-500/40 text-xs">TRIGGERED</Badge>
                        <span className="text-xs font-mono text-red-400/70">{c.ts} · {c.ip}</span>
                      </div>
                    ) : (
                      <Badge className="bg-green-500/10 text-green-400 border-green-500/30 text-xs">Clean</Badge>
                    )}
                  </TableCell>
                </TableRow>
              )))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Attacker Profiles */}
      <Card className="border-slate-700">
        <CardHeader className="border-b border-slate-700">
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-red-400" /> Attacker Profiles
            <span className="ml-2 text-sm font-normal text-slate-400">{ATTACKERS.length} unique IPs</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {ATTACKERS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              ATTACKERS.map((a) => (
              <div key={a.ip} className="p-5 rounded-lg border border-slate-700 bg-slate-800/30 hover:border-red-500/30 transition-all">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <p className="font-mono font-bold text-slate-100">{a.ip}</p>
                    <p className="text-xs text-slate-400">{a.geo}</p>
                  </div>
                  <Badge className={cn("text-xs border font-bold", scoreColor(a.score))}>{a.score}/100</Badge>
                </div>
                <div className="text-xs space-y-1 mb-3">
                  <div className="flex justify-between"><span className="text-slate-500">First seen</span><span className="text-slate-300 font-mono">{a.first_seen}</span></div>
                  <div className="flex justify-between"><span className="text-slate-500">Interactions</span><span className="text-slate-300 font-semibold">{a.interactions}</span></div>
                </div>
                <p className="text-xs text-slate-500 mb-1.5">Techniques observed</p>
                <div className="flex flex-wrap gap-1">
                  {a.techniques.map((t) => (
                    <span key={t} className="text-xs px-2 py-0.5 rounded-full bg-slate-700/60 text-slate-300 border border-slate-600">{t}</span>
                  )))}
                </div>
              </div>
            )))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
