import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import {
  Globe, Server, AlertTriangle, Shield, Activity, Lock, Unlock,
  ChevronRight, ArrowRight, Network, ExternalLink, RefreshCw
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie, Legend
} from "recharts";
import { knowledgeGraphApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
interface ExposedService {
  id: string;
  host: string;
  ip: string;
  port: number;
  protocol: string;
  service: string;
  version: string;
  tls: boolean;
  riskLevel: "Critical" | "High" | "Medium" | "Low";
  finding?: string;
  lastSeen: string;
  country: string;
}

interface NetworkPath {
  id: string;
  source: string;
  destination: string;
  hops: string[];
  exposure: "Direct" | "Indirect" | "Internal";
  riskScore: number;
  ports: string;
}

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_EXPOSED_SERVICES: ExposedService[] = [
  { id: "svc-1",  host: "api.payments.corp.com",      ip: "198.51.100.12", port: 443,  protocol: "HTTPS", service: "nginx",      version: "1.18.0",   tls: true,  riskLevel: "High",     finding: "CVE-2023-44487", lastSeen: "5m ago",  country: "AU" },
  { id: "svc-2",  host: "admin.corp.com",              ip: "198.51.100.88", port: 8443, protocol: "HTTPS", service: "Tomcat",     version: "9.0.70",   tls: true,  riskLevel: "Critical", finding: "CVE-2023-28708", lastSeen: "5m ago",  country: "AU" },
  { id: "svc-3",  host: "legacy-api.corp.com",         ip: "203.0.113.45",  port: 80,   protocol: "HTTP",  service: "Apache",     version: "2.4.51",   tls: false, riskLevel: "Critical", finding: "CVE-2021-41773", lastSeen: "5m ago",  country: "US" },
  { id: "svc-4",  host: "ssh.bastion.corp.com",        ip: "198.51.100.4",  port: 22,   protocol: "SSH",   service: "OpenSSH",    version: "8.2p1",    tls: false, riskLevel: "Medium",   finding: undefined,        lastSeen: "5m ago",  country: "AU" },
  { id: "svc-5",  host: "mail.corp.com",               ip: "198.51.100.22", port: 25,   protocol: "SMTP",  service: "Postfix",    version: "3.5.6",    tls: false, riskLevel: "High",     finding: "CVE-2023-10048", lastSeen: "8m ago",  country: "AU" },
  { id: "svc-6",  host: "vpn.corp.com",                ip: "198.51.100.9",  port: 1194, protocol: "OpenVPN","service": "OpenVPN", version: "2.5.7",    tls: true,  riskLevel: "Low",      finding: undefined,        lastSeen: "5m ago",  country: "AU" },
  { id: "svc-7",  host: "files.corp.com",              ip: "203.0.113.101", port: 21,   protocol: "FTP",   service: "vsftpd",     version: "3.0.3",    tls: false, riskLevel: "Critical", finding: "CVE-2021-3618",  lastSeen: "12m ago", country: "SG" },
  { id: "svc-8",  host: "metrics.corp.com",            ip: "198.51.100.55", port: 9090, protocol: "HTTP",  service: "Prometheus", version: "2.40.0",   tls: false, riskLevel: "High",     finding: "Unauth Access",  lastSeen: "5m ago",  country: "AU" },
  { id: "svc-9",  host: "ci.corp.com",                 ip: "198.51.100.71", port: 8080, protocol: "HTTP",  service: "Jenkins",    version: "2.387.3",  tls: false, riskLevel: "High",     finding: "CVE-2023-27898", lastSeen: "5m ago",  country: "AU" },
  { id: "svc-10", host: "k8s-api.corp.com",            ip: "198.51.100.200",port: 6443, protocol: "HTTPS", service: "k8s-api",    version: "1.26.4",   tls: true,  riskLevel: "Medium",   finding: undefined,        lastSeen: "5m ago",  country: "AU" },
];

const MOCK_PATHS: NetworkPath[] = [
  { id: "path-1", source: "0.0.0.0/0 (Internet)",    destination: "admin.corp.com:8443",      hops: ["CDN Edge", "WAF", "Load Balancer", "Tomcat"], exposure: "Direct",   riskScore: 92, ports: "8443/HTTPS" },
  { id: "path-2", source: "0.0.0.0/0 (Internet)",    destination: "legacy-api.corp.com:80",   hops: ["No WAF", "Apache"], exposure: "Direct",   riskScore: 97, ports: "80/HTTP" },
  { id: "path-3", source: "0.0.0.0/0 (Internet)",    destination: "files.corp.com:21",        hops: ["FTP Direct"], exposure: "Direct",   riskScore: 95, ports: "21/FTP" },
  { id: "path-4", source: "Corp Office (RFC1918)",    destination: "k8s-api.corp.com:6443",    hops: ["VPN Gateway", "Internal LB", "k8s-api"], exposure: "Indirect", riskScore: 44, ports: "6443/HTTPS" },
  { id: "path-5", source: "0.0.0.0/0 (Internet)",    destination: "metrics.corp.com:9090",    hops: ["No Auth", "Prometheus"], exposure: "Direct",   riskScore: 81, ports: "9090/HTTP" },
];

const PORT_BREAKDOWN = [
  { protocol: "HTTPS", count: 4, fill: "#22c55e" },
  { protocol: "HTTP",  count: 3, fill: "#f97316" },
  { protocol: "SSH",   count: 1, fill: "#3b82f6" },
  { protocol: "FTP",   count: 1, fill: "#ef4444" },
  { protocol: "SMTP",  count: 1, fill: "#a855f7" },
  { protocol: "Other", count: 2, fill: "#6b7280" },
];

const TLS_DATA = [
  { name: "TLS Enabled",  value: 4, fill: "#22c55e" },
  { name: "Plain Text",   value: 6, fill: "#ef4444" },
];

const riskConfig = {
  Critical: "bg-red-500/10 text-red-400 border-red-500/30",
  High:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  Medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  Low:      "bg-blue-500/10 text-blue-400 border-blue-500/30",
};

const exposureConfig = {
  Direct:   "bg-red-500/10 text-red-400 border-red-500/30",
  Indirect: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  Internal: "bg-blue-500/10 text-blue-400 border-blue-500/30",
};

// ── Network Path Card ──────────────────────────────────────────────────────
function NetworkPathCard({ path }: { path: NetworkPath }) {
  return (
    <Card className="border-border/50">
      <CardContent className="p-4 space-y-3">
        <div className="flex items-center justify-between gap-2">
          <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${exposureConfig[path.exposure]}`}>{path.exposure}</span>
          <span className={`text-sm font-bold tabular-nums ${path.riskScore >= 80 ? "text-red-400" : path.riskScore >= 60 ? "text-orange-400" : "text-yellow-400"}`}>
            Risk {path.riskScore}
          </span>
        </div>
        {/* Hop flow */}
        <div className="flex items-center gap-1 flex-wrap text-xs">
          <span className="bg-muted rounded px-1.5 py-0.5 font-mono text-[10px]">{path.source}</span>
          {path.hops.map((hop, i) => (
            <span key={i} className="flex items-center gap-1">
              <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />
              <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${i === path.hops.length - 1 ? "bg-primary/10 text-primary" : "bg-muted"}`}>{hop}</span>
            </span>
          ))}
        </div>
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>{path.destination}</span>
          <span className="font-mono">{path.ports}</span>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function Reachability() {
  const [riskFilter, setRiskFilter] = useState<string>("All");

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["reachability-surface"],
    queryFn: () => knowledgeGraphApi.visualize({ type: "internet_exposure" }),
    refetchInterval: 60_000,
  });

  const services = (data as any)?.data ?? MOCK_EXPOSED_SERVICES;
  const filtered = riskFilter === "All" ? services : services.filter((s: ExposedService) => s.riskLevel === riskFilter);

  const criticalCount = services.filter((s: ExposedService) => s.riskLevel === "Critical").length;
  const highCount     = services.filter((s: ExposedService) => s.riskLevel === "High").length;
  const noTlsCount    = services.filter((s: ExposedService) => !s.tls).length;
  const withFindings  = services.filter((s: ExposedService) => s.finding).length;

  const serviceColumns = [
    { key: "host", header: "Host", render: (r: ExposedService) => <span className="font-mono text-xs text-primary">{r.host}</span> },
    { key: "ip",   header: "IP", render: (r: ExposedService) => <span className="font-mono text-xs text-muted-foreground">{r.ip}</span> },
    { key: "port", header: "Port", render: (r: ExposedService) => <span className="font-mono text-xs">{r.port}/{r.protocol}</span> },
    { key: "service", header: "Service", render: (r: ExposedService) => <span>{r.service} <span className="text-muted-foreground font-mono text-xs">{r.version}</span></span> },
    { key: "tls", header: "TLS", render: (r: ExposedService) => r.tls
      ? <span className="flex items-center gap-1 text-green-400 text-xs"><Lock className="h-3 w-3" /> Enabled</span>
      : <span className="flex items-center gap-1 text-red-400 text-xs"><Unlock className="h-3 w-3" /> Plaintext</span>
    },
    { key: "riskLevel", header: "Risk", render: (r: ExposedService) => <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${riskConfig[r.riskLevel]}`}>{r.riskLevel}</span> },
    { key: "finding", header: "Finding", render: (r: ExposedService) => r.finding ? <span className="font-mono text-xs text-orange-400">{r.finding}</span> : <span className="text-muted-foreground text-xs">—</span> },
    { key: "country", header: "Region" },
    { key: "lastSeen", header: "Last Seen" },
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Reachability"
        description="Internet-reachable attack surface — exposed services, network paths, and port analysis"
        badge="VALIDATE"
        actions={
          <Button size="sm" variant="outline" onClick={() => { refetch(); toast.info("Refreshing surface scan..."); }}>
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Rescan
          </Button>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Critical Exposure" value={criticalCount} icon={AlertTriangle} trend="down" change={-1} changeLabel="vs last scan" />
        <KpiCard title="High Exposure" value={highCount} icon={Globe} trend="flat" />
        <KpiCard title="No TLS / Plaintext" value={noTlsCount} icon={Unlock} trend="down" change={-2} changeLabel="vs last scan" />
        <KpiCard title="Active Findings" value={withFindings} icon={Activity} trend="down" change={-3} changeLabel="vs last scan" />
      </div>

      {/* Attack Surface Summary */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <Card className="border-border/50 xl:col-span-2">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Server className="h-4 w-4 text-primary" /> Internet-Reachable Services
              </CardTitle>
              <div className="flex gap-1.5">
                {["All","Critical","High","Medium","Low"].map(r => (
                  <Button key={r} size="sm" variant={riskFilter === r ? "default" : "outline"} className="h-6 text-xs" onClick={() => setRiskFilter(r)}>
                    {r}
                  </Button>
                ))}
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={serviceColumns.slice(0, 7)}
              data={filtered}
              emptyMessage="No services match filter"
            />
          </CardContent>
        </Card>

        <div className="space-y-4">
          {/* Protocol Breakdown */}
          <Card className="border-border/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold">Protocol Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={PORT_BREAKDOWN} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                  <XAxis dataKey="protocol" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 6, fontSize: 11 }} />
                  <Bar dataKey="count" radius={[3,3,0,0]}>
                    {PORT_BREAKDOWN.map((d, i) => <Cell key={i} fill={d.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* TLS Coverage */}
          <Card className="border-border/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold">TLS Coverage</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={120}>
                <PieChart>
                  <Pie data={TLS_DATA} dataKey="value" cx="50%" cy="50%" innerRadius={30} outerRadius={50}>
                    {TLS_DATA.map((d, i) => <Cell key={i} fill={d.fill} />)}
                  </Pie>
                  <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 6, fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Network Paths */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Network className="h-4 w-4 text-primary" /> Network Path Analysis
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {MOCK_PATHS.map(path => <NetworkPathCard key={path.id} path={path} />)}
        </div>
      </div>
    </motion.div>
  );
}
