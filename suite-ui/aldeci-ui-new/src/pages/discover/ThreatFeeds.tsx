import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Radio, TrendingUp, Shield, AlertTriangle, Rss,
  RefreshCw, ExternalLink, Zap, Filter, Clock, Star, ChevronRight
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { threatFeedsApi } from "@/lib/api";
import { toast } from "sonner";

// ── Mock Data ──────────────────────────────────────────────────────────────────
const MOCK_FEEDS = [
  { id: "F001", name: "NVD CVE Feed", provider: "NIST", type: "vulnerability", status: "active", lastUpdate: "3m ago", entries: 218504, reliability: 99 },
  { id: "F002", name: "CISA KEV", provider: "CISA", type: "exploit", status: "active", lastUpdate: "1h ago", entries: 1007, reliability: 98 },
  { id: "F003", name: "AlienVault OTX", provider: "AT&T", type: "threat-intel", status: "active", lastUpdate: "5m ago", entries: 1240000, reliability: 87 },
  { id: "F004", name: "Shodan InternetDB", provider: "Shodan", type: "exposure", status: "active", lastUpdate: "10m ago", entries: 580000, reliability: 92 },
  { id: "F005", name: "Mandiant Threat Intel", provider: "Google", type: "apt", status: "active", lastUpdate: "2h ago", entries: 45000, reliability: 95 },
  { id: "F006", name: "Recorded Future", provider: "Recorded Future", type: "dark-web", status: "active", lastUpdate: "15m ago", entries: 340000, reliability: 91 },
  { id: "F007", name: "CrowdStrike Intel", provider: "CrowdStrike", type: "apt", status: "active", lastUpdate: "30m ago", entries: 89000, reliability: 94 },
  { id: "F008", name: "IBM X-Force Exchange", provider: "IBM", type: "threat-intel", status: "active", lastUpdate: "20m ago", entries: 720000, reliability: 88 },
  { id: "F009", name: "Abuse.ch MalwareBazaar", provider: "Abuse.ch", type: "malware", status: "active", lastUpdate: "8m ago", entries: 2100000, reliability: 86 },
  { id: "F010", name: "MISP Threat Sharing", provider: "MISP", type: "threat-intel", status: "active", lastUpdate: "45m ago", entries: 890000, reliability: 84 },
  { id: "F011", name: "URLhaus", provider: "Abuse.ch", type: "malware", status: "active", lastUpdate: "6m ago", entries: 3200000, reliability: 83 },
  { id: "F012", name: "VirusTotal Intelligence", provider: "Google", type: "malware", status: "active", lastUpdate: "Real-time", entries: 5000000, reliability: 93 },
  { id: "F013", name: "Palo Alto Unit 42", provider: "Palo Alto", type: "apt", status: "active", lastUpdate: "4h ago", entries: 67000, reliability: 92 },
  { id: "F014", name: "Cisco Talos", provider: "Cisco", type: "threat-intel", status: "active", lastUpdate: "12m ago", entries: 1800000, reliability: 91 },
  { id: "F015", name: "Shadowserver", provider: "Shadowserver", type: "exposure", status: "active", lastUpdate: "1h ago", entries: 450000, reliability: 89 },
  { id: "F016", name: "PhishTank", provider: "OpenDNS", type: "phishing", status: "active", lastUpdate: "22m ago", entries: 2800000, reliability: 81 },
  { id: "F017", name: "EmergingThreats", provider: "Proofpoint", type: "network", status: "active", lastUpdate: "35m ago", entries: 190000, reliability: 88 },
  { id: "F018", name: "OpenPhish", provider: "OpenPhish", type: "phishing", status: "active", lastUpdate: "18m ago", entries: 560000, reliability: 79 },
];

const TRENDING_CVES = [
  { cve: "CVE-2024-3400", product: "PAN-OS", cvss: 10.0, epss: 0.97, inKev: true, exploited: true, published: "2d ago", affected: "Palo Alto Networks GlobalProtect", trend: "+48%" },
  { cve: "CVE-2024-21762", product: "FortiOS", cvss: 9.6, epss: 0.94, inKev: true, exploited: true, published: "5d ago", affected: "Fortinet FortiOS SSL VPN", trend: "+31%" },
  { cve: "CVE-2024-1709", product: "ConnectWise", cvss: 10.0, epss: 0.99, inKev: true, exploited: true, published: "8d ago", affected: "ConnectWise ScreenConnect", trend: "+22%" },
  { cve: "CVE-2023-44487", product: "HTTP/2", cvss: 7.5, epss: 0.88, inKev: false, exploited: true, published: "6m ago", affected: "Multiple HTTP/2 implementations", trend: "+8%" },
  { cve: "CVE-2024-27198", product: "JetBrains TC", cvss: 9.8, epss: 0.91, inKev: true, exploited: true, published: "3d ago", affected: "JetBrains TeamCity", trend: "+19%" },
  { cve: "CVE-2024-0519", product: "Chrome V8", cvss: 8.8, epss: 0.82, inKev: true, exploited: true, published: "10d ago", affected: "Google Chrome V8 Engine", trend: "+12%" },
  { cve: "CVE-2024-21887", product: "Ivanti ICS", cvss: 9.1, epss: 0.95, inKev: true, exploited: true, published: "14d ago", affected: "Ivanti Connect Secure", trend: "+5%" },
  { cve: "CVE-2024-6387", product: "OpenSSH", cvss: 8.1, epss: 0.78, inKev: false, exploited: false, published: "1d ago", affected: "OpenSSH glibc Linux", trend: "+94%" },
];

const MITRE_MATRIX = [
  { tactic: "Initial Access", id: "TA0001", techniques: [
    { id: "T1566", name: "Phishing", severity: "high", observed: true },
    { id: "T1190", name: "Exploit Public App", severity: "critical", observed: true },
    { id: "T1078", name: "Valid Accounts", severity: "high", observed: true },
    { id: "T1133", name: "External Remote Services", severity: "medium", observed: false },
  ]},
  { tactic: "Execution", id: "TA0002", techniques: [
    { id: "T1059", name: "Command Scripting", severity: "high", observed: true },
    { id: "T1072", name: "Software Deployment", severity: "medium", observed: false },
    { id: "T1053", name: "Scheduled Task/Job", severity: "low", observed: false },
    { id: "T1204", name: "User Execution", severity: "medium", observed: true },
  ]},
  { tactic: "Persistence", id: "TA0003", techniques: [
    { id: "T1098", name: "Account Manipulation", severity: "high", observed: false },
    { id: "T1136", name: "Create Account", severity: "medium", observed: false },
    { id: "T1505", name: "Server Software Component", severity: "high", observed: true },
    { id: "T1542", name: "Pre-OS Boot", severity: "medium", observed: false },
  ]},
  { tactic: "Privilege Escalation", id: "TA0004", techniques: [
    { id: "T1078", name: "Valid Accounts", severity: "high", observed: true },
    { id: "T1068", name: "Exploit Privilege", severity: "critical", observed: false },
    { id: "T1548", name: "Abuse Elevation Control", severity: "high", observed: false },
    { id: "T1134", name: "Access Token Manip", severity: "medium", observed: false },
  ]},
  { tactic: "Exfiltration", id: "TA0010", techniques: [
    { id: "T1041", name: "C2 Channel Exfil", severity: "high", observed: false },
    { id: "T1567", name: "Exfil to Cloud", severity: "high", observed: true },
    { id: "T1048", name: "Exfil Other Net", severity: "medium", observed: false },
    { id: "T1030", name: "Data Transfer Limits", severity: "low", observed: false },
  ]},
  { tactic: "Impact", id: "TA0040", techniques: [
    { id: "T1486", name: "Data Encrypted (Ransom)", severity: "critical", observed: false },
    { id: "T1485", name: "Data Destruction", severity: "critical", observed: false },
    { id: "T1499", name: "Endpoint Denial", severity: "high", observed: false },
    { id: "T1498", name: "Network Denial", severity: "medium", observed: false },
  ]},
];

const AI_CORRELATIONS = [
  { id: "COR-001", title: "3 APT groups targeting CVE-2024-3400 in your asset portfolio", confidence: 94, feeds: 5, icon: Zap, severity: "critical" },
  { id: "COR-002", title: "Spike in credential stuffing attacks against your IP range (past 6h)", confidence: 87, feeds: 3, icon: TrendingUp, severity: "high" },
  { id: "COR-003", title: "Your payment-service version matches IoC from recent Carbanak campaign", confidence: 81, feeds: 7, icon: AlertTriangle, severity: "critical" },
  { id: "COR-004", title: "OpenSSH regreSSHion (CVE-2024-6387) affects 12 of your Linux hosts", confidence: 99, feeds: 2, icon: Shield, severity: "high" },
];

const FEED_TYPE_COLORS: Record<string, string> = {
  vulnerability: "bg-red-500/10 text-red-400 border-red-500/20",
  exploit: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  "threat-intel": "bg-purple-500/10 text-purple-400 border-purple-500/20",
  apt: "bg-pink-500/10 text-pink-400 border-pink-500/20",
  malware: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  exposure: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  phishing: "bg-teal-500/10 text-teal-400 border-teal-500/20",
  network: "bg-indigo-500/10 text-indigo-400 border-indigo-500/20",
  "dark-web": "bg-gray-500/10 text-gray-300 border-gray-500/20",
};

export default function ThreatFeeds() {
  const [feedSearch, setFeedSearch] = useState("");

  const { data: feeds } = useQuery({
    queryKey: ["threat-feeds"],
    queryFn: () => threatFeedsApi.list(),
  });

  const { data: trending } = useQuery({
    queryKey: ["threat-feeds", "trending"],
    queryFn: () => threatFeedsApi.trending(),
  });

  void feeds;
  void trending;

  const feedList = MOCK_FEEDS.filter((f) => !feedSearch || f.name.toLowerCase().includes(feedSearch.toLowerCase()) || f.provider.toLowerCase().includes(feedSearch.toLowerCase()));

  const cveColumns = [
    { key: "cve", header: "CVE ID", render: (row: typeof TRENDING_CVES[0]) => (
      <code className="font-mono text-xs text-primary font-semibold">{row.cve}</code>
    )},
    { key: "product", header: "Product", render: (row: typeof TRENDING_CVES[0]) => (
      <span className="text-sm font-medium">{row.product}</span>
    )},
    { key: "affected", header: "Affected", render: (row: typeof TRENDING_CVES[0]) => (
      <span className="text-xs text-muted-foreground">{row.affected}</span>
    )},
    { key: "cvss", header: "CVSS", render: (row: typeof TRENDING_CVES[0]) => (
      <span className={`text-sm font-bold ${row.cvss >= 9 ? "text-red-400" : row.cvss >= 7 ? "text-orange-400" : "text-yellow-400"}`}>
        {row.cvss.toFixed(1)}
      </span>
    )},
    { key: "epss", header: "EPSS", render: (row: typeof TRENDING_CVES[0]) => (
      <div>
        <span className="text-sm font-semibold">{(row.epss * 100).toFixed(0)}%</span>
        <Progress value={row.epss * 100} className="h-1 mt-1 w-16" />
      </div>
    )},
    { key: "inKev", header: "KEV", render: (row: typeof TRENDING_CVES[0]) => (
      row.inKev ? <Badge variant="destructive">CISA KEV</Badge> : <Badge variant="secondary">No</Badge>
    )},
    { key: "trend", header: "Trend", render: (row: typeof TRENDING_CVES[0]) => (
      <span className="text-xs text-green-400 font-semibold">{row.trend}</span>
    )},
    { key: "published", header: "Published", render: (row: typeof TRENDING_CVES[0]) => (
      <span className="text-xs text-muted-foreground">{row.published}</span>
    )},
    { key: "actions", header: "", render: (row: typeof TRENDING_CVES[0]) => (
      <Button size="sm" variant="ghost" onClick={() => toast.success(`Investigating ${row.cve}`)}><ExternalLink className="h-3.5 w-3.5" /></Button>
    )},
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Threat Feeds"
        description="Real-time threat intelligence from 50+ feeds, AI-correlated to your asset portfolio"
        badge="Live Intel"
        actions={
          <>
            <Button variant="outline" size="sm"><Filter className="h-4 w-4 mr-1.5" />Filter</Button>
            <Button size="sm" onClick={() => toast.success("All feeds syncing")}><RefreshCw className="h-4 w-4 mr-1.5" />Sync All</Button>
          </>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active Feeds" value={MOCK_FEEDS.length} change={3} trend="up" icon={Rss} />
        <KpiCard title="Trending CVEs" value={TRENDING_CVES.length} change={24} trend="up" icon={TrendingUp} />
        <KpiCard title="AI Correlations" value={AI_CORRELATIONS.length} trend="flat" icon={Zap} />
        <KpiCard title="MITRE Techniques Observed" value={MITRE_MATRIX.flatMap((t) => t.techniques).filter((t) => t.observed).length} icon={Shield} />
      </div>

      {/* AI Correlation highlights */}
      <div>
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Zap className="h-4 w-4 text-primary" />
          AI Correlation Highlights
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {AI_CORRELATIONS.map((cor) => {
            const Icon = cor.icon;
            return (
              <Card key={cor.id} className={`border ${cor.severity === "critical" ? "border-red-500/30" : "border-orange-500/20"}`}>
                <CardContent className="p-4 flex items-start gap-3">
                  <div className={`rounded-lg p-2 shrink-0 ${cor.severity === "critical" ? "bg-red-500/10" : "bg-orange-500/10"}`}>
                    <Icon className={`h-5 w-5 ${cor.severity === "critical" ? "text-red-400" : "text-orange-400"}`} />
                  </div>
                  <div className="flex-1">
                    <p className="text-sm font-medium leading-snug">{cor.title}</p>
                    <div className="flex items-center gap-3 mt-2">
                      <div>
                        <div className="flex justify-between text-xs mb-0.5">
                          <span className="text-muted-foreground">Confidence</span>
                          <span className="font-semibold">{cor.confidence}%</span>
                        </div>
                        <Progress value={cor.confidence} className="h-1 w-24" />
                      </div>
                      <span className="text-xs text-muted-foreground">{cor.feeds} feeds correlated</span>
                    </div>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => toast.success("Investigation opened")}><ChevronRight className="h-4 w-4" /></Button>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>

      <Tabs defaultValue="cves">
        <TabsList>
          <TabsTrigger value="cves">Trending CVEs</TabsTrigger>
          <TabsTrigger value="feeds">Feed Library (50+)</TabsTrigger>
          <TabsTrigger value="mitre">MITRE ATT&CK Matrix</TabsTrigger>
        </TabsList>

        <TabsContent value="cves" className="mt-4">
          <DataTable columns={cveColumns} data={TRENDING_CVES} emptyMessage="No trending CVEs" />
        </TabsContent>

        <TabsContent value="feeds" className="mt-4 space-y-4">
          <div className="relative">
            <Radio className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Search feeds by name or provider..." className="pl-9" value={feedSearch} onChange={(e) => setFeedSearch(e.target.value)} />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {feedList.map((feed) => (
              <Card key={feed.id} className="hover:border-primary/20 transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <div className="h-2 w-2 rounded-full bg-green-400 animate-pulse" />
                        <p className="font-semibold text-sm">{feed.name}</p>
                      </div>
                      <p className="text-xs text-muted-foreground">{feed.provider}</p>
                    </div>
                    <span className={`text-xs px-2 py-0.5 rounded-full border shrink-0 ${FEED_TYPE_COLORS[feed.type] ?? ""}`}>
                      {feed.type}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 mt-3 text-center">
                    <div>
                      <p className="text-xs font-semibold">{(feed.entries / 1000).toFixed(0)}K</p>
                      <p className="text-xs text-muted-foreground">Entries</p>
                    </div>
                    <div>
                      <p className="text-xs font-semibold text-green-400">{feed.reliability}%</p>
                      <p className="text-xs text-muted-foreground">Reliability</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground flex items-center justify-center gap-0.5">
                        <Clock className="h-2.5 w-2.5" />{feed.lastUpdate}
                      </p>
                      <p className="text-xs text-muted-foreground">Updated</p>
                    </div>
                  </div>
                  <div className="mt-2">
                    <div className="flex justify-between text-xs mb-0.5">
                      <span className="text-muted-foreground">Quality</span>
                      <span>{feed.reliability}%</span>
                    </div>
                    <Progress value={feed.reliability} className="h-1" />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="mitre" className="mt-4">
          <div className="overflow-x-auto">
            <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${MITRE_MATRIX.length}, minmax(160px, 1fr))` }}>
              {MITRE_MATRIX.map((tactic) => (
                <div key={tactic.id}>
                  <div className="bg-muted/50 rounded-t-lg px-3 py-2 border border-border/50">
                    <p className="text-xs font-bold uppercase tracking-wider text-primary">{tactic.tactic}</p>
                    <p className="text-xs text-muted-foreground font-mono">{tactic.id}</p>
                  </div>
                  <div className="space-y-1.5 pt-1.5">
                    {tactic.techniques.map((tech) => (
                      <div
                        key={tech.id}
                        className={`rounded-md px-2.5 py-2 text-xs border cursor-pointer hover:opacity-90 transition-opacity ${
                          tech.observed
                            ? tech.severity === "critical"
                              ? "bg-red-500/15 border-red-500/30 text-red-300"
                              : tech.severity === "high"
                              ? "bg-orange-500/15 border-orange-500/30 text-orange-300"
                              : "bg-yellow-500/15 border-yellow-500/30 text-yellow-300"
                            : "bg-muted/20 border-border/30 text-muted-foreground"
                        }`}
                        onClick={() => tech.observed && toast.success(`${tech.id} details opened`)}
                      >
                        <div className="flex items-start justify-between gap-1">
                          <div>
                            <code className="font-mono text-xs opacity-70">{tech.id}</code>
                            <p className="font-medium leading-tight mt-0.5">{tech.name}</p>
                          </div>
                          {tech.observed && <Star className="h-3 w-3 shrink-0 mt-0.5 fill-current opacity-80" />}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-6 mt-4 text-xs text-muted-foreground">
            <div className="flex items-center gap-2"><div className="h-3 w-6 rounded bg-red-500/20 border border-red-500/30" /><span>Critical (observed)</span></div>
            <div className="flex items-center gap-2"><div className="h-3 w-6 rounded bg-orange-500/20 border border-orange-500/30" /><span>High (observed)</span></div>
            <div className="flex items-center gap-2"><div className="h-3 w-6 rounded bg-muted/30 border border-border/30" /><span>Not observed</span></div>
            <Star className="h-3 w-3 fill-current" /><span>Actively observed in environment</span>
          </div>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}


