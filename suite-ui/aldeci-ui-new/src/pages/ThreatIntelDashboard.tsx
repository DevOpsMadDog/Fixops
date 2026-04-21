/**
 * Threat Intelligence Dashboard — "Signal Room" redesign
 *
 * Feed health grid, IOC browser with search + copy, threat actor cards,
 * severity table with expandable rows, feed stats bar chart, world map,
 * real-time indicator. Full framer-motion animation suite.
 *
 * Route: /threat-intel
 * API: GET /api/v1/feeds/status  GET /api/v1/threat-intel/iocs
 * Falls back to mock data on failure.
 */

import { useState, useMemo, useCallback, useRef, useEffect } from "react";
import { useAutoRefresh } from "@/hooks/use-auto-refresh";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import {
  Shield,
  Activity,
  Globe,
  Hash,
  Link,
  Server,
  Search,
  Copy,
  Check,
  RefreshCw,
  AlertTriangle,
  TrendingUp,
  Wifi,
  WifiOff,
  Radio,
  Pause,
  Play,
  ChevronDown,
  ChevronRight,
  Crosshair,
  Zap,
  Eye,
  TargetIcon,
  Skull,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

function authedFetch(url: string) {
  return fetch(url, { headers: { "X-API-Key": API_KEY } });
}

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type FeedStatus = "live" | "degraded" | "down";
type IocType = "ip" | "domain" | "hash" | "url";
type Severity = "critical" | "high" | "medium" | "low";

interface Feed {
  id: string;
  name: string;
  status: FeedStatus;
  ioc_count: number;
  last_updated: string;
}

interface IOC {
  type: IocType;
  value: string;
  severity: Severity;
  source: string;
  last_seen: string;
  tags?: string[];
  context?: string;
}

interface ThreatActor {
  name: string;
  nation: string;
  motivation: string;
  ttps: string[];
  active: boolean;
  threat_level: Severity;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_FEEDS: Feed[] = [
  { id: "otx", name: "AlienVault OTX", status: "live", ioc_count: 14832, last_updated: "2m ago" },
  { id: "shodan", name: "Shodan", status: "live", ioc_count: 3291, last_updated: "5m ago" },
  { id: "vt", name: "VirusTotal", status: "degraded", ioc_count: 8847, last_updated: "12m ago" },
  { id: "cisa", name: "CISA KEV", status: "live", ioc_count: 1087, last_updated: "1h ago" },
  { id: "nvd", name: "NVD", status: "live", ioc_count: 246943, last_updated: "6h ago" },
  { id: "abuse", name: "Abuse.ch", status: "live", ioc_count: 29441, last_updated: "8m ago" },
  { id: "urlhaus", name: "URLhaus", status: "live", ioc_count: 18220, last_updated: "3m ago" },
  { id: "emerging", name: "Emerging Threats", status: "down", ioc_count: 4120, last_updated: "2h ago" },
];

const MOCK_IOCS: IOC[] = [
  { type: "ip", value: "185.220.101.47", severity: "critical", source: "OTX", last_seen: "2m ago", tags: ["TOR", "C2"], context: "Known Tor exit node used as C2 relay by APT29. Observed in lateral movement campaigns." },
  { type: "domain", value: "evil-c2.example.net", severity: "high", source: "VirusTotal", last_seen: "15m ago", tags: ["phishing"], context: "Registered 3 days ago. Communicates with known botnet infrastructure." },
  { type: "hash", value: "d41d8cd98f00b204e9800998ecf8427e", severity: "high", source: "Abuse.ch", last_seen: "1h ago", tags: ["ransomware", "LockBit"], context: "LockBit 3.0 payload dropper. SHA-256 confirmed via sandbox analysis." },
  { type: "url", value: "http://phish.example.com/login", severity: "medium", source: "CISA", last_seen: "3h ago", tags: ["phishing"], context: "Credential harvesting page mimicking Microsoft 365 login portal." },
  { type: "ip", value: "91.108.56.130", severity: "critical", source: "Shodan", last_seen: "4m ago", tags: ["C2", "botnet"], context: "Active C2 server. 47 victims beaconing in last 24h." },
  { type: "domain", value: "malware-dropper.ru", severity: "critical", source: "OTX", last_seen: "6m ago", tags: ["dropper", "RU"], context: "Serving signed malware dropper. Infrastructure rotates every 6 hours." },
  { type: "hash", value: "5d41402abc4b2a76b9719d911017c592", severity: "medium", source: "Abuse.ch", last_seen: "2h ago", tags: ["trojan"], context: "Banking trojan variant. Targets financial institutions in EU region." },
  { type: "url", value: "https://fake-bank.example.org/auth", severity: "high", source: "VirusTotal", last_seen: "30m ago", tags: ["phishing", "finance"], context: "SSL-enabled phishing page with valid cert. Evades browser warnings." },
  { type: "ip", value: "198.51.100.42", severity: "low", source: "NVD", last_seen: "8h ago", tags: ["scanner"], context: "Mass-scanning host probing port 22/443. Likely automated reconnaissance." },
  { type: "domain", value: "c2-beacon.onion.example", severity: "high", source: "OTX", last_seen: "20m ago", tags: ["C2", "TOR"], context: "Onion-proxied C2 domain. Associated with Lazarus Group TTPs." },
];

const MOCK_ACTORS: ThreatActor[] = [
  {
    name: "APT29 / Cozy Bear",
    nation: "RU",
    motivation: "Espionage",
    ttps: ["T1566", "T1078", "T1021", "T1059"],
    active: true,
    threat_level: "critical",
  },
  {
    name: "Lazarus Group",
    nation: "KP",
    motivation: "Financial / Espionage",
    ttps: ["T1190", "T1027", "T1055", "T1486"],
    active: true,
    threat_level: "critical",
  },
  {
    name: "APT41",
    nation: "CN",
    motivation: "IP Theft",
    ttps: ["T1133", "T1505", "T1071", "T1003"],
    active: true,
    threat_level: "high",
  },
];

const TREND_DATA = [
  { day: "Mon", ip: 1240, domain: 830, hash: 560, url: 310 },
  { day: "Tue", ip: 1560, domain: 940, hash: 620, url: 280 },
  { day: "Wed", ip: 980, domain: 710, hash: 490, url: 340 },
  { day: "Thu", ip: 2100, domain: 1200, hash: 780, url: 420 },
  { day: "Fri", ip: 1830, domain: 1050, hash: 690, url: 390 },
  { day: "Sat", ip: 760, domain: 540, hash: 380, url: 210 },
  { day: "Sun", ip: 1420, domain: 870, hash: 530, url: 360 },
];

// ═══════════════════════════════════════════════════════════
// Design tokens
// ═══════════════════════════════════════════════════════════

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return n.toString();
}

const STATUS_CFG: Record<FeedStatus, {
  label: string;
  ringColor: string;
  dotColor: string;
  textColor: string;
  bgColor: string;
  borderColor: string;
  Icon: typeof Wifi;
}> = {
  live: {
    label: "Live",
    ringColor: "rgba(34,197,94,0.35)",
    dotColor: "#22c55e",
    textColor: "text-green-400",
    bgColor: "bg-green-500/8",
    borderColor: "border-green-500/20",
    Icon: Wifi,
  },
  degraded: {
    label: "Degraded",
    ringColor: "rgba(234,179,8,0.35)",
    dotColor: "#eab308",
    textColor: "text-yellow-400",
    bgColor: "bg-yellow-500/8",
    borderColor: "border-yellow-500/20",
    Icon: Radio,
  },
  down: {
    label: "Down",
    ringColor: "rgba(239,68,68,0.35)",
    dotColor: "#ef4444",
    textColor: "text-red-400",
    bgColor: "bg-red-500/8",
    borderColor: "border-red-500/20",
    Icon: WifiOff,
  },
};

const IOC_TYPE_CFG: Record<IocType, { label: string; Icon: typeof Globe; pill: string; mono: string }> = {
  ip:     { label: "IP",     Icon: Server, pill: "bg-cyan-500/12 text-cyan-400 border border-cyan-500/20",   mono: "text-cyan-300" },
  domain: { label: "Domain", Icon: Globe,  pill: "bg-violet-500/12 text-violet-400 border border-violet-500/20", mono: "text-violet-300" },
  hash:   { label: "Hash",   Icon: Hash,   pill: "bg-orange-500/12 text-orange-400 border border-orange-500/20", mono: "text-orange-300" },
  url:    { label: "URL",    Icon: Link,   pill: "bg-blue-500/12 text-blue-400 border border-blue-500/20",   mono: "text-blue-300" },
};

const SEV_CFG: Record<Severity, { badge: "critical" | "high" | "medium" | "low"; bar: string; glow: string }> = {
  critical: { badge: "critical", bar: "bg-red-500",    glow: "shadow-[0_0_8px_rgba(239,68,68,0.5)]" },
  high:     { badge: "high",     bar: "bg-orange-500", glow: "shadow-[0_0_8px_rgba(249,115,22,0.4)]" },
  medium:   { badge: "medium",   bar: "bg-yellow-500", glow: "" },
  low:      { badge: "low",      bar: "bg-blue-500",   glow: "" },
};

const ACTOR_NATION_FLAG: Record<string, string> = {
  RU: "🇷🇺", CN: "🇨🇳", KP: "🇰🇵", IR: "🇮🇷", US: "🇺🇸",
};

const CHART_COLORS: Record<string, string> = {
  ip: "#22d3ee", domain: "#a78bfa", hash: "#fb923c", url: "#60a5fa",
};

const CHART_TOOLTIP_STYLE = {
  background: "oklch(0.17 0.01 250)",
  border: "1px solid oklch(0.25 0.01 250)",
  borderRadius: 8,
  fontSize: 11,
  color: "oklch(0.93 0.005 250)",
  padding: "8px 12px",
};

// ═══════════════════════════════════════════════════════════
// Sonar Pulse dot — the signature animation
// ═══════════════════════════════════════════════════════════

function SonarDot({ color, ringColor, size = 8 }: { color: string; ringColor: string; size?: number }) {
  return (
    <span className="relative inline-flex" style={{ width: size, height: size }}>
      {/* Sonar ring 1 */}
      <motion.span
        className="absolute inset-0 rounded-full"
        style={{ background: ringColor }}
        animate={{ scale: [1, 2.4], opacity: [0.8, 0] }}
        transition={{ duration: 1.8, repeat: Infinity, ease: "easeOut" }}
      />
      {/* Sonar ring 2 — offset */}
      <motion.span
        className="absolute inset-0 rounded-full"
        style={{ background: ringColor }}
        animate={{ scale: [1, 1.8], opacity: [0.5, 0] }}
        transition={{ duration: 1.8, repeat: Infinity, ease: "easeOut", delay: 0.6 }}
      />
      {/* Core dot */}
      <span
        className="relative z-10 rounded-full"
        style={{ width: size, height: size, background: color }}
      />
    </span>
  );
}

// ═══════════════════════════════════════════════════════════
// Feed Card
// ═══════════════════════════════════════════════════════════

function FeedCard({ feed, index }: { feed: Feed; index: number }) {
  const cfg = STATUS_CFG[feed.status];
  const StatusIcon = cfg.Icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04, duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
    >
      <div
        className={cn(
          "relative rounded-xl border p-4 group cursor-default transition-all duration-200",
          "hover:border-primary/30 hover:bg-card/80",
          cfg.borderColor,
          "bg-card",
        )}
      >
        {/* Top accent line */}
        <div
          className="absolute top-0 left-4 right-4 h-px rounded-full opacity-80"
          style={{ background: cfg.dotColor }}
        />

        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-2.5">
            <SonarDot
              color={cfg.dotColor}
              ringColor={cfg.ringColor}
              size={feed.status === "down" ? 7 : 8}
            />
            <span className="text-xs font-semibold tracking-tight truncate max-w-[90px]">{feed.name}</span>
          </div>
          <span className={cn("text-[10px] font-mono font-medium", cfg.textColor)}>
            <StatusIcon className="inline w-2.5 h-2.5 mr-0.5 -mt-0.5" />
            {cfg.label}
          </span>
        </div>

        <p className="text-xl font-bold tabular-nums tracking-tight font-mono">
          {formatCount(feed.ioc_count)}
        </p>
        <p className="text-[10px] text-muted-foreground mt-0.5 font-mono">
          IOCs · {feed.last_updated}
        </p>
      </div>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// IOC Search Bar with type-ahead suggestions
// ═══════════════════════════════════════════════════════════

const SEARCH_SUGGESTIONS = [
  { label: "Search by IP address", prefix: "ip:", example: "185.220.101.47" },
  { label: "Search by domain", prefix: "domain:", example: "evil-c2.example.net" },
  { label: "Search by hash", prefix: "hash:", example: "d41d8cd9..." },
  { label: "Search by URL", prefix: "url:", example: "http://phish..." },
  { label: "Filter by severity", prefix: "severity:", example: "critical" },
  { label: "Filter by source", prefix: "source:", example: "OTX" },
];

function IOCSearchBar({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [focused, setFocused] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const suggestions = value.length === 0 && focused ? SEARCH_SUGGESTIONS : [];
  const filterSuggestions = value.length > 0 && focused
    ? SEARCH_SUGGESTIONS.filter(s => s.prefix.startsWith(value) || s.example.toLowerCase().includes(value.toLowerCase()))
    : [];
  const visible = suggestions.length > 0 ? suggestions : filterSuggestions;

  return (
    <div className="relative">
      <div className="relative flex items-center">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
        <Input
          ref={inputRef}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setTimeout(() => setFocused(false), 150)}
          placeholder="Search IP, domain, hash, URL…"
          className="pl-9 pr-3 h-9 text-xs font-mono bg-muted/50 border-border/60 focus:border-primary/50 focus:ring-0 w-64"
          aria-label="Search indicators"
          aria-autocomplete="list"
        />
        {value && (
          <button
            onClick={() => onChange("")}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
            aria-label="Clear search"
          >
            <span className="text-xs">✕</span>
          </button>
        )}
      </div>

      <AnimatePresence>
        {visible.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: -4, scaleY: 0.95 }}
            animate={{ opacity: 1, y: 0, scaleY: 1 }}
            exit={{ opacity: 0, y: -4, scaleY: 0.95 }}
            transition={{ duration: 0.15 }}
            className="absolute top-full left-0 right-0 mt-1 z-50 rounded-lg border border-border bg-popover shadow-xl overflow-hidden"
            style={{ transformOrigin: "top" }}
          >
            {visible.map((s) => (
              <button
                key={s.prefix}
                className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-accent transition-colors"
                onMouseDown={() => onChange(s.prefix)}
              >
                <span className="text-[10px] font-mono text-primary bg-primary/10 rounded px-1.5 py-0.5 shrink-0">
                  {s.prefix}
                </span>
                <span className="text-xs text-muted-foreground">{s.label}</span>
                <span className="text-[10px] font-mono text-muted-foreground/60 ml-auto">{s.example}</span>
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// IOC Row — expandable
// ═══════════════════════════════════════════════════════════

function IocRow({ ioc, index }: { ioc: IOC; index: number }) {
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const typeCfg = IOC_TYPE_CFG[ioc.type];
  const sevCfg = SEV_CFG[ioc.severity];
  const TypeIcon = typeCfg.Icon;

  function handleCopy(e: React.MouseEvent) {
    e.stopPropagation();
    navigator.clipboard.writeText(ioc.value).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <>
      <motion.tr
        initial={{ opacity: 0, x: -10 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: index * 0.025, duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
        className={cn(
          "border-b border-border/40 hover:bg-accent/20 transition-colors group cursor-pointer",
          expanded && "bg-accent/10",
        )}
        onClick={() => ioc.context && setExpanded((e) => !e)}
      >
        <td className="py-2.5 px-3 w-8">
          {ioc.context ? (
            <span className="text-muted-foreground/50 group-hover:text-muted-foreground transition-colors">
              {expanded
                ? <ChevronDown className="w-3.5 h-3.5" />
                : <ChevronRight className="w-3.5 h-3.5" />
              }
            </span>
          ) : (
            <span className="w-3.5 h-3.5 block" />
          )}
        </td>
        <td className="py-2.5 px-2">
          <span className={cn("inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide", typeCfg.pill)}>
            <TypeIcon className="w-2.5 h-2.5" />
            {typeCfg.label}
          </span>
        </td>
        <td className="py-2.5 px-3 max-w-[200px]">
          <span className={cn("font-mono text-xs truncate block", typeCfg.mono)}>
            {ioc.value}
          </span>
        </td>
        <td className="py-2.5 px-2">
          <div className="flex items-center gap-1.5">
            <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", sevCfg.bar, sevCfg.glow)} />
            <Badge variant={sevCfg.badge} className="text-[10px] uppercase tracking-wide py-0 px-1.5">
              {ioc.severity}
            </Badge>
          </div>
        </td>
        <td className="py-2.5 px-3">
          <span className="text-xs text-muted-foreground font-mono">{ioc.source}</span>
        </td>
        <td className="py-2.5 px-3 hidden md:table-cell">
          <div className="flex flex-wrap gap-1">
            {ioc.tags?.slice(0, 2).map((tag) => (
              <span key={tag} className="text-[9px] font-mono bg-muted/60 text-muted-foreground rounded px-1 py-0.5 uppercase tracking-wide">
                {tag}
              </span>
            ))}
          </div>
        </td>
        <td className="py-2.5 px-3 text-[10px] text-muted-foreground font-mono whitespace-nowrap">
          {ioc.last_seen}
        </td>
        <td className="py-2.5 pr-3 text-right">
          <Button
            size="sm"
            variant="ghost"
            className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
            onClick={handleCopy}
            aria-label={`Copy ${ioc.value}`}
          >
            {copied
              ? <Check className="w-3 h-3 text-green-400" />
              : <Copy className="w-3 h-3 text-muted-foreground" />
            }
          </Button>
        </td>
      </motion.tr>

      {/* Expandable context row */}
      <AnimatePresence>
        {expanded && ioc.context && (
          <motion.tr
            key="expanded"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="bg-accent/10"
          >
            <td colSpan={8} className="px-4 pb-3 pt-0">
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
                className="overflow-hidden"
              >
                <div className="border-l-2 border-primary/40 pl-3 py-1.5 mt-1">
                  <p className="text-[11px] text-muted-foreground leading-relaxed">{ioc.context}</p>
                </div>
              </motion.div>
            </td>
          </motion.tr>
        )}
      </AnimatePresence>
    </>
  );
}

// ═══════════════════════════════════════════════════════════
// Threat Actor Card
// ═══════════════════════════════════════════════════════════

function ThreatActorCard({ actor, index }: { actor: ThreatActor; index: number }) {
  const flag = ACTOR_NATION_FLAG[actor.nation] ?? "🏴";
  const sevColor = actor.threat_level === "critical"
    ? "border-red-500/30 bg-red-500/5"
    : actor.threat_level === "high"
    ? "border-orange-500/30 bg-orange-500/5"
    : "border-yellow-500/30 bg-yellow-500/5";

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.3 + index * 0.08, duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
      className={cn(
        "rounded-xl border p-4 relative overflow-hidden group transition-colors duration-200",
        "hover:border-primary/30",
        sevColor,
      )}
    >
      {/* Skull icon watermark */}
      <Skull className="absolute -right-3 -bottom-3 w-16 h-16 text-foreground/3 rotate-12" />

      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="flex items-center gap-1.5 mb-0.5">
            {actor.active && (
              <SonarDot color="#ef4444" ringColor="rgba(239,68,68,0.3)" size={6} />
            )}
            <span className="text-xs font-bold tracking-tight">{actor.name}</span>
          </div>
          <div className="flex items-center gap-1.5 mt-1">
            <span className="text-base leading-none">{flag}</span>
            <span className="text-[10px] text-muted-foreground font-mono">{actor.nation}</span>
            <span className="text-muted-foreground/40 text-[10px]">·</span>
            <span className="text-[10px] text-muted-foreground">{actor.motivation}</span>
          </div>
        </div>
        <Badge variant={SEV_CFG[actor.threat_level].badge} className="text-[10px] uppercase tracking-wide shrink-0">
          {actor.threat_level}
        </Badge>
      </div>

      <div className="flex flex-wrap gap-1 mt-2">
        {actor.ttps.map((ttp) => (
          <span
            key={ttp}
            className="text-[9px] font-mono bg-muted/50 text-primary/80 border border-primary/15 rounded px-1.5 py-0.5 uppercase tracking-wide hover:bg-primary/10 transition-colors cursor-default"
            title={`MITRE ATT&CK: ${ttp}`}
          >
            {ttp}
          </span>
        ))}
      </div>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// World Map — SVG world outline with threat pulse rings
// ═══════════════════════════════════════════════════════════

const THREAT_NODES = [
  { x: 487, y: 130, label: "Moscow", severity: "critical" },
  { x: 680, y: 200, label: "Beijing", severity: "critical" },
  { x: 200, y: 190, label: "New York", severity: "high" },
  { x: 350, y: 185, label: "London", severity: "high" },
  { x: 730, y: 305, label: "Jakarta", severity: "medium" },
  { x: 160, y: 285, label: "São Paulo", severity: "medium" },
  { x: 580, y: 190, label: "Tehran", severity: "high" },
  { x: 350, y: 320, label: "Lagos", severity: "low" },
];

function WorldMap() {
  const nodeColors: Record<string, string> = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#eab308",
    low: "#3b82f6",
  };

  return (
    <div className="relative w-full h-48 overflow-hidden rounded-lg bg-[oklch(0.12_0.01_250)]">
      {/* Grid lines */}
      <svg className="absolute inset-0 w-full h-full opacity-10" viewBox="0 0 900 400" preserveAspectRatio="xMidYMid slice">
        {/* Latitude lines */}
        {[80, 160, 240, 320].map((y) => (
          <line key={y} x1="0" y1={y} x2="900" y2={y} stroke="oklch(0.65 0.15 195)" strokeWidth="0.5" />
        ))}
        {/* Longitude lines */}
        {[150, 300, 450, 600, 750].map((x) => (
          <line key={x} x1={x} y1="0" x2={x} y2="400" stroke="oklch(0.65 0.15 195)" strokeWidth="0.5" />
        ))}
        {/* Equator */}
        <line x1="0" y1="200" x2="900" y2="200" stroke="oklch(0.65 0.15 195)" strokeWidth="1" strokeDasharray="4 4" />
      </svg>

      {/* World landmass silhouette — approximate simplified shapes */}
      <svg className="absolute inset-0 w-full h-full opacity-20" viewBox="0 0 900 400" preserveAspectRatio="xMidYMid slice">
        {/* North America */}
        <ellipse cx="170" cy="170" rx="95" ry="75" fill="oklch(0.45 0.02 250)" />
        {/* South America */}
        <ellipse cx="200" cy="295" rx="55" ry="75" fill="oklch(0.45 0.02 250)" />
        {/* Europe */}
        <ellipse cx="375" cy="155" rx="55" ry="45" fill="oklch(0.45 0.02 250)" />
        {/* Africa */}
        <ellipse cx="400" cy="280" rx="65" ry="90" fill="oklch(0.45 0.02 250)" />
        {/* Asia */}
        <ellipse cx="610" cy="175" rx="155" ry="90" fill="oklch(0.45 0.02 250)" />
        {/* Australia */}
        <ellipse cx="720" cy="320" rx="55" ry="38" fill="oklch(0.45 0.02 250)" />
      </svg>

      {/* Scan line animation */}
      <motion.div
        className="absolute top-0 bottom-0 w-px bg-gradient-to-b from-transparent via-primary/60 to-transparent pointer-events-none"
        animate={{ left: ["0%", "100%"] }}
        transition={{ duration: 6, repeat: Infinity, ease: "linear" }}
      />

      {/* Threat nodes */}
      <svg className="absolute inset-0 w-full h-full" viewBox="0 0 900 400" preserveAspectRatio="xMidYMid slice">
        {THREAT_NODES.map((node, i) => {
          const color = nodeColors[node.severity];
          return (
            <g key={node.label}>
              {/* Pulse rings */}
              <motion.circle
                cx={node.x} cy={node.y} r={6}
                fill="none"
                stroke={color}
                strokeWidth={1}
                animate={{ r: [6, 20], opacity: [0.8, 0] }}
                transition={{ duration: 2, repeat: Infinity, delay: i * 0.35, ease: "easeOut" }}
              />
              <motion.circle
                cx={node.x} cy={node.y} r={4}
                fill="none"
                stroke={color}
                strokeWidth={0.8}
                animate={{ r: [4, 14], opacity: [0.5, 0] }}
                transition={{ duration: 2, repeat: Infinity, delay: i * 0.35 + 0.5, ease: "easeOut" }}
              />
              {/* Core dot */}
              <circle cx={node.x} cy={node.y} r={3} fill={color} opacity={0.9} />
            </g>
          );
        })}
      </svg>

      {/* Legend */}
      <div className="absolute bottom-2 right-3 flex items-center gap-3">
        {(["critical", "high", "medium", "low"] as const).map((sev) => (
          <div key={sev} className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: nodeColors[sev] }} />
            <span className="text-[9px] font-mono text-muted-foreground uppercase">{sev}</span>
          </div>
        ))}
      </div>

      {/* Label overlay */}
      <div className="absolute top-2 left-3">
        <span className="text-[9px] font-mono text-primary/60 uppercase tracking-widest">
          Global Threat Distribution
        </span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Real-time indicator
// ═══════════════════════════════════════════════════════════

function LiveIndicator({ secondsAgo, isPaused, onToggle }: {
  secondsAgo: number;
  isPaused: boolean;
  onToggle: () => void;
}) {
  const isRecent = secondsAgo < 30;

  return (
    <div className="flex items-center gap-2.5 bg-card border border-border rounded-lg px-3 py-1.5">
      {isPaused ? (
        <span className="text-[10px] font-mono text-muted-foreground">Paused</span>
      ) : (
        <div className="flex items-center gap-1.5">
          <SonarDot
            color={isRecent ? "#22c55e" : "#eab308"}
            ringColor={isRecent ? "rgba(34,197,94,0.3)" : "rgba(234,179,8,0.3)"}
            size={6}
          />
          <span className="text-[10px] font-mono text-muted-foreground">
            {secondsAgo === 0 ? "Just now" : `${secondsAgo}s ago`}
          </span>
        </div>
      )}
      <Separator orientation="vertical" className="h-3" />
      <button
        onClick={onToggle}
        className="text-muted-foreground hover:text-foreground transition-colors"
        aria-label={isPaused ? "Resume auto-refresh" : "Pause auto-refresh"}
      >
        {isPaused
          ? <Play className="w-3 h-3" />
          : <Pause className="w-3 h-3" />
        }
      </button>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Custom bar chart tooltip
// ═══════════════════════════════════════════════════════════

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div style={CHART_TOOLTIP_STYLE} className="rounded-lg shadow-xl">
      <p className="text-[10px] font-mono text-muted-foreground mb-1.5 uppercase tracking-wide">{label}</p>
      {payload.map((p: any) => (
        <div key={p.dataKey} className="flex items-center justify-between gap-4 text-[11px]">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full" style={{ background: p.fill }} />
            <span className="font-mono text-muted-foreground">{p.name}</span>
          </div>
          <span className="font-mono font-semibold">{p.value.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function ThreatIntelDashboard() {
  const [search, setSearch] = useState("");
  const [activeTab, setActiveTab] = useState<"all" | IocType>("all");

  const { data: feeds, isLoading: feedsLoading, refetch: refetchFeeds } = useQuery<Feed[]>({
    queryKey: ["feeds-status"],
    queryFn: async () => {
      const res = await authedFetch(`${API}/api/v1/threat-feeds/sources?org_id=${ORG_ID}`);
      if (!res.ok) {
        const res2 = await authedFetch(`${API}/api/v1/feeds/status`);
        if (!res2.ok) throw new Error("feeds api unavailable");
        return res2.json();
      }
      return res.json();
    },
    retry: 1,
    staleTime: 60_000,
    initialData: MOCK_FEEDS,
  });

  const { data: iocs, isLoading: iocsLoading } = useQuery<IOC[]>({
    queryKey: ["threat-intel-iocs"],
    queryFn: async () => {
      const res = await authedFetch(`${API}/api/v1/threat-feeds/items?org_id=${ORG_ID}&limit=20`);
      if (!res.ok) {
        const res2 = await authedFetch(`${API}/api/v1/threat-intel/iocs`);
        if (!res2.ok) throw new Error("iocs api unavailable");
        return res2.json();
      }
      return res.json();
    },
    retry: 1,
    staleTime: 30_000,
    initialData: MOCK_IOCS,
  });

  const { data: feedStats } = useQuery<any>({
    queryKey: ["threat-feeds-stats"],
    queryFn: async () => {
      const res = await authedFetch(`${API}/api/v1/threat-feeds/stats?org_id=${ORG_ID}`);
      if (!res.ok) throw new Error("stats api unavailable");
      return res.json();
    },
    retry: 1,
    staleTime: 60_000,
  });

  const filteredIocs = useMemo(() => {
    if (!iocs) return [];
    let result = iocs;

    if (activeTab !== "all") {
      result = result.filter((i) => i.type === activeTab);
    }

    const q = search.toLowerCase().replace(/^(ip:|domain:|hash:|url:|severity:|source:)/, "");
    if (q) {
      result = result.filter(
        (i) =>
          i.value.toLowerCase().includes(q) ||
          i.type.includes(q) ||
          i.severity.includes(q) ||
          i.source.toLowerCase().includes(q) ||
          i.tags?.some((t) => t.toLowerCase().includes(q)),
      );
    }
    return result;
  }, [iocs, search, activeTab]);

  const refetchAll = useCallback(() => { refetchFeeds(); }, [refetchFeeds]);
  const { isPaused, togglePause, secondsAgo } = useAutoRefresh(refetchAll, 60_000);

  const liveCount    = feeds?.filter((f) => f.status === "live").length ?? 0;
  const totalIocs    = feeds?.reduce((s, f) => s + f.ioc_count, 0) ?? 0;
  const criticalIocs = iocs?.filter((i) => i.severity === "critical").length ?? 0;

  const iocTypeCounts = useMemo(() => ({
    all: iocs?.length ?? 0,
    ip: iocs?.filter((i) => i.type === "ip").length ?? 0,
    domain: iocs?.filter((i) => i.type === "domain").length ?? 0,
    hash: iocs?.filter((i) => i.type === "hash").length ?? 0,
    url: iocs?.filter((i) => i.type === "url").length ?? 0,
  }), [iocs]);

  const TAB_ITEMS: { key: "all" | IocType; label: string }[] = [
    { key: "all", label: "All" },
    { key: "ip", label: "IP" },
    { key: "domain", label: "Domain" },
    { key: "hash", label: "Hash" },
    { key: "url", label: "URL" },
  ];

  return (
    <div className="flex flex-col gap-5 p-6 min-h-0">

      {/* ── Header ── */}
      <PageHeader
        title="Threat Intelligence"
        description="Live IOC feeds · indicator browser · global threat distribution across 28+ sources"
        badge="Live"
        actions={
          <div className="flex items-center gap-2">
            <LiveIndicator secondsAgo={secondsAgo} isPaused={isPaused} onToggle={togglePause} />
            <Button
              size="sm"
              variant="outline"
              onClick={() => refetchFeeds()}
              className="gap-1.5 h-8 text-xs"
            >
              <RefreshCw className="w-3 h-3" />
              Refresh
            </Button>
          </div>
        }
      />

      {/* ── KPI Row ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <KpiCard
          title="Active Feeds"
          value={`${liveCount} / ${feeds?.length ?? 0}`}
          icon={Activity}
          trend="up"
          trendLabel="All healthy"
        />
        <KpiCard
          title="Total IOCs"
          value={totalIocs}
          icon={Shield}
          trend="up"
          trendLabel="+2.3K today"
        />
        <KpiCard
          title="Critical IOCs"
          value={criticalIocs}
          icon={AlertTriangle}
          trend="down"
          trendLabel="Requires action"
        />
        <KpiCard
          title="New Today"
          value={feedStats?.new_today ?? "4,218"}
          icon={TrendingUp}
          trend="up"
          trendLabel="vs 3,901 yesterday"
        />
      </div>

      {/* ── Feed Status Grid ── */}
      <section>
        <div className="flex items-center gap-2 mb-3">
          <Crosshair className="w-3.5 h-3.5 text-primary" />
          <span className="text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
            Feed Status
          </span>
          <Separator className="flex-1" />
          <span className="text-[10px] font-mono text-muted-foreground">
            {liveCount} live · {feeds?.filter((f) => f.status === "degraded").length ?? 0} degraded · {feeds?.filter((f) => f.status === "down").length ?? 0} down
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
          {(feeds ?? MOCK_FEEDS).map((feed, i) => (
            <FeedCard key={feed.id} feed={feed} index={i} />
          ))}
        </div>
      </section>

      {/* ── Main Content Row ── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 min-h-0">

        {/* Threat Actors */}
        <div className="xl:col-span-1 flex flex-col gap-3">
          <div className="flex items-center gap-2 mb-1">
            <Eye className="w-3.5 h-3.5 text-primary" />
            <span className="text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
              Active Threat Actors
            </span>
          </div>
          {MOCK_ACTORS.map((actor, i) => (
            <ThreatActorCard key={actor.name} actor={actor} index={i} />
          ))}

          {/* World Map */}
          <div className="mt-1">
            <div className="flex items-center gap-2 mb-2">
              <Globe className="w-3.5 h-3.5 text-primary" />
              <span className="text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
                Global Activity
              </span>
            </div>
            <WorldMap />
          </div>
        </div>

        {/* IOC Browser + Chart */}
        <div className="xl:col-span-2 flex flex-col gap-4">

          {/* IOC Browser */}
          <Card className="flex flex-col min-h-0">
            <CardHeader className="pb-0 pt-4 px-4">
              <div className="flex items-center justify-between gap-3 mb-3">
                <div className="flex items-center gap-2">
                  <Zap className="w-3.5 h-3.5 text-primary" />
                  <CardTitle className="text-sm font-semibold">IOC Browser</CardTitle>
                  <span className="text-[10px] font-mono text-muted-foreground bg-muted/60 rounded px-1.5 py-0.5">
                    {filteredIocs.length} results
                  </span>
                </div>
                <IOCSearchBar value={search} onChange={setSearch} />
              </div>

              {/* Type filter tabs */}
              <div className="flex items-center gap-1 -mx-1 pb-3 border-b border-border/60">
                {TAB_ITEMS.map(({ key, label }) => {
                  const count = iocTypeCounts[key];
                  const isActive = activeTab === key;
                  return (
                    <button
                      key={key}
                      onClick={() => setActiveTab(key)}
                      className={cn(
                        "relative px-2.5 py-1 rounded-md text-[11px] font-medium transition-all duration-150 flex items-center gap-1.5",
                        isActive
                          ? "bg-primary/15 text-primary"
                          : "text-muted-foreground hover:text-foreground hover:bg-accent",
                      )}
                    >
                      {label}
                      <span className={cn(
                        "text-[9px] font-mono rounded px-1 py-0.5",
                        isActive ? "bg-primary/20 text-primary" : "bg-muted/60 text-muted-foreground",
                      )}>
                        {count}
                      </span>
                    </button>
                  );
                })}
              </div>
            </CardHeader>

            <div className="flex-1 overflow-hidden">
              <ScrollArea className="h-[320px]">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 z-10 bg-card">
                    <tr className="border-b border-border/60">
                      <th className="py-2 w-8" />
                      <th className="py-2 px-2 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-16">Type</th>
                      <th className="py-2 px-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Indicator</th>
                      <th className="py-2 px-2 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-24">Severity</th>
                      <th className="py-2 px-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-16">Source</th>
                      <th className="py-2 px-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hidden md:table-cell w-24">Tags</th>
                      <th className="py-2 px-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-20">Last Seen</th>
                      <th className="py-2 w-10" />
                    </tr>
                  </thead>
                  <tbody>
                    {filteredIocs.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="py-14 text-center">
                          <Search className="w-6 h-6 text-muted-foreground/30 mx-auto mb-2" />
                          <p className="text-sm text-muted-foreground">No indicators match your search</p>
                        </td>
                      </tr>
                    ) : (
                      filteredIocs.map((ioc, i) => (
                        <IocRow key={`${ioc.type}-${ioc.value}`} ioc={ioc} index={i} />
                      ))
                    )}
                  </tbody>
                </table>
              </ScrollArea>
            </div>
          </Card>

          {/* Feed Statistics Chart */}
          <Card>
            <CardHeader className="pb-0 pt-4 px-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <TrendingUp className="w-3.5 h-3.5 text-primary" />
                  <CardTitle className="text-sm font-semibold">7-Day IOC Ingestion</CardTitle>
                </div>
                <div className="flex items-center gap-3">
                  {Object.entries(CHART_COLORS).map(([key, color]) => (
                    <div key={key} className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full" style={{ background: color }} />
                      <span className="text-[10px] font-mono text-muted-foreground uppercase">{key}</span>
                    </div>
                  ))}
                </div>
              </div>
            </CardHeader>
            <CardContent className="pt-3 pb-4 px-4">
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={TREND_DATA} barSize={7} barGap={1} margin={{ top: 4, right: 0, left: -20, bottom: 0 }}>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="oklch(0.25 0.01 250)"
                    vertical={false}
                  />
                  <XAxis
                    dataKey="day"
                    tick={{ fontSize: 10, fill: "oklch(0.55 0.01 250)", fontFamily: "JetBrains Mono, monospace" }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fontSize: 10, fill: "oklch(0.55 0.01 250)", fontFamily: "JetBrains Mono, monospace" }}
                    axisLine={false}
                    tickLine={false}
                    tickFormatter={(v: number) => `${(v / 1000).toFixed(0)}K`}
                  />
                  <Tooltip content={<ChartTooltip />} cursor={{ fill: "oklch(0.22 0.01 250 / 0.6)" }} />
                  <Bar dataKey="ip"     fill={CHART_COLORS.ip}     radius={[3, 3, 0, 0]} name="IP" />
                  <Bar dataKey="domain" fill={CHART_COLORS.domain} radius={[3, 3, 0, 0]} name="Domain" />
                  <Bar dataKey="hash"   fill={CHART_COLORS.hash}   radius={[3, 3, 0, 0]} name="Hash" />
                  <Bar dataKey="url"    fill={CHART_COLORS.url}     radius={[3, 3, 0, 0]} name="URL" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
