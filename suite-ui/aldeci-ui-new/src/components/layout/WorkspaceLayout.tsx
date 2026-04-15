import React, { useState, useMemo } from "react";
import { NavLink, Link, Outlet, useLocation } from "react-router-dom";
import { ErrorState } from "@/components/shared/ErrorState";

// Route-level error boundary that resets on navigation
class RouteErrorBoundary extends React.Component<
  { children: React.ReactNode; locationKey: string },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: React.ReactNode; locationKey: string }) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error: Error) { return { hasError: true, error }; }
  componentDidUpdate(prevProps: { locationKey: string }) {
    if (prevProps.locationKey !== this.props.locationKey && this.state.hasError) {
      this.setState({ hasError: false, error: null });
    }
  }
  render() {
    if (this.state.hasError) {
      return <ErrorState message={`Page error: ${this.state.error?.message || 'Unknown error'}`} onRetry={() => this.setState({ hasError: false, error: null })} />;
    }
    return this.props.children;
  }
}
import { cn } from "@/lib/utils";
import { useAppStore } from "@/stores";
import { motion, AnimatePresence } from "framer-motion";
import {
  Target,
  Search,
  ShieldCheck,
  Wrench,
  Shield,
  Settings,
  Bot,
  ChevronLeft,
  ChevronRight,
  LayoutDashboard,
  Crown,
  Clock,
  Activity,
  AlertTriangle,
  Bug,
  Code,
  KeyRound,
  Server,
  Cloud,
  Container,
  Package,
  Share2,
  Route,
  Rss,
  GitMerge,
  Database,
  Globe,
  Crosshair,
  Swords,
  Flame,
  BookOpen,
  Network,
  CheckCircle,
  Wand2,
  Layers,
  Users,
  Workflow,
  Ticket,
  ClipboardCheck,
  Lock,
  Download,
  FileCheck,
  FileSignature,
  ScrollText,
  FileText,
  BarChart3,
  Sun,
  Moon,
  PanelRightOpen,
  PanelRightClose,
  Brain,
  Cpu,
  FlaskConical,
  TrendingUp,
  Scale,
  Code2,
  Wifi,
  Building2,
  ShieldAlert,
  Siren,
  Radar,
  HardDrive,
  UserX,
  ListChecks,
  RefreshCcw,
  Link2,
  ShieldOff,
  ScanSearch,
  UserCheck,
  GraduationCap,
  Map,
  Eye,
  Mail,
  Monitor,
  Award,
  Zap,
  BarChart2,
  List,
  Smartphone,
  Key,
  Tag,
  GitBranch,
  type LucideIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { CopilotSidebar } from "./CopilotSidebar";
import { useAuth } from "@/lib/auth";

interface NavItem {
  label: string;
  to: string;
  icon: LucideIcon;
  badge?: string;
  /** If set, only users with one of these roles see this item. Omit for everyone. */
  roles?: string[];
}

interface NavGroup {
  label: string;
  icon: LucideIcon;
  items: NavItem[];
}

const navGroups: NavGroup[] = [
  {
    label: "Mission Control",
    icon: Target,
    items: [
      { label: "Command Dashboard", to: "/mission-control", icon: LayoutDashboard },
      { label: "SOC Alert Triage", to: "/mission-control/soc", icon: AlertTriangle, badge: "P03" },
      { label: "Executive View", to: "/mission-control/executive", icon: Crown, roles: ["admin", "security_analyst"] },
      { label: "SLA Dashboard", to: "/sla-dashboard", icon: Clock, roles: ["admin", "security_analyst"] },
      { label: "Live Feed", to: "/mission-control/live-feed", icon: Activity },
      { label: "Risk Overview", to: "/mission-control/risk", icon: AlertTriangle },
      { label: "Risk Register", to: "/mission-control/risk-register", icon: ClipboardCheck },
    ],
  },
  {
    label: "Discover",
    icon: Search,
    items: [
      { label: "Finding Explorer", to: "/discover", icon: Bug },
      { label: "Code Scanning", to: "/discover/code", icon: Code },
      { label: "Secrets", to: "/discover/secrets", icon: KeyRound },
      { label: "IaC Scanning", to: "/discover/iac", icon: Server },
      { label: "Cloud Posture", to: "/discover/cloud", icon: Cloud, roles: ["admin", "security_analyst"] },
      { label: "Containers", to: "/discover/containers", icon: Container },
      { label: "SBOM & Inventory", to: "/discover/sbom", icon: Package },
      { label: "Knowledge Graph", to: "/discover/graph", icon: Share2, roles: ["admin", "security_analyst"] },
      { label: "Attack Paths", to: "/discover/attack-paths", icon: Route, roles: ["admin", "security_analyst"] },
      { label: "Threat Feeds", to: "/discover/threats", icon: Rss, roles: ["admin", "security_analyst"] },
      { label: "Correlation Engine", to: "/discover/correlation", icon: GitMerge, roles: ["admin", "security_analyst"] },
      { label: "Data Fabric", to: "/discover/data-fabric", icon: Database, roles: ["admin", "security_analyst"] },
    ],
  },
  {
    label: "Validate",
    icon: ShieldCheck,
    items: [
      { label: "MPTE Console", to: "/validate/mpte", icon: Crosshair, roles: ["admin", "security_analyst"] },
      { label: "Attack Simulation", to: "/validate/simulation", icon: Swords, roles: ["admin", "security_analyst"] },
      { label: "FAIL Engine", to: "/validate/fail", icon: Flame, badge: "NEW", roles: ["admin", "security_analyst"] },
      { label: "Playbooks", to: "/validate/playbooks", icon: BookOpen, roles: ["admin", "security_analyst"] },
      { label: "Reachability", to: "/validate/reachability", icon: Network },
    ],
  },
  {
    label: "Remediate",
    icon: Wrench,
    items: [
      { label: "Remediation Center", to: "/remediate", icon: CheckCircle },
      { label: "AutoFix", to: "/remediate/autofix", icon: Wand2 },
      { label: "Bulk Operations", to: "/remediate/bulk", icon: Layers, roles: ["admin", "security_analyst"] },
      { label: "Collaboration", to: "/remediate/collaborate", icon: Users },
      { label: "Workflows", to: "/remediate/workflows", icon: Workflow, roles: ["admin", "security_analyst"] },
      { label: "Exposure Cases", to: "/remediate/cases", icon: AlertTriangle },
      { label: "Ticket Integration", to: "/remediate/tickets", icon: Ticket, roles: ["admin", "security_analyst"] },
      { label: "Risk Acceptance", to: "/risk-acceptance", icon: ShieldAlert, badge: "GRC", roles: ["admin", "security_analyst"] },
    ],
  },
  {
    label: "Comply",
    icon: Shield,
    items: [
      { label: "Compliance Dashboard", to: "/comply", icon: ClipboardCheck },
      { label: "Evidence Vault", to: "/comply/evidence", icon: Lock, roles: ["admin", "security_analyst"] },
      { label: "Evidence Export", to: "/comply/export", icon: Download, roles: ["admin", "security_analyst"] },
      { label: "SOC2 Evidence", to: "/comply/soc2", icon: FileCheck, roles: ["admin", "security_analyst"] },
      { label: "SLSA Provenance", to: "/comply/slsa", icon: FileSignature, roles: ["admin", "security_analyst"] },
      { label: "Audit Trail", to: "/comply/audit", icon: ScrollText, roles: ["admin", "security_analyst"] },
      { label: "Reports", to: "/comply/reports", icon: FileText },
      { label: "Analytics", to: "/comply/analytics", icon: BarChart3 },
    ],
  },
  {
    label: "SBOM",
    icon: Package,
    items: [
      { label: "SBOM Management", to: "/sbom", icon: Package, badge: "NEW" },
    ],
  },
  {
    label: "Attack Surface",
    icon: Globe,
    items: [
      { label: "Surface Overview", to: "/attack-surface", icon: Globe, badge: "CTEM" },
    ],
  },
  {
    label: "Integrations",
    icon: Wifi,
    items: [
      { label: "Integration Health", to: "/integrations", icon: Activity },
    ],
  },
  {
    label: "Threat Hunting",
    icon: Crosshair,
    items: [
      { label: "Hunt Operations", to: "/hunting", icon: Crosshair, badge: "P04" },
      { label: "Threat Hunting", to: "/threat-hunting", icon: Crosshair, badge: "NEW" },
    ],
  },
  {
    label: "AI Engine",
    icon: Brain,
    items: [
      { label: "Copilot", to: "/ai", icon: Bot },
      { label: "Brain Pipeline", to: "/ai/brain", icon: Workflow, roles: ["admin", "security_analyst"] },
      { label: "Multi-LLM Consensus", to: "/ai/consensus", icon: Scale, roles: ["admin", "security_analyst"] },
      { label: "Algorithmic Lab", to: "/ai/algorithms", icon: FlaskConical, roles: ["admin", "security_analyst"] },
      { label: "ML Dashboard", to: "/ai/ml", icon: Cpu, roles: ["admin", "security_analyst"] },
      { label: "Predictions", to: "/ai/predictions", icon: TrendingUp, roles: ["admin", "security_analyst"] },
    ],
  },
  {
    label: "Developer",
    icon: Code2,
    items: [
      { label: "Security Portal", to: "/developer", icon: Code2, badge: "P10" },
    ],
  },
  {
    label: "Vendors",
    icon: Building2,
    items: [
      { label: "Vendor Management", to: "/vendors", icon: Building2, badge: "TPRM" },
    ],
  },
  {
    label: "Security Operations",
    icon: Siren,
    items: [
      { label: "Incident Response", to: "/incidents", icon: Siren, badge: "IR" },
      { label: "Incident Timeline", to: "/incident-timeline", icon: AlertTriangle, badge: "NEW" },
      { label: "Network Analysis", to: "/network-analysis", icon: Network, badge: "NEW" },
      { label: "Firewall Analyzer", to: "/firewall", icon: Shield, badge: "NEW" },
      { label: "Email Security", to: "/email-security", icon: Mail, badge: "NEW" },
      { label: "Endpoint Security (EDR)", to: "/endpoint-security", icon: Monitor, badge: "NEW" },
      { label: "SOAR Automation", to: "/soar", icon: Zap, badge: "NEW" },
      { label: "Threat Correlation", to: "/threat-correlation", icon: Link2, badge: "NEW" },
      { label: "SOC", to: "/soc", icon: Monitor, badge: "NEW" },
      { label: "User Behavior", to: "/uba", icon: Activity, badge: "NEW" },
      { label: "Breach Response", to: "/breach-response", icon: AlertTriangle, badge: "NEW" },
    ],
  },
  {
    label: "Threat Intelligence",
    icon: Radar,
    items: [
      { label: "Threat Intel Dashboard", to: "/threat-intel", icon: Radar, badge: "NEW" },
      { label: "CVE Search", to: "/cve-search", icon: ScanSearch },
      { label: "IP Reputation", to: "/ip-reputation", icon: Globe },
    ],
  },
  {
    label: "Vulnerability Mgmt",
    icon: Bug,
    items: [
      { label: "Vulnerability Lifecycle", to: "/vuln-lifecycle", icon: Bug, badge: "NEW" },
      { label: "Patch Queue", to: "/patch-prioritizer", icon: ListChecks },
      { label: "Attack Paths", to: "/attack-paths", icon: Route },
      { label: "Vuln Heatmap", to: "/vuln-heatmap", icon: Map, badge: "NEW" },
      { label: "Bug Bounty", to: "/bug-bounty", icon: Award, badge: "NEW" },
      { label: "Security Metrics", to: "/security-metrics", icon: BarChart2, badge: "NEW" },
      { label: "Vuln Risk Queue", to: "/vuln-risk", icon: List, badge: "NEW" },
    ],
  },
  {
    label: "Asset Inventory",
    icon: HardDrive,
    items: [
      { label: "Asset Inventory", to: "/assets", icon: HardDrive, badge: "NEW" },
    ],
  },
  {
    label: "Identity & Access",
    icon: UserX,
    items: [
      { label: "Insider Threats", to: "/insider-threats", icon: UserX, badge: "NEW" },
      { label: "Zero Trust", to: "/zero-trust", icon: Lock },
      { label: "Cloud IAM", to: "/cloud-iam", icon: KeyRound, badge: "NEW" },
      { label: "Identity Governance", to: "/identity-governance", icon: UserCheck, badge: "NEW" },
      { label: "Security Awareness", to: "/security-awareness", icon: GraduationCap, badge: "NEW" },
      { label: "Security Training", to: "/security-training", icon: GraduationCap, badge: "NEW" },
      { label: "Password Policy", to: "/password-policy", icon: Key, badge: "NEW" },
      { label: "Mobile Security", to: "/mobile-security", icon: Smartphone, badge: "NEW" },
    ],
  },
  {
    label: "Risk & Compliance",
    icon: ClipboardCheck,
    items: [
      { label: "Compliance Dashboard", to: "/compliance", icon: ClipboardCheck, badge: "P07" },
      { label: "Risk Acceptance", to: "/risk-acceptance", icon: ShieldAlert, roles: ["admin", "security_analyst"] },
      { label: "Vendor Risk", to: "/vendor-risk", icon: Building2 },
      { label: "Security KPIs", to: "/security-kpis", icon: BarChart3 },
      { label: "Executive Report", to: "/executive-report", icon: BarChart3, badge: "NEW" },
      { label: "Audit Log", to: "/audit-log", icon: FileText, badge: "NEW" },
      { label: "GRC Dashboard", to: "/grc", icon: ClipboardCheck, badge: "NEW" },
      { label: "Supply Chain Risk", to: "/supply-chain-risk", icon: Package, badge: "NEW" },
      { label: "Watchlist Manager", to: "/watchlist", icon: Eye, badge: "NEW" },
      { label: "IOC Hunter", to: "/ioc-hunter", icon: Search, badge: "NEW" },
      { label: "Data Classification", to: "/data-classification", icon: Tag, badge: "NEW" },
    ],
  },
  {
    label: "Architecture",
    icon: Layers,
    items: [
      { label: "Posture Advisor", to: "/posture-advisor", icon: Target, badge: "NEW" },
      { label: "Threat Modeling", to: "/threat-modeling", icon: Layers },
      { label: "Supply Chain", to: "/supply-chain", icon: Link2 },
      { label: "CSPM", to: "/cspm", icon: Cloud, badge: "NEW" },
      { label: "Certificate Manager", to: "/certificates", icon: ShieldCheck, badge: "NEW" },
    ],
  },
  {
    label: "Cloud & Infrastructure",
    icon: Cloud,
    items: [
      { label: "Cloud Security", to: "/cloud-security", icon: Cloud, badge: "NEW" },
      { label: "Network Topology", to: "/network-topology", icon: GitBranch, badge: "NEW" },
      { label: "CMDB", to: "/cmdb", icon: Database, badge: "NEW" },
    ],
  },
  {
    label: "Application Security",
    icon: Code,
    items: [
      { label: "AppSec (SAST/DAST)", to: "/app-security", icon: Code, badge: "NEW" },
      { label: "API Security", to: "/api-security", icon: Wifi, badge: "NEW" },
      { label: "API Vuln Mgmt", to: "/api-sec", icon: Wifi, badge: "NEW" },
      { label: "Phishing Simulation", to: "/phishing", icon: Mail, badge: "NEW" },
      { label: "Social Engineering", to: "/social-engineering", icon: Users, badge: "NEW" },
    ],
  },
  {
    label: "Data Protection",
    icon: ShieldOff,
    items: [
      { label: "Data Loss Prevention", to: "/dlp", icon: ShieldOff, badge: "NEW" },
      { label: "API Abuse Detection", to: "/api-abuse", icon: AlertTriangle },
      { label: "Secrets Rotation", to: "/secrets-rotation", icon: RefreshCcw },
    ],
  },
];

// ── User identity badge for sidebar ──
import { LogOut, UserCircle } from "lucide-react";

function UserBadge({ collapsed }: { collapsed: boolean }) {
  const { user, isAuthenticated, logout } = useAuth();
  if (!isAuthenticated || !user) return null;

  const initials = `${(user.first_name?.[0] ?? "").toUpperCase()}${(user.last_name?.[0] ?? "").toUpperCase()}` || "U";

  if (collapsed) {
    return (
      <button
        onClick={logout}
        className="flex w-full items-center justify-center rounded-lg px-3 py-2 text-sm text-sidebar-foreground hover:bg-sidebar-accent/50 transition-colors"
        title={`${user.email} — Sign out`}
      >
        <div className="h-6 w-6 rounded-full bg-primary/20 flex items-center justify-center text-[10px] font-bold text-primary">
          {initials}
        </div>
      </button>
    );
  }

  return (
    <div className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm">
      <div className="h-7 w-7 rounded-full bg-primary/20 flex items-center justify-center text-[10px] font-bold text-primary shrink-0">
        {initials}
      </div>
      <div className="flex-1 truncate">
        <div className="truncate text-xs font-medium text-foreground">{user.first_name} {user.last_name}</div>
        <div className="truncate text-[10px] text-muted-foreground">{user.role}</div>
      </div>
      <button onClick={logout} className="text-muted-foreground hover:text-foreground" title="Sign out">
        <LogOut className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

// ── Breadcrumb navigation derived from route + navGroups ──
function Breadcrumbs({ navGroups, pathname }: { navGroups: NavGroup[]; pathname: string }) {
  const crumbs = useMemo(() => {
    const result: { label: string; to?: string; icon?: LucideIcon }[] = [];
    for (const group of navGroups) {
      const match = group.items.find(
        (item) => pathname === item.to || pathname.startsWith(item.to + "/")
      );
      if (match) {
        result.push({ label: group.label, to: group.items[0]?.to, icon: group.icon });
        if (match.to !== group.items[0]?.to || pathname !== match.to) {
          result.push({ label: match.label, to: match.to, icon: match.icon });
        }
        // If there's a deeper path beyond the matched item, show it
        const rest = pathname.slice(match.to.length).replace(/^\//, "");
        if (rest) {
          const label = rest.split("/").pop()?.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()) ?? rest;
          result.push({ label });
        }
        break;
      }
    }
    if (result.length === 0) {
      // Settings or other top-level pages
      if (pathname.startsWith("/settings")) {
        result.push({ label: "Settings", to: "/settings", icon: Settings });
        const sub = pathname.slice("/settings/".length).replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
        if (sub && pathname !== "/settings") result.push({ label: sub });
      }
    }
    return result;
  }, [navGroups, pathname]);

  // Cross-space quick-jump: show other spaces for fast navigation
  const otherSpaces = useMemo(
    () => navGroups.filter((g) => !g.items.some((i) => pathname === i.to || pathname.startsWith(i.to + "/"))).slice(0, 4),
    [navGroups, pathname]
  );

  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground min-w-0 flex-1">
      {crumbs.map((crumb, i) => (
        <React.Fragment key={i}>
          {i > 0 && <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground/50" />}
          {crumb.to ? (
            <Link to={crumb.to} className="flex items-center gap-1.5 hover:text-foreground transition-colors truncate">
              {crumb.icon && <crumb.icon className="h-3.5 w-3.5 shrink-0" />}
              <span className={i === crumbs.length - 1 ? "font-medium text-foreground" : ""}>{crumb.label}</span>
            </Link>
          ) : (
            <span className="flex items-center gap-1.5 font-medium text-foreground truncate">
              {crumb.icon && <crumb.icon className="h-3.5 w-3.5 shrink-0" />}
              {crumb.label}
            </span>
          )}
        </React.Fragment>
      ))}
      {/* Cross-space quick-jump */}
      {otherSpaces.length > 0 && (
        <div className="ml-auto flex items-center gap-1 pl-4">
          {otherSpaces.map((space) => (
            <Link
              key={space.label}
              to={space.items[0]?.to ?? "/"}
              className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
              title={space.label}
            >
              <space.icon className="h-3 w-3" />
              <span className="hidden xl:inline">{space.label}</span>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

export function WorkspaceLayout() {
  const { preferences, toggleSidebar, toggleCopilot, toggleTheme } = useAppStore();
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null);
  const location = useLocation();
  const { user } = useAuth();

  const collapsed = preferences.sidebarCollapsed;
  const copilotOpen = preferences.copilotOpen;
  const userRole = user?.role ?? "viewer";

  // Filter nav items by role — items without `roles` are visible to all
  const filteredGroups = navGroups
    .map((g) => ({
      ...g,
      items: g.items.filter((item) => !item.roles || item.roles.includes(userRole)),
    }))
    .filter((g) => g.items.length > 0);

  // Auto-expand active group
  const activeGroup = filteredGroups.find((g) =>
    g.items.some((item) => location.pathname === item.to || location.pathname.startsWith(item.to + "/"))
  );

  const currentExpanded = expandedGroup ?? activeGroup?.label ?? null;

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* ── Left Sidebar ── */}
      <aside
        className={cn(
          "flex flex-col border-r border-sidebar-border bg-sidebar transition-[width] duration-300",
          collapsed ? "w-16" : "w-60",
          "max-md:w-16"
        )}
      >
        {/* Logo */}
        <div className="flex h-14 items-center gap-3 border-b border-sidebar-border px-4">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary font-bold text-primary-foreground text-sm">
            A
          </div>
          {!collapsed && (
            <span className="text-sm font-semibold tracking-tight">ALdeci</span>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-2 px-2">
          {filteredGroups.map((group) => {
            const isExpanded = currentExpanded === group.label;
            const isActive = group.items.some(
              (item) =>
                location.pathname === item.to ||
                location.pathname.startsWith(item.to + "/")
            );

            return (
              <div key={group.label} className="mb-1">
                <button
                  onClick={() => setExpandedGroup(isExpanded ? null : group.label)}
                  className={cn(
                    "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                    isActive
                      ? "bg-sidebar-accent text-foreground"
                      : "text-sidebar-foreground hover:bg-sidebar-accent/50 hover:text-foreground"
                  )}
                >
                  <group.icon className="h-4 w-4 shrink-0" />
                  {!collapsed && (
                    <>
                      <span className="flex-1 text-left">{group.label}</span>
                      <ChevronRight
                        className={cn(
                          "h-3 w-3 transition-transform duration-200",
                          isExpanded && "rotate-90"
                        )}
                      />
                    </>
                  )}
                </button>

                {/* Sub-items */}
                <AnimatePresence initial={false}>
                  {isExpanded && !collapsed && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.2 }}
                      className="overflow-hidden"
                    >
                      <div className="ml-3 border-l border-sidebar-border pl-3 py-1">
                        {group.items.map((item) => (
                          <NavLink
                            key={item.to}
                            to={item.to}
                            end={item.to === "/mission-control" || item.to === "/discover" || item.to === "/remediate" || item.to === "/comply"}
                            className={({ isActive: active }) =>
                              cn(
                                "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-xs transition-colors",
                                active
                                  ? "bg-primary/10 text-primary font-medium"
                                  : "text-sidebar-foreground hover:bg-sidebar-accent/50 hover:text-foreground"
                              )
                            }
                          >
                            <item.icon className="h-3.5 w-3.5 shrink-0" />
                            <span className="truncate">{item.label}</span>
                            {item.badge && (
                              <span className="ml-auto rounded bg-purple-500/20 px-1.5 py-0.5 text-[10px] font-medium text-purple-400">
                                {item.badge}
                              </span>
                            )}
                          </NavLink>
                        ))}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </nav>

        {/* Bottom Actions */}
        <div className="border-t border-sidebar-border p-2 space-y-1">
          {/* User identity */}
          <UserBadge collapsed={collapsed} />
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                isActive
                  ? "bg-sidebar-accent text-foreground"
                  : "text-sidebar-foreground hover:bg-sidebar-accent/50"
              )
            }
          >
            <Settings className="h-4 w-4 shrink-0" />
            {!collapsed && <span>Settings</span>}
          </NavLink>

          <button
            onClick={toggleTheme}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-sidebar-foreground hover:bg-sidebar-accent/50 transition-colors"
          >
            {preferences.theme === "dark" ? (
              <Sun className="h-4 w-4 shrink-0" />
            ) : (
              <Moon className="h-4 w-4 shrink-0" />
            )}
            {!collapsed && <span>{preferences.theme === "dark" ? "Light Mode" : "Dark Mode"}</span>}
          </button>

          <button
            onClick={toggleSidebar}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-sidebar-foreground hover:bg-sidebar-accent/50 transition-colors"
          >
            {collapsed ? (
              <ChevronRight className="h-4 w-4 shrink-0" />
            ) : (
              <ChevronLeft className="h-4 w-4 shrink-0" />
            )}
            {!collapsed && <span>Collapse</span>}
          </button>
        </div>
      </aside>

      {/* ── Main Content ── */}
      <main className="flex-1 min-w-0 overflow-y-auto">
        <div className="h-full">
          {/* Top Bar with Breadcrumbs */}
          <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-border bg-background/80 backdrop-blur-md px-6">
            <Breadcrumbs navGroups={filteredGroups} pathname={location.pathname} />
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="icon"
                onClick={toggleCopilot}
                className={cn(copilotOpen && "bg-primary/10 text-primary")}
              >
                {copilotOpen ? (
                  <PanelRightClose className="h-4 w-4" />
                ) : (
                  <PanelRightOpen className="h-4 w-4" />
                )}
              </Button>
              <Button variant="ghost" size="icon" onClick={toggleCopilot}>
                <Bot className="h-4 w-4" />
              </Button>
            </div>
          </header>

          {/* Page Content */}
          <div className="p-6 max-w-[1600px] mx-auto w-full">
            <RouteErrorBoundary locationKey={location.pathname}>
              <Outlet />
            </RouteErrorBoundary>
          </div>
        </div>
      </main>

      {/* ── AI Copilot Sidebar ── */}
      <AnimatePresence>
        {copilotOpen && (
          <motion.div
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 380, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
            className="border-l border-border bg-card overflow-hidden"
          >
            <CopilotSidebar onClose={toggleCopilot} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
