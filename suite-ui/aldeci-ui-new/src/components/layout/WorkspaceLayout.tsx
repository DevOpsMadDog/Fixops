import React, { useState, useMemo, useEffect } from "react";
import { NavLink, Link, Outlet, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { billingApi, type BillingTier } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { UpgradeDialog } from "@/components/billing/UpgradeDialog";
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
import * as Tooltip from "@radix-ui/react-tooltip";
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
  ChevronDown,
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
  Flag,
  Trophy,
  CalendarClock,
  FileBarChart,
  Gauge,
  Scan,
  LogOut,
  UserCircle,
  Bell,
  Command,
  Upload,
  Rocket,
  Webhook,
  type LucideIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { CopilotSidebar } from "./CopilotSidebar";
import { NotificationBell } from "./NotificationBell";
import { GlobalSearch } from "./GlobalSearch";
import { OrgSwitcher } from "./OrgSwitcher";
import { useAuth, isDevBypassActive } from "@/lib/auth";

// ── Types ──────────────────────────────────────────────────────────────────

interface NavItem {
  label: string;
  to: string;
  icon: LucideIcon;
  badge?: string;
  roles?: string[];
}

interface NavGroup {
  label: string;
  icon: LucideIcon;
  items: NavItem[];
}

interface NavSection {
  /** Section heading shown in expanded sidebar */
  section: string;
  /** Icon shown for the section in collapsed mode — represents the whole section */
  icon: LucideIcon;
  groups: NavGroup[];
}

// ── Navigation data ────────────────────────────────────────────────────────
// TRIMMED 2026-05-05: 38 leaf links → 21 daily-use + 10 RARE in collapsed Admin group
// (Multica #4088 — sidebar prune to <25 visible top-level entries)
//
// RARE items (moved to adminItems below, hidden behind collapsible Admin group):
//   BRS Executive, Developer Security Hub, Architect View,
//   Identity Governance, Privileged Access (PAM),
//   DPO Privacy Center, SBOM & Provenance, Auditor View,
//   Integration Targets, Webhook Ingestion, Air-Gap Mode, Training & Culture
//
// All routes remain mounted in App.tsx and reachable via direct URL.

const navSections: NavSection[] = [
  // ── 0. EXECUTIVE ─────────────────────────────────────────────────────────
  {
    section: "Executive",
    icon: Crown,
    groups: [
      {
        label: "CISO View",
        icon: Crown,
        items: [
          { label: "CISO Dashboard", to: "/executive", icon: Crown, badge: "P01" },
          { label: "Board Overview", to: "/board", icon: BarChart3, badge: "P24" },
          { label: "Risk Overview", to: "/mission-control/risk", icon: Target },
        ],
      },
    ],
  },

  // ── 1. DISCOVER ───────────────────────────────────────────────────────────
  {
    section: "Discover",
    icon: Search,
    groups: [
      {
        label: "Assets & Network",
        icon: HardDrive,
        items: [
          { label: "Asset Inventory", to: "/discover/assets/inventory", icon: HardDrive },
          { label: "Network Monitoring", to: "/discover/network", icon: Network },
        ],
      },
      {
        label: "Code & Secrets",
        icon: Code,
        items: [
          { label: "Import Repo / Zip", to: "/import", icon: Upload },
          { label: "Secrets Scanner", to: "/discover/secrets-hub", icon: KeyRound },
          { label: "Supply Chain", to: "/discover/supply-chain", icon: Package },
        ],
      },
      {
        label: "Cloud & Containers",
        icon: Cloud,
        items: [
          { label: "Cloud Posture", to: "/discover/cloud-posture", icon: Cloud },
          { label: "Container Security", to: "/discover/container-security", icon: Container },
        ],
      },
      {
        label: "Application & API",
        icon: Code2,
        items: [
          { label: "App Layer Security", to: "/discover/app-security", icon: Code2 },
          { label: "API Security", to: "/discover/api-security", icon: Wifi },
          { label: "Detect & Respond", to: "/discover/detect-respond", icon: Radar },
        ],
      },
    ],
  },

  // ── 2. PROTECT ────────────────────────────────────────────────────────────
  {
    section: "Protect",
    icon: Shield,
    groups: [
      {
        label: "Vulnerability",
        icon: Bug,
        items: [
          { label: "Vuln Lifecycle Pipeline", to: "/discover/vuln-pipeline", icon: Bug },
          { label: "Vuln Intelligence", to: "/discover/vuln-intel", icon: Radar },
        ],
      },
      {
        label: "Validate",
        icon: ShieldCheck,
        items: [
          { label: "Offensive Validation", to: "/validate/offensive", icon: Crosshair, badge: "MPTE" },
          { label: "Threat Modeling", to: "/attack/threat-modeling", icon: Layers },
        ],
      },
    ],
  },

  // ── 3. RESPOND ────────────────────────────────────────────────────────────
  {
    section: "Respond",
    icon: Siren,
    groups: [
      {
        label: "Incidents",
        icon: Siren,
        items: [
          { label: "Incident Knowledge", to: "/remediate/incidents/knowledge", icon: Siren, badge: "IR" },
          { label: "Exceptions", to: "/remediate/exceptions", icon: ShieldAlert },
        ],
      },
      {
        label: "Remediation",
        icon: Wrench,
        items: [
          { label: "Automation & Orchestration", to: "/remediate/automation", icon: Zap },
          { label: "Forensics", to: "/remediate/forensics", icon: ScanSearch },
        ],
      },
      {
        label: "Hunting & Intel",
        icon: Crosshair,
        items: [
          { label: "Threat Hunting", to: "/mission-control/hunt", icon: Crosshair },
          { label: "Behavior Analytics", to: "/mission-control/behavior", icon: Activity },
          { label: "Threat Intel Ops", to: "/attack/intel/ops", icon: Radar },
          { label: "Threat Actors", to: "/attack/intel/actors", icon: Flag },
        ],
      },
      {
        label: "AI & Agents",
        icon: Brain,
        items: [
          { label: "AI Copilot Agents", to: "/ai/agents", icon: Bot, badge: "AI" },
        ],
      },
    ],
  },

  // ── 4. COMPLY ─────────────────────────────────────────────────────────────
  {
    section: "Comply",
    icon: ClipboardCheck,
    groups: [
      {
        label: "Frameworks & Coverage",
        icon: ClipboardCheck,
        items: [
          { label: "Compliance Coverage", to: "/comply/coverage", icon: ClipboardCheck },
          { label: "Policy Management", to: "/comply/policies/authoring", icon: FileSignature },
        ],
      },
      {
        label: "Posture & Risk",
        icon: BarChart3,
        items: [
          { label: "Strategic Posture", to: "/comply/strategic-posture", icon: Target },
          { label: "Risk Quantification", to: "/comply/risk-quant", icon: Scale },
        ],
      },
    ],
  },
];

// ── RARE / Admin items — hidden behind collapsed "Admin & Integrations" row ──
// Routes still mounted in App.tsx and reachable via direct URL.
interface AdminNavItem {
  label: string;
  to: string;
  icon: LucideIcon;
  badge?: string;
}

const adminItems: AdminNavItem[] = [
  { label: "BRS Executive",           to: "/brs-executive",                  icon: Building2 },
  { label: "Developer Security",      to: "/developer",                      icon: GitBranch },
  { label: "Architect View",          to: "/discover/architect",             icon: Network   },
  { label: "Identity Governance",     to: "/discover/identity-governance",   icon: UserCheck },
  { label: "Privileged Access (PAM)", to: "/discover/privileged-access",     icon: Key       },
  { label: "DPO Privacy Center",      to: "/comply/dpo",                     icon: ShieldAlert },
  { label: "SBOM & Provenance",       to: "/comply/provenance",              icon: Package   },
  { label: "Auditor View",            to: "/comply/auditor",                 icon: ScrollText },
  { label: "Integration Targets",     to: "/connect/targets",                icon: Wifi      },
  { label: "Webhook Ingestion",       to: "/connect/webhook-ingestion",      icon: Rss       },
  { label: "Outbound Webhooks",       to: "/admin/webhooks-out",             icon: Webhook   },
  { label: "Air-Gap Mode",            to: "/connect/mcp/air-gap",            icon: ShieldOff, badge: "AIRGAP" },
  { label: "Training & Culture",      to: "/admin/training-culture",         icon: GraduationCap },
  { label: "Admin Audit Log",         to: "/admin/audit-log",                icon: ScrollText },
];

// Flat navGroups derived from sections — used for breadcrumbs
const navGroups: NavGroup[] = navSections.flatMap((s) => s.groups);

// ── Tooltip wrapper ────────────────────────────────────────────────────────

function NavTooltip({ label, children, disabled }: { label: string; children: React.ReactNode; disabled?: boolean }) {
  if (disabled) return <>{children}</>;
  return (
    <Tooltip.Root delayDuration={300}>
      <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content
          side="right"
          sideOffset={8}
          className="z-[100] rounded-md bg-zinc-800 px-2.5 py-1.5 text-xs font-medium text-zinc-100 shadow-lg border border-zinc-700/60 select-none"
        >
          {label}
          <Tooltip.Arrow className="fill-zinc-800" />
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

// ── Tier badge + upgrade button ────────────────────────────────────────────

function TierBadgeButton() {
  const [upgradeOpen, setUpgradeOpen] = useState(false);

  const { data } = useQuery({
    queryKey: ["billing-tier"],
    queryFn: () => billingApi.tier(),
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });

  const tier = (data?.data?.tier ?? "starter") as BillingTier;

  const badgeConfig: Record<BillingTier, { label: string; className: string }> = {
    starter: {
      label: "Starter",
      className: "border-zinc-600/40 bg-zinc-700/40 text-zinc-300",
    },
    pro: {
      label: "Pro",
      className: "border-blue-500/30 bg-blue-500/15 text-blue-400",
    },
    enterprise: {
      label: "Enterprise",
      className: "border-amber-500/30 bg-amber-500/15 text-amber-400",
    },
  };

  const config = badgeConfig[tier];

  return (
    <>
      <div className="flex items-center gap-1.5">
        <Badge className={`text-[10px] font-semibold uppercase tracking-wider border ${config.className}`}>
          {config.label}
        </Badge>
        {tier !== "enterprise" && (
          <button
            onClick={() => setUpgradeOpen(true)}
            className="rounded-md border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-cyan-400 hover:bg-cyan-500/20 transition-colors"
          >
            Upgrade
          </button>
        )}
      </div>
      <UpgradeDialog open={upgradeOpen} onOpenChange={setUpgradeOpen} currentTier={tier} />
    </>
  );
}

// ── User badge ─────────────────────────────────────────────────────────────

function UserBadge({ collapsed }: { collapsed: boolean }) {
  const { user, isAuthenticated, logout } = useAuth();
  if (!isAuthenticated || !user) return null;

  const initials =
    `${(user.first_name?.[0] ?? "").toUpperCase()}${(user.last_name?.[0] ?? "").toUpperCase()}` || "U";
  const fullName = [user.first_name, user.last_name].filter(Boolean).join(" ") || "User";

  if (collapsed) {
    return (
      <NavTooltip label={`${fullName} · ${user.role ?? "viewer"}`}>
        <button
          onClick={logout}
          className="flex w-full items-center justify-center rounded-lg p-2 text-sm text-sidebar-foreground hover:bg-sidebar-accent/60 transition-colors"
          title={`${user.email} — Sign out`}
        >
          <div className="h-7 w-7 rounded-full bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center text-[11px] font-bold text-cyan-400">
            {initials}
          </div>
        </button>
      </NavTooltip>
    );
  }

  return (
    <div className="flex items-center gap-2.5 rounded-lg px-3 py-2.5 hover:bg-sidebar-accent/40 transition-colors group">
      <div className="h-8 w-8 rounded-full bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center text-[11px] font-bold text-cyan-400 shrink-0">
        {initials}
      </div>
      <div className="flex-1 min-w-0">
        <div className="truncate text-xs font-semibold text-foreground">{fullName}</div>
        <div className="flex items-center gap-1.5 mt-0.5">
          <span className="truncate text-[10px] text-muted-foreground leading-none">
            ALDECI
          </span>
          {user.role && (
            <span className="rounded-sm bg-cyan-500/15 px-1 py-px text-[9px] font-semibold uppercase tracking-wider text-cyan-400 leading-none">
              {user.role}
            </span>
          )}
        </div>
      </div>
      <button
        onClick={logout}
        className="text-muted-foreground hover:text-foreground transition-colors opacity-0 group-hover:opacity-100 shrink-0"
        title="Sign out"
      >
        <LogOut className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

// ── Section tab (top of sidebar) ───────────────────────────────────────────

function SectionTabs({
  sections,
  activeSection,
  collapsed,
  onSelect,
}: {
  sections: NavSection[];
  activeSection: string;
  collapsed: boolean;
  onSelect: (s: string) => void;
}) {
  if (collapsed) {
    return (
      <div className="flex flex-col gap-0.5 px-2 py-2 border-b border-sidebar-border">
        {sections.map((s) => {
          const isActive = s.section === activeSection;
          return (
            <NavTooltip key={s.section} label={s.section}>
              <button
                onClick={() => onSelect(s.section)}
                className={cn(
                  "flex h-8 w-full items-center justify-center rounded-md transition-colors",
                  isActive
                    ? "bg-cyan-500/15 text-cyan-400"
                    : "text-muted-foreground hover:bg-sidebar-accent/50 hover:text-foreground"
                )}
              >
                <s.icon className="h-4 w-4 shrink-0" />
              </button>
            </NavTooltip>
          );
        })}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-3 gap-1 px-3 py-2.5 border-b border-sidebar-border">
      {sections.map((s) => {
        const isActive = s.section === activeSection;
        return (
          <button
            key={s.section}
            onClick={() => onSelect(s.section)}
            className={cn(
              "flex flex-col items-center gap-1 rounded-lg px-1 py-2 text-[10px] font-medium transition-all",
              isActive
                ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/25"
                : "text-muted-foreground hover:bg-sidebar-accent/50 hover:text-foreground border border-transparent"
            )}
          >
            <s.icon className="h-3.5 w-3.5 shrink-0" />
            <span className="leading-none tracking-wide">{s.section}</span>
          </button>
        );
      })}
    </div>
  );
}

// ── Cmd+K search hint ─────────────────────────────────────────────────────

function SidebarSearchHint({ collapsed, onClick }: { collapsed: boolean; onClick: () => void }) {
  if (collapsed) {
    return (
      <NavTooltip label="Search (⌘K)">
        <button
          onClick={onClick}
          className="flex w-full items-center justify-center rounded-lg p-2 text-muted-foreground hover:bg-sidebar-accent/50 hover:text-foreground transition-colors"
        >
          <Search className="h-4 w-4 shrink-0" />
        </button>
      </NavTooltip>
    );
  }

  return (
    <button
      onClick={onClick}
      className="flex w-full items-center gap-2 rounded-lg border border-sidebar-border bg-sidebar-accent/30 px-3 py-2 text-xs text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground transition-colors group"
    >
      <Search className="h-3.5 w-3.5 shrink-0 group-hover:text-cyan-400 transition-colors" />
      <span className="flex-1 text-left">Search...</span>
      <kbd className="flex items-center gap-0.5 rounded bg-background/60 px-1.5 py-0.5 text-[9px] font-mono border border-sidebar-border text-muted-foreground leading-none">
        <Command className="h-2.5 w-2.5" />K
      </kbd>
    </button>
  );
}

// ── Nav group with collapsible items ──────────────────────────────────────

function NavGroupItem({
  group,
  collapsed,
  expandedGroup,
  onToggle,
  pathname,
}: {
  group: NavGroup;
  collapsed: boolean;
  expandedGroup: string | null;
  onToggle: (label: string) => void;
  pathname: string;
}) {
  const isGroupExpanded = expandedGroup === group.label;
  const isGroupActive = group.items.some(
    (item) => pathname === item.to || pathname.startsWith(item.to + "/")
  );

  if (collapsed) {
    // In collapsed mode show group icon with tooltip linking to first item
    return (
      <NavTooltip label={group.label}>
        <NavLink
          to={group.items[0]?.to ?? "/"}
          className={({ isActive: active }) =>
            cn(
              "flex h-9 w-full items-center justify-center rounded-lg transition-all relative",
              (active || isGroupActive)
                ? "bg-cyan-500/15 text-cyan-400"
                : "text-muted-foreground hover:bg-sidebar-accent/50 hover:text-foreground"
            )
          }
        >
          {({ isActive: active }) => (
            <>
              {(active || isGroupActive) && (
                <span className="absolute left-0 top-1/2 -translate-y-1/2 h-4 w-0.5 rounded-r-full bg-cyan-400" />
              )}
              <group.icon className="h-4 w-4 shrink-0" />
            </>
          )}
        </NavLink>
      </NavTooltip>
    );
  }

  return (
    <div className="mb-0.5">
      <button
        onClick={() => onToggle(group.label)}
        className={cn(
          "group flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-xs font-medium transition-all relative",
          isGroupActive
            ? "text-foreground"
            : "text-sidebar-foreground hover:text-foreground hover:bg-sidebar-accent/40"
        )}
      >
        {isGroupActive && (
          <span className="absolute left-0 top-1/2 -translate-y-1/2 h-4 w-0.5 rounded-r-full bg-cyan-400" />
        )}
        <group.icon className={cn("h-3.5 w-3.5 shrink-0 transition-colors", isGroupActive ? "text-cyan-400" : "text-muted-foreground group-hover:text-foreground")} />
        <span className="flex-1 text-left">{group.label}</span>
        <ChevronDown
          className={cn(
            "h-3 w-3 shrink-0 text-muted-foreground/60 transition-transform duration-200",
            isGroupExpanded && "rotate-180"
          )}
        />
      </button>

      <AnimatePresence initial={false}>
        {isGroupExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden"
          >
            <div className="ml-4 border-l border-sidebar-border/60 pl-2.5 py-0.5 space-y-px">
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={
                    item.to === "/mission-control" ||
                    item.to === "/discover" ||
                    item.to === "/remediate" ||
                    item.to === "/comply"
                  }
                  className={({ isActive: active }) =>
                    cn(
                      "flex items-center gap-2 rounded-md px-2 py-1.5 text-[11px] transition-all relative",
                      active
                        ? "bg-cyan-500/12 text-cyan-300 font-medium"
                        : "text-sidebar-foreground/80 hover:bg-sidebar-accent/40 hover:text-foreground"
                    )
                  }
                >
                  {({ isActive: active }) => (
                    <>
                      {active && (
                        <span className="absolute left-0 top-1/2 -translate-y-1/2 h-3 w-0.5 rounded-r-full bg-cyan-400" />
                      )}
                      <item.icon className={cn("h-3 w-3 shrink-0", active ? "text-cyan-400" : "text-muted-foreground/60")} />
                      <span className="flex-1 truncate">{item.label}</span>
                      {item.badge && (
                        <span className={cn(
                          "ml-auto rounded px-1.5 py-px text-[9px] font-semibold uppercase tracking-wider leading-none",
                          item.badge === "LIVE" || item.badge === "IR"
                            ? "bg-red-500/15 text-red-400 border border-red-500/20"
                            : item.badge === "AI"
                            ? "bg-violet-500/15 text-violet-400 border border-violet-500/20"
                            : item.badge === "GRC" || item.badge === "CTEM"
                            ? "bg-amber-500/15 text-amber-400 border border-amber-500/20"
                            : "bg-cyan-500/15 text-cyan-400 border border-cyan-500/20"
                        )}>
                          {item.badge}
                        </span>
                      )}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ── Admin & Integrations collapsible (RARE items) ─────────────────────────

function AdminGroup({ collapsed, pathname }: { collapsed: boolean; pathname: string }) {
  const [open, setOpen] = useState(false);
  const isAnyActive = adminItems.some(
    (item) => pathname === item.to || pathname.startsWith(item.to + "/")
  );

  // Auto-open if current route is inside admin items
  useEffect(() => {
    if (isAnyActive) setOpen(true);
  }, [isAnyActive]);

  if (collapsed) {
    return (
      <NavTooltip label="Admin & Integrations">
        <NavLink
          to={adminItems[0]?.to ?? "/"}
          className={({ isActive: active }) =>
            cn(
              "flex h-9 w-full items-center justify-center rounded-lg transition-all relative",
              (active || isAnyActive)
                ? "bg-cyan-500/15 text-cyan-400"
                : "text-muted-foreground hover:bg-sidebar-accent/50 hover:text-foreground"
            )
          }
        >
          {({ isActive: active }) => (
            <>
              {(active || isAnyActive) && (
                <span className="absolute left-0 top-1/2 -translate-y-1/2 h-4 w-0.5 rounded-r-full bg-cyan-400" />
              )}
              <Settings className="h-4 w-4 shrink-0" />
            </>
          )}
        </NavLink>
      </NavTooltip>
    );
  }

  return (
    <div className="mb-0.5">
      <button
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "group flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-xs font-medium transition-all relative",
          isAnyActive
            ? "text-foreground"
            : "text-sidebar-foreground hover:text-foreground hover:bg-sidebar-accent/40"
        )}
      >
        {isAnyActive && (
          <span className="absolute left-0 top-1/2 -translate-y-1/2 h-4 w-0.5 rounded-r-full bg-cyan-400" />
        )}
        <Settings className={cn("h-3.5 w-3.5 shrink-0 transition-colors", isAnyActive ? "text-cyan-400" : "text-muted-foreground group-hover:text-foreground")} />
        <span className="flex-1 text-left">Admin & Integrations</span>
        <ChevronDown
          className={cn(
            "h-3 w-3 shrink-0 text-muted-foreground/60 transition-transform duration-200",
            open && "rotate-180"
          )}
        />
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden"
          >
            <div className="ml-4 border-l border-sidebar-border/60 pl-2.5 py-0.5 space-y-px">
              {adminItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive: active }) =>
                    cn(
                      "flex items-center gap-2 rounded-md px-2 py-1.5 text-[11px] transition-all relative",
                      active
                        ? "bg-cyan-500/12 text-cyan-300 font-medium"
                        : "text-sidebar-foreground/80 hover:bg-sidebar-accent/40 hover:text-foreground"
                    )
                  }
                >
                  {({ isActive: active }) => (
                    <>
                      {active && (
                        <span className="absolute left-0 top-1/2 -translate-y-1/2 h-3 w-0.5 rounded-r-full bg-cyan-400" />
                      )}
                      <item.icon className={cn("h-3 w-3 shrink-0", active ? "text-cyan-400" : "text-muted-foreground/60")} />
                      <span className="flex-1 truncate">{item.label}</span>
                      {item.badge && (
                        <span className={cn(
                          "ml-auto rounded px-1.5 py-px text-[9px] font-semibold uppercase tracking-wider leading-none",
                          item.badge === "AIRGAP"
                            ? "bg-amber-500/15 text-amber-400 border border-amber-500/20"
                            : "bg-cyan-500/15 text-cyan-400 border border-cyan-500/20"
                        )}>
                          {item.badge}
                        </span>
                      )}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ── Breadcrumbs ────────────────────────────────────────────────────────────

function Breadcrumbs({ navGroups: groups, pathname }: { navGroups: NavGroup[]; pathname: string }) {
  const crumbs = useMemo(() => {
    const result: { label: string; to?: string; icon?: LucideIcon }[] = [];
    for (const group of groups) {
      const match = group.items.find(
        (item) => pathname === item.to || pathname.startsWith(item.to + "/")
      );
      if (match) {
        result.push({ label: group.label, to: group.items[0]?.to, icon: group.icon });
        if (match.to !== group.items[0]?.to || pathname !== match.to) {
          result.push({ label: match.label, to: match.to, icon: match.icon });
        }
        const rest = pathname.slice(match.to.length).replace(/^\//, "");
        if (rest) {
          const label = rest.split("/").pop()?.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()) ?? rest;
          result.push({ label });
        }
        break;
      }
    }
    if (result.length === 0 && pathname.startsWith("/settings")) {
      result.push({ label: "Settings", to: "/settings", icon: Settings });
      const sub = pathname.slice("/settings/".length).replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
      if (sub && pathname !== "/settings") result.push({ label: sub });
    }
    return result;
  }, [groups, pathname]);

  return (
    <div className="flex items-center gap-1.5 text-sm text-muted-foreground min-w-0 flex-1">
      {crumbs.map((crumb, i) => (
        <React.Fragment key={i}>
          {i > 0 && <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground/30" />}
          {crumb.to ? (
            <Link
              to={crumb.to}
              className="flex items-center gap-1.5 hover:text-foreground transition-colors truncate"
            >
              {crumb.icon && <crumb.icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground/60" />}
              <span className={i === crumbs.length - 1 ? "font-medium text-foreground" : "text-muted-foreground"}>
                {crumb.label}
              </span>
            </Link>
          ) : (
            <span className="flex items-center gap-1.5 font-medium text-foreground truncate">
              {crumb.icon && <crumb.icon className="h-3.5 w-3.5 shrink-0" />}
              {crumb.label}
            </span>
          )}
        </React.Fragment>
      ))}
    </div>
  );
}

// ── Main layout ────────────────────────────────────────────────────────────

export function WorkspaceLayout() {
  const { preferences, toggleSidebar, toggleCopilot, toggleTheme } = useAppStore();
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<string>("Discover");
  const [searchOpen, setSearchOpen] = useState(false);
  const location = useLocation();
  const { user } = useAuth();

  const collapsed = preferences.sidebarCollapsed;
  const copilotOpen = preferences.copilotOpen;
  const userRole = user?.role ?? "viewer";

  // Filter items by role across all sections
  const filteredSections = navSections.map((s) => ({
    ...s,
    groups: s.groups
      .map((g) => ({
        ...g,
        items: g.items.filter((item) => !item.roles || item.roles.includes(userRole)),
      }))
      .filter((g) => g.items.length > 0),
  }));

  const filteredNavGroups = filteredSections.flatMap((s) => s.groups);

  // Auto-select section based on current route
  useEffect(() => {
    for (const section of filteredSections) {
      const found = section.groups.some((g) =>
        g.items.some((item) => location.pathname === item.to || location.pathname.startsWith(item.to + "/"))
      );
      if (found) {
        setActiveSection(section.section);
        break;
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);

  // Auto-expand active group within current section
  const currentSectionData = filteredSections.find((s) => s.section === activeSection);

  useEffect(() => {
    if (!currentSectionData) return;
    const active = currentSectionData.groups.find((g) =>
      g.items.some((item) => location.pathname === item.to || location.pathname.startsWith(item.to + "/"))
    );
    if (active) setExpandedGroup(active.label);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSection, location.pathname]);

  // Open global search via Cmd+K
  useEffect(() => {
    function handler(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen(true);
      }
    }
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  const handleGroupToggle = (label: string) => {
    setExpandedGroup((prev) => (prev === label ? null : label));
  };

  return (
    <Tooltip.Provider>
      <div className="flex h-screen overflow-hidden bg-background">
        {/* ── Left Sidebar ── */}
        <aside
          className={cn(
            "flex flex-col border-r border-sidebar-border bg-sidebar transition-[width] duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]",
            collapsed ? "w-[52px]" : "w-[220px]",
            "max-md:w-[52px]"
          )}
        >
          {/* ── Logo / Brand ── */}
          <div className={cn(
            "flex h-14 items-center gap-3 border-b border-sidebar-border",
            collapsed ? "px-2 justify-center" : "px-4"
          )}>
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-cyan-600 shadow-[0_0_12px_oklch(0.65_0.15_195/0.3)]">
              <span className="text-[11px] font-black text-white tracking-tight">AL</span>
            </div>
            {!collapsed && (
              <div className="min-w-0 flex-1">
                <span className="block text-[13px] font-bold tracking-tight text-foreground">ALDECI</span>
                <span className="block text-[9px] font-medium uppercase tracking-[0.12em] text-muted-foreground/70 leading-none mt-px">
                  Security Platform
                </span>
              </div>
            )}
            {!collapsed && (
              <NavTooltip label="Get Started — onboarding wizard" disabled={false}>
                <NavLink
                  to="/onboard"
                  className={({ isActive }) =>
                    cn(
                      "shrink-0 flex h-6 w-6 items-center justify-center rounded-md transition-colors",
                      isActive
                        ? "bg-cyan-500/20 text-cyan-400"
                        : "text-muted-foreground/60 hover:text-cyan-400 hover:bg-cyan-500/10"
                    )
                  }
                  title="Get Started"
                >
                  <Rocket className="h-3.5 w-3.5" />
                </NavLink>
              </NavTooltip>
            )}
          </div>

          {/* ── Section tabs ── */}
          <SectionTabs
            sections={filteredSections}
            activeSection={activeSection}
            collapsed={collapsed}
            onSelect={(s) => {
              setActiveSection(s);
              setExpandedGroup(null);
            }}
          />

          {/* ── Search hint ── */}
          <div className={cn("px-2 pt-2", collapsed ? "pb-1" : "pb-2")}>
            <SidebarSearchHint
              collapsed={collapsed}
              onClick={() => setSearchOpen(true)}
            />
          </div>

          {/* ── Nav groups for active section ── */}
          <nav className="flex-1 overflow-y-auto px-2 py-1 space-y-px scrollbar-thin scrollbar-thumb-sidebar-border scrollbar-track-transparent">
            {!collapsed && currentSectionData && (
              <div className="mb-2 px-2 pt-1">
                <span className="text-[9px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/50">
                  {currentSectionData.section}
                </span>
              </div>
            )}
            {(currentSectionData?.groups ?? []).map((group) => (
              <NavGroupItem
                key={group.label}
                group={group}
                collapsed={collapsed}
                expandedGroup={expandedGroup}
                onToggle={handleGroupToggle}
                pathname={location.pathname}
              />
            ))}

            {/* ── Admin & Integrations (RARE — collapsed by default) ── */}
            <div className={cn("mt-2 pt-2 border-t border-sidebar-border/40")}>
              {!collapsed && (
                <div className="mb-1 px-2">
                  <span className="text-[9px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/30">
                    Admin
                  </span>
                </div>
              )}
              <AdminGroup collapsed={collapsed} pathname={location.pathname} />
            </div>
          </nav>

          {/* ── Bottom: User + actions ── */}
          <div className="border-t border-sidebar-border pb-1">
            <div className="px-2 pt-2 pb-1">
              <UserBadge collapsed={collapsed} />
            </div>

            <div className={cn("flex px-2 gap-1", collapsed ? "flex-col" : "flex-row items-center")}>
              <NavTooltip label={`${preferences.theme === "dark" ? "Light" : "Dark"} mode`} disabled={!collapsed}>
                <button
                  onClick={toggleTheme}
                  className="flex h-8 w-full items-center justify-center gap-2.5 rounded-lg px-2 text-xs text-muted-foreground hover:bg-sidebar-accent/50 hover:text-foreground transition-colors"
                >
                  {preferences.theme === "dark" ? (
                    <Sun className="h-3.5 w-3.5 shrink-0" />
                  ) : (
                    <Moon className="h-3.5 w-3.5 shrink-0" />
                  )}
                  {!collapsed && <span className="flex-1 text-left text-[11px]">{preferences.theme === "dark" ? "Light mode" : "Dark mode"}</span>}
                </button>
              </NavTooltip>

              <NavTooltip label="Settings" disabled={!collapsed}>
                <NavLink
                  to="/settings"
                  className={({ isActive }) =>
                    cn(
                      "flex h-8 w-full items-center justify-center gap-2.5 rounded-lg px-2 text-xs transition-colors",
                      isActive
                        ? "bg-sidebar-accent text-foreground"
                        : "text-muted-foreground hover:bg-sidebar-accent/50 hover:text-foreground"
                    )
                  }
                >
                  <Settings className="h-3.5 w-3.5 shrink-0" />
                  {!collapsed && <span className="flex-1 text-left text-[11px]">Settings</span>}
                </NavLink>
              </NavTooltip>

              <NavTooltip label={collapsed ? "Expand sidebar" : "Collapse sidebar"} disabled={false}>
                <button
                  onClick={toggleSidebar}
                  className="flex h-8 w-full items-center justify-center gap-2.5 rounded-lg px-2 text-xs text-muted-foreground hover:bg-sidebar-accent/50 hover:text-foreground transition-colors"
                >
                  {collapsed ? (
                    <ChevronRight className="h-3.5 w-3.5 shrink-0" />
                  ) : (
                    <ChevronLeft className="h-3.5 w-3.5 shrink-0" />
                  )}
                  {!collapsed && <span className="flex-1 text-left text-[11px]">Collapse</span>}
                </button>
              </NavTooltip>
            </div>
          </div>
        </aside>

        {/* ── Main Content ── */}
        <main className="flex-1 min-w-0 overflow-y-auto">
          <div className="h-full">
            {/* Top Bar */}
            <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-border bg-background/80 backdrop-blur-md px-6 gap-4">
              <Breadcrumbs navGroups={filteredNavGroups} pathname={location.pathname} />

              <div className="flex items-center gap-1.5 shrink-0">
                {/* Dev-bypass badge — visible only when auth has been bypassed */}
                {isDevBypassActive() && (
                  <span
                    data-testid="dev-bypass-badge"
                    title="Auth bypass active — Vite dev mode or FIXOPS_VISUAL_VERIFY=1"
                    className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-amber-400"
                  >
                    DEV MODE
                  </span>
                )}
                {/* Org switcher */}
                <OrgSwitcher />
                {/* Tier badge + upgrade button */}
                <TierBadgeButton />
                {/* Global search — also triggered by Cmd+K  */}
                {searchOpen && (
                  <div className="contents">
                    {/* Render GlobalSearch in open state by triggering its internal state */}
                  </div>
                )}
                <GlobalSearch />

                <NotificationBell />

                <Button
                  variant="ghost"
                  size="icon"
                  onClick={toggleCopilot}
                  className={cn("h-8 w-8", copilotOpen && "bg-primary/10 text-primary")}
                  title="AI Copilot"
                >
                  {copilotOpen ? (
                    <PanelRightClose className="h-4 w-4" />
                  ) : (
                    <Bot className="h-4 w-4" />
                  )}
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
    </Tooltip.Provider>
  );
}
