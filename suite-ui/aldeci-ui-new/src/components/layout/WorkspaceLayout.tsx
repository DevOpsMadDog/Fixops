import React, { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
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
      { label: "Executive View", to: "/mission-control/executive", icon: Crown },
      { label: "SLA Dashboard", to: "/mission-control/sla", icon: Clock },
      { label: "Live Feed", to: "/mission-control/live-feed", icon: Activity },
      { label: "Risk Overview", to: "/mission-control/risk", icon: AlertTriangle },
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
      { label: "Cloud Posture", to: "/discover/cloud", icon: Cloud },
      { label: "Containers", to: "/discover/containers", icon: Container },
      { label: "SBOM & Inventory", to: "/discover/sbom", icon: Package },
      { label: "Knowledge Graph", to: "/discover/graph", icon: Share2 },
      { label: "Attack Paths", to: "/discover/attack-paths", icon: Route },
      { label: "Threat Feeds", to: "/discover/threats", icon: Rss },
      { label: "Correlation Engine", to: "/discover/correlation", icon: GitMerge },
      { label: "Data Fabric", to: "/discover/data-fabric", icon: Database },
    ],
  },
  {
    label: "Validate",
    icon: ShieldCheck,
    items: [
      { label: "MPTE Console", to: "/validate/mpte", icon: Crosshair },
      { label: "Attack Simulation", to: "/validate/simulation", icon: Swords },
      { label: "FAIL Engine", to: "/validate/fail", icon: Flame, badge: "NEW" },
      { label: "Playbooks", to: "/validate/playbooks", icon: BookOpen },
      { label: "Reachability", to: "/validate/reachability", icon: Network },
    ],
  },
  {
    label: "Remediate",
    icon: Wrench,
    items: [
      { label: "Remediation Center", to: "/remediate", icon: CheckCircle },
      { label: "AutoFix", to: "/remediate/autofix", icon: Wand2 },
      { label: "Bulk Operations", to: "/remediate/bulk", icon: Layers },
      { label: "Collaboration", to: "/remediate/collaborate", icon: Users },
      { label: "Workflows", to: "/remediate/workflows", icon: Workflow },
      { label: "Exposure Cases", to: "/remediate/cases", icon: AlertTriangle },
      { label: "Ticket Integration", to: "/remediate/tickets", icon: Ticket },
    ],
  },
  {
    label: "Comply",
    icon: Shield,
    items: [
      { label: "Compliance Dashboard", to: "/comply", icon: ClipboardCheck },
      { label: "Evidence Vault", to: "/comply/evidence", icon: Lock },
      { label: "Evidence Export", to: "/comply/export", icon: Download },
      { label: "SOC2 Evidence", to: "/comply/soc2", icon: FileCheck },
      { label: "SLSA Provenance", to: "/comply/slsa", icon: FileSignature },
      { label: "Audit Trail", to: "/comply/audit", icon: ScrollText },
      { label: "Reports", to: "/comply/reports", icon: FileText },
      { label: "Analytics", to: "/comply/analytics", icon: BarChart3 },
    ],
  },
  {
    label: "AI Engine",
    icon: Brain,
    items: [
      { label: "Copilot", to: "/ai", icon: Bot },
      { label: "Brain Pipeline", to: "/ai/brain", icon: Workflow },
      { label: "Multi-LLM Consensus", to: "/ai/consensus", icon: Scale },
      { label: "Algorithmic Lab", to: "/ai/algorithms", icon: FlaskConical },
      { label: "ML Dashboard", to: "/ai/ml", icon: Cpu },
      { label: "Predictions", to: "/ai/predictions", icon: TrendingUp },
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

export function WorkspaceLayout() {
  const { preferences, toggleSidebar, toggleCopilot, toggleTheme } = useAppStore();
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null);
  const location = useLocation();

  const collapsed = preferences.sidebarCollapsed;
  const copilotOpen = preferences.copilotOpen;

  // Auto-expand active group
  const activeGroup = navGroups.find((g) =>
    g.items.some((item) => location.pathname === item.to || location.pathname.startsWith(item.to + "/"))
  );

  const currentExpanded = expandedGroup ?? activeGroup?.label ?? null;

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* ── Left Sidebar ── */}
      <aside
        className={cn(
          "flex flex-col border-r border-sidebar-border bg-sidebar transition-all duration-300",
          collapsed ? "w-16" : "w-60"
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
          {navGroups.map((group) => {
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
      <main className="flex-1 overflow-y-auto">
        <div className="h-full">
          {/* Top Bar */}
          <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-border bg-background/80 backdrop-blur-md px-6">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              {activeGroup && (
                <>
                  <activeGroup.icon className="h-4 w-4" />
                  <span className="font-medium text-foreground">{activeGroup.label}</span>
                </>
              )}
            </div>
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
          <div className="p-6">
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
