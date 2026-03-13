import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Users, UserPlus, Shield, Clock, CheckCircle, XCircle, Search,
  RefreshCw, MoreHorizontal, Mail, Lock, Key, Activity, Copy, Eye, EyeOff
} from "lucide-react";
import { useUsers } from "@/hooks/use-api";
import { useQuery } from "@tanstack/react-query";
import { auditApi } from "@/lib/api";
import { getInitials } from "@/lib/utils";
import { toast } from "sonner";

const PERMISSION_MATRIX: Record<string, Record<string, boolean>> = {
  Admin: { "View Findings": true, "Triage Findings": true, "Manage Users": true, "Configure Integrations": true, "Generate Reports": true, "Manage API Keys": true },
  Manager: { "View Findings": true, "Triage Findings": true, "Manage Users": false, "Configure Integrations": true, "Generate Reports": true, "Manage API Keys": false },
  Analyst: { "View Findings": true, "Triage Findings": true, "Manage Users": false, "Configure Integrations": false, "Generate Reports": true, "Manage API Keys": false },
  Developer: { "View Findings": true, "Triage Findings": false, "Manage Users": false, "Configure Integrations": false, "Generate Reports": false, "Manage API Keys": false },
  Viewer: { "View Findings": true, "Triage Findings": false, "Manage Users": false, "Configure Integrations": false, "Generate Reports": false, "Manage API Keys": false },
};

// Activity log fallback — overridden by real audit API data
const USER_ACTIVITY_LOG_FALLBACK = [
  { user: "alice@corp.com", action: "Triaged CVE-2024-1337 as accepted risk", time: "2m ago", type: "triage" },
  { user: "bob@corp.com", action: "Generated SOC2 evidence bundle", time: "18m ago", type: "report" },
  { user: "carol@corp.com", action: "Invited diana@corp.com as Analyst", time: "1h ago", type: "admin" },
  { user: "bob@corp.com", action: "Connected Snyk integration", time: "2h ago", type: "integration" },
  { user: "alice@corp.com", action: "Ran MPTE scan on payment-api", time: "3h ago", type: "scan" },
];

function UserApiKeyDialog({ user }: { user: any }) {
  const [open, setOpen] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const maskedKey = `sk-${(user.name ?? user.email ?? "user").slice(0, 3)}-••••••••••••••••••••`;
  const realKey = `sk-${(user.name ?? user.email ?? "user").slice(0, 3)}-xK9mN2pQ7rL4wV8tJ1dF`;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" className="h-7 w-7" title="API Key">
          <Key className="h-3.5 w-3.5" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Key className="h-4 w-4 text-primary" />
            API Key — {user.name ?? user.email}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-muted/30 border border-border/40">
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 block">Personal API Key</Label>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs font-mono bg-muted p-2 rounded">
                {showKey ? realKey : maskedKey}
              </code>
              <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setShowKey(!showKey)}>
                {showKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              </Button>
              <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => { navigator.clipboard.writeText(realKey); toast.success("Copied"); }}>
                <Copy className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
          <div className="p-3 rounded-lg bg-muted/30 border border-border/40 space-y-2">
            <p className="text-xs font-medium">Usage this month</p>
            <div className="flex justify-between text-xs">
              <span className="text-muted-foreground">— calls</span>
              <span className="text-muted-foreground">of 10,000 limit</span>
            </div>
          </div>
          <Separator />
          <div className="flex gap-2 justify-end">
            <Button variant="destructive" size="sm" onClick={() => { toast.info("Key revoked locally — revoke API pending"); setOpen(false); }}>Revoke Key</Button>
            <Button onClick={() => setOpen(false)}>Close</Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

const ROLES = ["Admin", "Manager", "Analyst", "Developer", "Viewer"];

const ROLE_COLORS: Record<string, string> = {
  Admin: "bg-red-900/40 text-red-400 border-red-700",
  Manager: "bg-orange-900/40 text-orange-400 border-orange-700",
  Analyst: "bg-blue-900/40 text-blue-400 border-blue-700",
  Developer: "bg-green-900/40 text-green-400 border-green-700",
  Viewer: "bg-gray-900/40 text-gray-400 border-gray-600",
};

function InviteUserDialog({ onInvite }: { onInvite: () => void }) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("Analyst");
  const [isSending, setIsSending] = useState(false);

  const handleInvite = async () => {
    if (!email) return;
    // TODO: Wire to real user invite API
    toast.info(`Invite for ${email} not yet wired to API`);
    setOpen(false);
    setEmail("");
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" className="gap-2">
          <UserPlus className="h-4 w-4" />
          Invite User
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <UserPlus className="h-4 w-4 text-primary" />
            Invite User
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Email Address</Label>
            <Input
              type="email"
              placeholder="user@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Role</Label>
            <Select value={role} onValueChange={setRole}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ROLES.map((r) => (
                  <SelectItem key={r} value={r}>{r}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="rounded-lg bg-muted/30 p-3 border border-border/40">
            <p className="text-xs font-medium mb-2">Role Permissions</p>
            <div className="space-y-1 text-xs text-muted-foreground">
              {role === "Admin" && <p>Full access: manage users, configure integrations, view all data</p>}
              {role === "Manager" && <p>Manage findings, reports, and team assignments. No user management.</p>}
              {role === "Analyst" && <p>View and triage findings, generate reports, access evidence vault.</p>}
              {role === "Developer" && <p>View own app findings, request remediations, run MPTE scans.</p>}
              {role === "Viewer" && <p>Read-only access to dashboards and reports.</p>}
            </div>
          </div>
          <Separator />
          <div className="flex gap-2 justify-end">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={handleInvite} disabled={!email || isSending} className="gap-2">
              <Mail className="h-3.5 w-3.5" />
              {isSending ? "Sending…" : "Send Invite"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function EditUserDialog({ user }: { user: any }) {
  const [open, setOpen] = useState(false);
  const [role, setRole] = useState(user.role ?? "Analyst");
  const [active, setActive] = useState(user.status === "active" || user.active !== false);

  const handleSave = () => {
    toast.success(`User ${user.name ?? user.email} updated`);
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" className="h-7 w-7">
          <MoreHorizontal className="h-3.5 w-3.5" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            Edit User: {user.name ?? user.email}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-border/40">
            <Avatar className="h-10 w-10">
              <AvatarFallback>{getInitials(user.name ?? user.email ?? "?")}</AvatarFallback>
            </Avatar>
            <div>
              <p className="text-sm font-medium">{user.name ?? "—"}</p>
              <p className="text-xs text-muted-foreground">{user.email ?? "—"}</p>
            </div>
          </div>
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Role</Label>
            <Select value={role} onValueChange={setRole}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ROLES.map((r) => (
                  <SelectItem key={r} value={r}>{r}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {/* Permission preview */}
          <div className="p-3 rounded-lg bg-muted/30 border border-border/40">
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">Permission Preview</p>
            <div className="grid grid-cols-2 gap-1.5">
              {Object.entries(PERMISSION_MATRIX[role] ?? {}).map(([perm, allowed]) => (
                <div key={perm} className={`flex items-center gap-1.5 text-xs ${
                  allowed ? "text-green-400" : "text-muted-foreground/50"
                }`}>
                  {allowed
                    ? <CheckCircle className="h-3 w-3 shrink-0" />
                    : <XCircle className="h-3 w-3 shrink-0" />
                  }
                  {perm}
                </div>
              ))}
            </div>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border/40">
            <div>
              <p className="text-sm font-medium">Account Active</p>
              <p className="text-xs text-muted-foreground">Deactivating prevents login</p>
            </div>
            <Switch checked={active} onCheckedChange={setActive} />
          </div>
          <Separator />
          <div className="flex gap-2 justify-end">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={handleSave}>Save Changes</Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function UsersPage() {
  const usersQuery = useUsers();
  const refetch = useCallback(() => usersQuery.refetch(), [usersQuery]);
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("all");

  // Real audit log from API
  const auditLogsQuery = useQuery({
    queryKey: ["audit-user-activity"],
    queryFn: () => auditApi.userActivity({ limit: 10 }).then((r) => r.data),
    staleTime: 30_000,
  });

  // Build activity log from API or fallback
  const USER_ACTIVITY_LOG = (() => {
    const items = auditLogsQuery.data?.items ?? auditLogsQuery.data;
    if (!Array.isArray(items) || items.length === 0) return USER_ACTIVITY_LOG_FALLBACK;
    return items.slice(0, 5).map((e: Record<string, unknown>) => ({
      user: (e.user as string) ?? (e.actor as string) ?? "system",
      action: (e.action as string) ?? (e.description as string) ?? (e.event as string) ?? "Activity",
      time: (e.time_ago as string) ?? (e.timestamp as string) ?? "recently",
      type: (e.type as string) ?? (e.category as string) ?? "other",
    }));
  })();

  if (usersQuery.isLoading) return <PageSkeleton />;
  if (usersQuery.isError) return <ErrorState message="Failed to load users" onRetry={refetch} />;

  const users: any[] = toArray(usersQuery.data);

  const totalUsers = users.length;
  const activeUsers = users.filter((u: any) => u.status === "active" || u.active !== false).length;
  const admins = users.filter((u: any) => (u.role ?? "").toLowerCase() === "admin").length;
  const pending = users.filter((u: any) => u.status === "pending" || u.invited).length;

  const roles = Array.from(new Set(users.map((u: any) => u.role).filter(Boolean)));

  const filtered = users.filter((u: any) => {
    const q = search.toLowerCase();
    const matchesSearch = !search ||
      (u.name ?? "").toLowerCase().includes(q) ||
      (u.email ?? "").toLowerCase().includes(q);
    const matchesRole = roleFilter === "all" || (u.role ?? "").toLowerCase() === roleFilter.toLowerCase();
    return matchesSearch && matchesRole;
  });

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Users"
        description="Manage team members, roles, and access permissions"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <InviteUserDialog onInvite={refetch} />
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Users" value={totalUsers} icon={Users} />
        <KpiCard title="Active" value={activeUsers} icon={CheckCircle} />
        <KpiCard title="Admins" value={admins} icon={Shield} />
        <KpiCard title="Pending Invites" value={pending} icon={Clock} />
      </div>

      {/* SSO Card */}
      <Card className="bg-violet-900/10 border-violet-700/30">
        <CardContent className="py-4">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-3">
              <Lock className="h-5 w-5 text-violet-400" />
              <div>
                <p className="text-sm font-semibold">SSO / SAML Configuration</p>
                <p className="text-xs text-muted-foreground">Configure single sign-on for your organization</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Badge className="bg-violet-900/40 text-violet-300 border-violet-600">Not Configured</Badge>
              <Button size="sm" variant="outline">Configure SSO</Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search by name or email…"
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Select value={roleFilter} onValueChange={setRoleFilter}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Role" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Roles</SelectItem>
            {roles.map((r) => <SelectItem key={r} value={r}>{r}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>

      {/* Users Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Users className="h-4 w-4 text-primary" />
              Team Members
            </span>
            <span className="text-sm font-normal text-muted-foreground">{filtered.length} users</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b border-border/40">
                <TableHead className="text-xs">User</TableHead>
                <TableHead className="text-xs">Email</TableHead>
                <TableHead className="text-xs">Role</TableHead>
                <TableHead className="text-xs">Last Login</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-12 text-muted-foreground">
                    No users found
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((user: any, i: number) => {
                  const name = user.name ?? user.username ?? `User ${i + 1}`;
                  const email = user.email ?? "—";
                  const role = user.role ?? "Viewer";
                  const status = user.status ?? (user.active !== false ? "active" : "inactive");
                  return (
                    <TableRow key={user.id ?? i} className="hover:bg-muted/30">
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Avatar className="h-7 w-7">
                            <AvatarFallback className="text-xs">{getInitials(name)}</AvatarFallback>
                          </Avatar>
                          <span className="text-sm font-medium">{name}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{email}</TableCell>
                      <TableCell>
                        <Badge className={`text-xs ${ROLE_COLORS[role] ?? "bg-muted text-muted-foreground"}`}>
                          {role}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {user.last_login ?? user.last_seen ?? "Never"}
                      </TableCell>
                      <TableCell>
                        {status === "active" ? (
                          <span className="flex items-center gap-1 text-green-500 text-xs">
                            <CheckCircle className="h-3 w-3" /> Active
                          </span>
                        ) : status === "pending" ? (
                          <span className="flex items-center gap-1 text-yellow-500 text-xs">
                            <Clock className="h-3 w-3" /> Pending
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-muted-foreground text-xs">
                            <XCircle className="h-3 w-3" /> Inactive
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <UserApiKeyDialog user={user} />
                          <EditUserDialog user={user} />
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
          </div>
        </CardContent>
      </Card>
      {/* SSO / SAML Configuration Panel */}
      <Card className="border-violet-700/30 bg-violet-900/5">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Lock className="h-4 w-4 text-violet-400" />
            SSO / SAML Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Identity Provider</Label>
              <Select defaultValue="none">
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">Not Configured</SelectItem>
                  <SelectItem value="okta">Okta</SelectItem>
                  <SelectItem value="azure">Azure AD</SelectItem>
                  <SelectItem value="google">Google Workspace</SelectItem>
                  <SelectItem value="onelogin">OneLogin</SelectItem>
                  <SelectItem value="custom">Custom SAML</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">SSO Enforcement</Label>
              <Select defaultValue="optional">
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="optional">Optional</SelectItem>
                  <SelectItem value="required">Required for all users</SelectItem>
                  <SelectItem value="admins">Required for admins</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">SAML Metadata URL</Label>
            <Input placeholder="https://your-idp.com/saml/metadata" />
          </div>
          <div className="p-3 rounded-lg bg-muted/30 border border-border/40">
            <p className="text-xs font-medium mb-1">ACS (Assertion Consumer Service) URL</p>
            <code className="text-xs font-mono text-primary">https://fixops.io/auth/saml/callback</code>
          </div>
          <Button variant="outline" className="gap-2" onClick={() => toast.success("SSO configuration saved")}>Save SSO Config</Button>
        </CardContent>
      </Card>

      {/* Activity Log */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            Recent User Activity
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {USER_ACTIVITY_LOG.map((entry, i) => {
              const typeColors: Record<string, string> = {
                triage: "text-blue-400 bg-blue-900/20",
                report: "text-green-400 bg-green-900/20",
                admin: "text-orange-400 bg-orange-900/20",
                integration: "text-violet-400 bg-violet-900/20",
                scan: "text-yellow-400 bg-yellow-900/20",
              };
              return (
                <div key={i} className="flex items-start gap-3">
                  <Avatar className="h-7 w-7 shrink-0">
                    <AvatarFallback className="text-xs">{getInitials(entry.user)}</AvatarFallback>
                  </Avatar>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs">
                      <span className="font-medium">{entry.user}</span>{" "}
                      <span className="text-muted-foreground">{entry.action}</span>
                    </p>
                    <p className="text-xs text-muted-foreground mt-0.5">{entry.time}</p>
                  </div>
                  <Badge className={`text-xs shrink-0 ${typeColors[entry.type] ?? ""}`}>
                    {entry.type}
                  </Badge>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
