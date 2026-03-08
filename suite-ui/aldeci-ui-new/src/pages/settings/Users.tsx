import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Users,
  UserPlus,
  Shield,
  Search,
  MoreHorizontal,
  CheckCircle,
  XCircle,
  Clock,
  KeyRound,
  Lock,
  Mail,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { usersApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock data ───────────────────────────────────────────────────────────────
const MOCK_USERS = [
  { id: "u1", name: "Sarah Chen", email: "s.chen@acme.com", role: "Admin", status: "active", mfa: true, last_active: "2m ago", team: "Security Platform" },
  { id: "u2", name: "Marcus Williams", email: "m.williams@acme.com", role: "Security Lead", status: "active", mfa: true, last_active: "15m ago", team: "Red Team" },
  { id: "u3", name: "Priya Sharma", email: "p.sharma@acme.com", role: "Analyst", status: "active", mfa: true, last_active: "1h ago", team: "AppSec" },
  { id: "u4", name: "James Park", email: "j.park@acme.com", role: "Developer", status: "active", mfa: false, last_active: "2h ago", team: "Platform Eng" },
  { id: "u5", name: "Elena Vasquez", email: "e.vasquez@acme.com", role: "Auditor", status: "active", mfa: true, last_active: "3h ago", team: "GRC" },
  { id: "u6", name: "Tom Bradley", email: "t.bradley@acme.com", role: "Security Lead", status: "active", mfa: true, last_active: "4h ago", team: "Cloud Security" },
  { id: "u7", name: "Aisha Okonkwo", email: "a.okonkwo@acme.com", role: "Analyst", status: "active", mfa: false, last_active: "6h ago", team: "AppSec" },
  { id: "u8", name: "Ryan Liu", email: "r.liu@acme.com", role: "Developer", status: "active", mfa: true, last_active: "8h ago", team: "Mobile" },
  { id: "u9", name: "Nina Kowalski", email: "n.kowalski@acme.com", role: "ReadOnly", status: "active", mfa: true, last_active: "1d ago", team: "Leadership" },
  { id: "u10", name: "Derek Stone", email: "d.stone@acme.com", role: "Analyst", status: "suspended", mfa: false, last_active: "14d ago", team: "AppSec" },
  { id: "u11", name: "Fatima Al-Hassan", email: "f.alhassan@acme.com", role: "Security Lead", status: "active", mfa: true, last_active: "2d ago", team: "Red Team" },
  { id: "u12", name: "Chris Yamamoto", email: "c.yamamoto@acme.com", role: "Developer", status: "active", mfa: false, last_active: "3d ago", team: "Backend" },
];

const ROLES = ["Admin", "Security Lead", "Analyst", "Developer", "Auditor", "ReadOnly"];

const ROLE_COLORS: Record<string, string> = {
  Admin: "text-red-400 bg-red-500/10",
  "Security Lead": "text-orange-400 bg-orange-500/10",
  Analyst: "text-blue-400 bg-blue-500/10",
  Developer: "text-green-400 bg-green-500/10",
  Auditor: "text-purple-400 bg-purple-500/10",
  ReadOnly: "text-muted-foreground bg-muted/30",
};

export default function UsersPage() {
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("all");
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [newUser, setNewUser] = useState({ name: "", email: "", role: "Analyst" });

  const { data } = useQuery({
    queryKey: ["users"],
    queryFn: () => usersApi.list(),
  });

  const users = data?.data ?? MOCK_USERS;

  const createMutation = useMutation({
    mutationFn: async (user: unknown) => {
      await new Promise((r) => setTimeout(r, 600));
      return user;
    },
    onSuccess: () => {
      toast.success(`Invite sent to ${newUser.email}`);
      setShowAddDialog(false);
      setNewUser({ name: "", email: "", role: "Analyst" });
    },
  });

  const filtered = (users as any[]).filter((u) => {
    const matchSearch = u.name.toLowerCase().includes(search.toLowerCase()) || u.email.toLowerCase().includes(search.toLowerCase());
    const matchRole = roleFilter === "all" || u.role === roleFilter;
    return matchSearch && matchRole;
  });

  const activeCount = (users as any[]).filter((u) => u.status === "active").length;
  const mfaCount = (users as any[]).filter((u) => u.mfa).length;
  const noMfaCount = (users as any[]).filter((u) => !u.mfa).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Users & Access"
        description="Manage team members, roles, and authentication settings"
        actions={
          <Button size="sm" onClick={() => setShowAddDialog(true)}>
            <UserPlus className="h-3.5 w-3.5 mr-1.5" />
            Add User
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Total Users" value={(users as any[]).length} icon={Users} trend="flat" />
        <KpiCard title="Active" value={activeCount} icon={CheckCircle} trend="flat" />
        <KpiCard title="MFA Enabled" value={mfaCount} icon={Shield} trend="up" />
        <KpiCard title="MFA Missing" value={noMfaCount} icon={XCircle} trend="down" />
      </div>

      {/* Add User Dialog */}
      {showAddDialog && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="border-primary/30 bg-primary/5">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <UserPlus className="h-4 w-4" />
                Invite New User
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <Input
                  placeholder="Full name"
                  value={newUser.name}
                  onChange={(e) => setNewUser({ ...newUser, name: e.target.value })}
                  className="h-8 text-sm"
                />
                <Input
                  placeholder="Work email"
                  type="email"
                  value={newUser.email}
                  onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                  className="h-8 text-sm"
                />
                <Select value={newUser.role} onValueChange={(v) => setNewUser({ ...newUser, role: v })}>
                  <SelectTrigger className="h-8 text-sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ROLES.map((r) => (
                      <SelectItem key={r} value={r}>{r}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex gap-2 mt-3">
                <Button size="sm" className="h-7 text-xs" onClick={() => createMutation.mutate(newUser)}>
                  <Mail className="h-3 w-3 mr-1" />
                  Send Invite
                </Button>
                <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setShowAddDialog(false)}>Cancel</Button>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Filter Bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search users..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-8 pl-8 text-sm"
          />
        </div>
        <Select value={roleFilter} onValueChange={setRoleFilter}>
          <SelectTrigger className="h-8 w-40 text-sm">
            <SelectValue placeholder="All roles" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All roles</SelectItem>
            {ROLES.map((r) => (
              <SelectItem key={r} value={r}>{r}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Users Table */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border/50">
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3">User</th>
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3">Role</th>
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3">Team</th>
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3">MFA</th>
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3">Status</th>
                  <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3">Last Active</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody>
                {filtered.map((user, i) => (
                  <tr key={user.id} className={`border-b border-border/30 hover:bg-muted/20 transition-colors ${i === filtered.length - 1 ? "border-b-0" : ""}`}>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2.5">
                        <div className="h-7 w-7 rounded-full bg-primary/15 flex items-center justify-center text-xs font-semibold text-primary">
                          {user.name.split(" ").map((n: string) => n[0]).join("").slice(0, 2)}
                        </div>
                        <div>
                          <p className="text-sm font-medium">{user.name}</p>
                          <p className="text-xs text-muted-foreground">{user.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${ROLE_COLORS[user.role]}`}>
                        {user.role}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">{user.team}</td>
                    <td className="px-4 py-3">
                      {user.mfa
                        ? <CheckCircle className="h-4 w-4 text-green-400" />
                        : <XCircle className="h-4 w-4 text-red-400" />
                      }
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant={user.status === "active" ? "success" : "destructive"}>{user.status}</Badge>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      <div className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {user.last_active}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <Button variant="ghost" size="sm" className="h-7 w-7 p-0">
                        <MoreHorizontal className="h-3.5 w-3.5" />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length === 0 && (
              <div className="flex items-center justify-center py-12 text-sm text-muted-foreground">No users match your filter</div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* SSO / SAML Configuration */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-primary" />
              <CardTitle className="text-base">SSO / SAML Configuration</CardTitle>
            </div>
            <Badge variant="success">Active</Badge>
          </div>
          <CardDescription>Enterprise SSO via Okta. All users provisioned via SCIM 2.0.</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            { label: "Identity Provider", value: "Okta (enterprise)" },
            { label: "Entity ID", value: "https://sso.acme.com/saml/aldeci" },
            { label: "ACS URL", value: "https://aldeci.acme.com/auth/saml/callback" },
            { label: "SCIM Endpoint", value: "https://aldeci.acme.com/scim/v2" },
            { label: "Provisioning", value: "SCIM 2.0 — Just-in-Time + Push" },
            { label: "Session Timeout", value: "8 hours (enforced)" },
          ].map((item) => (
            <div key={item.label} className="rounded-lg border border-border/50 bg-muted/20 px-3 py-2">
              <p className="text-xs text-muted-foreground">{item.label}</p>
              <p className="text-sm font-medium font-mono truncate">{item.value}</p>
            </div>
          ))}
          <div className="md:col-span-2 flex gap-2 pt-1">
            <Button variant="outline" size="sm" className="h-7 text-xs">
              <Lock className="h-3 w-3 mr-1" />
              Test SSO Login
            </Button>
            <Button variant="outline" size="sm" className="h-7 text-xs">Download Metadata XML</Button>
            <Button variant="outline" size="sm" className="h-7 text-xs">Force Re-provision</Button>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
