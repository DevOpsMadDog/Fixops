import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Users,
  Plus,
  ChevronRight,
  Package,
  Shield,
  Code2,
  CloudIcon,
  Smartphone,
  Globe,
  Database,
  LayoutGrid,
  X,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { teamsApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock data ───────────────────────────────────────────────────────────────
const MOCK_TEAMS = [
  { id: "t1", name: "AppSec", icon: Shield, color: "text-red-400 bg-red-500/10", members: 6, lead: "Priya Sharma", components: 34, open_findings: 847, sla_breach: 3 },
  { id: "t2", name: "Cloud Security", icon: CloudIcon, color: "text-blue-400 bg-blue-500/10", members: 4, lead: "Tom Bradley", components: 21, open_findings: 2341, sla_breach: 12 },
  { id: "t3", name: "Platform Engineering", icon: LayoutGrid, color: "text-green-400 bg-green-500/10", members: 8, lead: "James Park", components: 47, open_findings: 312, sla_breach: 1 },
  { id: "t4", name: "Red Team", icon: Shield, color: "text-orange-400 bg-orange-500/10", members: 3, lead: "Marcus Williams", components: 0, open_findings: 0, sla_breach: 0 },
  { id: "t5", name: "Mobile", icon: Smartphone, color: "text-purple-400 bg-purple-500/10", members: 5, lead: "Ryan Liu", components: 12, open_findings: 189, sla_breach: 0 },
  { id: "t6", name: "Backend Services", icon: Database, color: "text-cyan-400 bg-cyan-500/10", members: 7, lead: "Chris Yamamoto", components: 58, open_findings: 623, sla_breach: 5 },
  { id: "t7", name: "Frontend", icon: Globe, color: "text-yellow-400 bg-yellow-500/10", members: 6, lead: "Nina Kowalski", components: 22, open_findings: 114, sla_breach: 0 },
  { id: "t8", name: "GRC", icon: Code2, color: "text-pink-400 bg-pink-500/10", members: 3, lead: "Elena Vasquez", components: 5, open_findings: 67, sla_breach: 0 },
];

const MOCK_OWNERSHIP = [
  { component: "payment-service", app: "CoreBanking", team: "Backend Services", criticality: "critical", findings: 89 },
  { component: "auth-gateway", app: "IdentityPlatform", team: "AppSec", criticality: "critical", findings: 143 },
  { component: "api-gateway", app: "CoreBanking", team: "Platform Engineering", criticality: "high", findings: 34 },
  { component: "user-portal", app: "CustomerPortal", team: "Frontend", criticality: "high", findings: 56 },
  { component: "mobile-sdk-ios", app: "MobileApp", team: "Mobile", criticality: "high", findings: 78 },
  { component: "data-pipeline", app: "Analytics", team: "Backend Services", criticality: "medium", findings: 23 },
  { component: "infra-terraform", app: "CloudInfra", team: "Cloud Security", criticality: "high", findings: 201 },
  { component: "reporting-engine", app: "ComplianceHub", team: "GRC", criticality: "medium", findings: 12 },
  { component: "notification-svc", app: "CoreBanking", team: "Backend Services", criticality: "low", findings: 7 },
  { component: "search-service", app: "CustomerPortal", team: "Frontend", criticality: "medium", findings: 19 },
];

const CRITICALITY_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
};

export default function Teams() {
  const [selectedTeam, setSelectedTeam] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newTeam, setNewTeam] = useState({ name: "", lead: "", description: "" });

  const { data } = useQuery({
    queryKey: ["teams"],
    queryFn: () => teamsApi.list(),
  });

  const teams = (data?.data as any[]) ?? MOCK_TEAMS;

  const createMutation = useMutation({
    mutationFn: async (team: unknown) => {
      await new Promise((r) => setTimeout(r, 700));
      return team;
    },
    onSuccess: () => {
      toast.success(`Team "${newTeam.name}" created`);
      setShowCreate(false);
      setNewTeam({ name: "", lead: "", description: "" });
    },
  });

  const selected = selectedTeam ? MOCK_TEAMS.find((t) => t.id === selectedTeam) : null;
  const teamMembers: Record<string, string[]> = {
    t1: ["Priya Sharma", "Aisha Okonkwo", "Derek Stone", "Sam Patel", "Kim Lee", "Alex Johnson"],
    t2: ["Tom Bradley", "Maria Garcia", "Wei Zhang", "Carlos Ruiz"],
    t3: ["James Park", "Emma Wilson", "Liam Davis", "Olivia Brown", "Noah Taylor", "Ava Miller", "Lucas Anderson", "Mia Thomas"],
    t4: ["Marcus Williams", "Fatima Al-Hassan", "Jason Chen"],
    t5: ["Ryan Liu", "Sophie Martin", "Kai Nakamura", "Ana Costa", "Ben Harris"],
    t6: ["Chris Yamamoto", "Rachel White", "David Kim", "Lisa Turner", "Mike Chen", "Jenny Park", "Sam Scott"],
    t7: ["Nina Kowalski", "Alex Brown", "Sam Rivera", "Taylor Swift", "Jordan Lee", "Casey Moore"],
    t8: ["Elena Vasquez", "Robert James", "Diana Prince"],
  };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Teams"
        description="Manage team structure, ownership mapping, and component assignments"
        actions={
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="h-3.5 w-3.5 mr-1.5" />
            Create Team
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Total Teams" value={MOCK_TEAMS.length} icon={Users} trend="flat" />
        <KpiCard title="Components Owned" value={MOCK_TEAMS.reduce((a, t) => a + t.components, 0)} icon={Package} trend="flat" />
        <KpiCard title="Open Findings" value={MOCK_TEAMS.reduce((a, t) => a + t.open_findings, 0).toLocaleString()} icon={Shield} trend="down" />
        <KpiCard title="SLA Breaches" value={MOCK_TEAMS.reduce((a, t) => a + t.sla_breach, 0)} icon={Shield} trend="down" />
      </div>

      {/* Create Team Dialog */}
      {showCreate && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="border-primary/30 bg-primary/5">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm flex items-center gap-2"><Plus className="h-4 w-4" />Create Team</CardTitle>
                <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => setShowCreate(false)}><X className="h-3.5 w-3.5" /></Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <Input placeholder="Team name" value={newTeam.name} onChange={(e) => setNewTeam({ ...newTeam, name: e.target.value })} className="h-8 text-sm" />
                <Input placeholder="Team lead email" value={newTeam.lead} onChange={(e) => setNewTeam({ ...newTeam, lead: e.target.value })} className="h-8 text-sm" />
                <Input placeholder="Description (optional)" value={newTeam.description} onChange={(e) => setNewTeam({ ...newTeam, description: e.target.value })} className="h-8 text-sm" />
              </div>
              <div className="flex gap-2 mt-3">
                <Button size="sm" className="h-7 text-xs" onClick={() => createMutation.mutate(newTeam)}>Create Team</Button>
                <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setShowCreate(false)}>Cancel</Button>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Teams Grid */}
        <div className="lg:col-span-2">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {MOCK_TEAMS.map((team) => {
              const Icon = team.icon;
              return (
                <Card
                  key={team.id}
                  className={`cursor-pointer border-border/50 hover:border-border transition-all ${selectedTeam === team.id ? "border-primary/60 bg-primary/5" : ""}`}
                  onClick={() => setSelectedTeam(selectedTeam === team.id ? null : team.id)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-2.5">
                        <div className={`rounded-lg p-2 ${team.color}`}>
                          <Icon className="h-4 w-4" />
                        </div>
                        <div>
                          <p className="text-sm font-semibold">{team.name}</p>
                          <p className="text-xs text-muted-foreground">Lead: {team.lead}</p>
                        </div>
                      </div>
                      <ChevronRight className={`h-4 w-4 text-muted-foreground transition-transform ${selectedTeam === team.id ? "rotate-90" : ""}`} />
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-center">
                      <div>
                        <p className="text-sm font-bold">{team.members}</p>
                        <p className="text-xs text-muted-foreground">Members</p>
                      </div>
                      <div>
                        <p className="text-sm font-bold">{team.components}</p>
                        <p className="text-xs text-muted-foreground">Components</p>
                      </div>
                      <div>
                        <p className={`text-sm font-bold ${team.sla_breach > 0 ? "text-red-400" : "text-green-400"}`}>
                          {team.sla_breach}
                        </p>
                        <p className="text-xs text-muted-foreground">SLA Issues</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>

        {/* Team Detail / Component Ownership */}
        <div className="space-y-4">
          {selected ? (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Users className="h-4 w-4 text-primary" />
                  {selected.name} Members
                </CardTitle>
                <CardDescription>{selected.members} team members</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {(teamMembers[selected.id] || []).map((m) => (
                  <div key={m} className="flex items-center gap-2.5 py-1">
                    <div className="h-6 w-6 rounded-full bg-primary/15 flex items-center justify-center text-xs font-semibold text-primary shrink-0">
                      {m.split(" ").map((n) => n[0]).join("").slice(0, 2)}
                    </div>
                    <span className="text-sm">{m}</span>
                    {m === selected.lead && <Badge variant="secondary" className="text-xs ml-auto">Lead</Badge>}
                  </div>
                ))}
                <Button variant="outline" size="sm" className="w-full h-7 text-xs mt-2">
                  <Plus className="h-3 w-3 mr-1" />
                  Add Member
                </Button>
              </CardContent>
            </Card>
          ) : (
            <Card className="border-border/30 bg-muted/10">
              <CardContent className="py-10 flex flex-col items-center gap-2 text-center">
                <Users className="h-8 w-8 text-muted-foreground/40" />
                <p className="text-sm text-muted-foreground">Select a team to view members</p>
              </CardContent>
            </Card>
          )}

          {/* Component Ownership Table */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Package className="h-4 w-4 text-primary" />
                Component Ownership
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-hidden">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border/50">
                      <th className="text-left text-xs text-muted-foreground px-3 py-2">Component</th>
                      <th className="text-left text-xs text-muted-foreground px-3 py-2">Team</th>
                      <th className="text-right text-xs text-muted-foreground px-3 py-2">Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {MOCK_OWNERSHIP.slice(0, selected ? 5 : 10).map((row) => (
                      <tr key={row.component} className="border-b border-border/20 hover:bg-muted/20 last:border-0">
                        <td className="px-3 py-2">
                          <p className="text-xs font-mono text-foreground">{row.component}</p>
                          <p className={`text-xs capitalize ${CRITICALITY_COLORS[row.criticality]}`}>{row.criticality}</p>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">{row.team}</td>
                        <td className="px-3 py-2 text-xs font-semibold text-right">{row.findings}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
