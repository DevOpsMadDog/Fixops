import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Users, Plus, RefreshCw, Clock, Shield, Layers, TrendingUp,
  CheckCircle, MoreHorizontal, Activity, UserMinus, UserPlus2,
  GitBranch, Target, BarChart3
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { useTeams, useUsers, useCreateTeam, useUpdateTeam } from "@/hooks/use-api";
import { getInitials } from "@/lib/utils";
import { toast } from "sonner";

const COMPONENT_CATEGORIES = ["Frontend", "Backend", "Infrastructure", "Security", "Data", "DevOps"];

function MemberManagementDialog({ team, allUsers }: { team: any; allUsers: any[] }) {
  const [open, setOpen] = useState(false);
  const updateTeam = useUpdateTeam();
  const members: any[] = team.members ?? [];
  const memberIds = new Set(members.map((m: any) => m.id ?? m.email));
  const nonMembers = allUsers.filter((u: any) => !memberIds.has(u.id ?? u.email));

  const handleAdd = (user: any) => {
    const updated = [...members, { id: user.id ?? user.email, name: user.name, email: user.email }];
    updateTeam.mutate({ id: team.id, data: { members: updated } });
  };
  const handleRemove = (member: any) => {
    const updated = members.filter((m: any) => (m.id ?? m.email) !== (member.id ?? member.email));
    updateTeam.mutate({ id: team.id, data: { members: updated } });
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm" className="h-7 gap-1.5 text-xs">
          <Users className="h-3.5 w-3.5" />
          Manage Members
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Users className="h-4 w-4 text-primary" />
            Manage Members — {team.name}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-5">
          {/* Current members */}
          <div>
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">
              Current Members ({members.length})
            </p>
            {members.length === 0 ? (
              <p className="text-xs text-muted-foreground">No members yet</p>
            ) : (
              <div className="space-y-2 max-h-40 overflow-y-auto">
                {members.map((m: any, i: number) => (
                  <div key={m.id ?? i} className="flex items-center gap-2">
                    <Avatar className="h-7 w-7">
                      <AvatarFallback className="text-xs">{getInitials(m.name ?? m.email ?? "?")}</AvatarFallback>
                    </Avatar>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm truncate">{m.name ?? m.email}</p>
                      <p className="text-xs text-muted-foreground">{m.role ?? "Member"}</p>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-red-400 hover:text-red-300"
                      onClick={() => handleRemove(m)}
                    >
                      <UserMinus className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                ))
                )}
              </div>
            )}
          </div>
          <Separator />
          {/* Add members */}
          {nonMembers.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">
                Add Members
              </p>
              <div className="space-y-2 max-h-40 overflow-y-auto">
                {nonMembers.slice(0, 10).map((u: any, i: number) => (
                  <div key={u.id ?? i} className="flex items-center gap-2 p-2 rounded-lg hover:bg-muted/30">
                    <Avatar className="h-7 w-7">
                      <AvatarFallback className="text-xs">{getInitials(u.name ?? u.email ?? "?")}</AvatarFallback>
                    </Avatar>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm truncate">{u.name ?? u.email}</p>
                      <p className="text-xs text-muted-foreground">{u.role ?? "User"}</p>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-green-400 hover:text-green-300"
                      onClick={() => handleAdd(u)}
                    >
                      <UserPlus2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="flex justify-end">
            <Button onClick={() => setOpen(false)}>Done</Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function CreateTeamDialog({ users, onSave }: { users: any[]; onSave: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selectedMembers, setSelectedMembers] = useState<string[]>([]);
  const [isSaving, setIsSaving] = useState(false);
  const createTeam = useCreateTeam();

  const toggleMember = (id: string) => {
    setSelectedMembers((prev) => prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]);
  };

  const handleSave = async () => {
    if (!name) return;
    setIsSaving(true);
    const memberList = users.filter((u) => selectedMembers.includes(u.id ?? u.email));
    createTeam.mutate({ name, description, members: memberList }, {
      onSuccess: () => { onSave(); setOpen(false); setName(""); setDescription(""); setSelectedMembers([]); setIsSaving(false); },
      onError: () => { setIsSaving(false); },
    });
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" className="gap-2">
          <Plus className="h-4 w-4" />
          Create Team
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Users className="h-4 w-4 text-primary" />
            Create Team
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Team Name</Label>
            <Input placeholder="e.g. Platform Security" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Description</Label>
            <Textarea
              placeholder="Team purpose and responsibilities…"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
            />
          </div>
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">
              Members ({selectedMembers.length} selected)
            </Label>
            <div className="max-h-40 overflow-y-auto space-y-1">
              {users.slice(0, 20).map((u: any) => {
                const id = u.id ?? u.email;
                const name = u.name ?? u.email ?? "User";
                return (
                  <div
                    key={id}
                    className={`flex items-center gap-2 p-2 rounded-lg cursor-pointer transition-colors ${selectedMembers.includes(id) ? "bg-primary/10 border border-primary/30" : "hover:bg-muted/30"}`}
                    onClick={() => toggleMember(id)}
                  >
                    <Avatar className="h-6 w-6">
                      <AvatarFallback className="text-xs">{getInitials(name)}</AvatarFallback>
                    </Avatar>
                    <span className="text-sm">{name}</span>
                    {selectedMembers.includes(id) && (
                      <CheckCircle className="h-3.5 w-3.5 text-primary ml-auto" />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
          <Separator />
          <div className="flex gap-2 justify-end">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={handleSave} disabled={!name || isSaving}>
              {isSaving ? "Creating…" : "Create Team"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function TeamDetailDialog({ team }: { team: any }) {
  const [open, setOpen] = useState(false);
  const members: any[] = team.members ?? [];

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" className="h-7 w-7">
          <MoreHorizontal className="h-3.5 w-3.5" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Users className="h-4 w-4 text-primary" />
            {team.name ?? "Team"}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-5">
          {/* Metrics */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: "Members", value: team.members_count ?? members.length, icon: Users },
              { label: "Components", value: team.components_count ?? team.components_owned ?? 0, icon: Layers },
              { label: "Avg MTTR", value: team.avg_mttr ? `${team.avg_mttr}h` : "—", icon: Clock },
            ].map(({ label, value, icon: Icon }) => (
              <div key={label} className="text-center p-3 rounded-lg bg-muted/30 border border-border/40">
                <Icon className="h-4 w-4 mx-auto text-primary mb-1" />
                <p className="text-lg font-bold">{value}</p>
                <p className="text-xs text-muted-foreground">{label}</p>
              </div>
            ))}
          </div>

          {/* SLA compliance */}
          {team.sla_compliance !== undefined && (
            <div className="p-3 rounded-lg bg-muted/30 border border-border/40">
              <div className="flex justify-between text-xs mb-2">
                <span className="font-medium">SLA Compliance</span>
                <span className="text-primary">{team.sla_compliance}%</span>
              </div>
              <Progress value={team.sla_compliance ?? 0} className="h-2" />
            </div>
          )}

          {/* Members list */}
          {members.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">Members</p>
              <div className="space-y-2">
                {members.map((m: any, i: number) => (
                  <div key={m.id ?? i} className="flex items-center gap-2">
                    <Avatar className="h-7 w-7">
                      <AvatarFallback className="text-xs">{getInitials(m.name ?? m.email ?? "?")}</AvatarFallback>
                    </Avatar>
                    <span className="text-sm">{m.name ?? m.email ?? `Member ${i + 1}`}</span>
                    <Badge variant="outline" className="text-xs ml-auto">{m.role ?? "Member"}</Badge>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Owned components */}
          {team.owned_components && team.owned_components.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">Owned Components</p>
              <div className="flex flex-wrap gap-2">
                {(team.owned_components as string[]).map((comp) => (
                  <Badge key={comp} variant="secondary" className="text-xs">{comp}</Badge>
                ))}
              </div>
            </div>
          )}

          {/* Performance metrics bar */}
          <div>
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">Performance Metrics</p>
            <div className="space-y-2">
              {[
                { label: "Critical Response", value: 95, target: 100, unit: "% on-time" },
                { label: "Remediation Velocity", value: 78, target: 100, unit: "% weekly" },
                { label: "Code Review Coverage", value: 88, target: 100, unit: "% PRs" },
              ].map(({ label, value, unit }) => (
                <div key={label}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-muted-foreground">{label}</span>
                    <span className="font-medium">{value}{unit.includes("%") ? "" : " "}{unit}</span>
                  </div>
                  <Progress value={value} className="h-1.5" />
                </div>
              ))}
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function TeamsPage() {
  const teamsQuery = useTeams();
  const usersQuery = useUsers();
  const refetchAll = useCallback(() => {
    teamsQuery.refetch();
    usersQuery.refetch();
  }, [teamsQuery, usersQuery]);

  if (teamsQuery.isLoading) return <PageSkeleton />;
  if (teamsQuery.isError) return <ErrorState message="Failed to load teams" onRetry={refetchAll} />;

  const teams: any[] = toArray(teamsQuery.data);
  const users: any[] = toArray(usersQuery.data);

  const totalTeams = teams.length;
  const totalMembers = teams.reduce((acc: number, t: any) => acc + (t.members_count ?? (t.members ?? []).length ?? 0), 0);
  const componentsOwned = teams.reduce((acc: number, t: any) => acc + (t.components_count ?? t.components_owned ?? 0), 0);
  const avgResponseTime = teams.length > 0
    ? Math.round(teams.reduce((acc: number, t: any) => acc + (t.avg_mttr ?? 0), 0) / teams.length)
    : 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Teams"
        description="Manage security teams, component ownership, and performance metrics"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetchAll} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <CreateTeamDialog users={users} onSave={refetchAll} />
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Teams" value={totalTeams} icon={Users} />
        <KpiCard title="Total Members" value={totalMembers} icon={Activity} />
        <KpiCard title="Components Owned" value={componentsOwned} icon={Layers} />
        <KpiCard title="Avg Response Time" value={avgResponseTime > 0 ? `${avgResponseTime}h` : "—"} icon={Clock} />
      </div>

      {/* Teams Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Users className="h-4 w-4 text-primary" />
              Teams
            </span>
            <span className="text-sm font-normal text-muted-foreground">{teams.length} teams</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b border-border/40">
                <TableHead className="text-xs">Team Name</TableHead>
                <TableHead className="text-xs">Members</TableHead>
                <TableHead className="text-xs">Components</TableHead>
                <TableHead className="text-xs">MTTR</TableHead>
                <TableHead className="text-xs">SLA Compliance</TableHead>
                <TableHead className="text-xs text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {teams.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-12 text-muted-foreground">
                    No teams created yet
                  </TableCell>
                </TableRow>
              ) : (
                teams.map((team: any, i: number) => {
                  const sla = team.sla_compliance ?? null;
                  return (
                    <TableRow key={team.id ?? i} className="hover:bg-muted/30">
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <div className="h-7 w-7 rounded-lg bg-primary/10 flex items-center justify-center">
                            <Users className="h-3.5 w-3.5 text-primary" />
                          </div>
                          <div>
                            <p className="text-sm font-medium">{team.name ?? `Team ${i + 1}`}</p>
                            {team.description && (
                              <p className="text-xs text-muted-foreground line-clamp-1">{team.description}</p>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <div className="flex -space-x-1">
                            {(team.members ?? []).slice(0, 3).map((m: any, j: number) => (
                              <Avatar key={j} className="h-6 w-6 border-2 border-background">
                                <AvatarFallback className="text-xs">{getInitials(m.name ?? m.email ?? "?")}</AvatarFallback>
                              </Avatar>
                            ))}
                          </div>
                          <span className="text-xs text-muted-foreground ml-1">
                            {team.members_count ?? (team.members ?? []).length}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-xs">
                          {team.components_count ?? team.components_owned ?? 0}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {team.avg_mttr ? `${team.avg_mttr}h` : "—"}
                      </TableCell>
                      <TableCell>
                        {sla !== null ? (
                          <div className="flex items-center gap-2 min-w-24">
                            <Progress value={sla} className="h-1.5 flex-1" />
                            <span className="text-xs text-muted-foreground shrink-0">{sla}%</span>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <MemberManagementDialog team={team} allUsers={users} />
                          <TeamDetailDialog team={team} />
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
      {/* Component Ownership Mapping */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <GitBranch className="h-4 w-4 text-primary" />
            Component Ownership Mapping
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {COMPONENT_CATEGORIES.map((cat, i) => {
              const ownerTeam = teams[i % Math.max(teams.length, 1)];
              return (
                <div key={cat} className="p-3 rounded-lg bg-muted/30 border border-border/40 hover:bg-muted/50 transition-colors">
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">{cat}</p>
                  {ownerTeam ? (
                    <div className="flex items-center gap-1.5">
                      <div className="h-5 w-5 rounded bg-primary/10 flex items-center justify-center">
                        <Users className="h-3 w-3 text-primary" />
                      </div>
                      <span className="text-xs font-medium truncate">{ownerTeam.name ?? `Team ${i + 1}`}</span>
                    </div>
                  ) : (
                    <span className="text-xs text-muted-foreground">Unassigned</span>
                  )}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Team Performance Metrics Chart */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-primary" />
            Team Performance — MTTR vs SLA Compliance
          </CardTitle>
        </CardHeader>
        <CardContent>
          {teams.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">No team performance data available</p>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart
                data={teams.slice(0, 8).map((t: any) => ({
                  name: (t.name ?? "Team").slice(0, 12),
                  mttr: t.avg_mttr ?? 0,
                  sla: t.sla_compliance ?? 0,
                ))
              }
                margin={{ top: 4, right: 12, left: -10, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, fontSize: 11 }} />
                <Bar dataKey="mttr" fill="#f59e0b" name="MTTR (hrs)" radius={[2, 2, 0, 0]} />
                <Bar dataKey="sla" fill="#6366f1" name="SLA Compliance (%)" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
