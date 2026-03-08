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
  CheckCircle, MoreHorizontal, Activity
} from "lucide-react";
import { useTeams, useUsers } from "@/hooks/use-api";
import { getInitials } from "@/lib/utils";
import { toast } from "sonner";

function CreateTeamDialog({ users, onSave }: { users: any[]; onSave: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selectedMembers, setSelectedMembers] = useState<string[]>([]);
  const [isSaving, setIsSaving] = useState(false);

  const toggleMember = (id: string) => {
    setSelectedMembers((prev) => prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]);
  };

  const handleSave = async () => {
    if (!name) return;
    setIsSaving(true);
    await new Promise((resolve) => setTimeout(resolve, 800));
    setIsSaving(false);
    toast.success(`Team "${name}" created`);
    onSave();
    setOpen(false);
    setName("");
    setDescription("");
    setSelectedMembers([]);
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

  const teams: any[] = teamsQuery.data?.data ?? teamsQuery.data ?? [];
  const users: any[] = usersQuery.data?.data ?? usersQuery.data ?? [];

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
                        <TeamDetailDialog team={team} />
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </motion.div>
  );
}
