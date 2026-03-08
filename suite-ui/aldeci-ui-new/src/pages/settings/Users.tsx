import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Users as UsersIcon, Plus, RefreshCw, Shield } from "lucide-react";
import { useUsers } from "@/hooks/use-api";

export default function UsersPage() {
  const users = useUsers();
  const refetch = useCallback(() => users.refetch(), [users]);
  if (users.isLoading) return <PageSkeleton />;
  if (users.isError) return <ErrorState onRetry={refetch} />;
  const list = Array.isArray(users.data) ? users.data : users.data?.users ?? [];
  const cols = [
    { key: "name", header: "Name", render: (r: Record<string, unknown>) => <span className="font-medium text-sm">{String(r.name ?? r.username ?? r.email ?? "")}</span> },
    { key: "email", header: "Email", render: (r: Record<string, unknown>) => <span className="text-sm text-muted-foreground">{String(r.email ?? "")}</span> },
    { key: "role", header: "Role", render: (r: Record<string, unknown>) => <Badge variant="outline" className="capitalize">{String(r.role ?? "user")}</Badge> },
    { key: "status", header: "Status", render: (r: Record<string, unknown>) => <Badge variant={r.status === "active" ? "default" : "outline"} className="capitalize">{String(r.status ?? "active")}</Badge> },
  ];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Users" description="User account management" actions={<div className="flex gap-2"><Button size="sm"><Plus className="mr-2 h-4 w-4" />Add User</Button><Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button></div>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Users" value={list.length} icon={UsersIcon} /><KpiCard title="Active" value={list.filter((u: Record<string, unknown>) => u.status === "active").length} icon={Shield} /><KpiCard title="Admins" value={list.filter((u: Record<string, unknown>) => u.role === "admin").length} icon={Shield} /></div>
      <Card><CardContent className="pt-6"><DataTable columns={cols} data={list} emptyMessage="No users found. Add team members to get started." /></CardContent></Card>
    </div>
  );
}
