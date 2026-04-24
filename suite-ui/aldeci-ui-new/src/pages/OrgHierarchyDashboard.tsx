/**
 * Organization Hierarchy Dashboard
 *
 * Multi-tenant org tree with ancestors, children, and effective policies.
 * Route: /org-hierarchy
 * API: GET /api/v1/orgs/{id}/children, /ancestors, /effective-policies
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Network, Building2, RefreshCw, ChevronRight, ShieldCheck, Users } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface OrgNode {
  id?: string;
  org_id?: string;
  name?: string;
  parent_id?: string | null;
  depth?: number;
  user_count?: number;
}

interface Policy {
  id?: string;
  policy_id?: string;
  name?: string;
  type?: string;
  inherited_from?: string;
  active?: boolean;
}

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    ...opts,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
      ...(opts.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function OrgHierarchyDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [orgId, setOrgId] = useState<string>(getStoredOrgId() || "default");
  const [children, setChildren] = useState<OrgNode[]>([]);
  const [ancestors, setAncestors] = useState<OrgNode[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);

  const load = async (target: string) => {
    setErr(null);
    setRefreshing(true);
    try {
      const [c, a, p] = await Promise.allSettled([
        apiFetch<OrgNode[] | { children?: OrgNode[] }>(`/api/v1/orgs/${encodeURIComponent(target)}/children`),
        apiFetch<OrgNode[] | { ancestors?: OrgNode[] }>(`/api/v1/orgs/${encodeURIComponent(target)}/ancestors`),
        apiFetch<Policy[] | { policies?: Policy[] }>(`/api/v1/orgs/${encodeURIComponent(target)}/effective-policies`),
      ]);
      setChildren(c.status === "fulfilled" ? (Array.isArray(c.value) ? c.value : c.value.children ?? []) : []);
      setAncestors(a.status === "fulfilled" ? (Array.isArray(a.value) ? a.value : a.value.ancestors ?? []) : []);
      setPolicies(p.status === "fulfilled" ? (Array.isArray(p.value) ? p.value : p.value.policies ?? []) : []);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(orgId); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Organization Hierarchy"
        description="Multi-tenant org tree, inherited policies, and tenant isolation boundaries"
        actions={
          <div className="flex items-center gap-2">
            <Input value={orgId} onChange={e => setOrgId(e.target.value)} placeholder="org_id" className="h-8 w-40 text-xs" />
            <Button variant="outline" size="sm" onClick={() => load(orgId)} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <KpiCard title="Direct Children" value={children.length} icon={Network} />
        <KpiCard title="Ancestor Depth" value={ancestors.length} icon={Building2} />
        <KpiCard title="Effective Policies" value={policies.length} icon={ShieldCheck} />
      </div>

      {loading ? (
        <div className="p-6 text-sm text-muted-foreground">Loading hierarchy…</div>
      ) : err ? (
        <ErrorState message={err} onRetry={() => load(orgId)} />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {/* Breadcrumb trail of ancestors */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2"><Building2 className="h-4 w-4" /> Ancestor Path</CardTitle>
              <CardDescription className="text-xs">Parent organizations from root → current</CardDescription>
            </CardHeader>
            <CardContent>
              {ancestors.length === 0 ? (
                <EmptyState icon={Building2} title="No ancestors" description="This organization has no parent." />
              ) : (
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  {ancestors.map((n, i) => (
                    <div key={n.id ?? n.org_id ?? i} className="flex items-center gap-2">
                      <Badge className="text-[11px] border border-border bg-muted/40">{n.name ?? n.org_id ?? n.id}</Badge>
                      {i < ancestors.length - 1 && <ChevronRight className="h-3 w-3 text-muted-foreground" />}
                    </div>
                  ))}
                  <ChevronRight className="h-3 w-3 text-muted-foreground" />
                  <Badge className="text-[11px] border border-primary/30 text-primary bg-primary/10">{orgId}</Badge>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Children */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2"><Users className="h-4 w-4" /> Child Organizations</CardTitle>
              <CardDescription className="text-xs">Direct descendants inheriting from this org</CardDescription>
            </CardHeader>
            <CardContent>
              {children.length === 0 ? (
                <EmptyState icon={Users} title="No child orgs" description="This organization is a leaf node." />
              ) : (
                <div className="space-y-1.5">
                  {children.map((n, i) => (
                    <div key={n.id ?? n.org_id ?? i} className="flex items-center justify-between rounded border border-border/50 bg-muted/20 px-3 py-2 text-xs">
                      <span className="font-mono">{n.name ?? n.org_id ?? n.id}</span>
                      <span className="text-muted-foreground">{n.user_count ?? 0} users</span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Effective policies (inherited) */}
          <Card className="lg:col-span-2">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2"><ShieldCheck className="h-4 w-4" /> Effective Policies</CardTitle>
              <CardDescription className="text-xs">Policies applied to this org, including inherited</CardDescription>
            </CardHeader>
            <CardContent>
              {policies.length === 0 ? (
                <EmptyState icon={ShieldCheck} title="No policies" description="No effective policies for this org." />
              ) : (
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {policies.map((p, i) => (
                    <div key={p.id ?? p.policy_id ?? i} className="rounded border border-border/50 bg-muted/20 p-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium">{p.name ?? p.policy_id ?? "—"}</span>
                        {p.active !== false && <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Active</Badge>}
                      </div>
                      <div className="text-[11px] text-muted-foreground mt-1 capitalize">{p.type ?? "policy"}</div>
                      {p.inherited_from && (
                        <div className="text-[10px] text-muted-foreground mt-1">↑ from {p.inherited_from}</div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </motion.div>
  );
}
