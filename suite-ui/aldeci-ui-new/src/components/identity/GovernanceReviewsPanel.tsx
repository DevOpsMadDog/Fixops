/**
 * GovernanceReviewsPanel — wires GET /api/v1/identity-governance/reviews
 * and GET /api/v1/identity-governance/stats → stat cards + reviews table.
 * Used by IdentityGovernanceHub "governance" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, ShieldCheck, Users, Clock, CheckCircle2 } from "lucide-react";
import { identityGovernanceApi } from "@/lib/api";

interface GovernanceStats {
  total_reviews: number;
  open_reviews: number;
  total_entitlements: number;
  orphaned_entitlements: number;
  excessive_entitlements: number;
  total_policies: number;
}

interface AccessReview {
  id: string;
  name: string;
  review_type: string;
  status: string;
  reviewer_id?: string;
  start_date?: string;
  due_date?: string;
  item_count?: number;
  pending_count?: number;
}

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  accent: string;
}) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-border/60 bg-card p-4 shadow-sm">
      <div className="flex items-center gap-2 text-muted-foreground text-xs font-medium uppercase tracking-wider">
        <Icon className={`h-4 w-4 ${accent}`} />
        {label}
      </div>
      <p className="text-2xl font-bold text-foreground">{value}</p>
    </div>
  );
}

const STATUS_BADGE: Record<string, string> = {
  open: "bg-sky-500/15 text-sky-400",
  in_progress: "bg-amber-500/15 text-amber-400",
  completed: "bg-green-500/15 text-green-400",
  cancelled: "bg-muted text-muted-foreground",
};

const TYPE_BADGE: Record<string, string> = {
  quarterly: "bg-indigo-500/15 text-indigo-400",
  annual: "bg-purple-500/15 text-purple-400",
  ad_hoc: "bg-orange-500/15 text-orange-400",
  emergency: "bg-red-500/15 text-red-400",
};

export function GovernanceReviewsPanel() {
  const [stats, setStats] = useState<GovernanceStats | null>(null);
  const [reviews, setReviews] = useState<AccessReview[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      identityGovernanceApi.stats("default"),
      identityGovernanceApi.reviews("default"),
    ])
      .then(([statsRes, reviewsRes]) => {
        if (cancelled) return;
        setStats(statsRes.data as GovernanceStats);
        const raw = reviewsRes.data;
        setReviews(
          Array.isArray(raw) ? raw : (raw as { reviews?: AccessReview[] }).reviews ?? [],
        );
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load governance data");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col gap-4 animate-pulse">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 rounded-xl border border-border/40 bg-muted/30" />
          ))}
        </div>
        <div className="h-48 rounded-xl border border-border/40 bg-muted/30" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-destructive text-sm">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        {error}
      </div>
    );
  }

  if (!stats || stats.total_reviews === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <ShieldCheck className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No access reviews created yet</p>
        <p className="text-xs opacity-70">
          Create a quarterly or ad-hoc access review to govern entitlements and orphaned accounts.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          label="Total Reviews"
          value={stats.total_reviews}
          icon={ShieldCheck}
          accent="text-indigo-400"
        />
        <StatCard
          label="Open Reviews"
          value={stats.open_reviews}
          icon={Clock}
          accent="text-amber-400"
        />
        <StatCard
          label="Orphaned Entitlements"
          value={stats.orphaned_entitlements}
          icon={AlertTriangle}
          accent="text-red-400"
        />
        <StatCard
          label="Total Entitlements"
          value={stats.total_entitlements}
          icon={Users}
          accent="text-sky-400"
        />
      </div>

      {/* Reviews table */}
      {reviews.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-border/40">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Access Reviews
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/30 text-xs text-muted-foreground">
                  <th className="px-4 py-2 text-left font-medium">Name</th>
                  <th className="px-4 py-2 text-left font-medium">Type</th>
                  <th className="px-4 py-2 text-left font-medium">Status</th>
                  <th className="px-4 py-2 text-left font-medium">Due Date</th>
                  <th className="px-4 py-2 text-left font-medium">Items</th>
                </tr>
              </thead>
              <tbody>
                {reviews.slice(0, 50).map((r) => (
                  <tr
                    key={r.id}
                    className="border-b border-border/20 hover:bg-muted/20 transition-colors"
                  >
                    <td className="px-4 py-2 font-medium text-foreground truncate max-w-[200px]">
                      {r.name}
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${TYPE_BADGE[r.review_type] ?? "bg-muted text-muted-foreground"}`}
                      >
                        {r.review_type.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_BADGE[r.status] ?? "bg-muted text-muted-foreground"}`}
                      >
                        {r.status.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-muted-foreground text-xs">
                      {r.due_date ? new Date(r.due_date).toLocaleDateString() : "—"}
                    </td>
                    <td className="px-4 py-2 text-muted-foreground text-xs">
                      {r.item_count ?? "—"}
                      {r.pending_count != null && r.pending_count > 0 && (
                        <span className="ml-1 text-amber-400">({r.pending_count} pending)</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Excessive entitlements callout */}
      {stats.excessive_entitlements > 0 && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
          <AlertTriangle className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" />
          <div>
            <p className="text-sm font-medium text-amber-300">
              {stats.excessive_entitlements} excessive entitlement
              {stats.excessive_entitlements !== 1 ? "s" : ""} detected
            </p>
            <p className="text-xs text-muted-foreground mt-0.5">
              Review over-privileged identities to enforce least-privilege access.
            </p>
          </div>
        </div>
      )}

      {/* Policies count */}
      {stats.total_policies > 0 && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />
          {stats.total_policies} access polic{stats.total_policies !== 1 ? "ies" : "y"} active
        </div>
      )}
    </div>
  );
}
