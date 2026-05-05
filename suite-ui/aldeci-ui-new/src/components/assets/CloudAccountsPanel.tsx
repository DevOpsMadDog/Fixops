import { useEffect, useState } from "react";
import { Server } from "lucide-react";
import { cloudAccountsApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";

interface CloudAccount {
  id?: string;
  account_id: string;
  account_name?: string;
  provider: string;
  region?: string;
  status?: string;
  findings_count?: number;
  risk_score?: number;
  last_scan?: string;
  registered_at?: string;
}

interface RiskSummary {
  by_provider?: Record<string, { account_count: number; avg_risk_score: number; total_findings: number }>;
  total_accounts?: number;
}

const PROVIDER_COLOR: Record<string, string> = {
  aws: "bg-orange-500/15 text-orange-400",
  azure: "bg-blue-500/15 text-blue-400",
  gcp: "bg-green-500/15 text-green-400",
  alibaba: "bg-red-500/15 text-red-400",
  oracle: "bg-purple-500/15 text-purple-400",
};

const STATUS_COLOR: Record<string, string> = {
  active: "bg-green-500/15 text-green-400 border-green-500/30",
  inactive: "bg-muted/30 text-muted-foreground",
  error: "bg-red-500/15 text-red-400 border-red-500/30",
  syncing: "bg-blue-500/15 text-blue-400 border-blue-500/30",
};

function RiskBar({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score));
  const color =
    pct >= 75 ? "bg-red-500" : pct >= 50 ? "bg-orange-500" : pct >= 25 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-muted/40">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs tabular-nums w-8 text-right">{pct.toFixed(0)}</span>
    </div>
  );
}

export function CloudAccountsPanel() {
  const [accounts, setAccounts] = useState<CloudAccount[]>([]);
  const [riskSummary, setRiskSummary] = useState<RiskSummary>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      cloudAccountsApi.listAccounts().catch(() => ({ data: [] })),
      cloudAccountsApi.riskSummary().catch(() => ({ data: {} })),
    ])
      .then(([acctRes, riskRes]) => {
        if (cancelled) return;
        const raw = acctRes.data;
        setAccounts(Array.isArray(raw) ? raw : (raw?.accounts ?? raw?.items ?? []));
        setRiskSummary(riskRes.data ?? {});
      })
      .catch((e) => {
        if (!cancelled) setError(e?.message ?? "Failed to load cloud accounts");
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
      <div className="space-y-2 animate-pulse">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-12 rounded-lg bg-muted/50" />
        ))}
      </div>
    );
  }

  if (error) {
    return <EmptyState icon={Server} title="Error loading cloud accounts" description={error} />;
  }

  if (accounts.length === 0) {
    return (
      <EmptyState
        icon={Server}
        title="No cloud accounts"
        description="Register AWS, Azure, or GCP accounts to monitor cloud posture and events."
      />
    );
  }

  const providerSummary = riskSummary.by_provider ?? {};

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Total Accounts</p>
          <p className="text-2xl font-bold">{riskSummary.total_accounts ?? accounts.length}</p>
        </div>
        {Object.entries(providerSummary)
          .slice(0, 3)
          .map(([provider, summary]) => (
            <div key={provider} className="rounded-lg border border-border bg-card p-3">
              <p className="text-xs text-muted-foreground uppercase">{provider}</p>
              <p className="text-2xl font-bold">{summary.account_count}</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                {summary.total_findings} findings
              </p>
            </div>
          ))}
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        <div className="px-4 py-2 bg-muted/30 border-b border-border text-xs font-medium text-muted-foreground">
          Cloud Accounts ({accounts.length})
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/10">
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Account</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Provider</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Region</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Status</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Findings</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground w-36">Risk Score</th>
            </tr>
          </thead>
          <tbody>
            {accounts.slice(0, 30).map((a, i) => (
              <tr
                key={a.id ?? a.account_id ?? i}
                className="border-b border-border/50 hover:bg-muted/20 transition-colors"
              >
                <td className="px-4 py-2.5">
                  <p className="font-medium">{a.account_name || a.account_id}</p>
                  {a.account_name && (
                    <p className="text-xs text-muted-foreground font-mono">{a.account_id}</p>
                  )}
                </td>
                <td className="px-4 py-2.5">
                  <span
                    className={`text-xs px-1.5 py-0.5 rounded uppercase ${
                      PROVIDER_COLOR[a.provider] ?? "bg-muted/30 text-muted-foreground"
                    }`}
                  >
                    {a.provider}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-muted-foreground text-xs font-mono">{a.region || "—"}</td>
                <td className="px-4 py-2.5">
                  {a.status ? (
                    <Badge className={`text-xs ${STATUS_COLOR[a.status] ?? "bg-muted/30"}`}>
                      {a.status}
                    </Badge>
                  ) : (
                    "—"
                  )}
                </td>
                <td className="px-4 py-2.5 tabular-nums">{a.findings_count ?? "—"}</td>
                <td className="px-4 py-2.5 w-36">
                  {a.risk_score !== undefined ? <RiskBar score={a.risk_score} /> : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
