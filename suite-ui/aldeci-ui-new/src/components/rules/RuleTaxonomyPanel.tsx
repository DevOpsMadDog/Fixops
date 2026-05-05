/**
 * RuleTaxonomyPanel — taxonomy tab for RulesCatalogHub
 * Fetches GET /api/v1/rules/unified/taxonomy and renders
 * a collapsible domain → category → rule-key tree.
 */

import { useEffect, useState } from "react";
import { ChevronRight, ChevronDown, GitBranch, AlertCircle, RefreshCw } from "lucide-react";
import { unifiedRulesApi, type RuleTaxonomy } from "@/lib/api";

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-400",
  low: "bg-blue-400",
  info: "bg-slate-400",
};

function SeverityDots({ dist }: { dist?: Record<string, number> }) {
  if (!dist) return null;
  return (
    <span className="flex items-center gap-1 ml-2">
      {Object.entries(dist).map(([sev, count]) => (
        <span key={sev} className="flex items-center gap-0.5" title={`${sev}: ${count}`}>
          <span className={`inline-block h-1.5 w-1.5 rounded-full ${SEVERITY_DOT[sev] ?? "bg-slate-400"}`} />
          <span className="text-[9px] text-muted-foreground">{count}</span>
        </span>
      ))}
    </span>
  );
}

function CategoryNode({
  name,
  ruleKeys,
  severityDist,
}: {
  name: string;
  ruleKeys: string[];
  severityDist?: Record<string, number>;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="ml-4">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 py-1 text-xs text-muted-foreground hover:text-foreground w-full text-left"
        aria-expanded={open}
      >
        {open ? (
          <ChevronDown className="h-3 w-3 shrink-0" />
        ) : (
          <ChevronRight className="h-3 w-3 shrink-0" />
        )}
        <span className="font-medium text-foreground/80">{name}</span>
        <span className="ml-1 rounded bg-muted/60 px-1 py-0.5 text-[10px]">
          {ruleKeys.length}
        </span>
        <SeverityDots dist={severityDist} />
      </button>
      {open && (
        <ul className="ml-5 border-l border-border/40 pl-3 space-y-0.5 py-1">
          {ruleKeys.map((key) => (
            <li
              key={key}
              className="font-mono text-[11px] text-muted-foreground/80 truncate"
              title={key}
            >
              {key}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function DomainNode({
  name,
  domain,
}: {
  name: string;
  domain: { categories: Record<string, { rule_keys: string[]; severity_distribution?: Record<string, number> }>; rule_count?: number };
}) {
  const [open, setOpen] = useState(true);
  const categoryEntries = Object.entries(domain.categories ?? {});
  return (
    <div className="rounded-lg border border-border/60 bg-card">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-4 py-3 text-left"
        aria-expanded={open}
      >
        {open ? (
          <ChevronDown className="h-4 w-4 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
        )}
        <span className="text-sm font-semibold text-foreground capitalize">{name}</span>
        <span className="ml-auto rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-semibold text-primary">
          {domain.rule_count ?? categoryEntries.reduce((acc, [, c]) => acc + (c.rule_keys?.length ?? 0), 0)} rules
        </span>
      </button>
      {open && categoryEntries.length > 0 && (
        <div className="border-t border-border/40 pb-3 pt-1">
          {categoryEntries.map(([catName, cat]) => (
            <CategoryNode
              key={catName}
              name={catName}
              ruleKeys={cat.rule_keys ?? []}
              severityDist={cat.severity_distribution}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export function RuleTaxonomyPanel() {
  const [taxonomy, setTaxonomy] = useState<RuleTaxonomy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    unifiedRulesApi
      .taxonomy()
      .then((res) => setTaxonomy(res.data))
      .catch((err) => {
        setError(err?.response?.data?.detail ?? err?.message ?? "Failed to load taxonomy");
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const domainEntries = taxonomy ? Object.entries(taxonomy.domains ?? {}) : [];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          {taxonomy?.total_rules != null
            ? `${taxonomy.total_rules} total rules across ${domainEntries.length} domains`
            : "Rule taxonomy from /api/v1/rules/unified/taxonomy"}
        </p>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground disabled:opacity-50"
          aria-label="Refresh taxonomy"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {error && !loading && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {loading && (
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-14 animate-pulse rounded-lg bg-muted/40" />
          ))}
        </div>
      )}

      {!loading && !error && domainEntries.length === 0 && (
        <div className="flex flex-col items-center gap-3 rounded-xl border border-border/60 bg-card py-16 text-center">
          <GitBranch className="h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm font-medium text-muted-foreground">Taxonomy is empty</p>
          <p className="text-xs text-muted-foreground/60">
            Register rules via POST /api/v1/rules/unified to populate the taxonomy.
          </p>
        </div>
      )}

      {!loading && domainEntries.length > 0 && (
        <div className="space-y-3">
          {domainEntries.map(([name, domain]) => (
            <DomainNode key={name} name={name} domain={domain} />
          ))}
        </div>
      )}
    </div>
  );
}
