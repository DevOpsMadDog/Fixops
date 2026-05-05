/**
 * RulesCatalogHub — Policies & Rules unified hero (Rules sub-cluster)
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 4 standalone rule-authoring / catalog pages into a single tabbed
 * hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.26 (S26 Policies &
 * Rules — Rules / DSL sub-cluster).
 *
 *   tab        | source page              | endpoint
 *   -----------|--------------------------|--------------------------------------------------
 *   catalog    | UnifiedRulesCatalog      | /api/v1/rules/unified
 *   taxonomy   | RuleTaxonomyInspector    | /api/v1/rules/unified/taxonomy
 *   author     | RuleDSLAuthoringStudio   | /api/v1/rules/dsl + /api/v1/rules/dsl/schema
 *   validate   | RuleDSLValidator         | POST /api/v1/rules/dsl/validate
 *
 * Route: /comply/rules
 * Persona target: Security Architect (#11), AppSec Engineer (#10), GRC Analyst (#12)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.26
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ListChecks, GitBranch, Code2, CheckCircle2 } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "catalog" | "taxonomy" | "author" | "validate";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "catalog",
    label: "Catalog",
    icon: ListChecks,
    description:
      "Browse and toggle every rule across all sub-engines from a single catalog (Folded from UnifiedRulesCatalog).",
  },
  {
    key: "taxonomy",
    label: "Taxonomy",
    icon: GitBranch,
    description:
      "Hierarchical view of rule categories → sub-categories → keys (Folded from RuleTaxonomyInspector).",
  },
  {
    key: "author",
    label: "DSL Studio",
    icon: Code2,
    description:
      "Author and publish DSL rules with live schema-driven hints (Folded from RuleDSLAuthoringStudio).",
  },
  {
    key: "validate",
    label: "DSL Validator",
    icon: CheckCircle2,
    description:
      "Paste DSL text and check the parser/AST result before publishing (Folded from RuleDSLValidator).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function RulesCatalogHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "catalog";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /rules/catalog → /comply/rules?tab=catalog) work.
  useEffect(() => {
    if (params.get("tab") !== tab) {
      const next = new URLSearchParams(params);
      next.set("tab", tab);
      setParams(next, { replace: true });
    }
  }, [tab, params, setParams]);

  // React when query string changes (e.g. user clicks an old link in another tab).
  useEffect(() => {
    const incoming = params.get("tab");
    if (isTabKey(incoming) && incoming !== tab) setTab(incoming);
  }, [params, tab]);

  const activeMeta = useMemo(() => TABS.find(t => t.key === tab) ?? TABS[0], [tab]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Rules Catalog & DSL Studio"
        description="Unified rule workspace — browse the catalog, inspect taxonomy, and author / validate DSL rules."
        badge={activeMeta.label}
      />

      <Tabs value={tab} onValueChange={v => setTab(v as TabKey)} className="w-full">
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="text-xs gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <p className="text-xs text-muted-foreground mt-2 mb-1">{activeMeta.description}</p>

        <TabsContent value="catalog">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="taxonomy">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="author">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="validate">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
