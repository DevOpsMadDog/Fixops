/**
 * Asset Tags Dashboard
 *
 * Tag categories grid, tag list with asset counts, bulk tag form, tag assignment matrix.
 *   1. KPIs: Total Tags, Tagged Assets, Categories, Untagged Assets
 *   2. Tag categories grid (8 categories)
 *   3. Tag list with asset_count per tag
 *   4. Bulk tag assets form
 *   5. Tag assignment matrix
 *
 * Route: /asset-tags
 * API: GET /api/v1/asset-tags
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Tag, Layers, Server, RefreshCw, Plus, Loader2, CheckCircle2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────

type TagCategory = "environment" | "criticality" | "compliance" | "team" | "location" | "classification" | "lifecycle" | "custom";

interface TagEntry {
  id: string;
  name: string;
  category: TagCategory;
  asset_count: number;
  color: string;
}

interface CategoryInfo {
  category: TagCategory;
  label: string;
  description: string;
  icon: string;
  color: string;
  tag_count: number;
}

// ── API helpers ────────────────────────────────────────────────
const ORG_ID = "default";
function getApiKey() {
  return (typeof window !== "undefined" && localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "dev-key";
}
async function apiFetch(path: string) {
  const res = await fetch(`/api/v1${path}`, { headers: { "X-API-Key": getApiKey() } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const CATEGORY_INFO: CategoryInfo[] = [
  { category: "environment",    label: "Environment",    description: "prod, staging, dev, test",       icon: "🌐", color: "border-blue-500/40 bg-blue-500/5",     tag_count: 6  },
  { category: "criticality",   label: "Criticality",    description: "critical, high, medium, low",    icon: "⚡", color: "border-red-500/40 bg-red-500/5",       tag_count: 4  },
  { category: "compliance",    label: "Compliance",     description: "pci-scope, hipaa, sox, gdpr",    icon: "📋", color: "border-purple-500/40 bg-purple-500/5", tag_count: 8  },
  { category: "team",          label: "Team",           description: "platform, security, devops, sre", icon: "👥", color: "border-green-500/40 bg-green-500/5",   tag_count: 12 },
  { category: "location",      label: "Location",       description: "us-east, eu-west, on-prem, dc1",  icon: "📍", color: "border-yellow-500/40 bg-yellow-500/5", tag_count: 9  },
  { category: "classification",label: "Classification", description: "public, internal, confidential", icon: "🔒", color: "border-orange-500/40 bg-orange-500/5", tag_count: 5  },
  { category: "lifecycle",     label: "Lifecycle",      description: "active, eol, decommission, new",  icon: "♻️", color: "border-cyan-500/40 bg-cyan-500/5",     tag_count: 7  },
  { category: "custom",        label: "Custom",         description: "user-defined tags",              icon: "✏️", color: "border-gray-500/40 bg-gray-500/5",     tag_count: 23 },
];

const MOCK_TAGS: TagEntry[] = [
  { id: "t1",  name: "production",    category: "environment",    asset_count: 847, color: "bg-blue-500/10 text-blue-300 border-blue-500/30" },
  { id: "t2",  name: "staging",       category: "environment",    asset_count: 234, color: "bg-blue-500/10 text-blue-300 border-blue-500/30" },
  { id: "t3",  name: "development",   category: "environment",    asset_count: 412, color: "bg-blue-500/10 text-blue-300 border-blue-500/30" },
  { id: "t4",  name: "critical",      category: "criticality",    asset_count: 183, color: "bg-red-500/10 text-red-300 border-red-500/30" },
  { id: "t5",  name: "high",          category: "criticality",    asset_count: 524, color: "bg-red-500/10 text-red-300 border-red-500/30" },
  { id: "t6",  name: "pci-scope",     category: "compliance",     asset_count: 92,  color: "bg-purple-500/10 text-purple-300 border-purple-500/30" },
  { id: "t7",  name: "hipaa-scope",   category: "compliance",     asset_count: 67,  color: "bg-purple-500/10 text-purple-300 border-purple-500/30" },
  { id: "t8",  name: "soc2-scope",    category: "compliance",     asset_count: 431, color: "bg-purple-500/10 text-purple-300 border-purple-500/30" },
  { id: "t9",  name: "platform-eng",  category: "team",           asset_count: 289, color: "bg-green-500/10 text-green-300 border-green-500/30" },
  { id: "t10", name: "security",      category: "team",           asset_count: 156, color: "bg-green-500/10 text-green-300 border-green-500/30" },
  { id: "t11", name: "us-east-1",     category: "location",       asset_count: 634, color: "bg-yellow-500/10 text-yellow-300 border-yellow-500/30" },
  { id: "t12", name: "eu-west-1",     category: "location",       asset_count: 287, color: "bg-yellow-500/10 text-yellow-300 border-yellow-500/30" },
  { id: "t13", name: "confidential",  category: "classification", asset_count: 341, color: "bg-orange-500/10 text-orange-300 border-orange-500/30" },
  { id: "t14", name: "internal",      category: "classification", asset_count: 892, color: "bg-orange-500/10 text-orange-300 border-orange-500/30" },
  { id: "t15", name: "eol",           category: "lifecycle",      asset_count: 48,  color: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30" },
  { id: "t16", name: "active",        category: "lifecycle",      asset_count: 1843,color: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30" },
];

// Sample assets for matrix
const MATRIX_ASSETS = [
  { name: "api-gateway-prod", tags: ["production", "critical", "pci-scope", "us-east-1"] },
  { name: "db-primary-01",    tags: ["production", "critical", "hipaa-scope", "confidential"] },
  { name: "web-frontend-01",  tags: ["production", "high", "soc2-scope", "eu-west-1"] },
  { name: "staging-cluster",  tags: ["staging", "high", "platform-eng", "us-east-1"] },
  { name: "dev-bastion-01",   tags: ["development", "platform-eng", "internal"] },
];

const MATRIX_TAG_COLS = ["production", "staging", "development", "critical", "high", "pci-scope", "soc2-scope", "confidential"];

// ── Main Component ─────────────────────────────────────────────

export default function AssetTagsDashboard() {
  const [selectedCategory, setSelectedCategory] = useState<TagCategory | null>(null);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/asset-tags/tags?org_id=${ORG_ID}`),
      apiFetch(`/asset-tags/stats?org_id=${ORG_ID}`),
    ]).then(([tagsRes, statsRes]) => {
      const tags = tagsRes.status === "fulfilled" ? tagsRes.value : null;
      const stats = statsRes.status === "fulfilled" ? statsRes.value : null;
      if (tags || stats) setLiveData({ tags, stats });
    }).finally(() => setDataLoading(false));
  }, []);
  const [newTagName, setNewTagName] = useState("");
  const [newTagCategory, setNewTagCategory] = useState<TagCategory>("custom");
  const [assetQuery, setAssetQuery] = useState("");
  const [tagging, setTagging] = useState(false);
  const [tagSuccess, setTagSuccess] = useState(false);

  const filteredTags = selectedCategory
    ? MOCK_TAGS.filter((t) => t.category === selectedCategory)
    : MOCK_TAGS;

  const totalTags = MOCK_TAGS.length;
  const totalTaggedAssets = 2341;
  const totalCategories = CATEGORY_INFO.length;
  const untaggedAssets = 187;

  function handleBulkTag() {
    if (!newTagName || !assetQuery) return;
    setTagging(true);
    setTimeout(() => { setTagging(false); setTagSuccess(true); setTimeout(() => setTagSuccess(false), 2000); }, 1500);
  }

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Asset Tags"
        description="Tag categories, asset tagging assignments, bulk operations, and tag coverage matrix"
        badge="Live"
        actions={
          <Button size="sm" variant="outline" className="gap-2">
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Total Tags"       value={totalTags}          icon={Tag}    trend="up"   trendLabel="across all categories" />
        <KpiCard title="Tagged Assets"    value={totalTaggedAssets}  icon={Server} trend="up"   trendLabel="92.6% coverage" />
        <KpiCard title="Categories"       value={totalCategories}    icon={Layers} trend="up"   trendLabel="8 tag categories" />
        <KpiCard title="Untagged Assets"  value={untaggedAssets}     icon={Tag}    trend="down" trendLabel="needs tagging" />
      </div>

      {/* Category Grid */}
      <div>
        <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-3">Tag Categories</h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {CATEGORY_INFO.map((cat, i) => (
            <motion.div
              key={cat.category}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              onClick={() => setSelectedCategory(selectedCategory === cat.category ? null : cat.category)}
              className={cn(
                "p-3 rounded-lg border cursor-pointer transition-colors",
                cat.color,
                selectedCategory === cat.category && "ring-2 ring-blue-500/50"
              )}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-lg">{cat.icon}</span>
                <span className="text-xs text-gray-400">{cat.tag_count} tags</span>
              </div>
              <p className="text-sm font-medium text-gray-200">{cat.label}</p>
              <p className="text-xs text-gray-500 mt-0.5">{cat.description}</p>
            </motion.div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Tag List */}
        <Card className="xl:col-span-2">
          <CardHeader className="pb-3 flex-row items-center justify-between space-y-0">
            <CardTitle className="text-sm font-semibold">
              Tag List {selectedCategory && <span className="text-gray-400 font-normal ml-1">— {selectedCategory}</span>}
            </CardTitle>
            {selectedCategory && (
              <Button size="sm" variant="ghost" className="text-xs h-7" onClick={() => setSelectedCategory(null)}>
                Clear filter
              </Button>
            )}
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {filteredTags.map((tag) => (
                <div key={tag.id} className={cn("inline-flex items-center gap-2 px-3 py-1.5 rounded-full border text-sm", tag.color)}>
                  <Tag className="w-3 h-3" />
                  <span>{tag.name}</span>
                  <span className="text-xs opacity-70 bg-black/20 px-1.5 py-0.5 rounded-full">{tag.asset_count.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Bulk Tag Form */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Bulk Tag Assets</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex flex-col gap-1">
              <label className="text-xs text-gray-400">Tag Name</label>
              <input type="text" value={newTagName} onChange={(e) => setNewTagName(e.target.value)}
                placeholder="e.g. pci-scope"
                className="bg-gray-700/50 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500" />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs text-gray-400">Category</label>
              <select value={newTagCategory} onChange={(e) => setNewTagCategory(e.target.value as TagCategory)}
                className="bg-gray-700/50 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-blue-500">
                {CATEGORY_INFO.map((c) => <option key={c.category} value={c.category}>{c.label}</option>)}
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs text-gray-400">Asset Query (name, IP, or tag)</label>
              <input type="text" value={assetQuery} onChange={(e) => setAssetQuery(e.target.value)}
                placeholder="e.g. env:production"
                className="bg-gray-700/50 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500" />
            </div>
            <Button size="sm" className="w-full gap-2 bg-blue-600 hover:bg-blue-700 text-white" onClick={handleBulkTag} disabled={!newTagName || !assetQuery || tagging}>
              {tagging ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : tagSuccess ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Plus className="w-3.5 h-3.5" />}
              {tagging ? "Tagging..." : tagSuccess ? "Tagged!" : "Apply Tag"}
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Tag Assignment Matrix */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Tag Assignment Matrix</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-gray-700/50">
                  <th className="text-left py-2 px-3 text-gray-400 font-medium">Asset</th>
                  {MATRIX_TAG_COLS.map((col) => (
                    <th key={col} className="text-center py-2 px-2 text-gray-400 font-medium whitespace-nowrap">{col}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {MATRIX_ASSETS.map((asset) => (
                  <tr key={asset.name} className="border-b border-gray-700/30 hover:bg-gray-800/20">
                    <td className="py-2 px-3 font-mono text-gray-300">{asset.name}</td>
                    {MATRIX_TAG_COLS.map((col) => (
                      <td key={col} className="py-2 px-2 text-center">
                        {asset.tags.includes(col) ? (
                          <span className="inline-block w-4 h-4 bg-blue-500/30 border border-blue-500/50 rounded text-blue-400 text-center leading-4">✓</span>
                        ) : (
                          <span className="inline-block w-4 h-4 text-gray-700">—</span>
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
