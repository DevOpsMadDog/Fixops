import { useState, useEffect, useCallback } from "react";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { motion } from "framer-motion";
import {
  Brain, Cpu, CheckCircle, AlertTriangle, Clock,
  BarChart3, RefreshCw, Activity, Zap, MessageSquare,
  Shield, ThumbsUp, ThumbsDown, Scale, Settings
} from "lucide-react";
import { apiClient, toArray } from "@/lib/api-utils";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface LLMProvider {
  id: string;
  name: string;
  model: string;
  status: string;
  latency_ms: number;
  cost_per_1k: number;
  accuracy: number;
  total_decisions: number;
}

interface ConsensusDecision {
  id: string;
  finding_id: string;
  action: string;
  confidence: number;
  votes: { provider: string; action: string; reasoning: string; confidence: number }[];
  consensus_reached: boolean;
  timestamp: string;
}

export default function MultiLLM() {
  const [providers, setProviders] = useState<LLMProvider[]>([]);
  const [decisions, setDecisions] = useState<ConsensusDecision[]>([]);
  const [llmHealth, setLlmHealth] = useState<Record<string, unknown>>({});
  const [agentStatus, setAgentStatus] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [provRes, decRes, healthRes, agentRes] = await Promise.allSettled([
        apiClient("/api/v1/llm/providers"),
        apiClient("/api/v1/analytics/decisions"),
        apiClient("/api/v1/llm/health"),
        apiClient("/api/v1/ai-agent/status"),
      ]);
      if (provRes.status === "fulfilled") {
        const raw = provRes.value;
        setProviders(toArray(raw?.providers ?? raw));
      }
      if (decRes.status === "fulfilled") setDecisions(toArray(decRes.value).slice(0, 30) as unknown as ConsensusDecision[]);
      if (healthRes.status === "fulfilled") setLlmHealth(healthRes.value ?? {});
      if (agentRes.status === "fulfilled") setAgentStatus(agentRes.value ?? {});
    } catch { /* handled */ } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  if (loading) return <PageSkeleton />;

  const totalDecisions = decisions.length || Number(agentStatus?.total_decisions ?? 0);
  const consensusRate = decisions.filter(d => d.consensus_reached !== false).length / Math.max(decisions.length, 1) * 100;
  const activeProviders = providers.filter(p => p.status === "active").length;

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Multi-LLM Consensus"
        description="Security decisions made by committee — 3+ LLMs must agree before action is taken"
        badge="AI Engine"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={fetchData}><RefreshCw className="h-4 w-4 mr-1" />Refresh</Button>
            <Button size="sm" onClick={async () => {
              try {
                await apiClient("/api/v1/llm/test", { method: "POST", body: JSON.stringify({ prompt: "Triage CVE-2024-3094: critical xz-utils backdoor" }) });
                toast.success("LLM test completed");
                fetchData();
              } catch (e: unknown) { toast.error(`Test failed: ${e instanceof Error ? e.message : ""}`); }
            }}><Zap className="h-4 w-4 mr-1" />Test Consensus</Button>
          </div>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active Providers" value={activeProviders} icon={Cpu} trend="up" trendLabel={`${providers.length} configured`} />
        <KpiCard title="Total Decisions" value={totalDecisions.toLocaleString()} icon={Scale} trend="up" trendLabel="All time" />
        <KpiCard title="Consensus Rate" value={`${consensusRate.toFixed(1)}%`} icon={CheckCircle} trend={consensusRate > 85 ? "up" : "down"} trendLabel="Agreement" />
        <KpiCard title="Avg Latency" value={`${Math.round(providers.reduce((s, p) => s + (p.latency_ms || 0), 0) / Math.max(providers.length, 1)) || 0}ms`} icon={Clock} trend="flat" trendLabel="Response time" />
      </div>

      {/* Provider Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {providers.map((provider, idx) => (
          <motion.div key={provider.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.05 }}>
            <Card className={cn("transition-all", provider.status === "active" ? "border-emerald-500/30" : "border-border/50 opacity-70")}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <div className={cn("p-1.5 rounded-md", provider.status === "active" ? "bg-emerald-500/10 text-emerald-400" : "bg-muted text-muted-foreground")}>
                      <Cpu className="h-4 w-4" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold">{provider.name}</p>
                      <p className="text-[10px] text-muted-foreground font-mono">{provider.model}</p>
                    </div>
                  </div>
                  <Badge variant={provider.status === "active" ? "default" : "outline"} className="text-[10px]">{provider.status}</Badge>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-xs"><span className="text-muted-foreground">Accuracy</span><span className="font-medium">{provider.accuracy}%</span></div>
                  <Progress value={provider.accuracy} className="h-1" />
                  <div className="flex justify-between text-xs"><span className="text-muted-foreground">Latency</span><span className="font-medium">{provider.latency_ms || 0}ms</span></div>
                  <div className="flex justify-between text-xs"><span className="text-muted-foreground">Cost/1K</span><span className="font-medium">${provider.cost_per_1k}</span></div>
                  <div className="flex justify-between text-xs"><span className="text-muted-foreground">Decisions</span><span className="font-medium">{(provider.total_decisions ?? 0).toLocaleString()}</span></div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      <Tabs defaultValue="decisions" className="space-y-4">
        <TabsList>
          <TabsTrigger value="decisions">Recent Decisions</TabsTrigger>
          <TabsTrigger value="comparison">Model Comparison</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>

        <TabsContent value="decisions">
          <Card>
            <CardContent className="p-0">
              <ScrollArea className="h-[400px]">
                <div className="divide-y divide-border/50">
                  {decisions.length === 0 && (
                    <div className="p-8 text-center text-muted-foreground">
                      <Scale className="h-12 w-12 mx-auto mb-3 opacity-40" />
                      <p className="text-sm font-medium">No consensus decisions yet</p>
                      <p className="text-xs mt-1">Run the Brain Pipeline to generate multi-LLM decisions</p>
                    </div>
                  )}
                  {decisions.map((d, i) => (
                    <div key={d.id || i} className="p-4 hover:bg-accent/30 transition-colors">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Badge variant={d.action === "fix" ? "destructive" : d.action === "accept" ? "default" : "secondary"}>{d.action || "triage"}</Badge>
                          <span className="text-sm font-medium">{d.finding_id || `Finding ${i + 1}`}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-muted-foreground">{d.confidence ? `${(d.confidence * 100).toFixed(0)}% confidence` : ""}</span>
                          {d.consensus_reached !== false ? <CheckCircle className="h-3.5 w-3.5 text-emerald-400" /> : <AlertTriangle className="h-3.5 w-3.5 text-yellow-400" />}
                        </div>
                      </div>
                      {d.votes && d.votes.length > 0 && (
                        <div className="flex gap-2 mt-2">
                          {d.votes.map((v, vi) => (
                            <div key={vi} className="text-[10px] px-2 py-1 rounded bg-muted">
                              <span className="font-medium">{v.provider}</span>: {v.action} ({v.confidence ? `${(v.confidence * 100).toFixed(0)}%` : "—"})
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="comparison">
          <Card>
            <CardContent className="p-6">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border/50">
                      <th className="text-left py-2 px-3 text-muted-foreground font-medium">Provider</th>
                      <th className="text-right py-2 px-3 text-muted-foreground font-medium">Accuracy</th>
                      <th className="text-right py-2 px-3 text-muted-foreground font-medium">Latency</th>
                      <th className="text-right py-2 px-3 text-muted-foreground font-medium">Cost/1K</th>
                      <th className="text-right py-2 px-3 text-muted-foreground font-medium">Decisions</th>
                      <th className="text-right py-2 px-3 text-muted-foreground font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {providers.map(p => (
                      <tr key={p.id} className="border-b border-border/30 hover:bg-accent/20">
                        <td className="py-2 px-3 font-medium">{p.name}</td>
                        <td className="py-2 px-3 text-right">{p.accuracy}%</td>
                        <td className="py-2 px-3 text-right">{p.latency_ms}ms</td>
                        <td className="py-2 px-3 text-right">${p.cost_per_1k}</td>
                        <td className="py-2 px-3 text-right">{(p.total_decisions ?? 0).toLocaleString()}</td>
                        <td className="py-2 px-3 text-right"><Badge variant={p.status === "active" ? "default" : "outline"} className="text-[10px]">{p.status}</Badge></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="settings">
          <Card>
            <CardContent className="p-6 space-y-4">
              {[
                { label: "Minimum Consensus", desc: "Require at least N providers to agree", value: "3 of 4" },
                { label: "Confidence Threshold", desc: "Minimum confidence for auto-action", value: "85%" },
                { label: "Timeout", desc: "Max wait for slowest provider", value: "30s" },
                { label: "Fallback Strategy", desc: "When consensus fails", value: "Escalate to human" },
                { label: "Cost Cap", desc: "Max monthly LLM spend", value: "$5,000" },
                { label: "Retry Policy", desc: "On provider failure", value: "2 retries, 5s backoff" },
              ].map(s => (
                <div key={s.label} className="flex items-center justify-between p-3 border border-border/50 rounded-lg">
                  <div><p className="text-sm font-medium">{s.label}</p><p className="text-xs text-muted-foreground">{s.desc}</p></div>
                  <Badge variant="outline">{s.value}</Badge>
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
