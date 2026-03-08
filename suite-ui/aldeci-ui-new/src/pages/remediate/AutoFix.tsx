import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import {
  Code2, GitPullRequest, CheckCircle2, XCircle, Clock,
  Zap, BarChart3, Eye, ThumbsUp, GitBranch, ChevronRight
} from "lucide-react";
import { remediationApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
type FixStatus = "pending_review" | "approved" | "rejected" | "applied" | "generating";
type FixConfidence = "High" | "Medium" | "Low";

interface AutoFixCard {
  id: string;
  findingId: string;
  title: string;
  component: string;
  language: string;
  fixType: string;
  confidence: number;
  confidenceLabel: FixConfidence;
  status: FixStatus;
  prNumber?: number;
  prBranch?: string;
  changedFiles: number;
  linesAdded: number;
  linesRemoved: number;
  historicSuccessRate: number;
  generatedAt: string;
  reviewer?: string;
}

interface DiffLine {
  type: "context" | "added" | "removed" | "header";
  content: string;
}

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_FIXES: AutoFixCard[] = [
  { id: "af-1", findingId: "FIND-8821", title: "Upgrade log4j-core to 2.17.2", component: "logging-service", language: "Java", fixType: "Dependency Bump", confidence: 97, confidenceLabel: "High", status: "pending_review", prNumber: 447, prBranch: "autofix/log4j-upgrade-8821", changedFiles: 2, linesAdded: 3, linesRemoved: 3, historicSuccessRate: 99, generatedAt: "14:22" },
  { id: "af-2", findingId: "FIND-8801", title: "Add SSRF allowlist validation in PaymentClient", component: "payment-svc", language: "Java", fixType: "Code Patch", confidence: 82, confidenceLabel: "High", status: "pending_review", prNumber: 448, prBranch: "autofix/ssrf-payment-8801", changedFiles: 1, linesAdded: 18, linesRemoved: 4, historicSuccessRate: 84, generatedAt: "14:31" },
  { id: "af-3", findingId: "FIND-8690", title: "Bump spring-webmvc to 5.3.26", component: "api-gateway", language: "Java", fixType: "Dependency Bump", confidence: 99, confidenceLabel: "High", status: "approved", prNumber: 441, prBranch: "autofix/spring-upgrade-8690", changedFiles: 1, linesAdded: 1, linesRemoved: 1, historicSuccessRate: 99, generatedAt: "Yesterday", reviewer: "a.patel@corp" },
  { id: "af-4", findingId: "FIND-8540", title: "Bump lodash to 4.17.21", component: "web-app-frontend", language: "TypeScript", fixType: "Dependency Bump", confidence: 96, confidenceLabel: "High", status: "applied", prNumber: 432, prBranch: "autofix/lodash-bump-8540", changedFiles: 2, linesAdded: 2, linesRemoved: 2, historicSuccessRate: 98, generatedAt: "2d ago", reviewer: "j.kim@corp" },
  { id: "af-5", findingId: "FIND-8470", title: "Replace Java ObjectInputStream with SafeObjectInputStream", component: "message-broker", language: "Java", fixType: "Code Patch", confidence: 61, confidenceLabel: "Medium", status: "generating", prNumber: undefined, prBranch: undefined, changedFiles: 0, linesAdded: 0, linesRemoved: 0, historicSuccessRate: 72, generatedAt: "Now" },
  { id: "af-6", findingId: "FIND-8622", title: "Add BasicAuth middleware to Prometheus endpoint", component: "metrics-exporter", language: "Go", fixType: "Code Patch", confidence: 78, confidenceLabel: "Medium", status: "rejected", prNumber: 438, prBranch: "autofix/prometheus-auth-8622", changedFiles: 3, linesAdded: 24, linesRemoved: 0, historicSuccessRate: 68, generatedAt: "3d ago", reviewer: "l.muller@corp" },
];

const MOCK_DIFF: DiffLine[] = [
  { type: "header",  content: "@@ -42,8 +42,8 @@ dependencies {" },
  { type: "context", content: "    implementation 'org.springframework.boot:spring-boot-starter-web'" },
  { type: "context", content: "    implementation 'com.fasterxml.jackson.core:jackson-databind:2.14.2'" },
  { type: "removed", content: "-   implementation 'org.apache.logging.log4j:log4j-core:2.14.1'" },
  { type: "removed", content: "-   implementation 'org.apache.logging.log4j:log4j-api:2.14.1'" },
  { type: "added",   content: "+   implementation 'org.apache.logging.log4j:log4j-core:2.17.2'" },
  { type: "added",   content: "+   implementation 'org.apache.logging.log4j:log4j-api:2.17.2'" },
  { type: "context", content: "    testImplementation 'org.springframework.boot:spring-boot-starter-test'" },
  { type: "header",  content: "@@ -88,5 +88,5 @@ ext {" },
  { type: "context", content: "    set('springCloudVersion', '2022.0.1')" },
  { type: "removed", content: "-   set('log4jVersion', '2.14.1')" },
  { type: "added",   content: "+   set('log4jVersion', '2.17.2')" },
  { type: "context", content: "}" },
];

// ── Fix Status Config ──────────────────────────────────────────────────────
const statusConfig: Record<FixStatus, { label: string; cls: string }> = {
  pending_review: { label: "Pending Review", cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30" },
  approved:       { label: "Approved",       cls: "bg-green-500/10 text-green-400 border-green-500/30" },
  rejected:       { label: "Rejected",       cls: "bg-red-500/10 text-red-400 border-red-500/30" },
  applied:        { label: "Applied",        cls: "bg-primary/10 text-primary border-primary/30" },
  generating:     { label: "Generating...",  cls: "bg-blue-500/10 text-blue-400 border-blue-500/30" },
};

const confConfig: Record<FixConfidence, string> = {
  High:   "text-green-400",
  Medium: "text-yellow-400",
  Low:    "text-red-400",
};

// ── Diff View ──────────────────────────────────────────────────────────────
function DiffView({ lines }: { lines: DiffLine[] }) {
  return (
    <div className="rounded-lg border border-border/50 overflow-hidden bg-[hsl(var(--card))] font-mono text-xs">
      <div className="bg-muted/20 border-b border-border/50 px-3 py-1.5 text-xs text-muted-foreground flex items-center gap-2">
        <Code2 className="h-3 w-3" /> build.gradle
      </div>
      {lines.map((line, i) => (
        <div key={i} className={`flex gap-3 px-3 py-0.5 leading-5 ${
          line.type === "added"   ? "bg-green-500/10 text-green-300" :
          line.type === "removed" ? "bg-red-500/10 text-red-300" :
          line.type === "header"  ? "bg-blue-500/5 text-blue-400" :
          "text-muted-foreground"
        }`}>
          <span className="select-none w-3 shrink-0 text-muted-foreground/50">
            {line.type === "added" ? "+" : line.type === "removed" ? "-" : " "}
          </span>
          <span className="whitespace-pre">{line.content}</span>
        </div>
      ))}
    </div>
  );
}

// ── Fix Detail Panel ───────────────────────────────────────────────────────
function FixDetailPanel({ fix, onApprove, onReject }: {
  fix: AutoFixCard;
  onApprove: (id: string) => void;
  onReject: (id: string) => void;
}) {
  return (
    <Card className="border-border/50 h-full flex flex-col">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <div>
            <CardTitle className="text-sm font-semibold">{fix.title}</CardTitle>
            <CardDescription className="text-xs mt-0.5">{fix.component} · {fix.language} · {fix.fixType}</CardDescription>
          </div>
          <span className={`inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-xs font-medium ${statusConfig[fix.status].cls}`}>{statusConfig[fix.status].label}</span>
        </div>
      </CardHeader>
      <CardContent className="flex-1 space-y-4 overflow-y-auto">
        {/* Confidence + PR info */}
        <div className="grid grid-cols-3 gap-3">
          <div className="rounded-lg bg-muted/30 p-3 text-center">
            <p className={`text-2xl font-bold tabular-nums ${confConfig[fix.confidenceLabel]}`}>{fix.confidence}%</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">AI Confidence</p>
          </div>
          <div className="rounded-lg bg-muted/30 p-3 text-center">
            <p className="text-2xl font-bold tabular-nums text-green-400">{fix.historicSuccessRate}%</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">Historical Success</p>
          </div>
          <div className="rounded-lg bg-muted/30 p-3 text-center">
            <p className="text-sm font-bold">{fix.changedFiles} file{fix.changedFiles !== 1 ? "s" : ""}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5 text-green-400">+{fix.linesAdded} <span className="text-red-400">-{fix.linesRemoved}</span></p>
          </div>
        </div>

        {fix.prNumber && (
          <div className="flex items-center gap-2 rounded-lg border border-border/50 p-3">
            <GitPullRequest className="h-4 w-4 text-primary shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium">PR #{fix.prNumber}</p>
              <p className="text-[10px] font-mono text-muted-foreground truncate">{fix.prBranch}</p>
            </div>
            <Button size="sm" variant="ghost" className="h-6 text-xs">
              <Eye className="h-3 w-3 mr-1" /> View
            </Button>
          </div>
        )}

        {fix.status === "generating" ? (
          <div className="space-y-2 py-4 text-center">
            <div className="animate-pulse flex justify-center">
              <Code2 className="h-8 w-8 text-primary" />
            </div>
            <p className="text-sm text-muted-foreground">AST analysis in progress...</p>
            <Progress value={42} className="h-1.5" />
          </div>
        ) : (
          <DiffView lines={MOCK_DIFF} />
        )}

        {(fix.status === "pending_review") && (
          <div className="flex gap-2 pt-2">
            <Button size="sm" className="flex-1" onClick={() => onApprove(fix.id)}>
              <ThumbsUp className="h-3.5 w-3.5 mr-1.5" /> Approve & Merge
            </Button>
            <Button size="sm" variant="destructive" className="flex-1" onClick={() => onReject(fix.id)}>
              <XCircle className="h-3.5 w-3.5 mr-1.5" /> Reject
            </Button>
          </div>
        )}
        {fix.reviewer && (
          <p className="text-xs text-muted-foreground text-center">Reviewed by {fix.reviewer}</p>
        )}
      </CardContent>
    </Card>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function AutoFix() {
  const queryClient = useQueryClient();
  const [selectedFix, setSelectedFix] = useState<AutoFixCard>(MOCK_FIXES[0]);

  const { data } = useQuery({
    queryKey: ["autofix-list"],
    queryFn: () => remediationApi.list({ type: "autofix" }),
    refetchInterval: 15_000,
  });

  const approveMutation = useMutation({
    mutationFn: (id: string) => remediationApi.update(id, { status: "approved" }),
    onSuccess: () => { toast.success("Fix approved — merging PR"); queryClient.invalidateQueries({ queryKey: ["autofix-list"] }); },
    onError: () => toast.error("Approval failed"),
  });

  const rejectMutation = useMutation({
    mutationFn: (id: string) => remediationApi.update(id, { status: "rejected" }),
    onSuccess: () => { toast.info("Fix rejected"); queryClient.invalidateQueries({ queryKey: ["autofix-list"] }); },
    onError: () => toast.error("Rejection failed"),
  });

  const fixes: AutoFixCard[] = (data as any)?.data ?? MOCK_FIXES;
  const pendingCount  = fixes.filter(f => f.status === "pending_review").length;
  const appliedCount  = fixes.filter(f => f.status === "applied").length;
  const avgConfidence = Math.round(fixes.filter(f => f.confidence > 0).reduce((s, f) => s + f.confidence, 0) / fixes.filter(f => f.confidence > 0).length);
  const avgSuccess    = Math.round(fixes.reduce((s, f) => s + f.historicSuccessRate, 0) / fixes.length);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="AutoFix"
        description="AST-based fix generation — review AI-generated patches and approve PRs with confidence scoring"
        badge="REMEDIATE"
        actions={
          <Badge variant="outline" className="border-primary/40 text-primary">
            {pendingCount} pending review
          </Badge>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Pending Review" value={pendingCount} icon={GitPullRequest} trend="flat" />
        <KpiCard title="Applied" value={appliedCount} icon={CheckCircle2} trend="up" change={8} changeLabel="this sprint" />
        <KpiCard title="Avg Confidence" value={`${avgConfidence}%`} icon={BarChart3} trend="up" change={3} changeLabel="vs last month" />
        <KpiCard title="Historical Success" value={`${avgSuccess}%`} icon={Zap} trend="up" change={2} changeLabel="vs last quarter" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        {/* Fix list */}
        <div className="xl:col-span-2 space-y-2">
          {fixes.map(fix => (
            <Card
              key={fix.id}
              className={`border-border/50 cursor-pointer transition-all hover:border-primary/40 ${selectedFix.id === fix.id ? "border-primary/60 bg-primary/5" : ""}`}
              onClick={() => setSelectedFix(fix)}
            >
              <CardContent className="p-4 space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium line-clamp-1">{fix.title}</p>
                    <p className="text-xs text-muted-foreground mt-0.5 font-mono">{fix.findingId} · {fix.component}</p>
                  </div>
                  <span className={`shrink-0 inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium ${statusConfig[fix.status].cls}`}>{statusConfig[fix.status].label}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className={`font-bold ${confConfig[fix.confidenceLabel]}`}>{fix.confidence}% confidence</span>
                  <span className="text-muted-foreground">{fix.language} · {fix.fixType}</span>
                </div>
                {fix.status !== "generating" && (
                  <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                    <span className="flex items-center gap-0.5"><GitBranch className="h-2.5 w-2.5" /> PR #{fix.prNumber}</span>
                    <span className="text-green-400">+{fix.linesAdded}</span>
                    <span className="text-red-400">-{fix.linesRemoved}</span>
                    <span>{fix.changedFiles} file{fix.changedFiles !== 1 ? "s" : ""}</span>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Detail panel */}
        <div className="xl:col-span-3">
          <FixDetailPanel
            fix={selectedFix}
            onApprove={(id) => approveMutation.mutate(id)}
            onReject={(id) => rejectMutation.mutate(id)}
          />
        </div>
      </div>
    </motion.div>
  );
}
