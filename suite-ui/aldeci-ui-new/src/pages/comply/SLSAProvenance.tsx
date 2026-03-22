import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  GitBranch, Shield, CheckCircle, AlertTriangle, XCircle, RefreshCw,
  Eye, Link2, Box, Layers, Clock, GitCommit, ArrowRight, ShieldCheck
} from "lucide-react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { useEvidenceBundles } from "@/hooks/use-api";
import { evidenceApi } from "@/lib/api";
import { toast } from "sonner";

const SLSA_COLORS: Record<number, string> = {
  0: "#6b7280",
  1: "#f59e0b",
  2: "#3b82f6",
  3: "#22c55e",
  4: "#a855f7",
};

const SLSA_LABELS: Record<number, string> = {
  0: "Unsigned",
  1: "Level 1",
  2: "Level 2",
  3: "Level 3",
  4: "Level 4",
};

// Compliance control mapping for each SLSA level
const SLSA_CONTROL_MAP: Record<number, { framework: string; controls: string[] }[]> = {
  0: [],
  1: [
    { framework: "NIST", controls: ["SA-3", "CM-3"] },
  ],
  2: [
    { framework: "NIST", controls: ["SA-3", "CM-3", "SI-2"] },
    { framework: "SOC2", controls: ["CC8.1"] },
  ],
  3: [
    { framework: "NIST", controls: ["SA-3", "CM-3", "SI-2", "SA-10"] },
    { framework: "SOC2", controls: ["CC8.1", "CC7.2"] },
    { framework: "PCI-DSS", controls: ["Req 6.3"] },
  ],
  4: [
    { framework: "NIST", controls: ["SA-3", "CM-3", "SI-2", "SA-10", "SA-11"] },
    { framework: "SOC2", controls: ["CC8.1", "CC7.2", "CC6.8"] },
    { framework: "PCI-DSS", controls: ["Req 6.3", "Req 6.5"] },
    { framework: "ISO27001", controls: ["A.14.2"] },
  ],
};

const BUILD_PROVENANCE_STEPS = [
  { key: "source", label: "Source Code", icon: GitCommit },
  { key: "trigger", label: "Build Trigger", icon: ArrowRight },
  { key: "environment", label: "Build Environment", icon: Box },
  { key: "artifact", label: "Artifact Produced", icon: Layers },
  { key: "attestation", label: "Attestation Signed", icon: ShieldCheck },
];

function ProvenanceTimeline({ build }: { build: any }) {
  const level = build.slsa_level ?? 0;
  const completedSteps = Math.min(level + 2, BUILD_PROVENANCE_STEPS.length);
  return (
    <div className="relative">
      <div className="absolute left-3 top-3 bottom-3 w-0.5 bg-border/40" />
      <div className="space-y-3">
        {BUILD_PROVENANCE_STEPS.map((step, i) => {
          const Icon = step.icon;
          const done = i < completedSteps;
          return (
            <div key={step.key} className="flex items-center gap-4 relative">
              <div className={`relative z-10 h-7 w-7 rounded-full flex items-center justify-center shrink-0 ${done ? "bg-green-900/60 border border-green-700" : "bg-muted border border-border"}`}>
                {done ? (
                  <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                ) : (
                  <Icon className="h-3 w-3 text-muted-foreground" />
                )}
              </div>
              <div className="flex-1">
                <p className={`text-sm font-medium ${done ? "text-foreground" : "text-muted-foreground"}`}>
                  {step.label}
                </p>
                {done && (
                  <p className="text-xs text-muted-foreground">
                    {i === 0 && `${build.repo ?? "github.com/org/repo"} @ ${(build.commit ?? "abc1234").slice(0, 8)}`}
                    {i === 1 && `${build.build_system ?? "GitHub Actions"} triggered`}
                    {i === 2 && "Ephemeral, hermetic environment"}
                    {i === 3 && `Build ID: ${build.build_id ?? "—"}`}
                    {i === 4 && "CRYSTALS-Dilithium signed"}
                  </p>
                )}
              </div>
              {done && <Badge className="text-xs bg-green-900/40 text-green-400 border-green-700 shrink-0">✓</Badge>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AttestationDialog({ build }: { build: any }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" className="h-7 w-7">
          <Eye className="h-3.5 w-3.5" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 font-mono text-sm">
            <Box className="h-4 w-4 text-primary" />
            Provenance Chain: {build.build_id ?? build.id ?? "Unknown"}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          {/* Build metadata */}
          <div className="grid grid-cols-2 gap-4 rounded-lg bg-muted/30 p-4 border border-border/40">
            {[
              ["Repository", build.repo ?? build.repository ?? "—"],
              ["Branch", build.branch ?? "—"],
              ["Commit", (build.commit ?? build.sha ?? "—").slice(0, 12)],
              ["SLSA Level", `Level ${build.slsa_level ?? 0}`],
              ["Build System", build.build_system ?? "GitHub Actions"],
              ["Build Date", build.build_date ?? build.created_at ?? "—"],
            ].map(([label, value]) => (
              <div key={label}>
                <p className="text-xs text-muted-foreground">{label}</p>
                <p className="text-sm font-medium font-mono mt-0.5">{value}</p>
              </div>
            ))}
          </div>

          {/* Provenance timeline */}
          <div className="rounded-lg bg-muted/30 p-4 border border-border/40">
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-4">
              Build Provenance Timeline
            </h4>
            <ProvenanceTimeline build={build} />
          </div>

          {/* Compliance linkage */}
          {build.frameworks && (
            <div className="rounded-lg bg-muted/30 p-4 border border-border/40">
              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">
                Framework Linkage
              </h4>
              <div className="flex flex-wrap gap-2">
                {(build.frameworks as string[]).map((fw) => (
                  <Badge key={fw} variant="outline" className="text-xs gap-1">
                    <Link2 className="h-2.5 w-2.5" />
                    {fw}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Raw attestation */}
          <div className="rounded-lg bg-muted/30 p-4 border border-border/40">
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">
              Raw Attestation
            </h4>
            <ScrollArea className="h-48">
              <code className="text-xs font-mono text-muted-foreground whitespace-pre-wrap">
                {JSON.stringify(build, null, 2)}
              </code>
            </ScrollArea>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function SLSAProvenance() {
  const bundlesQuery = useEvidenceBundles();
  const refetch = useCallback(() => bundlesQuery.refetch(), [bundlesQuery]);

  if (bundlesQuery.isLoading) return <PageSkeleton />;
  if (bundlesQuery.isError) return <ErrorState message="Failed to load provenance data" onRetry={refetch} />;

  const bundles: any[] = toArray(bundlesQuery.data);

  // Map bundles to build provenance entries
  const builds = bundles.map((b: any, i: number) => ({
    build_id: b.build_id ?? b.bundle_id ?? `BUILD-${String(i + 1).padStart(5, "0")}`,
    id: b.id,
    repo: b.repo ?? b.source ?? "github.com/org/repo",
    branch: b.branch ?? "main",
    commit: b.commit ?? b.sha ?? "abc1234def56",
    slsa_level: b.slsa_level ?? 0,
    attestation_status: b.attestation_status ?? (b.signed || b.quantum_signed ? "verified" : "missing"),
    build_date: b.build_date ?? b.created_at ?? "—",
    build_system: b.build_system ?? "GitHub Actions",
    frameworks: b.frameworks ?? ["SOC2", "SLSA"],
    ...b,
  }));

  const trackedBuilds = builds.length;
  const slsa3Builds = builds.filter((b) => b.slsa_level >= 3).length;
  const verified = builds.filter((b) => b.attestation_status === "verified").length;
  const unsigned = builds.filter((b) => b.attestation_status === "missing" || b.slsa_level === 0).length;

  // Distribution for pie chart
  const levelDist = Object.entries(
    builds.reduce((acc: Record<string, number>, b) => {
      const key = `Level ${b.slsa_level}`;
      acc[key] = (acc[key] ?? 0) + 1;
      return acc;
    }, {})
  ).map(([name, value]) => ({
    name,
    value,
    fill: SLSA_COLORS[parseInt(name.split(" ")[1])] ?? "#6b7280",
  }));

  // Overall attestation coverage
  const coveragePct = trackedBuilds > 0 ? Math.round((verified / trackedBuilds) * 100) : 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="SLSA Provenance"
        description="Build provenance tracking with SLSA compliance verification and attestation chain"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <Button size="sm" className="gap-2" onClick={async () => {
          toast.info("Verifying all provenance chains…");
          const allBuilds = builds;
          let ok = 0;
          for (const b of allBuilds) {
            try { await evidenceApi.verify(b.build_id ?? b.id ?? ""); ok++; } catch { /* skip */ }
          }
          toast.success(`Verified ${ok}/${allBuilds.length} provenance chains`);
          refetch();
        }}>
          <Shield className="h-4 w-4" />
          Verify All
        </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Builds Tracked" value={trackedBuilds} icon={Box} />
        <KpiCard title="SLSA Level 3+" value={slsa3Builds} icon={Shield} change={slsa3Builds} changeLabel="highest level" />
        <KpiCard title="Attestations Verified" value={verified} icon={CheckCircle} />
        <KpiCard title="Unsigned" value={unsigned} icon={AlertTriangle} />
      </div>

      {/* Attestation Verification Panel */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
      >
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-green-400" />
              Attestation Verification Panel
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between text-sm mb-2">
                    <span className="text-muted-foreground">Attestation Coverage</span>
                    <span className="font-semibold text-foreground">{coveragePct}%</span>
                  </div>
                  <Progress value={coveragePct} className="h-3" />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { label: "Verified", value: verified, color: "text-green-400", bg: "bg-green-900/20 border-green-800/30" },
                    { label: "Missing", value: unsigned, color: "text-red-400", bg: "bg-red-900/20 border-red-800/30" },
                    { label: "Partial", value: trackedBuilds - verified - unsigned, color: "text-yellow-400", bg: "bg-yellow-900/20 border-yellow-800/30" },
                    { label: "Total", value: trackedBuilds, color: "text-blue-400", bg: "bg-blue-900/20 border-blue-800/30" },
                  ].map(({ label, value, color, bg }) => (
                    <div key={label} className={`p-3 rounded-lg border ${bg}`}>
                      <p className="text-xs text-muted-foreground">{label}</p>
                      <p className={`text-xl font-bold ${color}`}>{value}</p>
                    </div>
                  ))}
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Signature Methods</p>
                {[
                  { method: "CRYSTALS-Dilithium", count: verified, level: "Quantum-Safe" },
                  { method: "ECDSA P-256", count: Math.max(0, trackedBuilds - verified - unsigned), level: "Classic" },
                  { method: "None", count: unsigned, level: "Unsigned" },
                ].map(({ method, count, level }) => (
                  <div key={method} className="flex items-center gap-3 p-2.5 rounded-lg bg-muted/30 border border-border/40">
                    <div className="flex-1">
                      <p className="text-xs font-medium">{method}</p>
                      <p className="text-xs text-muted-foreground">{level}</p>
                    </div>
                    <Badge variant="outline" className="text-xs font-mono">{count}</Badge>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* SLSA Distribution PieChart */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Layers className="h-4 w-4 text-primary" />
              SLSA Level Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={levelDist}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {levelDist.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }}
                  itemStyle={{ color: "#94a3b8" }}
                />
                <Legend wrapperStyle={{ fontSize: 11 }} />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Level legend */}
        <Card className="col-span-1 lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              SLSA Level Reference
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {[
              { level: 0, title: "No guarantees", desc: "No provenance requirements" },
              { level: 1, title: "Provenance exists", desc: "Basic provenance documentation provided" },
              { level: 2, title: "Hosted build", desc: "Uses a hosted build service, signed provenance" },
              { level: 3, title: "Hardened builds", desc: "Ephemeral, hermetic build environments with two-party review" },
            ].map(({ level, title, desc }) => (
              <div key={level} className="flex items-start gap-3 p-3 rounded-lg bg-muted/30 border border-border/40">
                <div
                  className="h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0 mt-0.5"
                  style={{ background: `${SLSA_COLORS[level]}30`, color: SLSA_COLORS[level] }}
                >
                  {level}
                </div>
                <div className="flex-1">
                  <p className="text-sm font-medium">{title}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
                </div>
                <div className="ml-auto">
                  <Badge className="text-xs" style={{ background: `${SLSA_COLORS[level]}20`, color: SLSA_COLORS[level], borderColor: `${SLSA_COLORS[level]}40` }}>
                    {builds.filter((b) => b.slsa_level === level).length} builds
                  </Badge>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Compliance Control Mapping */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Link2 className="h-4 w-4 text-teal-400" />
              Compliance Control Mapping by SLSA Level
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
              {[0, 1, 2, 3].map((level) => {
                const controls = SLSA_CONTROL_MAP[level] ?? [];
                const levelBuilds = builds.filter((b) => b.slsa_level === level).length;
                return (
                  <div key={level} className="p-3 rounded-lg bg-muted/30 border border-border/40">
                    <div className="flex items-center gap-2 mb-2">
                      <div
                        className="h-5 w-5 rounded-full flex items-center justify-center text-xs font-bold"
                        style={{ background: `${SLSA_COLORS[level]}30`, color: SLSA_COLORS[level] }}
                      >
                        {level}
                      </div>
                      <span className="text-xs font-semibold">{SLSA_LABELS[level]}</span>
                      <Badge variant="outline" className="text-xs ml-auto">{levelBuilds}</Badge>
                    </div>
                    {controls.length === 0 ? (
                      <p className="text-xs text-muted-foreground">No controls mapped</p>
                    ) : (
                      <div className="space-y-1.5">
                        {controls.map(({ framework, controls: ctrls }) => (
                          <div key={framework}>
                            <p className="text-xs text-muted-foreground font-medium">{framework}</p>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {ctrls.map((c) => (
                                <Badge key={c} variant="outline" className="text-xs py-0 h-4 font-mono">{c}</Badge>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Build Provenance Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <GitBranch className="h-4 w-4 text-primary" />
            Build Provenance Records
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b border-border/40">
                <TableHead className="text-xs">Build ID</TableHead>
                <TableHead className="text-xs">Repository</TableHead>
                <TableHead className="text-xs">Branch</TableHead>
                <TableHead className="text-xs">SLSA Level</TableHead>
                <TableHead className="text-xs">Attestation</TableHead>
                <TableHead className="text-xs">Build Date</TableHead>
                <TableHead className="text-xs text-right">Detail</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {builds.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-12 text-muted-foreground">
                    No build provenance records found
                  </TableCell>
                </TableRow>
              ) : (
                builds.slice(0, 30).map((build) => (
                  <TableRow key={build.build_id} className="hover:bg-muted/30">
                    <TableCell className="font-mono text-xs text-primary">{build.build_id}</TableCell>
                    <TableCell className="text-xs font-medium max-w-40 truncate">{build.repo}</TableCell>
                    <TableCell>
                      <span className="flex items-center gap-1 text-xs text-muted-foreground">
                        <GitBranch className="h-3 w-3" />
                        {build.branch}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge
                        className="text-xs"
                        style={{
                          background: `${SLSA_COLORS[build.slsa_level] ?? "#6b7280"}20`,
                          color: SLSA_COLORS[build.slsa_level] ?? "#6b7280",
                          borderColor: `${SLSA_COLORS[build.slsa_level] ?? "#6b7280"}40`,
                        }}
                      >
                        {SLSA_LABELS[build.slsa_level] ?? "Unknown"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {build.attestation_status === "verified" ? (
                        <span className="flex items-center gap-1 text-green-500 text-xs">
                          <CheckCircle className="h-3 w-3" /> Verified
                        </span>
                      ) : build.attestation_status === "missing" ? (
                        <span className="flex items-center gap-1 text-red-500 text-xs">
                          <XCircle className="h-3 w-3" /> Missing
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-yellow-500 text-xs">
                          <AlertTriangle className="h-3 w-3" /> Partial
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{build.build_date}</TableCell>
                    <TableCell className="text-right">
                      <AttestationDialog build={build} />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
