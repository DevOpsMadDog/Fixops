import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  ChevronRight,
  ChevronDown,
  FileCheck,
  ShieldCheck,
  Eye,
  ExternalLink,
  Lock,
  Users,
  Activity,
  AlertCircle,
  CheckCircle2,
  Circle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { complianceApi, evidenceApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock Data ───────────────────────────────────────────────────────────────

interface SOC2Control {
  id: string;
  category: string;
  categoryCode: string;
  name: string;
  description: string;
  evidenceCount: number;
  evidenceRequired: number;
  status: "complete" | "partial" | "missing";
  linkedBundles: string[];
}

interface SOC2Category {
  code: string;
  name: string;
  icon: React.ElementType;
  controls: SOC2Control[];
}

const MOCK_SOC2_CATEGORIES: SOC2Category[] = [
  {
    code: "CC1",
    name: "Control Environment",
    icon: ShieldCheck,
    controls: [
      {
        id: "CC1.1", category: "Control Environment", categoryCode: "CC1",
        name: "COSO Principle 1 — Board Oversight",
        description: "The entity demonstrates a commitment to integrity and ethical values.",
        evidenceCount: 3, evidenceRequired: 3, status: "complete",
        linkedBundles: ["EVB-2025-001", "EVB-2025-004"],
      },
      {
        id: "CC1.2", category: "Control Environment", categoryCode: "CC1",
        name: "COSO Principle 2 — Board Independence",
        description: "The board of directors demonstrates independence from management.",
        evidenceCount: 2, evidenceRequired: 2, status: "complete",
        linkedBundles: ["EVB-2025-001"],
      },
      {
        id: "CC1.3", category: "Control Environment", categoryCode: "CC1",
        name: "COSO Principle 3 — Management Structure",
        description: "Management establishes, with board oversight, structures, reporting lines, and authorities.",
        evidenceCount: 1, evidenceRequired: 3, status: "partial",
        linkedBundles: ["EVB-2025-004"],
      },
    ],
  },
  {
    code: "CC2",
    name: "Communication & Information",
    icon: Activity,
    controls: [
      {
        id: "CC2.1", category: "Communication & Information", categoryCode: "CC2",
        name: "Information Quality",
        description: "The entity obtains or generates and uses relevant, quality information.",
        evidenceCount: 4, evidenceRequired: 4, status: "complete",
        linkedBundles: ["EVB-2025-002", "EVB-2025-006"],
      },
      {
        id: "CC2.2", category: "Communication & Information", categoryCode: "CC2",
        name: "Internal Communication",
        description: "Internal communications support the functioning of internal control.",
        evidenceCount: 2, evidenceRequired: 2, status: "complete",
        linkedBundles: ["EVB-2025-002"],
      },
    ],
  },
  {
    code: "CC6",
    name: "Logical & Physical Access",
    icon: Lock,
    controls: [
      {
        id: "CC6.1", category: "Logical & Physical Access", categoryCode: "CC6",
        name: "Access Provisioning",
        description: "Logical access security software, infrastructure, and architectures have been implemented.",
        evidenceCount: 6, evidenceRequired: 6, status: "complete",
        linkedBundles: ["EVB-2025-001", "EVB-2025-004", "EVB-2025-006"],
      },
      {
        id: "CC6.2", category: "Logical & Physical Access", categoryCode: "CC6",
        name: "User Authentication",
        description: "Prior to issuing system credentials and granting access, the entity registers and authorizes new users.",
        evidenceCount: 3, evidenceRequired: 4, status: "partial",
        linkedBundles: ["EVB-2025-002"],
      },
      {
        id: "CC6.3", category: "Logical & Physical Access", categoryCode: "CC6",
        name: "Access Removal",
        description: "The entity authorizes, modifies, or removes access to data, software, functions, and other IT resources.",
        evidenceCount: 0, evidenceRequired: 3, status: "missing",
        linkedBundles: [],
      },
    ],
  },
  {
    code: "CC7",
    name: "System Operations",
    icon: Activity,
    controls: [
      {
        id: "CC7.1", category: "System Operations", categoryCode: "CC7",
        name: "Change Management",
        description: "The entity uses detection and monitoring procedures to identify changes to configurations.",
        evidenceCount: 5, evidenceRequired: 5, status: "complete",
        linkedBundles: ["EVB-2025-001", "EVB-2025-006"],
      },
      {
        id: "CC7.2", category: "System Operations", categoryCode: "CC7",
        name: "Incident Management",
        description: "Security incidents are identified and responded to in accordance with stated policies.",
        evidenceCount: 4, evidenceRequired: 5, status: "partial",
        linkedBundles: ["EVB-2025-001"],
      },
    ],
  },
  {
    code: "CC9",
    name: "Risk Mitigation",
    icon: AlertCircle,
    controls: [
      {
        id: "CC9.1", category: "Risk Mitigation", categoryCode: "CC9",
        name: "Risk Identification",
        description: "The entity identifies, selects, and develops risk mitigation activities.",
        evidenceCount: 2, evidenceRequired: 2, status: "complete",
        linkedBundles: ["EVB-2025-004"],
      },
      {
        id: "CC9.2", category: "Risk Mitigation", categoryCode: "CC9",
        name: "Vendor Risk",
        description: "The entity assesses and manages risks associated with vendors and business partners.",
        evidenceCount: 0, evidenceRequired: 2, status: "missing",
        linkedBundles: [],
      },
    ],
  },
  {
    code: "P",
    name: "Privacy",
    icon: Users,
    controls: [
      {
        id: "P1.1", category: "Privacy", categoryCode: "P",
        name: "Privacy Notice",
        description: "The entity provides notice to data subjects about its privacy practices.",
        evidenceCount: 3, evidenceRequired: 3, status: "complete",
        linkedBundles: ["EVB-2025-002"],
      },
      {
        id: "P4.1", category: "Privacy", categoryCode: "P",
        name: "Data Use Limitation",
        description: "Personal information is used, retained, disclosed, and disposed of only as necessary.",
        evidenceCount: 1, evidenceRequired: 3, status: "partial",
        linkedBundles: ["EVB-2025-002"],
      },
    ],
  },
];

// ─── Helper ──────────────────────────────────────────────────────────────────

function getControlStatusIcon(status: SOC2Control["status"]) {
  switch (status) {
    case "complete":
      return <CheckCircle2 className="h-4 w-4 text-green-400 shrink-0" />;
    case "partial":
      return <AlertCircle className="h-4 w-4 text-yellow-400 shrink-0" />;
    case "missing":
      return <Circle className="h-4 w-4 text-red-400 shrink-0" />;
  }
}

function getControlStatusBadge(status: SOC2Control["status"]) {
  switch (status) {
    case "complete":
      return <Badge variant="success">Complete</Badge>;
    case "partial":
      return <Badge variant="warning">Partial</Badge>;
    case "missing":
      return <Badge variant="destructive">Missing</Badge>;
  }
}

// ─── Category Row ─────────────────────────────────────────────────────────────

function CategoryRow({
  category,
  onControlSelect,
  selectedControl,
}: {
  category: SOC2Category;
  onControlSelect: (ctrl: SOC2Control) => void;
  selectedControl: SOC2Control | null;
}) {
  const [expanded, setExpanded] = useState(true);
  const Icon = category.icon;
  const total = category.controls.reduce((a, c) => a + c.evidenceRequired, 0);
  const covered = category.controls.reduce((a, c) => a + c.evidenceCount, 0);
  const pct = total > 0 ? Math.round((covered / total) * 100) : 0;
  const missingCount = category.controls.filter((c) => c.status === "missing").length;

  return (
    <div className="rounded-lg border border-border/50 overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-4 hover:bg-muted/20 transition-colors"
      >
        <div className="flex items-center gap-3">
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
          <div className="flex items-center gap-2.5">
            <div className="h-7 w-7 rounded-md bg-primary/10 flex items-center justify-center">
              <Icon className="h-4 w-4 text-primary" />
            </div>
            <div className="text-left">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold">{category.code}</span>
                <span className="text-sm text-muted-foreground">{category.name}</span>
              </div>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-4 shrink-0">
          {missingCount > 0 && (
            <span className="text-xs text-red-400">{missingCount} missing</span>
          )}
          <div className="flex items-center gap-2 min-w-[120px]">
            <Progress value={pct} className="h-1.5 w-20" />
            <span className="text-xs text-muted-foreground tabular-nums">{pct}%</span>
          </div>
        </div>
      </button>

      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            initial={{ height: 0 }}
            animate={{ height: "auto" }}
            exit={{ height: 0 }}
            className="overflow-hidden"
          >
            <div className="border-t border-border/50 divide-y divide-border/30">
              {category.controls.map((ctrl) => {
                const isSelected = selectedControl?.id === ctrl.id;
                return (
                  <button
                    key={ctrl.id}
                    onClick={() => onControlSelect(ctrl)}
                    className={`w-full flex items-center justify-between px-4 py-3 text-left transition-colors ${
                      isSelected ? "bg-primary/5" : "hover:bg-muted/20"
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="w-5" />
                      {getControlStatusIcon(ctrl.status)}
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono text-primary">{ctrl.id}</span>
                          <span className="text-sm font-medium truncate">{ctrl.name}</span>
                        </div>
                        <p className="text-xs text-muted-foreground truncate max-w-md mt-0.5">
                          {ctrl.description}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 shrink-0 ml-4">
                      <span className="text-xs text-muted-foreground tabular-nums">
                        {ctrl.evidenceCount}/{ctrl.evidenceRequired} evidence
                      </span>
                      {getControlStatusBadge(ctrl.status)}
                    </div>
                  </button>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function SOC2Evidence() {
  const [selectedControl, setSelectedControl] = useState<SOC2Control | null>(null);
  const [activeTab, setActiveTab] = useState("controls");

  const { data: frameworkData } = useQuery({
    queryKey: ["compliance-soc2"],
    queryFn: () => complianceApi.controls("soc2"),
  });

  const { data: evidenceData } = useQuery({
    queryKey: ["evidence-soc2"],
    queryFn: () => evidenceApi.list({ framework: "soc2" }),
  });

  const categories = (frameworkData as { data?: SOC2Category[] })?.data ?? MOCK_SOC2_CATEGORIES;

  const allControls = categories.flatMap((c) => c.controls);
  const completeControls = allControls.filter((c) => c.status === "complete").length;
  const partialControls = allControls.filter((c) => c.status === "partial").length;
  const missingControls = allControls.filter((c) => c.status === "missing").length;
  const coveragePct = Math.round((completeControls / allControls.length) * 100);

  const _ = evidenceData; // used for cache hydration

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="SOC 2 Evidence"
        description="Control mapping, evidence completeness tracking, and auditor portal for SOC 2 Type II"
        badge="Type II"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => toast.info("Opening auditor preview...")}>
              <Eye className="mr-2 h-4 w-4" />
              Auditor Preview
            </Button>
            <Button size="sm" onClick={() => toast.success("Generating SOC 2 evidence package...")}>
              <FileCheck className="mr-2 h-4 w-4" />
              Export Package
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Overall Coverage"
          value={`${coveragePct}%`}
          change={4}
          changeLabel="vs last period"
          icon={ShieldCheck}
          trend="up"
        />
        <KpiCard
          title="Complete Controls"
          value={completeControls}
          change={6}
          changeLabel="this quarter"
          icon={CheckCircle2}
          trend="up"
        />
        <KpiCard
          title="Partial Controls"
          value={partialControls}
          icon={AlertCircle}
          trend="flat"
        />
        <KpiCard
          title="Missing Evidence"
          value={missingControls}
          icon={Circle}
          trend={missingControls > 0 ? "down" : "flat"}
        />
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="controls">Control Tree</TabsTrigger>
          <TabsTrigger value="auditor">Auditor Portal</TabsTrigger>
        </TabsList>

        <TabsContent value="controls">
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            {/* Control tree */}
            <div className="xl:col-span-2 space-y-3">
              {categories.map((cat) => (
                <CategoryRow
                  key={cat.code}
                  category={cat}
                  onControlSelect={setSelectedControl}
                  selectedControl={selectedControl}
                />
              ))}
            </div>

            {/* Control detail panel */}
            <div className="xl:col-span-1">
              <Card className="border-border/50 sticky top-4">
                {selectedControl ? (
                  <>
                    <CardHeader className="pb-3">
                      <div className="flex items-start justify-between">
                        <div>
                          <span className="text-xs font-mono text-primary">{selectedControl.id}</span>
                          <CardTitle className="text-sm mt-1">{selectedControl.name}</CardTitle>
                        </div>
                        {getControlStatusBadge(selectedControl.status)}
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <p className="text-xs text-muted-foreground leading-relaxed">
                        {selectedControl.description}
                      </p>
                      <div className="space-y-1.5">
                        <div className="flex justify-between text-xs">
                          <span className="text-muted-foreground">Evidence Completeness</span>
                          <span className="font-medium tabular-nums">
                            {selectedControl.evidenceCount}/{selectedControl.evidenceRequired}
                          </span>
                        </div>
                        <Progress
                          value={
                            selectedControl.evidenceRequired > 0
                              ? (selectedControl.evidenceCount / selectedControl.evidenceRequired) * 100
                              : 0
                          }
                          className="h-2"
                        />
                      </div>
                      {selectedControl.linkedBundles.length > 0 ? (
                        <div className="space-y-2">
                          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                            Linked Evidence
                          </p>
                          {selectedControl.linkedBundles.map((bundleId) => (
                            <button
                              key={bundleId}
                              onClick={() => toast.info(`Opening bundle ${bundleId}...`)}
                              className="flex items-center justify-between w-full p-2.5 rounded-lg border border-border/50 hover:border-primary/50 transition-colors"
                            >
                              <span className="text-xs font-mono text-primary">{bundleId}</span>
                              <ExternalLink className="h-3.5 w-3.5 text-muted-foreground" />
                            </button>
                          ))}
                        </div>
                      ) : (
                        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                          <p className="text-xs text-red-400 font-medium">No evidence linked</p>
                          <p className="text-xs text-muted-foreground mt-1">
                            Generate an evidence bundle to satisfy this control.
                          </p>
                        </div>
                      )}
                      <Button
                        className="w-full"
                        size="sm"
                        variant={selectedControl.status === "complete" ? "outline" : "default"}
                        onClick={() =>
                          toast.info(`Generating evidence for ${selectedControl.id}...`)
                        }
                      >
                        {selectedControl.status === "complete"
                          ? "View Evidence"
                          : "Generate Evidence"}
                      </Button>
                    </CardContent>
                  </>
                ) : (
                  <CardContent className="py-16">
                    <div className="text-center space-y-2">
                      <FileCheck className="h-8 w-8 text-muted-foreground mx-auto opacity-50" />
                      <p className="text-sm text-muted-foreground">
                        Select a control to view details
                      </p>
                    </div>
                  </CardContent>
                )}
              </Card>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="auditor">
          <Card className="border-border/50">
            <CardHeader>
              <div className="flex items-start justify-between">
                <div>
                  <CardTitle className="text-base">Auditor Portal Preview</CardTitle>
                  <p className="text-xs text-muted-foreground mt-1">
                    View what your external auditor sees in the read-only portal
                  </p>
                </div>
                <Button variant="outline" size="sm" onClick={() => toast.info("Generating auditor link...")}>
                  <ExternalLink className="mr-2 h-4 w-4" />
                  Share Link
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 rounded-lg bg-muted/20 border border-border/50">
                  <div className="flex items-center gap-3">
                    <ShieldCheck className="h-5 w-5 text-primary" />
                    <div>
                      <p className="text-sm font-semibold">SOC 2 Type II — FY2025</p>
                      <p className="text-xs text-muted-foreground">
                        Audit period: Jan 1, 2025 — Dec 31, 2025
                      </p>
                    </div>
                  </div>
                  <Badge variant="success">{coveragePct}% Ready</Badge>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {categories.map((cat) => {
                    const catComplete = cat.controls.filter((c) => c.status === "complete").length;
                    const catTotal = cat.controls.length;
                    const catPct = Math.round((catComplete / catTotal) * 100);
                    return (
                      <div
                        key={cat.code}
                        className="p-3 rounded-lg border border-border/50 space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold">{cat.code}</span>
                          <span className="text-xs text-muted-foreground">{catPct}%</span>
                        </div>
                        <p className="text-xs text-muted-foreground">{cat.name}</p>
                        <Progress value={catPct} className="h-1.5" />
                        <p className="text-xs text-muted-foreground">
                          {catComplete}/{catTotal} controls
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
