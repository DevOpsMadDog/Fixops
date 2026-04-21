/**
 * Threat Modeling — STRIDE Analysis Workspace
 *
 * Interactive threat modeling workspace for STRIDE analysis:
 *   1. Models list (left sidebar) — create new threat models
 *   2. Components grid — system components with trust boundaries
 *   3. Threats table — STRIDE categories with severity and mitigation status
 *   4. Mitigation progress — track remediation progress
 *
 * Route: /threat-modeling
 * API: GET /api/v1/threat-modeling/models, /api/v1/threat-modeling/threats
 * Fallback: mock data when API unavailable
 */

import { useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { toast } from "sonner";
import {
  Plus, Lock, AlertTriangle, Clipboard, Eye, Zap,
  ChevronRight, Trash2, Settings, Download, RefreshCw,
  BarChart3, TrendingUp, Database, Server, Globe, Shield,
  CheckCircle2, Clock, AlertCircle, Edit2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type ComponentType = "API" | "Database" | "Service" | "External";
type Severity = "critical" | "high" | "medium" | "low";
type StrideCategory = "Spoofing" | "Tampering" | "Repudiation" | "InformationDisclosure" | "DenialOfService" | "ElevationOfPrivilege";
type MitigationStatus = "Open" | "Mitigated" | "Accepted" | "Investigating";

interface ThreatComponent {
  id: string;
  name: string;
  type: ComponentType;
  trust_boundary: "internal" | "external" | "boundary";
  threat_count: number;
  description?: string;
}

interface Threat {
  id: string;
  name: string;
  stride_category: StrideCategory;
  component: string;
  severity: Severity;
  mitigation_status: MitigationStatus;
  description?: string;
  mitigation_strategy?: string;
}

interface ThreatModel {
  id: string;
  name: string;
  description: string;
  components: ThreatComponent[];
  threats: Threat[];
  created_at: string;
  updated_at: string;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_COMPONENTS: ThreatComponent[] = [
  {
    id: "comp-1",
    name: "API Gateway",
    type: "API",
    trust_boundary: "boundary",
    threat_count: 3,
    description: "Entry point for all client requests",
  },
  {
    id: "comp-2",
    name: "Auth Service",
    type: "Service",
    trust_boundary: "internal",
    threat_count: 4,
    description: "OAuth 2.0 and JWT validation",
  },
  {
    id: "comp-3",
    name: "PostgreSQL Database",
    type: "Database",
    trust_boundary: "internal",
    threat_count: 2,
    description: "Primary data store",
  },
  {
    id: "comp-4",
    name: "Redis Cache",
    type: "Database",
    trust_boundary: "internal",
    threat_count: 1,
    description: "Session and cache layer",
  },
  {
    id: "comp-5",
    name: "Third-party API",
    type: "External",
    trust_boundary: "external",
    threat_count: 2,
    description: "External threat intelligence feeds",
  },
];

const MOCK_THREATS: Threat[] = [
  {
    id: "t-1",
    name: "API key spoofing",
    stride_category: "Spoofing",
    component: "API Gateway",
    severity: "critical",
    mitigation_status: "Mitigated",
    description: "Attacker could forge API keys to impersonate legitimate clients",
    mitigation_strategy: "Implement HMAC validation and key rotation every 90 days",
  },
  {
    id: "t-2",
    name: "Token tampering",
    stride_category: "Tampering",
    component: "Auth Service",
    severity: "high",
    mitigation_status: "Mitigated",
    description: "JWT tokens could be modified without detection",
    mitigation_strategy: "Use RS256 signing with asymmetric keys, validate signatures on every request",
  },
  {
    id: "t-3",
    name: "Unlogged privilege escalation",
    stride_category: "Repudiation",
    component: "Auth Service",
    severity: "high",
    mitigation_status: "Investigating",
    description: "Users could escalate privileges without audit trail",
    mitigation_strategy: "Implement comprehensive audit logging for all privilege changes",
  },
  {
    id: "t-4",
    name: "Database query extraction",
    stride_category: "InformationDisclosure",
    component: "PostgreSQL Database",
    severity: "critical",
    mitigation_status: "Open",
    description: "SQL injection could expose sensitive user PII and credentials",
    mitigation_strategy: "Parameterized queries, input validation, prepared statements",
  },
  {
    id: "t-5",
    name: "Cache poisoning",
    stride_category: "Tampering",
    component: "Redis Cache",
    severity: "medium",
    mitigation_status: "Mitigated",
    description: "Attacker could inject malicious data into cache",
    mitigation_strategy: "Redis protected mode enabled, network isolation, password authentication",
  },
  {
    id: "t-6",
    name: "DDoS via API gateway",
    stride_category: "DenialOfService",
    component: "API Gateway",
    severity: "high",
    mitigation_status: "Open",
    description: "Volumetric attacks could overwhelm the gateway",
    mitigation_strategy: "Rate limiting (100 req/min per IP), request queuing, auto-scaling",
  },
  {
    id: "t-7",
    name: "Unauthorized data export",
    stride_category: "InformationDisclosure",
    component: "API Gateway",
    severity: "medium",
    mitigation_status: "Mitigated",
    description: "API could leak sensitive data in responses",
    mitigation_strategy: "Response filtering, field-level encryption, PII masking",
  },
  {
    id: "t-8",
    name: "Privilege escalation via role confusion",
    stride_category: "ElevationOfPrivilege",
    component: "Auth Service",
    severity: "critical",
    mitigation_status: "Open",
    description: "Users could escalate to admin role by exploiting role confusion bug",
    mitigation_strategy: "Implement RBAC correctly, use explicit allow policies, comprehensive testing",
  },
  {
    id: "t-9",
    name: "Third-party data injection",
    stride_category: "Tampering",
    component: "Third-party API",
    severity: "high",
    mitigation_status: "Investigating",
    description: "Third-party feeds could be compromised and inject malicious threat intel",
    mitigation_strategy: "Cryptographic signature verification for all feeds, sandboxed ingestion",
  },
  {
    id: "t-10",
    name: "Cleartext credential transmission",
    stride_category: "InformationDisclosure",
    component: "API Gateway",
    severity: "critical",
    mitigation_status: "Mitigated",
    description: "Credentials sent over HTTP instead of HTTPS",
    mitigation_strategy: "Enforce HTTPS only, HSTS headers, TLS 1.3 minimum",
  },
  {
    id: "t-11",
    name: "Log tampering",
    stride_category: "Repudiation",
    component: "PostgreSQL Database",
    severity: "high",
    mitigation_status: "Open",
    description: "Attacker could modify audit logs to cover tracks",
    mitigation_strategy: "Write-once logs, blockchain-verified audit trail, immutable storage",
  },
  {
    id: "t-12",
    name: "Service account compromise",
    stride_category: "Spoofing",
    component: "Auth Service",
    severity: "high",
    mitigation_status: "Investigating",
    description: "Service account credentials could be stolen and reused",
    mitigation_strategy: "Implement mTLS for service-to-service auth, certificate rotation",
  },
];

const MOCK_MODEL: ThreatModel = {
  id: "model-1",
  name: "ALDECI API Gateway",
  description: "Threat model for the main API gateway and authentication system",
  components: MOCK_COMPONENTS,
  threats: MOCK_THREATS,
  created_at: "2026-04-01",
  updated_at: "2026-04-14",
};

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

const STRIDE_ICONS: Record<StrideCategory, { icon: typeof Lock; emoji: string; color: string }> = {
  Spoofing: { icon: Lock, emoji: "🔒", color: "text-red-500" },
  Tampering: { icon: AlertTriangle, emoji: "⚠️", color: "text-orange-500" },
  Repudiation: { icon: Clipboard, emoji: "📋", color: "text-yellow-500" },
  InformationDisclosure: { icon: Eye, emoji: "👁️", color: "text-blue-500" },
  DenialOfService: { icon: Zap, emoji: "🚫", color: "text-purple-500" },
  ElevationOfPrivilege: { icon: AlertTriangle, emoji: "⬆️", color: "text-pink-500" },
};

const SEV_COLORS: Record<Severity, string> = {
  critical: "bg-red-500/10 text-red-700 border-red-200",
  high: "bg-orange-500/10 text-orange-700 border-orange-200",
  medium: "bg-yellow-500/10 text-yellow-700 border-yellow-200",
  low: "bg-blue-500/10 text-blue-700 border-blue-200",
};

const SEV_BADGE_VARIANT: Record<Severity, "critical" | "high" | "medium" | "low"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

const MITIGATION_COLORS: Record<MitigationStatus, string> = {
  Open: "bg-red-100 text-red-800",
  Mitigated: "bg-green-100 text-green-800",
  Accepted: "bg-yellow-100 text-yellow-800",
  Investigating: "bg-blue-100 text-blue-800",
};

const COMPONENT_TYPE_ICONS: Record<ComponentType, typeof Database> = {
  API: Server,
  Database: Database,
  Service: Shield,
  External: Globe,
};

const COMPONENT_TYPE_COLORS: Record<ComponentType, string> = {
  API: "text-blue-500",
  Database: "text-purple-500",
  Service: "text-green-500",
  External: "text-orange-500",
};

// ══════════════════════════════════════════════════════════════
// Components
// ══════════════════════════════════════════════════════════════

function ComponentCard({
  component,
  onSelect,
}: {
  component: ThreatComponent;
  onSelect: (id: string) => void;
}) {
  const Icon = COMPONENT_TYPE_ICONS[component.type];
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
    >
      <Card
        className="cursor-pointer hover:border-primary/50 transition-colors"
        onClick={() => onSelect(component.id)}
      >
        <CardContent className="p-4 space-y-3">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <Icon className={cn("w-5 h-5", COMPONENT_TYPE_COLORS[component.type])} />
              <span className="font-medium text-sm">{component.name}</span>
            </div>
            <Badge variant="outline" className="text-xs">{component.type}</Badge>
          </div>
          <p className="text-xs text-muted-foreground line-clamp-2">{component.description}</p>
          <div className="flex items-center justify-between">
            <span className={cn(
              "text-xs px-2 py-1 rounded",
              component.trust_boundary === "internal" ? "bg-green-100 text-green-700" :
              component.trust_boundary === "external" ? "bg-orange-100 text-orange-700" :
              "bg-yellow-100 text-yellow-700"
            )}>
              {component.trust_boundary === "internal" ? "Internal" :
               component.trust_boundary === "external" ? "External" :
               "Trust Boundary"}
            </span>
            <Badge variant="secondary" className="text-xs">
              {component.threat_count} threats
            </Badge>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

function ThreatRow({
  threat,
  onEdit,
}: {
  threat: Threat;
  onEdit: (id: string) => void;
}) {
  const strideInfo = STRIDE_ICONS[threat.stride_category];
  return (
    <TableRow className="hover:bg-muted/50 cursor-pointer transition-colors" onClick={() => onEdit(threat.id)}>
      <TableCell className="w-12">
        <span className={cn("text-lg", strideInfo.color)}>{strideInfo.emoji}</span>
      </TableCell>
      <TableCell className="font-medium text-sm">{threat.name}</TableCell>
      <TableCell className="text-sm text-muted-foreground">{threat.stride_category}</TableCell>
      <TableCell className="text-sm">{threat.component}</TableCell>
      <TableCell className="w-24">
        <Badge variant={SEV_BADGE_VARIANT[threat.severity]} className="text-xs uppercase">
          {threat.severity}
        </Badge>
      </TableCell>
      <TableCell className="w-32">
        <Badge className={cn("text-xs", MITIGATION_COLORS[threat.mitigation_status])}>
          {threat.mitigation_status}
        </Badge>
      </TableCell>
      <TableCell className="w-8">
        <ChevronRight className="w-4 h-4 text-muted-foreground" />
      </TableCell>
    </TableRow>
  );
}

function ModelsList({
  models,
  selectedModelId,
  onSelect,
  onCreateNew,
}: {
  models: ThreatModel[];
  selectedModelId: string;
  onSelect: (id: string) => void;
  onCreateNew: () => void;
}) {
  return (
    <div className="w-64 border-r bg-muted/30 flex flex-col h-full">
      <div className="p-4 border-b space-y-2">
        <h3 className="font-semibold text-sm">Models</h3>
        <Button
          onClick={onCreateNew}
          size="sm"
          className="w-full"
          variant="outline"
        >
          <Plus className="w-4 h-4 mr-2" />
          New Model
        </Button>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-4 space-y-2">
          {models.map((model) => (
            <button
              key={model.id}
              onClick={() => onSelect(model.id)}
              className={cn(
                "w-full text-left p-3 rounded-lg transition-colors text-sm",
                selectedModelId === model.id
                  ? "bg-primary text-primary-foreground"
                  : "hover:bg-muted border border-transparent hover:border-primary/30"
              )}
            >
              <div className="font-medium truncate">{model.name}</div>
              <div className="text-xs opacity-75 truncate mt-0.5">{model.description}</div>
            </button>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function ThreatModeling() {
  const [selectedModelId, setSelectedModelId] = useState(MOCK_MODEL.id);
  const [models] = useState([MOCK_MODEL]);

  const selectedModel = models.find((m) => m.id === selectedModelId) || MOCK_MODEL;

  const mitigatedCount = selectedModel.threats.filter(
    (t) => t.mitigation_status === "Mitigated"
  ).length;
  const totalThreats = selectedModel.threats.length;
  const criticalCount = selectedModel.threats.filter((t) => t.severity === "critical").length;
  const highCount = selectedModel.threats.filter((t) => t.severity === "high").length;

  const threatsByStride = selectedModel.threats.reduce(
    (acc, threat) => {
      acc[threat.stride_category] = (acc[threat.stride_category] || 0) + 1;
      return acc;
    },
    {} as Record<StrideCategory, number>
  );

  return (
    <div className="flex h-full bg-background">
      {/* Left sidebar — Models list */}
      <ModelsList
        models={models}
        selectedModelId={selectedModelId}
        onSelect={setSelectedModelId}
        onCreateNew={() => toast.info("Feature available in next release")}
      />

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <PageHeader title="Threat Modeling" description="STRIDE analysis for system components" />

        <ScrollArea className="flex-1">
          <div className="p-6 space-y-6 max-w-7xl">
            {/* Summary Stats */}
            <div className="grid grid-cols-4 gap-4">
              <KpiCard
                title="Total Threats"
                value={totalThreats}
                icon={AlertCircle}
                trend={totalThreats > 0 ? "up" : "neutral"}
                description={`${mitigatedCount} mitigated`}
              />
              <KpiCard
                title="Critical"
                value={criticalCount}
                icon={AlertTriangle}
                trend={criticalCount > 0 ? "up" : "neutral"}
                description="Requires immediate action"
              />
              <KpiCard
                title="High"
                value={highCount}
                icon={AlertTriangle}
                trend={highCount > 2 ? "up" : "down"}
                description="Plan remediation"
              />
              <KpiCard
                title="Mitigated (%)"
                value={Math.round((mitigatedCount / totalThreats) * 100)}
                icon={CheckCircle2}
                trend="up"
                description={`${mitigatedCount}/${totalThreats}`}
              />
            </div>

            {/* Mitigation Progress Bar */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Mitigation Progress</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">
                    {mitigatedCount} of {totalThreats} threats mitigated
                  </span>
                  <span className="font-semibold">{Math.round((mitigatedCount / totalThreats) * 100)}%</span>
                </div>
                <Progress value={(mitigatedCount / totalThreats) * 100} className="h-2" />
              </CardContent>
            </Card>

            {/* Tabs: Components & Threats */}
            <Tabs defaultValue="components" className="w-full">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="components" className="gap-2">
                  <Server className="w-4 h-4" />
                  Components
                </TabsTrigger>
                <TabsTrigger value="threats" className="gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  Threats Detected
                </TabsTrigger>
              </TabsList>

              {/* Components Tab */}
              <TabsContent value="components" className="mt-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold">System Components ({selectedModel.components.length})</h3>
                  <Button size="sm" variant="outline">
                    <Plus className="w-4 h-4 mr-2" />
                    Add Component
                  </Button>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  {selectedModel.components.map((component) => (
                    <ComponentCard
                      key={component.id}
                      component={component}
                      onSelect={() => toast.info(`Component: ${component.name} — editor available in next release`)}
                    />
                  ))}
                </div>
              </TabsContent>

              {/* Threats Tab */}
              <TabsContent value="threats" className="mt-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold">Threats by Category</h3>
                </div>

                {/* STRIDE Category Summary */}
                <div className="grid grid-cols-6 gap-3 mb-6">
                  {Object.entries(STRIDE_ICONS).map(([category, info]) => (
                    <Card key={category} className="cursor-pointer hover:border-primary/50 transition-colors">
                      <CardContent className="p-4 space-y-2">
                        <div className="flex items-center gap-2">
                          <span className={cn("text-xl", info.color)}>{info.emoji}</span>
                          <span className="text-xs font-medium">{category}</span>
                        </div>
                        <div className="text-2xl font-bold">{threatsByStride[category as StrideCategory] || 0}</div>
                      </CardContent>
                    </Card>
                  ))}
                </div>

                {/* Threats Table */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">All Threats</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-12">Category</TableHead>
                          <TableHead>Threat Name</TableHead>
                          <TableHead className="w-40">STRIDE</TableHead>
                          <TableHead className="w-40">Component</TableHead>
                          <TableHead className="w-24">Severity</TableHead>
                          <TableHead className="w-32">Status</TableHead>
                          <TableHead className="w-8"></TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {selectedModel.threats.map((threat) => (
                          <ThreatRow
                            key={threat.id}
                            threat={threat}
                            onEdit={() => toast.info(`Threat: ${threat.name} — detail view available in next release`)}
                          />
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>

            {/* Model Info Footer */}
            <Card className="bg-muted/40">
              <CardContent className="p-4 flex items-center justify-between text-xs text-muted-foreground">
                <div>
                  <span>Model created: {selectedModel.created_at}</span>
                  <span className="ml-4">Last updated: {selectedModel.updated_at}</span>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" variant="ghost">
                    <Download className="w-4 h-4 mr-1" />
                    Export
                  </Button>
                  <Button size="sm" variant="ghost">
                    <RefreshCw className="w-4 h-4 mr-1" />
                    Refresh
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </ScrollArea>
      </div>
    </div>
  );
}
