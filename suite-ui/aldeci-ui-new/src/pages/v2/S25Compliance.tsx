import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const ComplianceDashboard = lazy(() => import("@/pages/comply/ComplianceDashboard"));
const EvidenceExportCenter = lazy(() => import("@/pages/comply/EvidenceExportCenter"));
const AuditorEvidenceHub = lazy(() => import("@/pages/comply/AuditorEvidenceHub"));
const Reports = lazy(() => import("@/pages/comply/Reports"));
const SLSAProvenance = lazy(() => import("@/pages/comply/SLSAProvenance"));

export default function S25Compliance() {
  const [tab, setTab] = useState("dashboard");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S25 · Compliance"
        description="Compliance posture, evidence export, auditor hub, reports, and SLSA provenance."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
          <TabsTrigger value="evidence-export">Evidence Export</TabsTrigger>
          <TabsTrigger value="auditor">Auditor Hub</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
          <TabsTrigger value="slsa">SLSA Provenance</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="dashboard"><ComplianceDashboard /></TabsContent>
          <TabsContent value="evidence-export"><EvidenceExportCenter /></TabsContent>
          <TabsContent value="auditor"><AuditorEvidenceHub /></TabsContent>
          <TabsContent value="reports"><Reports /></TabsContent>
          <TabsContent value="slsa"><SLSAProvenance /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
