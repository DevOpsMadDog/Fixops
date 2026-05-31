import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const AdminApiKeysPage = lazy(() => import("@/pages/AdminApiKeysPage"));
const AdminUsersPage = lazy(() => import("@/pages/AdminUsersPage"));
const AdminAuditLogPage = lazy(() => import("@/pages/AdminAuditLogPage"));
const LogViewer = lazy(() => import("@/pages/settings/LogViewer"));
const PasswordPolicy = lazy(() => import("@/pages/PasswordPolicy"));

export default function S31SettingsAdmin() {
  const [tab, setTab] = useState("api-keys");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S31 · Settings &amp; Admin"
        description="API key management, user administration, audit log, log viewer, and password policy."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="api-keys">API Keys</TabsTrigger>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="audit">Audit Log</TabsTrigger>
          <TabsTrigger value="logs">Log Viewer</TabsTrigger>
          <TabsTrigger value="password">Password Policy</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="api-keys"><AdminApiKeysPage /></TabsContent>
          <TabsContent value="users"><AdminUsersPage /></TabsContent>
          <TabsContent value="audit"><AdminAuditLogPage /></TabsContent>
          <TabsContent value="logs"><LogViewer /></TabsContent>
          <TabsContent value="password"><PasswordPolicy /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
