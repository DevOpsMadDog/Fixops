import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const LoginPage = lazy(() => import("@/pages/auth/LoginPage"));
const ForgotPasswordPage = lazy(() => import("@/pages/auth/ForgotPasswordPage"));
const ResetPasswordPage = lazy(() => import("@/pages/auth/ResetPasswordPage"));

export default function S01LoginAuth() {
  const [tab, setTab] = useState("login");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S01 · Login & Auth"
        description="Unified authentication and password management"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="login">Login</TabsTrigger>
          <TabsTrigger value="forgot">Forgot Password</TabsTrigger>
          <TabsTrigger value="reset">Reset Password</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="login"><LoginPage /></TabsContent>
          <TabsContent value="forgot"><ForgotPasswordPage /></TabsContent>
          <TabsContent value="reset"><ResetPasswordPage /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
