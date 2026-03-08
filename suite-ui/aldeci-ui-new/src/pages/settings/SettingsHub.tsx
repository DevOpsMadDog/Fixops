import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/shared/page-header";
import { Settings, Shield, Users, Plug, FileText, Activity, Server } from "lucide-react";
import { Link } from "react-router-dom";

const SETTINGS_SECTIONS = [
  { title: "Integrations", desc: "Connect external tools and services", icon: Plug, path: "/settings/integrations" },
  { title: "Users", desc: "Manage user accounts and roles", icon: Users, path: "/settings/users" },
  { title: "Teams", desc: "Team management and permissions", icon: Users, path: "/settings/teams" },
  { title: "Policies", desc: "Security policies and rules", icon: FileText, path: "/settings/policies" },
  { title: "System Health", desc: "Platform health and metrics", icon: Server, path: "/settings/system-health" },
  { title: "Log Viewer", desc: "System and audit logs", icon: Activity, path: "/settings/log-viewer" },
  { title: "Marketplace", desc: "Extensions and plugins", icon: Shield, path: "/settings/marketplace" },
];

export default function SettingsHub() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Settings" description="Platform configuration and administration" />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {SETTINGS_SECTIONS.map((s) => (
          <Link key={s.path} to={s.path}>
            <Card className="hover:border-primary/50 transition-colors cursor-pointer h-full">
              <CardContent className="pt-6">
                <div className="flex items-start gap-3">
                  <div className="rounded-lg bg-primary/10 p-2.5"><s.icon className="h-5 w-5 text-primary" /></div>
                  <div><p className="font-medium">{s.title}</p><p className="text-sm text-muted-foreground">{s.desc}</p></div>
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
