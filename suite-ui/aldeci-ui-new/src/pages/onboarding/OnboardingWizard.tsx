import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Shield, ArrowRight, CheckCircle2, Plug, Server, Users } from "lucide-react";
import { useSystemHealth } from "@/hooks/use-api";

const STEPS = [
  { title: "System Check", icon: Server, desc: "Verify platform health and connectivity" },
  { title: "API Configuration", icon: Shield, desc: "Configure API keys and authentication" },
  { title: "Integrations", icon: Plug, desc: "Connect scanners and external tools" },
  { title: "Team Setup", icon: Users, desc: "Invite team members and assign roles" },
];

export default function OnboardingWizard() {
  const [step, setStep] = useState(0);
  const navigate = useNavigate();
  const health = useSystemHealth();

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-background">
      <div className="w-full max-w-2xl space-y-6">
        <div className="text-center space-y-2">
          <h1 className="text-3xl font-bold tracking-tight">Welcome to FixOps</h1>
          <p className="text-muted-foreground">Enterprise Security Platform — setup wizard</p>
        </div>

        <Progress value={(step + 1) / STEPS.length * 100} className="h-2" />

        <Card>
          <CardHeader>
            <div className="flex items-center gap-3">
              {(() => { const Icon = STEPS[step].icon; return <Icon className="h-6 w-6 text-primary" />; })()}
              <div>
                <CardTitle>{STEPS[step].title}</CardTitle>
                <p className="text-sm text-muted-foreground">{STEPS[step].desc}</p>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {step === 0 && (
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 rounded-lg border border-border/50">
                  <span className="text-sm">API Status</span>
                  <Badge variant={health.data?.status === "healthy" ? "default" : "outline"}>{health.data?.status ?? "Checking..."}</Badge>
                </div>
                <div className="flex items-center justify-between p-3 rounded-lg border border-border/50">
                  <span className="text-sm">Version</span>
                  <span className="font-mono text-sm">{health.data?.version ?? "—"}</span>
                </div>
                <div className="flex items-center justify-between p-3 rounded-lg border border-border/50">
                  <span className="text-sm">Mode</span>
                  <Badge variant="default">{String(health.data?.subsystems?.configuration?.mode ?? "enterprise").toUpperCase()}</Badge>
                </div>
              </div>
            )}
            {step === 1 && <div className="space-y-3"><Input placeholder="API Key" defaultValue="fixops_sk_***" disabled /><p className="text-xs text-muted-foreground">API key is pre-configured for this deployment.</p></div>}
            {step === 2 && <p className="text-sm text-muted-foreground">Configure integrations in Settings after completing setup.</p>}
            {step === 3 && <p className="text-sm text-muted-foreground">Invite team members from the Users page after setup.</p>}
          </CardContent>
        </Card>

        <div className="flex justify-between">
          <Button variant="outline" onClick={() => setStep(Math.max(0, step - 1))} disabled={step === 0}>Back</Button>
          {step < STEPS.length - 1 ? (
            <Button onClick={() => setStep(step + 1)}>Next <ArrowRight className="ml-2 h-4 w-4" /></Button>
          ) : (
            <Button onClick={() => navigate("/")}><CheckCircle2 className="mr-2 h-4 w-4" />Complete Setup</Button>
          )}
        </div>
      </div>
    </div>
  );
}
