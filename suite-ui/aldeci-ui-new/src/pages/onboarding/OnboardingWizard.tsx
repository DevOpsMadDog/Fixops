import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, ChevronRight, ChevronLeft, CheckCircle,
  GitBranch, Copy, Eye, EyeOff, Zap, ArrowRight,
  SkipForward, Building2, KeyRound, Plug, ScanLine,
  LayoutDashboard, Sparkles, ExternalLink, RefreshCw,
  MessageSquare, Kanban, Github
} from "lucide-react";
import { toast } from "sonner";

// ── Step definitions ────────────────────────────────────────────────────────
const STEPS = [
  { id: 1, title: "Welcome",      description: "Org setup",         icon: Building2 },
  { id: 2, title: "API Key",      description: "Generate key",      icon: KeyRound },
  { id: 3, title: "Integration",  description: "Connect a tool",    icon: Plug },
  { id: 4, title: "First Scan",   description: "Run SBOM scan",     icon: ScanLine },
  { id: 5, title: "Dashboard",    description: "You're ready",      icon: LayoutDashboard },
];

const INTEGRATIONS = [
  {
    id: "github",
    name: "GitHub",
    icon: Github,
    description: "Connect your repositories for SBOM and secret scanning",
    color: "text-white",
    bg: "bg-zinc-800",
    placeholder: "https://github.com/your-org",
    label: "GitHub Organization URL",
  },
  {
    id: "jira",
    name: "Jira",
    icon: Kanban,
    description: "Auto-create tickets for critical findings",
    color: "text-blue-400",
    bg: "bg-blue-950/40",
    placeholder: "https://yourorg.atlassian.net",
    label: "Jira Instance URL",
  },
  {
    id: "slack",
    name: "Slack",
    icon: MessageSquare,
    description: "Receive real-time security alerts in your channels",
    color: "text-green-400",
    bg: "bg-green-950/40",
    placeholder: "https://hooks.slack.com/services/…",
    label: "Slack Webhook URL",
  },
];

// ── Helpers ─────────────────────────────────────────────────────────────────
function generateApiKey(orgSlug: string): string {
  const prefix = "aldeci";
  const slug = (orgSlug || "org").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 8) || "org";
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(20)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${prefix}_${slug}_${rand}`;
}

// ── Step Indicator ───────────────────────────────────────────────────────────
function StepIndicator({ currentStep }: { currentStep: number }) {
  return (
    <div className="flex items-center gap-2">
      {STEPS.map((step, i) => {
        const isCompleted = step.id < currentStep;
        const isCurrent = step.id === currentStep;
        const Icon = step.icon;
        return (
          <div key={step.id} className="flex items-center gap-2">
            <div className="flex flex-col items-center gap-1">
              <div
                className={`h-8 w-8 rounded-full flex items-center justify-center text-xs font-bold transition-all duration-300 ${
                  isCompleted
                    ? "bg-primary text-primary-foreground"
                    : isCurrent
                    ? "bg-primary/20 text-primary border-2 border-primary"
                    : "bg-muted text-muted-foreground"
                }`}
              >
                {isCompleted ? <CheckCircle className="h-4 w-4" /> : <Icon className="h-3.5 w-3.5" />}
              </div>
              <span
                className={`text-xs hidden lg:block whitespace-nowrap ${
                  isCurrent ? "text-primary font-medium" : "text-muted-foreground"
                }`}
              >
                {step.title}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div
                className={`h-0.5 w-8 lg:w-14 transition-all duration-500 mb-4 ${
                  isCompleted ? "bg-primary" : "bg-muted"
                }`}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Step 1: Welcome + Org Name ───────────────────────────────────────────────
function StepWelcome({
  orgName,
  onChange,
}: {
  orgName: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="space-y-8 max-w-lg">
      <div className="space-y-2">
        <div className="flex items-center gap-2 mb-4">
          <div className="h-12 w-12 rounded-xl bg-primary/10 flex items-center justify-center">
            <Sparkles className="h-6 w-6 text-primary" />
          </div>
        </div>
        <h2 className="text-2xl font-bold">Welcome to ALDECI</h2>
        <p className="text-muted-foreground">
          Your AI-native security intelligence platform. Let's get you set up in under 2 minutes.
        </p>
      </div>

      <div className="grid grid-cols-3 gap-3 text-center">
        {[
          { label: "Engines", value: "344+" },
          { label: "Endpoints", value: "574+" },
          { label: "Frameworks", value: "7" },
        ].map(({ label, value }) => (
          <div key={label} className="p-3 rounded-xl bg-muted/30 border border-border/40">
            <p className="text-xl font-bold text-primary">{value}</p>
            <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      <div className="space-y-2">
        <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
          Organization Name
        </Label>
        <Input
          placeholder="e.g. Acme Corp, MyStartup, DevOps Team"
          value={orgName}
          onChange={(e) => onChange(e.target.value)}
          className="text-base"
          autoFocus
        />
        <p className="text-xs text-muted-foreground">
          This will appear in reports, dashboards, and audit logs.
        </p>
      </div>
    </div>
  );
}

// ── Step 2: API Key Generation ───────────────────────────────────────────────
function StepApiKey({
  orgName,
  apiKey,
  onRegenerate,
}: {
  orgName: string;
  apiKey: string;
  onRegenerate: () => void;
}) {
  const [visible, setVisible] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(apiKey);
      toast.success("API key copied to clipboard");
    } catch {
      toast.error("Copy failed — please select and copy manually");
    }
  }, [apiKey]);

  const displayKey = visible ? apiKey : apiKey.slice(0, 16) + "•".repeat(24);

  return (
    <div className="space-y-6 max-w-lg">
      <div className="space-y-2">
        <h2 className="text-xl font-bold">Your API Key</h2>
        <p className="text-muted-foreground text-sm">
          This key authenticates all API requests for{" "}
          <strong>{orgName || "your organization"}</strong>. Store it securely — it won't be shown again after you leave this page.
        </p>
      </div>

      <div className="p-4 rounded-xl bg-muted/20 border border-border/60 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
            API Key
          </span>
          <Badge variant="secondary" className="text-xs">
            Live
          </Badge>
        </div>
        <div className="flex items-center gap-2">
          <code className="flex-1 text-xs font-mono bg-background/60 px-3 py-2 rounded-lg border border-border/40 truncate select-all">
            {displayKey}
          </code>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setVisible((v) => !v)}
            className="shrink-0 h-8 w-8 p-0"
            title={visible ? "Hide key" : "Show key"}
          >
            {visible ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleCopy}
            className="shrink-0 gap-1.5"
          >
            <Copy className="h-3.5 w-3.5" />
            Copy
          </Button>
        </div>
      </div>

      <div className="space-y-3">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
          How to use
        </p>
        <div className="p-3 rounded-lg bg-zinc-900/60 border border-border/40 font-mono text-xs text-green-400 space-y-1">
          <p className="text-muted-foreground"># HTTP header</p>
          <p>X-API-Key: {visible ? apiKey : apiKey.slice(0, 16) + "…"}</p>
          <p className="text-muted-foreground mt-2"># Example cURL</p>
          <p className="break-all">
            curl -H "X-API-Key: {visible ? apiKey : "{YOUR_KEY}"}" \
          </p>
          <p className="pl-2 break-all">http://localhost:8000/api/v1/health</p>
        </div>
      </div>

      <Button
        variant="ghost"
        size="sm"
        onClick={onRegenerate}
        className="gap-2 text-muted-foreground hover:text-foreground"
      >
        <RefreshCw className="h-3.5 w-3.5" />
        Regenerate key
      </Button>
    </div>
  );
}

// ── Step 3: Connect First Integration ───────────────────────────────────────
function StepIntegration({
  selected,
  url,
  onSelect,
  onUrlChange,
}: {
  selected: string;
  url: string;
  onSelect: (id: string) => void;
  onUrlChange: (v: string) => void;
}) {
  const active = INTEGRATIONS.find((i) => i.id === selected);

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <h2 className="text-xl font-bold">Connect Your First Integration</h2>
        <p className="text-muted-foreground text-sm">
          Choose one tool to connect now. You can add more from the Marketplace later.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {INTEGRATIONS.map((integration) => {
          const Icon = integration.icon;
          const isSelected = selected === integration.id;
          return (
            <motion.button
              key={integration.id}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={() => onSelect(integration.id)}
              className={`relative p-4 rounded-xl border-2 text-left transition-all w-full ${
                isSelected
                  ? "border-primary bg-primary/5"
                  : "border-border/40 hover:border-border"
              }`}
            >
              <div
                className={`h-9 w-9 rounded-lg ${integration.bg} flex items-center justify-center mb-3`}
              >
                <Icon className={`h-5 w-5 ${integration.color}`} />
              </div>
              <p className="text-sm font-semibold">{integration.name}</p>
              <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                {integration.description}
              </p>
              {isSelected && (
                <motion.div
                  layoutId="integration-check"
                  className="absolute top-3 right-3"
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                >
                  <CheckCircle className="h-4 w-4 text-primary" />
                </motion.div>
              )}
            </motion.button>
          );
        })}
      </div>

      {active && (
        <motion.div
          key={active.id}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-2"
        >
          <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
            {active.label}
          </Label>
          <div className="flex gap-2">
            <Input
              placeholder={active.placeholder}
              value={url}
              onChange={(e) => onUrlChange(e.target.value)}
              className="flex-1"
            />
            {url && (
              <Button
                variant="outline"
                size="sm"
                className="shrink-0 gap-1.5"
                onClick={() => toast.success(`Testing ${active.name} connection…`)}
              >
                <ExternalLink className="h-3.5 w-3.5" />
                Test
              </Button>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            Leave blank to configure later from Settings → Integrations.
          </p>
        </motion.div>
      )}
    </div>
  );
}

// ── Step 4: Run First SBOM Scan ──────────────────────────────────────────────
function StepFirstScan({
  repoUrl,
  onRepoChange,
  onScanComplete,
}: {
  repoUrl: string;
  onRepoChange: (v: string) => void;
  onScanComplete: () => void;
}) {
  const [scanState, setScanState] = useState<"idle" | "running" | "done">("idle");
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState("");

  const PHASES = [
    "Cloning repository…",
    "Parsing manifests (package.json, requirements.txt, go.mod)…",
    "Generating CycloneDX SBOM…",
    "Running vulnerability correlation…",
    "Computing license risk…",
    "Finalizing report…",
  ];

  const handleScan = async () => {
    setScanState("running");
    setProgress(0);
    for (let i = 0; i < PHASES.length; i++) {
      setCurrentPhase(PHASES[i]);
      const target = Math.round(((i + 1) / PHASES.length) * 100);
      // animate progress to target
      for (let p = Math.round((i / PHASES.length) * 100); p <= target; p += 5) {
        setProgress(p);
        await new Promise((r) => setTimeout(r, 60));
      }
    }
    setProgress(100);
    setScanState("done");
    onScanComplete();
  };

  const DEMO_RESULTS = [
    { label: "Components found", value: "247", color: "text-foreground" },
    { label: "Vulnerabilities", value: "12", color: "text-orange-400" },
    { label: "Critical CVEs", value: "2", color: "text-red-500" },
    { label: "License issues", value: "3", color: "text-yellow-500" },
  ];

  return (
    <div className="space-y-6 max-w-lg">
      <div className="space-y-2">
        <h2 className="text-xl font-bold">Run Your First SBOM Scan</h2>
        <p className="text-muted-foreground text-sm">
          Enter a public GitHub repository URL to generate a Software Bill of Materials and discover vulnerabilities.
        </p>
      </div>

      <div className="space-y-2">
        <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
          Repository URL
        </Label>
        <Input
          placeholder="https://github.com/org/repo"
          value={repoUrl}
          onChange={(e) => onRepoChange(e.target.value)}
          disabled={scanState !== "idle"}
        />
        <div className="flex gap-2 flex-wrap">
          {["https://github.com/OWASP/WebGoat", "https://github.com/juice-shop/juice-shop"].map(
            (url) => (
              <button
                key={url}
                disabled={scanState !== "idle"}
                onClick={() => onRepoChange(url)}
                className="text-xs text-primary hover:underline disabled:opacity-50"
              >
                {url.split("/").slice(-2).join("/")}
              </button>
            )
          )}
        </div>
      </div>

      {scanState === "idle" && (
        <Button
          className="gap-2 w-full sm:w-auto"
          onClick={handleScan}
          disabled={!repoUrl.trim()}
        >
          <Zap className="h-4 w-4" />
          Start SBOM Scan
        </Button>
      )}

      {scanState === "running" && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-sm">
            <ScanLine className="h-4 w-4 text-primary animate-pulse" />
            <span>{currentPhase}</span>
            <span className="ml-auto text-primary font-mono tabular-nums">{progress}%</span>
          </div>
          <Progress value={progress} className="h-2" />
        </div>
      )}

      {scanState === "done" && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-4"
        >
          <div className="flex items-center gap-2 text-sm text-green-400">
            <CheckCircle className="h-4 w-4" />
            Scan complete — SBOM generated
          </div>
          <Progress value={100} className="h-2" />
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {DEMO_RESULTS.map(({ label, value, color }) => (
              <div
                key={label}
                className="p-3 rounded-xl bg-muted/30 border border-border/40 text-center"
              >
                <p className={`text-xl font-bold ${color}`}>{value}</p>
                <p className="text-xs text-muted-foreground mt-0.5 leading-tight">{label}</p>
              </div>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            Full SBOM report and remediation guidance are available in{" "}
            <span className="text-primary">SBOM Export</span> and{" "}
            <span className="text-primary">Vulnerability Intelligence</span>.
          </p>
        </motion.div>
      )}
    </div>
  );
}

// ── Step 5: View Dashboard ───────────────────────────────────────────────────
function StepViewDashboard({ orgName, onGo }: { orgName: string; onGo: () => void }) {
  const highlights = [
    { icon: Shield,        label: "Security Posture",   path: "/security-posture" },
    { icon: ScanLine,      label: "SBOM Export",        path: "/sbom-export" },
    { icon: GitBranch,     label: "Attack Paths",       path: "/attack-paths" },
    { icon: LayoutDashboard, label: "SOC Dashboard",    path: "/mission-control/soc-t1" },
  ];

  return (
    <div className="space-y-8">
      <div className="text-center space-y-3">
        <motion.div
          className="relative inline-block"
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ type: "spring", stiffness: 200, damping: 12 }}
        >
          <div className="h-20 w-20 rounded-full bg-primary/20 flex items-center justify-center mx-auto">
            <Sparkles className="h-10 w-10 text-primary" />
          </div>
          <motion.div
            className="absolute -right-1 -top-1 h-6 w-6 bg-green-500 rounded-full flex items-center justify-center"
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ delay: 0.35 }}
          >
            <CheckCircle className="h-4 w-4 text-white" />
          </motion.div>
        </motion.div>
        <div>
          <h2 className="text-2xl font-bold">
            {orgName ? `${orgName} is ready!` : "You're all set!"}
          </h2>
          <p className="text-muted-foreground mt-1">
            ALDECI is configured and protecting your environment.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {highlights.map(({ icon: Icon, label, path }) => (
          <motion.a
            key={path}
            href={path}
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            className="p-3 rounded-xl bg-muted/30 border border-border/40 flex flex-col items-center gap-2 text-center hover:border-primary/40 hover:bg-primary/5 transition-colors cursor-pointer no-underline"
          >
            <Icon className="h-5 w-5 text-primary" />
            <p className="text-xs text-muted-foreground leading-tight">{label}</p>
          </motion.a>
        ))}
      </div>

      <div className="flex flex-col items-center gap-3">
        <Button className="gap-2 w-full sm:w-auto" size="lg" onClick={onGo}>
          Go to Dashboard
          <ArrowRight className="h-4 w-4" />
        </Button>
        <p className="text-xs text-muted-foreground">You can revisit this wizard anytime from Settings.</p>
      </div>
    </div>
  );
}

// ── Main Component ───────────────────────────────────────────────────────────
export default function OnboardingWizard() {
  const navigate = useNavigate();

  const [step, setStep] = useState(1);

  // Step 1
  const [orgName, setOrgName] = useState("");

  // Step 2
  const [apiKey, setApiKey] = useState(() => generateApiKey(""));

  // Step 3
  const [selectedIntegration, setSelectedIntegration] = useState("github");
  const [integrationUrl, setIntegrationUrl] = useState("");

  // Step 4
  const [repoUrl, setRepoUrl] = useState("");
  const [scanDone, setScanDone] = useState(false);

  // Regenerate key when org name changes (only if user hasn't edited)
  const handleOrgChange = (v: string) => {
    setOrgName(v);
    setApiKey(generateApiKey(v));
  };

  const canProceed = (): boolean => {
    if (step === 1) return orgName.trim().length > 0;
    if (step === 4) return scanDone;
    return true;
  };

  const handleNext = () => {
    if (step < STEPS.length) setStep((s) => s + 1);
  };

  const handleBack = () => {
    if (step > 1) setStep((s) => s - 1);
  };

  const handleSkip = () => {
    if (step < STEPS.length) setStep((s) => s + 1);
  };

  const handleComplete = () => {
    toast.success("Welcome to ALDECI! Redirecting to your dashboard…");
    navigate("/dashboard");
  };

  const progress = ((step - 1) / (STEPS.length - 1)) * 100;

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-3xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-2 mb-3">
            <Shield className="h-7 w-7 text-primary" />
            <span className="text-xl font-bold">ALDECI</span>
          </div>
          <p className="text-muted-foreground text-sm">
            Setup Wizard — Step {step} of {STEPS.length}
          </p>
        </div>

        {/* Progress bar */}
        <div className="mb-8">
          <Progress value={progress} className="h-1 mb-6" />
          <div className="flex justify-center">
            <StepIndicator currentStep={step} />
          </div>
        </div>

        {/* Step content */}
        <Card className="shadow-xl border-border/60">
          <CardContent className="p-8">
            <AnimatePresence mode="wait">
              <motion.div
                key={step}
                initial={{ opacity: 0, x: 28 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -28 }}
                transition={{ duration: 0.22, ease: "easeInOut" }}
              >
                {step === 1 && (
                  <StepWelcome orgName={orgName} onChange={handleOrgChange} />
                )}
                {step === 2 && (
                  <StepApiKey
                    orgName={orgName}
                    apiKey={apiKey}
                    onRegenerate={() => setApiKey(generateApiKey(orgName))}
                  />
                )}
                {step === 3 && (
                  <StepIntegration
                    selected={selectedIntegration}
                    url={integrationUrl}
                    onSelect={(id) => {
                      setSelectedIntegration(id);
                      setIntegrationUrl("");
                    }}
                    onUrlChange={setIntegrationUrl}
                  />
                )}
                {step === 4 && (
                  <StepFirstScan
                    repoUrl={repoUrl}
                    onRepoChange={setRepoUrl}
                    onScanComplete={() => setScanDone(true)}
                  />
                )}
                {step === 5 && (
                  <StepViewDashboard orgName={orgName} onGo={handleComplete} />
                )}
              </motion.div>
            </AnimatePresence>
          </CardContent>

          {/* Navigation */}
          <div className="px-8 pb-6 flex items-center justify-between border-t border-border/40 pt-5">
            <Button
              variant="outline"
              onClick={handleBack}
              disabled={step === 1}
              className="gap-2"
            >
              <ChevronLeft className="h-4 w-4" />
              Back
            </Button>

            <div className="flex items-center gap-3">
              {step < STEPS.length && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleSkip}
                  className="gap-1.5 text-muted-foreground"
                >
                  <SkipForward className="h-3.5 w-3.5" />
                  Skip
                </Button>
              )}

              {step < STEPS.length ? (
                <Button onClick={handleNext} disabled={!canProceed()} className="gap-2">
                  Continue
                  <ChevronRight className="h-4 w-4" />
                </Button>
              ) : (
                <Button onClick={handleComplete} className="gap-2" size="lg">
                  Go to Dashboard
                  <ArrowRight className="h-4 w-4" />
                </Button>
              )}
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
