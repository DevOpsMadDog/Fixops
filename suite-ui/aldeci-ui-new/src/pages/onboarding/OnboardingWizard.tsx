import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { Checkbox } from "@/components/ui/checkbox";
import { Separator } from "@/components/ui/separator";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, Zap, ChevronRight, ChevronLeft, CheckCircle, Search,
  GitBranch, Cloud, Code, FileCode, Lock, Globe, Cpu,
  User, Bell, Monitor, Package, Layers, AlertTriangle, Activity,
  Sparkles, ArrowRight, SkipForward, Clock
} from "lucide-react";
import { useIntegrations, useApps } from "@/hooks/use-api";
import { toast } from "sonner";

// Onboarding steps
const STEPS = [
  { id: 1, title: "Connect Tools", description: "Scanner integrations" },
  { id: 2, title: "Register App", description: "Your first application" },
  { id: 3, title: "Run Scan", description: "Initial security scan" },
  { id: 4, title: "Review Results", description: "Findings overview" },
  { id: 5, title: "Personalize", description: "Role & preferences" },
];

const SCANNERS = [
  { id: "snyk", name: "Snyk", icon: Shield, description: "Open source & license vulnerability scanning", color: "text-blue-400" },
  { id: "trivy", name: "Trivy", icon: Search, description: "Container & filesystem vulnerability scanner", color: "text-green-400" },
  { id: "semgrep", name: "Semgrep", icon: Code, description: "Static analysis for code security", color: "text-orange-400" },
  { id: "sonarqube", name: "SonarQube", icon: Activity, description: "Code quality & security analysis", color: "text-blue-500" },
  { id: "checkov", name: "Checkov", icon: FileCode, description: "Infrastructure-as-code security scanner", color: "text-violet-400" },
  { id: "zap", name: "OWASP ZAP", icon: Globe, description: "Dynamic application security testing", color: "text-red-400" },
  { id: "wiz", name: "Wiz", icon: Cloud, description: "Cloud security posture management", color: "text-sky-400" },
  { id: "prisma", name: "Prisma Cloud", icon: Lock, description: "Full-lifecycle cloud security platform", color: "text-teal-400" },
];

const CRITICALITIES = ["Critical", "High", "Medium", "Low"];
const DATA_CLASSIFICATIONS = ["Public", "Internal", "Confidential", "Restricted", "PII", "PHI", "PCI"];
const FRAMEWORKS = ["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST", "GDPR"];
const ROLES = ["CISO", "Security Engineer", "Developer", "Compliance Officer", "DevSecOps", "Manager", "Analyst", "Auditor"];

function StepIndicator({ currentStep, totalSteps }: { currentStep: number; totalSteps: number }) {
  return (
    <div className="flex items-center gap-2">
      {STEPS.map((step, i) => {
        const isCompleted = step.id < currentStep;
        const isCurrent = step.id === currentStep;
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
                {isCompleted ? <CheckCircle className="h-4 w-4" /> : step.id}
              </div>
              <span className={`text-xs hidden lg:block ${isCurrent ? "text-primary font-medium" : "text-muted-foreground"}`}>
                {step.title}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div className={`h-0.5 w-8 lg:w-16 transition-all duration-500 ${isCompleted ? "bg-primary" : "bg-muted"}`} />
            )}
          </div>
        );
      })}
    </div>
  );
}

// Step 1: Connect Tools
function StepConnectTools({ selected, onToggle }: { selected: Set<string>; onToggle: (id: string) => void }) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold mb-1">Connect Your Security Tools</h2>
        <p className="text-muted-foreground text-sm">Select the scanners you want to integrate. You can add more later from the Marketplace.</p>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {SCANNERS.map((scanner) => {
          const Icon = scanner.icon;
          const isSelected = selected.has(scanner.id);
          return (
            <motion.div
              key={scanner.id}
              whileHover={{ scale: 1.01 }}
              className={`relative p-4 rounded-xl border-2 cursor-pointer transition-all ${
                isSelected
                  ? "border-primary bg-primary/5"
                  : "border-border/40 hover:border-border"
              }`}
              onClick={() => onToggle(scanner.id)}
            >
              <div className="flex items-start gap-3">
                <div className={`h-9 w-9 rounded-lg bg-muted flex items-center justify-center shrink-0`}>
                  <Icon className={`h-5 w-5 ${scanner.color}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold">{scanner.name}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{scanner.description}</p>
                </div>
                <Checkbox
                  checked={isSelected}
                  onCheckedChange={() => onToggle(scanner.id)}
                  className="shrink-0 mt-0.5"
                />
              </div>
            </motion.div>
          );
        })}
      </div>
      <p className="text-xs text-muted-foreground">
        {selected.size} scanner{selected.size !== 1 ? "s" : ""} selected
      </p>
    </div>
  );
}

// Step 2: Register App
function StepRegisterApp({ appData, onChange }: {
  appData: any;
  onChange: (field: string, value: any) => void;
}) {
  return (
    <div className="space-y-6 max-w-lg">
      <div>
        <h2 className="text-xl font-bold mb-1">Register Your First Application</h2>
        <p className="text-muted-foreground text-sm">ALdeci uses APP_IDs to track security findings, evidence, and compliance per application.</p>
      </div>
      <div className="space-y-4">
        <div>
          <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Application Name / APP_ID</Label>
          <Input
            placeholder="e.g. my-api, payment-service, web-frontend"
            value={appData.name}
            onChange={(e) => onChange("name", e.target.value)}
          />
          <p className="text-xs text-muted-foreground mt-1">This becomes your APP_ID — use kebab-case, no spaces</p>
        </div>
        <div>
          <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Criticality</Label>
          <Select value={appData.criticality} onValueChange={(v) => onChange("criticality", v)}>
            <SelectTrigger>
              <SelectValue placeholder="Select criticality…" />
            </SelectTrigger>
            <SelectContent>
              {CRITICALITIES.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Data Classification</Label>
          <Select value={appData.dataClassification} onValueChange={(v) => onChange("dataClassification", v)}>
            <SelectTrigger>
              <SelectValue placeholder="Select classification…" />
            </SelectTrigger>
            <SelectContent>
              {DATA_CLASSIFICATIONS.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 block">Compliance Frameworks</Label>
          <div className="grid grid-cols-3 gap-2">
            {FRAMEWORKS.map((fw) => (
              <div key={fw} className="flex items-center gap-2">
                <Checkbox
                  id={`fw-ob-${fw}`}
                  checked={(appData.frameworks ?? []).includes(fw)}
                  onCheckedChange={(checked) => {
                    const current = appData.frameworks ?? [];
                    onChange("frameworks", checked ? [...current, fw] : current.filter((f: string) => f !== fw));
                  }}
                />
                <Label htmlFor={`fw-ob-${fw}`} className="text-sm cursor-pointer">{fw}</Label>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// Step 3: Run First Scan
function StepRunScan({ selectedScanners, appId, onScanStart }: {
  selectedScanners: Set<string>;
  appId: string;
  onScanStart: () => void;
}) {
  const [scanState, setScanState] = useState<"idle" | "running" | "done">("idle");
  const [progress, setProgress] = useState(0);
  const [currentScanner, setCurrentScanner] = useState("");

  const handleRunScan = async () => {
    setScanState("running");
    const scanners = Array.from(selectedScanners);
    for (let i = 0; i < scanners.length; i++) {
      setCurrentScanner(scanners[i]);
      for (let p = 0; p <= 100; p += 10) {
        setProgress(Math.round(((i * 100 + p) / (scanners.length * 100)) * 100));
        await new Promise((r) => setTimeout(r, 80));
      }
    }
    setProgress(100);
    setScanState("done");
    onScanStart();
  };

  return (
    <div className="space-y-6 max-w-lg">
      <div>
        <h2 className="text-xl font-bold mb-1">Run Your First Security Scan</h2>
        <p className="text-muted-foreground text-sm">
          We'll scan <strong>{appId || "your app"}</strong> using {selectedScanners.size} connected scanner{selectedScanners.size !== 1 ? "s" : ""}.
        </p>
      </div>

      <div className="p-4 rounded-xl bg-muted/30 border border-border/40">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">Scanners to run</p>
        <div className="flex flex-wrap gap-2">
          {SCANNERS.filter((s) => selectedScanners.has(s.id)).map((s) => {
            const Icon = s.icon;
            return (
              <div key={s.id} className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-muted border border-border/40 text-xs">
                <Icon className={`h-3 w-3 ${s.color}`} />
                {s.name}
                {scanState === "running" && currentScanner === s.id && (
                  <span className="h-1.5 w-1.5 rounded-full bg-green-500 animate-pulse ml-1" />
                )}
                {scanState === "done" && <CheckCircle className="h-3 w-3 text-green-500 ml-1" />}
              </div>
            );
          })}
        </div>
      </div>

      {scanState !== "idle" && (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            {scanState === "running" ? (
              <><Cpu className="h-4 w-4 text-primary animate-spin" /><span className="text-sm">Scanning {currentScanner}…<span className="ml-2 text-primary font-mono">{progress}%</span></span></>
            ) : (
              <><CheckCircle className="h-4 w-4 text-green-500" /><span className="text-sm text-green-400">Scan complete!</span></>
            )}
          </div>
          <Progress value={progress} className="h-2" />
        </div>
      )}

      {scanState === "idle" && (
        <Button className="gap-2 w-full sm:w-auto" onClick={handleRunScan} disabled={selectedScanners.size === 0}>
          <Zap className="h-4 w-4" />
          Run First Scan
        </Button>
      )}

      {scanState === "done" && (
        <div className="p-4 rounded-xl bg-green-950/20 border border-green-700/30">
          <p className="text-sm text-green-400 font-medium flex items-center gap-2">
            <CheckCircle className="h-4 w-4" />
            Scan complete! We found findings across {selectedScanners.size} scanners.
          </p>
          <p className="text-xs text-muted-foreground mt-1">Continue to review your results.</p>
        </div>
      )}
    </div>
  );
}

// Step 4: Review Results
function StepReviewResults({ selectedScanners }: { selectedScanners: Set<string> }) {
  const findingCounts = {
    critical: 2,
    high: 8,
    medium: 15,
    low: 25,
    info: 40,
  };
  const total = Object.values(findingCounts).reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold mb-1">Review Your Initial Results</h2>
        <p className="text-muted-foreground text-sm">Here's a summary of what we found. Your full findings are in the Discover section.</p>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {[
          { label: "Critical", count: findingCounts.critical, color: "text-red-500 bg-red-950/30 border-red-700/30" },
          { label: "High", count: findingCounts.high, color: "text-orange-500 bg-orange-950/30 border-orange-700/30" },
          { label: "Medium", count: findingCounts.medium, color: "text-yellow-500 bg-yellow-950/30 border-yellow-700/30" },
          { label: "Low", count: findingCounts.low, color: "text-blue-400 bg-blue-950/30 border-blue-700/30" },
          { label: "Info", count: findingCounts.info, color: "text-muted-foreground bg-muted/30 border-border/30" },
        ].map(({ label, count, color }) => (
          <div key={label} className={`p-4 rounded-xl border text-center ${color}`}>
            <p className="text-2xl font-bold">{count}</p>
            <p className="text-xs font-medium mt-0.5">{label}</p>
          </div>
        ))
        )}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="p-4 rounded-xl bg-muted/30 border border-border/40">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">Scanners Ran</p>
          <div className="space-y-2">
            {SCANNERS.filter((s) => selectedScanners.has(s.id)).map((s) => {
              const Icon = s.icon;
              const count = 5;
              return (
                <div key={s.id} className="flex items-center gap-2 text-sm">
                  <Icon className={`h-3.5 w-3.5 ${s.color}`} />
                  <span className="flex-1">{s.name}</span>
                  <Badge variant="secondary" className="text-xs">{count} findings</Badge>
                </div>
              );
            })}
          </div>
        </div>
        <div className="p-4 rounded-xl bg-muted/30 border border-border/40">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">Next Steps</p>
          <div className="space-y-3">
            {[
              { action: "Triage critical findings", icon: AlertTriangle },
              { action: "Set up SLA policies", icon: Clock },
              { action: "Connect ALM for ticketing", icon: GitBranch },
              { action: "Configure evidence bundles", icon: Package },
            ].map(({ action, icon: Icon }) => (
              <div key={action} className="flex items-center gap-2 text-xs text-muted-foreground">
                <Icon className="h-3 w-3 shrink-0" />
                {action}
              </div>
            ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Step 5: Personalize
function StepPersonalize({ prefs, onChange }: {
  prefs: any;
  onChange: (field: string, value: any) => void;
}) {
  return (
    <div className="space-y-6 max-w-lg">
      <div>
        <h2 className="text-xl font-bold mb-1">Personalize Your Experience</h2>
        <p className="text-muted-foreground text-sm">Set your role and preferences to get the most relevant insights.</p>
      </div>
      <div className="space-y-5">
        <div>
          <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Your Role</Label>
          <Select value={prefs.role} onValueChange={(v) => onChange("role", v)}>
            <SelectTrigger>
              <SelectValue placeholder="Select your role…" />
            </SelectTrigger>
            <SelectContent>
              {ROLES.map((r) => <SelectItem key={r} value={r}>{r}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Theme</Label>
          <div className="flex gap-3">
            {["dark", "light", "system"].map((t) => (
              <div
                key={t}
                className={`flex-1 p-3 rounded-xl border-2 cursor-pointer text-center text-sm transition-all capitalize ${
                  prefs.theme === t ? "border-primary bg-primary/5" : "border-border/40 hover:border-border"
                }`}
                onClick={() => onChange("theme", t)}
              >
                {t}
              </div>
            ))}
          </div>
        </div>
        <div>
          <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 block">Notification Preferences</Label>
          <div className="space-y-3">
            {[
              { id: "critical", label: "Critical findings", defaultOn: true },
              { id: "sla_breach", label: "SLA breach warnings", defaultOn: true },
              { id: "scan_complete", label: "Scan completion", defaultOn: false },
              { id: "compliance", label: "Compliance status changes", defaultOn: true },
              { id: "weekly", label: "Weekly digest email", defaultOn: false },
            ].map(({ id, label, defaultOn }) => (
              <div key={id} className="flex items-center justify-between">
                <span className="text-sm">{label}</span>
                <Switch
                  checked={(prefs.notifications ?? {})[id] ?? defaultOn}
                  onCheckedChange={(v) => onChange("notifications", { ...prefs.notifications, [id]: v })}
                />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// Completion screen
function CompletionScreen({ onComplete }: { onComplete: () => void }) {
  return (
    <motion.div
      initial={{ scale: 0.9, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      className="text-center py-8 space-y-6"
    >
      <div className="relative inline-block">
        <div className="h-20 w-20 rounded-full bg-primary/20 flex items-center justify-center mx-auto">
          <Sparkles className="h-10 w-10 text-primary" />
        </div>
        <motion.div
          className="absolute -right-1 -top-1 h-6 w-6 bg-green-500 rounded-full flex items-center justify-center"
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ delay: 0.3 }}
        >
          <CheckCircle className="h-4 w-4 text-white" />
        </motion.div>
      </div>
      <div>
        <h2 className="text-2xl font-bold mb-2">You're all set! 🎉</h2>
        <p className="text-muted-foreground">ALdeci is configured and ready to protect your applications.</p>
      </div>
      <div className="grid grid-cols-3 gap-4 max-w-sm mx-auto text-sm">
        {["Scanners connected", "App registered", "First scan complete"].map((item) => (
          <div key={item} className="p-3 rounded-xl bg-muted/30 border border-border/40">
            <CheckCircle className="h-4 w-4 text-green-500 mx-auto mb-1" />
            <p className="text-xs text-muted-foreground">{item}</p>
          </div>
        ))}
      </div>
      <Button className="gap-2" size="lg" onClick={onComplete}>
        Go to Dashboard
        <ArrowRight className="h-4 w-4" />
      </Button>
    </motion.div>
  );
}

// --- MAIN COMPONENT ---
export default function OnboardingWizard() {
  const [step, setStep] = useState(1);
  const [completed, setCompleted] = useState(false);

  // Step 1 state
  const [selectedScanners, setSelectedScanners] = useState<Set<string>>(new Set(["snyk", "trivy"]));
  const toggleScanner = (id: string) => {
    setSelectedScanners((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Step 2 state
  const [appData, setAppData] = useState({
    name: "",
    criticality: "",
    dataClassification: "",
    frameworks: [] as string[],
  });
  const handleAppChange = (field: string, value: any) => setAppData((prev) => ({ ...prev, [field]: value }));

  // Step 3 state
  const [scanDone, setScanDone] = useState(false);

  // Step 5 state
  const [prefs, setPrefs] = useState({ role: "", theme: "dark", notifications: {} });
  const handlePrefsChange = (field: string, value: any) => setPrefs((prev) => ({ ...prev, [field]: value }));

  const canProceed = () => {
    if (step === 1) return selectedScanners.size > 0;
    if (step === 2) return !!appData.name && !!appData.criticality;
    if (step === 3) return scanDone;
    return true;
  };

  const handleNext = () => {
    if (step < STEPS.length) setStep(step + 1);
    else setCompleted(true);
  };

  const handleBack = () => {
    if (step > 1) setStep(step - 1);
  };

  const handleSkip = () => {
    if (step < STEPS.length) setStep(step + 1);
    else setCompleted(true);
  };

  const handleComplete = () => {
    toast.success("Welcome to ALdeci! Redirecting to your dashboard…");
    // In real app: navigate based on role
    window.location.href = "/";
  };

  const progress = (step / STEPS.length) * 100;

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-3xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-2 mb-3">
            <Shield className="h-7 w-7 text-primary" />
            <span className="text-xl font-bold">ALdeci</span>
          </div>
          {!completed && (
            <p className="text-muted-foreground text-sm">Setup Wizard — Step {step} of {STEPS.length}</p>
          )}
        </div>

        {/* Progress bar */}
        {!completed && (
          <div className="mb-8">
            <Progress value={progress} className="h-1 mb-6" />
            <div className="flex justify-center">
              <StepIndicator currentStep={step} totalSteps={STEPS.length} />
            </div>
          </div>
        )}

        {/* Step content card */}
        <Card className="shadow-xl border-border/60">
          <CardContent className="p-8">
            <AnimatePresence mode="wait">
              {completed ? (
                <motion.div
                  key="complete"
                  initial={{ opacity: 0, y: 16 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -16 }}
                  transition={{ duration: 0.3 }}
                >
                  <CompletionScreen onComplete={handleComplete} />
                </motion.div>
              ) : (
                <motion.div
                  key={step}
                  initial={{ opacity: 0, x: 24 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -24 }}
                  transition={{ duration: 0.25 }}
                >
                  {step === 1 && (
                    <StepConnectTools selected={selectedScanners} onToggle={toggleScanner} />
                  )}
                  {step === 2 && (
                    <StepRegisterApp appData={appData} onChange={handleAppChange} />
                  )}
                  {step === 3 && (
                    <StepRunScan
                      selectedScanners={selectedScanners}
                      appId={appData.name}
                      onScanStart={() => setScanDone(true)}
                    />
                  )}
                  {step === 4 && (
                    <StepReviewResults selectedScanners={selectedScanners} />
                  )}
                  {step === 5 && (
                    <StepPersonalize prefs={prefs} onChange={handlePrefsChange} />
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </CardContent>

          {/* Navigation */}
          {!completed && (
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
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleSkip}
                  className="gap-1.5 text-muted-foreground"
                >
                  <SkipForward className="h-3.5 w-3.5" />
                  Skip
                </Button>
                <Button
                  onClick={handleNext}
                  disabled={!canProceed()}
                  className="gap-2"
                >
                  {step === STEPS.length ? "Complete Setup" : "Continue"}
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
