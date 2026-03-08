import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  CheckCircle,
  ChevronRight,
  ChevronLeft,
  Shield,
  Scan,
  Eye,
  User,
  Loader2,
  Circle,
  Link2,
  GitBranch,
  AlertCircle,
  Sparkles,
  Play,
  ArrowRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAppStore } from "@/stores";
import { toast } from "sonner";

// ─── Constants ────────────────────────────────────────────────────────────────
const SCANNERS = [
  { id: "snyk", name: "Snyk", category: "SAST/SCA", logo: "S", color: "bg-purple-500/20 text-purple-400", popular: true },
  { id: "trivy", name: "Trivy", category: "Container/IaC", logo: "T", color: "bg-blue-500/20 text-blue-400", popular: true },
  { id: "wiz", name: "Wiz", category: "CSPM", logo: "W", color: "bg-cyan-500/20 text-cyan-400", popular: true },
  { id: "semgrep", name: "Semgrep", category: "SAST", logo: "Se", color: "bg-green-500/20 text-green-400", popular: false },
  { id: "prisma", name: "Prisma Cloud", category: "CNAPP", logo: "P", color: "bg-orange-500/20 text-orange-400", popular: false },
  { id: "checkov", name: "Checkov", category: "IaC", logo: "C", color: "bg-yellow-500/20 text-yellow-400", popular: false },
  { id: "sonarqube", name: "SonarQube", category: "SAST", logo: "SQ", color: "bg-red-500/20 text-red-400", popular: false },
  { id: "grype", name: "Grype", category: "SCA", logo: "G", color: "bg-pink-500/20 text-pink-400", popular: false },
  { id: "nuclei", name: "Nuclei", category: "DAST", logo: "N", color: "bg-indigo-500/20 text-indigo-400", popular: false },
  { id: "gitleaks", name: "Gitleaks", category: "Secrets", logo: "GL", color: "bg-rose-500/20 text-rose-400", popular: false },
  { id: "tenable", name: "Tenable.io", category: "Vuln Mgmt", logo: "Te", color: "bg-teal-500/20 text-teal-400", popular: false },
  { id: "codeql", name: "CodeQL", category: "SAST", logo: "CQ", color: "bg-violet-500/20 text-violet-400", popular: false },
];

const ROLES = [
  { value: "security-lead", label: "Security Lead", homeSpace: "/mission-control", description: "Mission Control with live risk dashboard" },
  { value: "analyst", label: "Security Analyst", homeSpace: "/discover", description: "Finding Explorer with triage queue" },
  { value: "developer", label: "Developer", homeSpace: "/remediate/autofix", description: "AutoFix center with assigned tasks" },
  { value: "auditor", label: "Auditor / GRC", homeSpace: "/comply", description: "Compliance dashboard with evidence vault" },
  { value: "admin", label: "Administrator", homeSpace: "/settings", description: "Settings hub with system overview" },
  { value: "executive", label: "Executive / CISO", homeSpace: "/mission-control/executive", description: "Executive view with posture metrics" },
];

const STEPS = [
  { id: 1, label: "Connect Tools", icon: Link2 },
  { id: 2, label: "Register App", icon: GitBranch },
  { id: 3, label: "First Scan", icon: Scan },
  { id: 4, label: "Review Results", icon: Eye },
  { id: 5, label: "Personalize", icon: User },
];

// ─── Slide animation variants ────────────────────────────────────────────────
const variants = {
  enter: (dir: number) => ({ x: dir > 0 ? 40 : -40, opacity: 0 }),
  center: { x: 0, opacity: 1 },
  exit: (dir: number) => ({ x: dir > 0 ? -40 : 40, opacity: 0 }),
};

// ─── Step Components ──────────────────────────────────────────────────────────
function StepConnectTools({ selected, onToggle }: { selected: Set<string>; onToggle: (id: string) => void }) {
  return (
    <div className="space-y-5">
      <div className="text-center">
        <div className="inline-flex rounded-full bg-primary/10 p-3 mb-3">
          <Link2 className="h-6 w-6 text-primary" />
        </div>
        <h2 className="text-xl font-bold">Connect your security tools</h2>
        <p className="text-sm text-muted-foreground mt-1.5">ALdeci will ingest and normalize findings from every scanner. Select the tools you use.</p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
        {SCANNERS.map((scanner) => {
          const isSelected = selected.has(scanner.id);
          return (
            <button
              key={scanner.id}
              onClick={() => onToggle(scanner.id)}
              className={`relative flex flex-col items-center gap-2 rounded-xl border p-3.5 text-center transition-all ${isSelected ? "border-primary bg-primary/5 shadow-sm shadow-primary/10" : "border-border/40 hover:border-border"}`}
            >
              {scanner.popular && (
                <span className="absolute top-1.5 right-1.5">
                  <Badge variant="new" className="text-[9px] px-1 py-0">Popular</Badge>
                </span>
              )}
              <div className={`h-9 w-9 rounded-lg flex items-center justify-center text-sm font-bold ${scanner.color}`}>
                {scanner.logo}
              </div>
              <div>
                <p className="text-xs font-semibold">{scanner.name}</p>
                <p className="text-[10px] text-muted-foreground">{scanner.category}</p>
              </div>
              {isSelected && (
                <div className="absolute bottom-1.5 right-1.5">
                  <CheckCircle className="h-3.5 w-3.5 text-primary" />
                </div>
              )}
            </button>
          );
        })}
      </div>

      <p className="text-center text-xs text-muted-foreground">{selected.size} scanner{selected.size !== 1 ? "s" : ""} selected — you can add more in Settings → Integrations</p>
    </div>
  );
}

function StepRegisterApp({
  form,
  onChange,
}: {
  form: { name: string; repo: string; team: string; classification: string };
  onChange: (f: Partial<typeof form>) => void;
}) {
  return (
    <div className="space-y-5">
      <div className="text-center">
        <div className="inline-flex rounded-full bg-primary/10 p-3 mb-3">
          <GitBranch className="h-6 w-6 text-primary" />
        </div>
        <h2 className="text-xl font-bold">Register your first application</h2>
        <p className="text-sm text-muted-foreground mt-1.5">Define an APP_ID so ALdeci can scope findings, track SLAs, and assign ownership.</p>
      </div>

      <div className="space-y-3 max-w-sm mx-auto">
        <div>
          <label className="text-xs font-medium text-muted-foreground mb-1 block">Application Name</label>
          <Input
            placeholder="e.g., payment-service"
            value={form.name}
            onChange={(e) => onChange({ name: e.target.value })}
            className="text-sm"
          />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground mb-1 block">Repository URL</label>
          <Input
            placeholder="https://github.com/acme/payment-service"
            value={form.repo}
            onChange={(e) => onChange({ repo: e.target.value })}
            className="text-sm font-mono"
          />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground mb-1 block">Owning Team</label>
          <Input
            placeholder="e.g., Backend Services"
            value={form.team}
            onChange={(e) => onChange({ team: e.target.value })}
            className="text-sm"
          />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground mb-1 block">Data Classification</label>
          <Select value={form.classification} onValueChange={(v) => onChange({ classification: v })}>
            <SelectTrigger className="text-sm">
              <SelectValue placeholder="Select classification" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="public">Public</SelectItem>
              <SelectItem value="internal">Internal</SelectItem>
              <SelectItem value="confidential">Confidential</SelectItem>
              <SelectItem value="restricted">Restricted / PCI</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="max-w-sm mx-auto rounded-lg border border-blue-500/30 bg-blue-500/5 p-3 flex gap-2.5">
        <AlertCircle className="h-4 w-4 text-blue-400 shrink-0 mt-0.5" />
        <p className="text-xs text-muted-foreground">ALdeci will auto-discover components and generate an APP_ID. You can register additional apps anytime from the Apps section.</p>
      </div>
    </div>
  );
}

function StepFirstScan({ scanState, onScan }: { scanState: "idle" | "scanning" | "done"; onScan: () => void }) {
  return (
    <div className="space-y-5">
      <div className="text-center">
        <div className="inline-flex rounded-full bg-primary/10 p-3 mb-3">
          <Scan className="h-6 w-6 text-primary" />
        </div>
        <h2 className="text-xl font-bold">Run your first scan</h2>
        <p className="text-sm text-muted-foreground mt-1.5">ALdeci will trigger all connected scanners against your registered application.</p>
      </div>

      <div className="max-w-sm mx-auto space-y-4">
        {scanState === "idle" && (
          <Button size="lg" className="w-full h-12 text-sm gap-2" onClick={onScan}>
            <Play className="h-4 w-4" />
            Start First Scan
          </Button>
        )}

        {scanState === "scanning" && (
          <div className="space-y-4">
            <div className="flex items-center gap-3 rounded-lg border border-primary/30 bg-primary/5 p-4">
              <Loader2 className="h-5 w-5 text-primary animate-spin shrink-0" />
              <div className="flex-1">
                <p className="text-sm font-medium">Scan in progress…</p>
                <p className="text-xs text-muted-foreground mt-0.5">Running all 3 connected scanners</p>
              </div>
            </div>
            {["Snyk SAST/SCA", "Trivy Container", "Wiz CSPM"].map((s, i) => (
              <div key={s} className="flex items-center gap-2.5 text-sm">
                <Loader2 className="h-3.5 w-3.5 text-primary animate-spin" style={{ animationDelay: `${i * 0.2}s` }} />
                <span className="text-muted-foreground">{s}</span>
                <span className="text-xs text-muted-foreground ml-auto">Running…</span>
              </div>
            ))}
          </div>
        )}

        {scanState === "done" && (
          <div className="space-y-3">
            <div className="flex items-center gap-3 rounded-lg border border-green-500/30 bg-green-500/5 p-4">
              <CheckCircle className="h-5 w-5 text-green-400 shrink-0" />
              <div>
                <p className="text-sm font-semibold text-green-300">Scan complete!</p>
                <p className="text-xs text-muted-foreground mt-0.5">147 findings discovered across 3 scanners</p>
              </div>
            </div>
            <div className="grid grid-cols-4 gap-2 text-center">
              {[
                { label: "Critical", value: 3, color: "text-red-400" },
                { label: "High", value: 14, color: "text-orange-400" },
                { label: "Medium", value: 52, color: "text-yellow-400" },
                { label: "Low", value: 78, color: "text-blue-400" },
              ].map((item) => (
                <div key={item.label} className="rounded-lg border border-border/40 p-2">
                  <p className={`text-xl font-bold ${item.color}`}>{item.value}</p>
                  <p className="text-[10px] text-muted-foreground">{item.label}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function StepReviewResults() {
  return (
    <div className="space-y-5">
      <div className="text-center">
        <div className="inline-flex rounded-full bg-primary/10 p-3 mb-3">
          <Eye className="h-6 w-6 text-primary" />
        </div>
        <h2 className="text-xl font-bold">Explore your results</h2>
        <p className="text-sm text-muted-foreground mt-1.5">Here's a preview of what you'll find in the ALdeci workspace.</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-xl mx-auto">
        {[
          { icon: Shield, title: "Mission Control", desc: "Live risk posture, SLA tracking, and prioritized findings queue", color: "text-primary bg-primary/10" },
          { icon: Scan, title: "Finding Explorer", desc: "Filter, triage, and bulk-action across all scanner findings", color: "text-blue-400 bg-blue-500/10" },
          { icon: Sparkles, title: "ALdeci Copilot", desc: "AI-assisted triage, remediation suggestions, and CVSS explanation", color: "text-purple-400 bg-purple-500/10" },
          { icon: CheckCircle, title: "AutoFix Engine", desc: "One-click PR generation for 73% of common vulnerability patterns", color: "text-green-400 bg-green-500/10" },
          { icon: Eye, title: "Evidence Vault", desc: "SOC2/ISO27001 evidence auto-collection with audit-ready bundles", color: "text-yellow-400 bg-yellow-500/10" },
          { icon: AlertCircle, title: "FAIL Engine", desc: "Adversarial drills to validate your detection and response capability", color: "text-orange-400 bg-orange-500/10" },
        ].map(({ icon: Icon, title, desc, color }) => (
          <div key={title} className="flex gap-3 rounded-xl border border-border/40 p-3.5 hover:border-border transition-colors">
            <div className={`rounded-lg p-2 h-fit ${color}`}>
              <Icon className="h-4 w-4" />
            </div>
            <div>
              <p className="text-sm font-semibold">{title}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function StepPersonalize({
  selectedRole,
  onSelectRole,
}: {
  selectedRole: string;
  onSelectRole: (v: string) => void;
}) {
  const selected = ROLES.find((r) => r.value === selectedRole);
  return (
    <div className="space-y-5">
      <div className="text-center">
        <div className="inline-flex rounded-full bg-primary/10 p-3 mb-3">
          <User className="h-6 w-6 text-primary" />
        </div>
        <h2 className="text-xl font-bold">Personalize your experience</h2>
        <p className="text-sm text-muted-foreground mt-1.5">Choose your role so ALdeci can tailor your home dashboard and default views.</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 max-w-xl mx-auto">
        {ROLES.map((role) => (
          <button
            key={role.value}
            onClick={() => onSelectRole(role.value)}
            className={`flex items-start gap-3 rounded-xl border p-3.5 text-left transition-all ${selectedRole === role.value ? "border-primary bg-primary/5 shadow-sm shadow-primary/10" : "border-border/40 hover:border-border"}`}
          >
            <div className={`mt-0.5 h-4 w-4 rounded-full border-2 flex items-center justify-center shrink-0 ${selectedRole === role.value ? "border-primary" : "border-muted-foreground/40"}`}>
              {selectedRole === role.value && <div className="h-2 w-2 rounded-full bg-primary" />}
            </div>
            <div>
              <p className="text-sm font-semibold">{role.label}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{role.description}</p>
            </div>
          </button>
        ))}
      </div>

      {selected && (
        <motion.div
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-xl mx-auto rounded-lg border border-primary/30 bg-primary/5 p-3 flex items-center gap-2.5"
        >
          <CheckCircle className="h-4 w-4 text-primary shrink-0" />
          <p className="text-xs text-muted-foreground">
            Your home space will be set to <span className="text-foreground font-medium">{selected.homeSpace}</span>
          </p>
        </motion.div>
      )}
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function OnboardingWizard() {
  const navigate = useNavigate();
  const { completeOnboarding, setPreferences } = useAppStore();

  const [step, setStep] = useState(1);
  const [direction, setDirection] = useState(1);
  const [selectedScanners, setSelectedScanners] = useState<Set<string>>(new Set(["snyk", "trivy", "wiz"]));
  const [appForm, setAppForm] = useState({ name: "", repo: "", team: "", classification: "" });
  const [scanState, setScanState] = useState<"idle" | "scanning" | "done">("idle");
  const [selectedRole, setSelectedRole] = useState("");

  const totalSteps = STEPS.length;
  const progress = ((step - 1) / (totalSteps - 1)) * 100;

  const toggleScanner = (id: string) => {
    setSelectedScanners((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const handleScan = () => {
    setScanState("scanning");
    setTimeout(() => setScanState("done"), 3000);
  };

  const goNext = () => {
    if (step === 3 && scanState === "idle") {
      toast.warning("Please run the scan first");
      return;
    }
    if (step < totalSteps) {
      setDirection(1);
      setStep((s) => s + 1);
    }
  };

  const goPrev = () => {
    if (step > 1) {
      setDirection(-1);
      setStep((s) => s - 1);
    }
  };

  const completeMutation = useMutation({
    mutationFn: async () => {
      await new Promise((r) => setTimeout(r, 800));
    },
    onSuccess: () => {
      const role = ROLES.find((r) => r.value === selectedRole);
      completeOnboarding();
      setPreferences({
        role: selectedRole,
        homeSpace: role?.homeSpace ?? "/mission-control",
      });
      toast.success("Setup complete! Welcome to ALdeci.");
      navigate(role?.homeSpace ?? "/mission-control");
    },
  });

  const canFinish = selectedRole !== "";

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4 relative overflow-hidden">
      {/* Ambient background */}
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-background to-background pointer-events-none" />
      <div className="absolute top-0 left-1/2 -translate-x-1/2 h-px w-1/2 bg-gradient-to-r from-transparent via-primary/30 to-transparent" />

      <div className="relative w-full max-w-2xl">
        {/* Logo / Brand */}
        <div className="flex items-center justify-center gap-2 mb-8">
          <div className="h-8 w-8 rounded-lg bg-primary/20 flex items-center justify-center">
            <Shield className="h-4 w-4 text-primary" />
          </div>
          <span className="text-xl font-bold tracking-tight">ALdeci</span>
          <Badge variant="secondary" className="text-xs">Setup</Badge>
        </div>

        {/* Progress Steps */}
        <div className="flex items-center justify-center gap-0 mb-8">
          {STEPS.map((s, i) => {
            const StepIcon = s.icon;
            const isCompleted = step > s.id;
            const isCurrent = step === s.id;
            return (
              <div key={s.id} className="flex items-center">
                <div className="flex flex-col items-center gap-1.5">
                  <div className={`h-8 w-8 rounded-full flex items-center justify-center transition-all ${isCompleted ? "bg-primary text-primary-foreground" : isCurrent ? "bg-primary/20 text-primary ring-2 ring-primary/40" : "bg-muted/50 text-muted-foreground"}`}>
                    {isCompleted ? <CheckCircle className="h-4 w-4" /> : <StepIcon className="h-3.5 w-3.5" />}
                  </div>
                  <span className={`text-[10px] font-medium hidden sm:block ${isCurrent ? "text-foreground" : "text-muted-foreground"}`}>{s.label}</span>
                </div>
                {i < STEPS.length - 1 && (
                  <div className={`h-px w-8 sm:w-12 mx-0.5 sm:mx-1 mb-3.5 transition-colors ${step > s.id ? "bg-primary" : "bg-border/40"}`} />
                )}
              </div>
            );
          })}
        </div>

        {/* Card */}
        <div className="relative overflow-hidden rounded-2xl border border-border/50 bg-card shadow-xl shadow-black/20">
          {/* Progress bar */}
          <div className="h-0.5 bg-muted/30">
            <motion.div
              className="h-full bg-primary"
              initial={false}
              animate={{ width: `${progress}%` }}
              transition={{ duration: 0.4, ease: "easeOut" }}
            />
          </div>

          <div className="p-6 sm:p-8 min-h-[480px] flex flex-col">
            {/* Step content */}
            <AnimatePresence mode="wait" custom={direction}>
              <motion.div
                key={step}
                custom={direction}
                variants={variants}
                initial="enter"
                animate="center"
                exit="exit"
                transition={{ duration: 0.25, ease: "easeOut" }}
                className="flex-1"
              >
                {step === 1 && <StepConnectTools selected={selectedScanners} onToggle={toggleScanner} />}
                {step === 2 && <StepRegisterApp form={appForm} onChange={(f) => setAppForm({ ...appForm, ...f })} />}
                {step === 3 && <StepFirstScan scanState={scanState} onScan={handleScan} />}
                {step === 4 && <StepReviewResults />}
                {step === 5 && <StepPersonalize selectedRole={selectedRole} onSelectRole={setSelectedRole} />}
              </motion.div>
            </AnimatePresence>

            {/* Navigation */}
            <div className="flex items-center justify-between mt-6 pt-4 border-t border-border/30">
              <Button
                variant="ghost"
                size="sm"
                onClick={goPrev}
                disabled={step === 1}
                className="gap-1.5"
              >
                <ChevronLeft className="h-4 w-4" />
                Back
              </Button>

              <span className="text-xs text-muted-foreground">{step} of {totalSteps}</span>

              {step < totalSteps ? (
                <Button size="sm" onClick={goNext} className="gap-1.5">
                  {step === 3 && scanState === "idle" ? (
                    <>Skip<ChevronRight className="h-4 w-4" /></>
                  ) : (
                    <>Continue<ChevronRight className="h-4 w-4" /></>
                  )}
                </Button>
              ) : (
                <Button
                  size="sm"
                  onClick={() => completeMutation.mutate()}
                  disabled={!canFinish || completeMutation.isPending}
                  className="gap-1.5 min-w-28"
                >
                  {completeMutation.isPending ? (
                    <><Loader2 className="h-3.5 w-3.5 animate-spin" />Setting up…</>
                  ) : (
                    <>Enter ALdeci<ArrowRight className="h-4 w-4" /></>
                  )}
                </Button>
              )}
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-muted-foreground mt-4">
          All settings can be changed later in <a href="/settings" className="text-primary hover:underline">Settings</a>
        </p>
      </div>
    </div>
  );
}
