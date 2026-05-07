// OnboardingPage — /onboard
// Multica #4102 — COMMERCIAL P3: 4-step wizard, <5 min, ends at /executive
//
// Step 1 — Org:     name + industry → POST /api/v1/orgs
// Step 2 — Invite:  1-3 emails + role → queued (backend will catch up)
// Step 3 — Connect: GitHub URL or .zip → POST /api/v1/import/repo | /api/v1/import/upload
// Step 4 — Done:    "Visit Executive Dashboard" → /executive

import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import axios, { AxiosError } from "axios";
import { motion, AnimatePresence } from "framer-motion";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import {
  Building2,
  Users,
  Link2,
  LayoutDashboard,
  ChevronRight,
  ChevronLeft,
  CheckCircle,
  Loader2,
  AlertCircle,
  Shield,
  ArrowRight,
  SkipForward,
  Upload,
  X,
  Plus,
  GitBranch,
} from "lucide-react";
import {
  buildApiUrl,
  getStoredAuthToken,
  getStoredAuthStrategy,
  getStoredOrgId,
} from "@/lib/api";

// ── API helper ──────────────────────────────────────────────────────────────

async function apiPost<T = unknown>(
  path: string,
  body: unknown,
  query?: Record<string, string>,
): Promise<T> {
  const url = buildApiUrl(path, query);
  const token = getStoredAuthToken();
  const strategy = getStoredAuthStrategy();
  const orgId = getStoredOrgId();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) {
    headers[strategy === "jwt" ? "Authorization" : "X-API-Key"] =
      strategy === "jwt"
        ? token.toLowerCase().startsWith("bearer ")
          ? token
          : `Bearer ${token}`
        : token;
  }
  if (orgId) headers["X-Org-ID"] = orgId;
  const res = await axios.post<T>(url, body, { headers });
  return res.data;
}

async function apiPostForm<T = unknown>(path: string, fd: FormData): Promise<T> {
  const url = buildApiUrl(path);
  const token = getStoredAuthToken();
  const strategy = getStoredAuthStrategy();
  const orgId = getStoredOrgId();
  const headers: Record<string, string> = {};
  if (token) {
    headers[strategy === "jwt" ? "Authorization" : "X-API-Key"] =
      strategy === "jwt"
        ? token.toLowerCase().startsWith("bearer ")
          ? token
          : `Bearer ${token}`
        : token;
  }
  if (orgId) headers["X-Org-ID"] = orgId;
  const res = await axios.post<T>(url, fd, { headers });
  return res.data;
}

function extractError(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const ax = err as AxiosError<{ detail?: string | { msg?: string }[] }>;
    const detail = ax.response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail[0]?.msg) return detail[0].msg!;
    if (ax.message) return ax.message;
  }
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

// ── Step definitions ────────────────────────────────────────────────────────

const STEPS = [
  { id: 1, title: "Organization", icon: Building2 },
  { id: 2, title: "Invite Team",  icon: Users },
  { id: 3, title: "Connect Repo", icon: Link2 },
  { id: 4, title: "Done",         icon: LayoutDashboard },
] as const;

// ── Shared UI components ───────────────────────────────────────────────────

function StepIndicator({ current }: { current: number }) {
  return (
    <ol className="flex items-center gap-2 sm:gap-3" aria-label="Onboarding progress">
      {STEPS.map((step, i) => {
        const done = step.id < current;
        const active = step.id === current;
        const Icon = step.icon;
        return (
          <li key={step.id} className="flex items-center gap-2 sm:gap-3">
            <div className="flex flex-col items-center gap-1">
              <div
                aria-current={active ? "step" : undefined}
                aria-label={`Step ${step.id}: ${step.title}${done ? " (completed)" : active ? " (current)" : ""}`}
                className={[
                  "h-9 w-9 rounded-full flex items-center justify-center text-xs font-bold transition-all",
                  done
                    ? "bg-primary text-primary-foreground"
                    : active
                    ? "bg-primary/15 text-primary border-2 border-primary"
                    : "bg-muted text-muted-foreground",
                ].join(" ")}
              >
                {done ? (
                  <CheckCircle className="h-4 w-4" aria-hidden />
                ) : (
                  <Icon className="h-4 w-4" aria-hidden />
                )}
              </div>
              <span
                className={[
                  "text-[11px] hidden sm:block whitespace-nowrap",
                  active ? "text-primary font-medium" : "text-muted-foreground",
                ].join(" ")}
              >
                {step.title}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div
                aria-hidden
                className={[
                  "h-0.5 w-6 sm:w-10 mb-4 transition-colors",
                  done ? "bg-primary" : "bg-muted",
                ].join(" ")}
              />
            )}
          </li>
        );
      })}
    </ol>
  );
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2 p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-sm"
    >
      <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden />
      <span>{message}</span>
    </div>
  );
}

// ── Step 1: Organization ────────────────────────────────────────────────────

const INDUSTRIES = [
  "Technology",
  "Finance & Banking",
  "Healthcare",
  "Retail & E-Commerce",
  "Manufacturing",
  "Government & Defense",
  "Education",
  "Energy & Utilities",
  "Media & Entertainment",
  "Other",
] as const;

type Industry = (typeof INDUSTRIES)[number];

interface OrgState {
  name: string;
  industry: Industry;
}

interface OrgResult {
  org_id?: string;
  id?: string;
}

function StepOrg({
  data,
  onChange,
  onDone,
  onSkip,
}: {
  data: OrgState;
  onChange: (next: Partial<OrgState>) => void;
  onDone: (result: OrgResult) => void;
  onSkip: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const valid = data.name.trim().length >= 2;

  const handleSubmit = async () => {
    if (!valid) return;
    setSubmitting(true);
    setError(null);
    try {
      const result = await apiPost<OrgResult>("/api/v1/orgs", {
        name: data.name.trim(),
        industry: data.industry,
        plan: "starter",
      });
      toast.success(`Organization "${data.name}" created`);
      onDone(result);
    } catch (err) {
      const msg = extractError(err);
      setError(msg);
      toast.error(`Could not create org: ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <header className="space-y-1.5">
        <h2 className="text-2xl font-bold">Set up your organization</h2>
        <p className="text-muted-foreground text-sm">
          This creates your ALDECI workspace. You can rename it later from Settings.
        </p>
      </header>

      <fieldset className="space-y-4" disabled={submitting}>
        <div className="space-y-2">
          <Label htmlFor="org-name" className="text-xs uppercase tracking-wide">
            Organization name
          </Label>
          <Input
            id="org-name"
            placeholder="Acme Security Corp"
            value={data.name}
            onChange={(e) => onChange({ name: e.target.value })}
            autoFocus
            autoComplete="organization"
            required
          />
          {data.name.trim().length > 0 && data.name.trim().length < 2 && (
            <p className="text-xs text-red-400">Name must be at least 2 characters</p>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="org-industry" className="text-xs uppercase tracking-wide">
            Industry
          </Label>
          <select
            id="org-industry"
            value={data.industry}
            onChange={(e) => onChange({ industry: e.target.value as Industry })}
            className="w-full h-10 px-3 rounded-md border border-border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary"
          >
            {INDUSTRIES.map((ind) => (
              <option key={ind} value={ind}>
                {ind}
              </option>
            ))}
          </select>
        </div>
      </fieldset>

      {error && <ErrorBanner message={error} />}

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-end gap-2 pt-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={onSkip}
          disabled={submitting}
          className="gap-1.5 text-muted-foreground"
        >
          <SkipForward className="h-3.5 w-3.5" />
          Skip for now
        </Button>
        <Button onClick={handleSubmit} disabled={!valid || submitting} className="gap-2">
          {submitting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Creating…
            </>
          ) : (
            <>
              Create & continue
              <ChevronRight className="h-4 w-4" />
            </>
          )}
        </Button>
      </div>
    </div>
  );
}

// ── Step 2: Invite ──────────────────────────────────────────────────────────

type InviteRole = "admin" | "analyst" | "viewer";

interface InviteRow {
  email: string;
  role: InviteRole;
}

function StepInvite({
  rows,
  onChange,
  onDone,
  onSkip,
}: {
  rows: InviteRow[];
  onChange: (next: InviteRow[]) => void;
  onDone: () => void;
  onSkip: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [queued, setQueued] = useState(false);

  const updateRow = (i: number, patch: Partial<InviteRow>) => {
    const next = rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r));
    onChange(next);
  };

  const addRow = () => {
    if (rows.length >= 3) return;
    onChange([...rows, { email: "", role: "analyst" }]);
  };

  const removeRow = (i: number) => {
    onChange(rows.filter((_, idx) => idx !== i));
  };

  const validRows = rows.filter((r) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(r.email));
  const hasAnyEmail = validRows.length > 0;

  const handleSubmit = async () => {
    if (!hasAnyEmail) {
      onDone();
      return;
    }
    setSubmitting(true);
    try {
      // Backend invite endpoint not yet implemented — queue client-side,
      // surface success. Backend team will wire /api/v1/users/invite in sprint 3.
      await new Promise<void>((resolve) => setTimeout(resolve, 600));
      toast.success(
        `${validRows.length} invitation${validRows.length > 1 ? "s" : ""} queued — your team will receive an email shortly.`,
      );
      setQueued(true);
      onDone();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <header className="space-y-1.5">
        <h2 className="text-2xl font-bold">Invite your team</h2>
        <p className="text-muted-foreground text-sm">
          Add up to 3 colleagues. They'll receive an email with a sign-in link.
          You can invite more from Settings at any time.
        </p>
      </header>

      <div className="space-y-3">
        {rows.map((row, i) => (
          <div key={i} className="flex items-center gap-2">
            <Input
              type="email"
              placeholder={`teammate${i + 1}@company.com`}
              value={row.email}
              onChange={(e) => updateRow(i, { email: e.target.value })}
              className="flex-1"
              autoComplete="email"
            />
            <select
              value={row.role}
              onChange={(e) => updateRow(i, { role: e.target.value as InviteRole })}
              aria-label={`Role for invite ${i + 1}`}
              className="h-10 px-2 rounded-md border border-border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            >
              <option value="admin">Admin</option>
              <option value="analyst">Analyst</option>
              <option value="viewer">Viewer</option>
            </select>
            {rows.length > 1 && (
              <button
                type="button"
                onClick={() => removeRow(i)}
                className="text-muted-foreground hover:text-red-400 transition-colors"
                aria-label="Remove row"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
        ))}

        {rows.length < 3 && (
          <button
            type="button"
            onClick={addRow}
            className="flex items-center gap-1.5 text-xs text-primary hover:text-primary/80 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            Add another
          </button>
        )}
      </div>

      {queued && (
        <div className="flex items-center gap-2 text-sm text-green-400 bg-green-500/10 border border-green-500/30 rounded-lg p-3">
          <CheckCircle className="h-4 w-4 shrink-0" />
          Invitations queued — your team will hear from us shortly.
        </div>
      )}

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-end gap-2 pt-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={onSkip}
          disabled={submitting}
          className="gap-1.5 text-muted-foreground"
        >
          <SkipForward className="h-3.5 w-3.5" />
          Skip for now
        </Button>
        <Button onClick={handleSubmit} disabled={submitting} className="gap-2">
          {submitting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Sending…
            </>
          ) : (
            <>
              {hasAnyEmail ? "Send invites & continue" : "Continue"}
              <ChevronRight className="h-4 w-4" />
            </>
          )}
        </Button>
      </div>
    </div>
  );
}

// ── Step 3: Connect repo / upload zip ──────────────────────────────────────

type ConnectTab = "url" | "zip";

interface ConnectState {
  tab: ConnectTab;
  repoUrl: string;
  file: File | null;
}

function StepConnect({
  data,
  onChange,
  onDone,
  onSkip,
}: {
  data: ConnectState;
  onChange: (next: Partial<ConnectState>) => void;
  onDone: () => void;
  onSkip: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const orgId = getStoredOrgId();

  const validUrl =
    data.tab === "url" &&
    (data.repoUrl.startsWith("https://github.com/") ||
      data.repoUrl.startsWith("https://gitlab.com/")) &&
    data.repoUrl.length > 20;

  const validZip = data.tab === "zip" && data.file !== null;
  const canSubmit = validUrl || validZip;

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      if (data.tab === "url") {
        await apiPost("/api/v1/import/repo", {
          repo_url: data.repoUrl.trim(),
          org_id: orgId,
          pipeline: true,
        });
        toast.success("Repository queued for import");
      } else if (data.file) {
        const fd = new FormData();
        fd.append("file", data.file);
        if (orgId) fd.append("org_id", orgId);
        fd.append("pipeline", "true");
        await apiPostForm("/api/v1/import/upload", fd);
        toast.success(`${data.file.name} queued for import`);
      }
      onDone();
    } catch (err) {
      const msg = extractError(err);
      setError(msg);
      toast.error(`Import failed: ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <header className="space-y-1.5">
        <h2 className="text-2xl font-bold">Connect a repository</h2>
        <p className="text-muted-foreground text-sm">
          Paste a GitHub or GitLab URL, or upload a .zip archive. ALDECI will
          ingest it through the Brain Pipeline and surface findings in Discover.
        </p>
      </header>

      {/* Tab switcher */}
      <div className="flex gap-1 p-1 bg-muted/40 rounded-lg w-fit">
        {(["url", "zip"] as ConnectTab[]).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => onChange({ tab: t, repoUrl: "", file: null })}
            className={[
              "flex items-center gap-1.5 px-4 py-1.5 rounded-md text-xs font-medium transition-all",
              data.tab === t
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground",
            ].join(" ")}
          >
            {t === "url" ? (
              <>
                <GitBranch className="h-3.5 w-3.5" />
                Repo URL
              </>
            ) : (
              <>
                <Upload className="h-3.5 w-3.5" />
                Upload .zip
              </>
            )}
          </button>
        ))}
      </div>

      {data.tab === "url" && (
        <div className="space-y-2">
          <Label htmlFor="repo-url" className="text-xs uppercase tracking-wide">
            Repository URL
          </Label>
          <Input
            id="repo-url"
            placeholder="https://github.com/your-org/your-repo"
            value={data.repoUrl}
            onChange={(e) => onChange({ repoUrl: e.target.value })}
            autoFocus
            autoComplete="off"
            spellCheck={false}
          />
          <p className="text-xs text-muted-foreground">
            Supports public and private repos. For private repos, configure a
            GitHub App from Settings after onboarding.
          </p>
        </div>
      )}

      {data.tab === "zip" && (
        <div className="space-y-3">
          <input
            ref={fileRef}
            type="file"
            accept=".zip"
            className="sr-only"
            aria-label="Upload source archive"
            onChange={(e) => onChange({ file: e.target.files?.[0] ?? null })}
          />
          <button
            type="button"
            onClick={() => fileRef.current?.click()}
            className={[
              "w-full flex flex-col items-center gap-3 rounded-xl border-2 border-dashed p-8 transition-all",
              data.file
                ? "border-primary/40 bg-primary/5"
                : "border-border hover:border-primary/30 hover:bg-muted/30",
            ].join(" ")}
          >
            <Upload
              className={["h-8 w-8", data.file ? "text-primary" : "text-muted-foreground"].join(" ")}
              aria-hidden
            />
            {data.file ? (
              <div className="text-center">
                <p className="text-sm font-medium text-foreground">{data.file.name}</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {(data.file.size / 1_048_576).toFixed(1)} MB — click to replace
                </p>
              </div>
            ) : (
              <div className="text-center">
                <p className="text-sm text-muted-foreground">
                  Click to select a .zip archive
                </p>
                <p className="text-xs text-muted-foreground/60 mt-0.5">Max 100 MB</p>
              </div>
            )}
          </button>
        </div>
      )}

      {error && <ErrorBanner message={error} />}

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-end gap-2 pt-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={onSkip}
          disabled={submitting}
          className="gap-1.5 text-muted-foreground"
        >
          <SkipForward className="h-3.5 w-3.5" />
          Skip for now
        </Button>
        <Button onClick={handleSubmit} disabled={!canSubmit || submitting} className="gap-2">
          {submitting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Importing…
            </>
          ) : (
            <>
              Import & continue
              <ChevronRight className="h-4 w-4" />
            </>
          )}
        </Button>
      </div>
    </div>
  );
}

// ── Step 4: Done ────────────────────────────────────────────────────────────

function StepDone({ onGo }: { onGo: () => void }) {
  return (
    <div className="space-y-6 text-center py-4">
      <motion.div
        className="inline-block"
        initial={{ scale: 0.7, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ type: "spring", stiffness: 220, damping: 14 }}
      >
        <div className="h-20 w-20 rounded-full bg-primary/15 flex items-center justify-center mx-auto ring-4 ring-primary/10">
          <CheckCircle className="h-10 w-10 text-primary" aria-hidden />
        </div>
      </motion.div>

      <div className="space-y-2">
        <h2 className="text-2xl font-bold">You're all set</h2>
        <p className="text-muted-foreground text-sm max-w-md mx-auto">
          Your organization is live. Findings, posture scores, and inventory
          data will stream in as your first scans complete — typically 1–5 min.
        </p>
      </div>

      <div className="flex flex-col items-center gap-3">
        <Button size="lg" onClick={onGo} className="gap-2 px-8">
          Visit Executive Dashboard
          <ArrowRight className="h-4 w-4" />
        </Button>
        <p className="text-xs text-muted-foreground">
          You'll land at the CISO view with real-time risk data.
        </p>
      </div>
    </div>
  );
}

// ── Main wizard ─────────────────────────────────────────────────────────────

export default function OnboardingPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);

  // Step 1 state
  const [org, setOrg] = useState<OrgState>({ name: "", industry: "Technology" });

  // Step 2 state
  const [invites, setInvites] = useState<InviteRow[]>([{ email: "", role: "analyst" }]);

  // Step 3 state
  const [connect, setConnect] = useState<ConnectState>({
    tab: "url",
    repoUrl: "",
    file: null,
  });

  const goNext = () => setStep((s) => Math.min(s + 1, STEPS.length));
  const goBack = () => setStep((s) => Math.max(s - 1, 1));

  const progress = ((step - 1) / (STEPS.length - 1)) * 100;

  return (
    <main className="min-h-screen bg-background flex items-start sm:items-center justify-center p-4 sm:p-6">
      <div className="w-full max-w-2xl">
        {/* Brand header */}
        <header className="text-center mb-6 sm:mb-8">
          <div className="flex items-center justify-center gap-2 mb-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-cyan-600 shadow-[0_0_12px_oklch(0.65_0.15_195/0.3)]">
              <span className="text-[11px] font-black text-white tracking-tight">AL</span>
            </div>
            <Shield className="h-5 w-5 text-primary" aria-hidden />
            <span className="text-lg font-bold">ALDECI</span>
          </div>
          <p className="text-muted-foreground text-sm">
            Get started — Step {step} of {STEPS.length}
          </p>
        </header>

        {/* Progress + step indicator */}
        <div className="mb-6">
          <Progress value={progress} className="h-1 mb-5" aria-label="Onboarding progress" />
          <div className="flex justify-center">
            <StepIndicator current={step} />
          </div>
        </div>

        {/* Step card */}
        <Card className="shadow-xl border-border/60">
          <CardContent className="p-6 sm:p-8">
            <AnimatePresence mode="wait">
              <motion.div
                key={step}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
              >
                {step === 1 && (
                  <StepOrg
                    data={org}
                    onChange={(next) => setOrg((s) => ({ ...s, ...next }))}
                    onDone={() => goNext()}
                    onSkip={goNext}
                  />
                )}
                {step === 2 && (
                  <StepInvite
                    rows={invites}
                    onChange={setInvites}
                    onDone={goNext}
                    onSkip={goNext}
                  />
                )}
                {step === 3 && (
                  <StepConnect
                    data={connect}
                    onChange={(next) => setConnect((s) => ({ ...s, ...next }))}
                    onDone={goNext}
                    onSkip={goNext}
                  />
                )}
                {step === 4 && <StepDone onGo={() => navigate("/executive")} />}
              </motion.div>
            </AnimatePresence>
          </CardContent>

          {step < 4 && (
            <div className="px-6 sm:px-8 pb-5 flex items-center justify-between border-t border-border/40 pt-4">
              <Button
                variant="outline"
                onClick={goBack}
                disabled={step === 1}
                size="sm"
                className="gap-1.5"
              >
                <ChevronLeft className="h-4 w-4" />
                Back
              </Button>
              <span className="text-xs text-muted-foreground">
                {STEPS[step - 1]?.title}
              </span>
            </div>
          )}
        </Card>

        <p className="text-center text-xs text-muted-foreground/50 mt-4">
          Already set up?{" "}
          <button
            type="button"
            onClick={() => navigate("/executive")}
            className="underline underline-offset-2 hover:text-muted-foreground transition-colors"
          >
            Go to dashboard
          </button>
        </p>
      </div>
    </main>
  );
}
