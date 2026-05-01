// FEATURE-1 — /onboarding wizard.  Real backend calls only, zero mocks.
//
// 4 steps per founder spec (2026-05-02):
//   1. Connect Cloud Account → POST /api/v1/cloud-accounts/accounts
//   2. Connect Source Repo  → POST /api/v1/github-app/register
//   3. Run First Scan       → POST /api/v1/iac/scan + /api/v1/cspm-engine/scan (parallel)
//   4. View Dashboard       → navigate("/mission-control")
//
// Endpoint substitutions made vs. spec:
//   - "cloud-connectors/accounts" → "cloud-accounts/accounts"
//     (cloud-accounts is the BUG-2 router; "cloud-connectors" doesn't exist)
//   - "connectors/github"          → "github-app/register"
//     (github-app is the canonical install registry — idempotent)
//   - "aspm/scan"                  → "cspm-engine/scan"
//     (no aspm scan endpoint exists; cspm-engine/scan is the closest org-wide scan)
//
// Each step has a "Skip for now" button that simply advances state.  Backend
// validates on submit; UI requires only non-empty fields client-side.

import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios, { AxiosError } from "axios";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield,
  ChevronRight,
  ChevronLeft,
  CheckCircle,
  Cloud,
  GitBranch,
  ScanLine,
  LayoutDashboard,
  Loader2,
  ArrowRight,
  SkipForward,
  AlertCircle,
} from "lucide-react";
import { toast } from "sonner";
import {
  buildApiUrl,
  getStoredAuthToken,
  getStoredAuthStrategy,
  getStoredOrgId,
} from "@/lib/api";

// ── Local axios POST helper (uses the same auth headers as lib/api.ts) ──────
async function apiPost<T = unknown>(
  path: string,
  body: unknown,
  query?: Record<string, string>,
): Promise<T> {
  const url = buildApiUrl(path, query);
  const token = getStoredAuthToken();
  const strategy = getStoredAuthStrategy();
  const orgId = getStoredOrgId();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) {
    if (strategy === "jwt") {
      headers["Authorization"] = token.toLowerCase().startsWith("bearer ")
        ? token
        : `Bearer ${token}`;
    } else {
      headers["X-API-Key"] = token;
    }
  }
  if (orgId) headers["X-Org-ID"] = orgId;
  const res = await axios.post<T>(url, body, { headers });
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

// ── Step indicator ──────────────────────────────────────────────────────────
const STEPS = [
  { id: 1, title: "Cloud Account", icon: Cloud },
  { id: 2, title: "Source Repo", icon: GitBranch },
  { id: 3, title: "First Scan", icon: ScanLine },
  { id: 4, title: "Dashboard", icon: LayoutDashboard },
];

function StepIndicator({ currentStep }: { currentStep: number }) {
  return (
    <ol
      className="flex items-center gap-2 sm:gap-3"
      aria-label="Onboarding progress"
    >
      {STEPS.map((step, i) => {
        const isDone = step.id < currentStep;
        const isCurrent = step.id === currentStep;
        const Icon = step.icon;
        return (
          <li key={step.id} className="flex items-center gap-2 sm:gap-3">
            <div className="flex flex-col items-center gap-1">
              <div
                className={`h-9 w-9 rounded-full flex items-center justify-center text-xs font-bold transition-colors ${
                  isDone
                    ? "bg-primary text-primary-foreground"
                    : isCurrent
                      ? "bg-primary/15 text-primary border-2 border-primary"
                      : "bg-muted text-muted-foreground"
                }`}
                aria-current={isCurrent ? "step" : undefined}
                aria-label={`Step ${step.id}: ${step.title}${isDone ? " (completed)" : isCurrent ? " (current)" : ""}`}
              >
                {isDone ? (
                  <CheckCircle className="h-4 w-4" aria-hidden="true" />
                ) : (
                  <Icon className="h-4 w-4" aria-hidden="true" />
                )}
              </div>
              <span
                className={`text-[11px] hidden sm:block whitespace-nowrap ${
                  isCurrent ? "text-primary font-medium" : "text-muted-foreground"
                }`}
              >
                {step.title}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div
                className={`h-0.5 w-6 sm:w-12 mb-4 transition-colors ${
                  isDone ? "bg-primary" : "bg-muted"
                }`}
                aria-hidden="true"
              />
            )}
          </li>
        );
      })}
    </ol>
  );
}

// ── Inline error banner ─────────────────────────────────────────────────────
function ErrorBanner({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2 p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-sm"
    >
      <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden="true" />
      <span>{message}</span>
    </div>
  );
}

// ─── Step 1: Cloud Account ──────────────────────────────────────────────────
type CloudProvider = "aws" | "azure" | "gcp";

function StepCloudAccount({
  data,
  onChange,
  onSubmitted,
  onSkip,
}: {
  data: {
    account_id: string;
    account_name: string;
    provider: CloudProvider;
    region: string;
    role_arn: string;
  };
  onChange: (
    next: Partial<{
      account_id: string;
      account_name: string;
      provider: CloudProvider;
      region: string;
      role_arn: string;
    }>,
  ) => void;
  onSubmitted: (result: unknown) => void;
  onSkip: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const valid =
    data.account_id.trim().length > 0 &&
    data.account_name.trim().length > 0 &&
    data.region.trim().length > 0;

  const handleSubmit = async () => {
    if (!valid) return;
    setSubmitting(true);
    setError(null);
    try {
      const orgId = getStoredOrgId();
      const result = await apiPost(
        "/api/v1/cloud-accounts/accounts",
        {
          account_id: data.account_id.trim(),
          account_name: data.account_name.trim(),
          provider: data.provider,
          region: data.region.trim(),
        },
        { org_id: orgId },
      );
      toast.success(`Connected ${data.provider.toUpperCase()} account ${data.account_id}`);
      onSubmitted(result);
    } catch (err) {
      const msg = extractError(err);
      setError(msg);
      toast.error(`Could not register account: ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h2 className="text-2xl font-bold">Connect a cloud account</h2>
        <p className="text-muted-foreground text-sm">
          We monitor configuration drift, posture risk, and access events for the
          account you connect. Pick a non-prod account first to validate access.
        </p>
      </header>

      <fieldset className="space-y-4" disabled={submitting}>
        <div className="space-y-2">
          <Label htmlFor="cloud-provider" className="text-xs uppercase tracking-wide">
            Provider
          </Label>
          <select
            id="cloud-provider"
            value={data.provider}
            onChange={(e) =>
              onChange({ provider: e.target.value as CloudProvider })
            }
            className="w-full h-10 px-3 rounded-md border border-border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary"
          >
            <option value="aws">AWS</option>
            <option value="azure">Azure</option>
            <option value="gcp">GCP</option>
          </select>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="account-id" className="text-xs uppercase tracking-wide">
              Account ID
            </Label>
            <Input
              id="account-id"
              placeholder={
                data.provider === "aws"
                  ? "123456789012"
                  : data.provider === "azure"
                    ? "subscription-uuid"
                    : "my-gcp-project"
              }
              value={data.account_id}
              onChange={(e) => onChange({ account_id: e.target.value })}
              autoComplete="off"
              spellCheck={false}
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="account-name" className="text-xs uppercase tracking-wide">
              Friendly name
            </Label>
            <Input
              id="account-name"
              placeholder="prod-us-east"
              value={data.account_name}
              onChange={(e) => onChange({ account_name: e.target.value })}
              autoComplete="off"
              required
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="region" className="text-xs uppercase tracking-wide">
            Default region
          </Label>
          <Input
            id="region"
            placeholder={data.provider === "aws" ? "us-east-1" : "global"}
            value={data.region}
            onChange={(e) => onChange({ region: e.target.value })}
            autoComplete="off"
            spellCheck={false}
            required
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="role-arn" className="text-xs uppercase tracking-wide">
            {data.provider === "aws"
              ? "IAM Role ARN"
              : data.provider === "azure"
                ? "Service Principal ID"
                : "Service Account email"}{" "}
            <span className="text-muted-foreground normal-case">(optional)</span>
          </Label>
          <Input
            id="role-arn"
            placeholder={
              data.provider === "aws"
                ? "arn:aws:iam::123456789012:role/AldeciScanner"
                : data.provider === "azure"
                  ? "00000000-0000-0000-0000-000000000000"
                  : "scanner@my-gcp-project.iam.gserviceaccount.com"
            }
            value={data.role_arn}
            onChange={(e) => onChange({ role_arn: e.target.value })}
            autoComplete="off"
            spellCheck={false}
          />
          <p className="text-xs text-muted-foreground">
            Role-based access is preferred over keys. You can wire credentials from
            Settings → Cloud Accounts later.
          </p>
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
        <Button
          onClick={handleSubmit}
          disabled={!valid || submitting}
          className="gap-2"
        >
          {submitting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Connecting…
            </>
          ) : (
            <>
              Connect & continue
              <ChevronRight className="h-4 w-4" />
            </>
          )}
        </Button>
      </div>
    </div>
  );
}

// ─── Step 2: Source Repo ────────────────────────────────────────────────────
type SourceProvider = "github" | "gitlab";

function StepSourceRepo({
  data,
  onChange,
  onSubmitted,
  onSkip,
}: {
  data: {
    provider: SourceProvider;
    repo_url: string;
    app_id: string;
    installation_id: string;
    access_token: string;
  };
  onChange: (
    next: Partial<{
      provider: SourceProvider;
      repo_url: string;
      app_id: string;
      installation_id: string;
      access_token: string;
    }>,
  ) => void;
  onSubmitted: (result: unknown) => void;
  onSkip: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const valid =
    data.repo_url.trim().length > 0 &&
    data.app_id.trim().length > 0 &&
    data.installation_id.trim().length > 0 &&
    data.access_token.trim().length >= 8;

  const handleSubmit = async () => {
    if (!valid) return;
    setSubmitting(true);
    setError(null);
    try {
      // /api/v1/github-app/register accepts: org_id, app_id, installation_id, webhook_secret
      // For GitLab we still post — backend may 4xx; we surface the error.
      const orgId = getStoredOrgId();
      const result = await apiPost("/api/v1/github-app/register", {
        org_id: orgId,
        app_id: data.app_id.trim(),
        installation_id: data.installation_id.trim(),
        webhook_secret: data.access_token.trim(),
        app_slug: data.repo_url.trim().slice(0, 256),
      });
      toast.success(`Repo registered: ${data.repo_url}`);
      onSubmitted(result);
    } catch (err) {
      const msg = extractError(err);
      setError(msg);
      toast.error(`Could not register repo: ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h2 className="text-2xl font-bold">Connect a source repository</h2>
        <p className="text-muted-foreground text-sm">
          Link a GitHub installation (or GitLab project) so ALDECI can pull
          source for SBOM, secret, and code scans. Credentials are stored
          hashed; raw tokens are never persisted.
        </p>
      </header>

      <fieldset className="space-y-4" disabled={submitting}>
        <div className="space-y-2">
          <Label htmlFor="src-provider" className="text-xs uppercase tracking-wide">
            Provider
          </Label>
          <select
            id="src-provider"
            value={data.provider}
            onChange={(e) =>
              onChange({ provider: e.target.value as SourceProvider })
            }
            className="w-full h-10 px-3 rounded-md border border-border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary"
          >
            <option value="github">GitHub</option>
            <option value="gitlab">GitLab</option>
          </select>
        </div>

        <div className="space-y-2">
          <Label htmlFor="repo-url" className="text-xs uppercase tracking-wide">
            Repository URL
          </Label>
          <Input
            id="repo-url"
            placeholder={
              data.provider === "github"
                ? "https://github.com/your-org/your-repo"
                : "https://gitlab.com/your-org/your-repo"
            }
            value={data.repo_url}
            onChange={(e) => onChange({ repo_url: e.target.value })}
            autoComplete="off"
            spellCheck={false}
            required
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="app-id" className="text-xs uppercase tracking-wide">
              {data.provider === "github" ? "App ID" : "Project ID"}
            </Label>
            <Input
              id="app-id"
              placeholder={data.provider === "github" ? "123456" : "12345678"}
              value={data.app_id}
              onChange={(e) => onChange({ app_id: e.target.value })}
              autoComplete="off"
              spellCheck={false}
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="installation-id" className="text-xs uppercase tracking-wide">
              Installation ID
            </Label>
            <Input
              id="installation-id"
              placeholder="78901234"
              value={data.installation_id}
              onChange={(e) => onChange({ installation_id: e.target.value })}
              autoComplete="off"
              spellCheck={false}
              required
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="access-token" className="text-xs uppercase tracking-wide">
            Access token / webhook secret
          </Label>
          <Input
            id="access-token"
            type="password"
            placeholder="ghp_…  or  glpat_…"
            value={data.access_token}
            onChange={(e) => onChange({ access_token: e.target.value })}
            autoComplete="new-password"
            spellCheck={false}
            minLength={8}
            required
          />
          <p className="text-xs text-muted-foreground">
            Stored as a SHA-256 hash. Used to verify webhook signatures.
          </p>
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
        <Button
          onClick={handleSubmit}
          disabled={!valid || submitting}
          className="gap-2"
        >
          {submitting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Registering…
            </>
          ) : (
            <>
              Register & continue
              <ChevronRight className="h-4 w-4" />
            </>
          )}
        </Button>
      </div>
    </div>
  );
}

// ─── Step 3: First Scan ─────────────────────────────────────────────────────
type ScanRunResult = {
  iac: { ok: boolean; scan_id?: string; total_findings?: number; error?: string };
  cspm: { ok: boolean; count?: number; org_id?: string; error?: string };
};

function StepFirstScan({
  iacContent,
  onIacContentChange,
  onScanned,
  onSkip,
}: {
  iacContent: string;
  onIacContentChange: (v: string) => void;
  onScanned: (r: ScanRunResult) => void;
  onSkip: () => void;
}) {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ScanRunResult | null>(null);

  const SAMPLE_TF = `resource "aws_s3_bucket" "demo" {
  bucket = "aldeci-onboarding-demo"
  acl    = "public-read"
}
`;

  const handleRunScan = async () => {
    setRunning(true);
    setResult(null);
    const orgId = getStoredOrgId();
    const scanId = `onboarding-${Date.now()}`;
    const content = iacContent.trim().length > 0 ? iacContent : SAMPLE_TF;

    const iacPromise = apiPost<{ scan_id?: string; total_findings?: number; findings?: unknown[] }>(
      "/api/v1/iac/scan",
      { content, filename: "main.tf", scan_id: scanId },
    )
      .then((r) => ({
        ok: true,
        scan_id: r.scan_id ?? scanId,
        total_findings:
          typeof r.total_findings === "number"
            ? r.total_findings
            : Array.isArray(r.findings)
              ? r.findings.length
              : 0,
      }))
      .catch((e) => ({ ok: false, error: extractError(e) }));

    const cspmPromise = apiPost<{ count?: number; org_id?: string }>(
      "/api/v1/cspm-engine/scan",
      { org_id: orgId },
    )
      .then((r) => ({ ok: true, count: r.count ?? 0, org_id: r.org_id ?? orgId }))
      .catch((e) => ({ ok: false, error: extractError(e) }));

    const [iac, cspm] = await Promise.all([iacPromise, cspmPromise]);
    const final: ScanRunResult = { iac, cspm };
    setResult(final);
    setRunning(false);

    if (iac.ok || cspm.ok) {
      toast.success("Scan complete");
      onScanned(final);
    } else {
      toast.error("Both scans failed — see details below");
    }
  };

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h2 className="text-2xl font-bold">Run your first scan</h2>
        <p className="text-muted-foreground text-sm">
          We'll fire an Infrastructure-as-Code scan and a cloud-posture scan in
          parallel against your account. This usually takes under 30 seconds.
        </p>
      </header>

      <div className="space-y-2">
        <Label htmlFor="iac-content" className="text-xs uppercase tracking-wide">
          Terraform / IaC content{" "}
          <span className="text-muted-foreground normal-case">(optional — sample used if blank)</span>
        </Label>
        <textarea
          id="iac-content"
          value={iacContent}
          onChange={(e) => onIacContentChange(e.target.value)}
          placeholder={SAMPLE_TF}
          rows={6}
          spellCheck={false}
          className="w-full px-3 py-2 rounded-md border border-border bg-background text-xs font-mono focus:outline-none focus:ring-2 focus:ring-primary"
        />
      </div>

      {!running && !result && (
        <Button onClick={handleRunScan} className="gap-2 w-full sm:w-auto">
          <ScanLine className="h-4 w-4" />
          Run IaC + Cloud Posture scan
        </Button>
      )}

      {running && (
        <div className="space-y-3" role="status" aria-live="polite">
          <div className="flex items-center gap-2 text-sm">
            <Loader2 className="h-4 w-4 text-primary animate-spin" />
            <span>Scanning… IaC and CSPM running in parallel.</span>
          </div>
          <Progress value={66} className="h-2" />
        </div>
      )}

      {result && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-4"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div
              className={`p-4 rounded-xl border ${
                result.iac.ok
                  ? "border-green-500/30 bg-green-500/5"
                  : "border-red-500/30 bg-red-500/5"
              }`}
            >
              <div className="flex items-center gap-2 mb-2">
                {result.iac.ok ? (
                  <CheckCircle className="h-4 w-4 text-green-500" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-red-500" />
                )}
                <span className="text-sm font-semibold">IaC scan</span>
              </div>
              {result.iac.ok ? (
                <p className="text-xs text-muted-foreground">
                  scan_id: <code>{result.iac.scan_id}</code> —{" "}
                  <strong className="text-foreground">{result.iac.total_findings ?? 0}</strong>{" "}
                  findings.
                </p>
              ) : (
                <p className="text-xs text-red-400">{result.iac.error}</p>
              )}
            </div>

            <div
              className={`p-4 rounded-xl border ${
                result.cspm.ok
                  ? "border-green-500/30 bg-green-500/5"
                  : "border-red-500/30 bg-red-500/5"
              }`}
            >
              <div className="flex items-center gap-2 mb-2">
                {result.cspm.ok ? (
                  <CheckCircle className="h-4 w-4 text-green-500" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-red-500" />
                )}
                <span className="text-sm font-semibold">Cloud posture scan</span>
              </div>
              {result.cspm.ok ? (
                <p className="text-xs text-muted-foreground">
                  org_id: <code>{result.cspm.org_id}</code> —{" "}
                  <strong className="text-foreground">{result.cspm.count ?? 0}</strong>{" "}
                  checks executed.
                </p>
              ) : (
                <p className="text-xs text-red-400">{result.cspm.error}</p>
              )}
            </div>
          </div>
        </motion.div>
      )}

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-end gap-2 pt-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={onSkip}
          disabled={running}
          className="gap-1.5 text-muted-foreground"
        >
          <SkipForward className="h-3.5 w-3.5" />
          Skip for now
        </Button>
        <Button
          onClick={() => onScanned(result ?? { iac: { ok: false }, cspm: { ok: false } })}
          disabled={running || !result}
          className="gap-2"
        >
          Continue
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

// ─── Step 4: View Dashboard ─────────────────────────────────────────────────
function StepDashboard({ onGo }: { onGo: () => void }) {
  return (
    <div className="space-y-6 text-center">
      <motion.div
        className="inline-block"
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ type: "spring", stiffness: 220, damping: 14 }}
      >
        <div className="h-20 w-20 rounded-full bg-primary/15 flex items-center justify-center mx-auto">
          <CheckCircle className="h-10 w-10 text-primary" aria-hidden="true" />
        </div>
      </motion.div>
      <div>
        <h2 className="text-2xl font-bold">Your dashboard is populating</h2>
        <p className="text-muted-foreground mt-2 text-sm">
          Findings, posture scores, and inventory data will stream in as your
          first scan completes. This typically takes 1–5 minutes.
        </p>
      </div>
      <div className="flex flex-col items-center gap-2">
        <Button size="lg" className="gap-2" onClick={onGo}>
          Go to Mission Control
          <ArrowRight className="h-4 w-4" />
        </Button>
        <Link
          to="/mission-control"
          className="text-xs text-muted-foreground hover:text-foreground underline-offset-4 hover:underline"
        >
          Or open /mission-control directly
        </Link>
      </div>
    </div>
  );
}

// ─── Main wizard ────────────────────────────────────────────────────────────
export default function OnboardingWizard() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);

  // Step 1 state
  const [cloud, setCloud] = useState<{
    account_id: string;
    account_name: string;
    provider: CloudProvider;
    region: string;
    role_arn: string;
  }>({
    account_id: "",
    account_name: "",
    provider: "aws",
    region: "us-east-1",
    role_arn: "",
  });

  // Step 2 state
  const [source, setSource] = useState<{
    provider: SourceProvider;
    repo_url: string;
    app_id: string;
    installation_id: string;
    access_token: string;
  }>({
    provider: "github",
    repo_url: "",
    app_id: "",
    installation_id: "",
    access_token: "",
  });

  // Step 3 state
  const [iacContent, setIacContent] = useState<string>("");

  const goNext = () => setStep((s) => Math.min(s + 1, STEPS.length));
  const goBack = () => setStep((s) => Math.max(s - 1, 1));
  const goDashboard = () => navigate("/mission-control");

  const progressPct = ((step - 1) / (STEPS.length - 1)) * 100;

  return (
    <main className="min-h-screen bg-background flex items-start sm:items-center justify-center p-4 sm:p-6">
      <div className="w-full max-w-3xl">
        <header className="text-center mb-6 sm:mb-8">
          <div className="flex items-center justify-center gap-2 mb-2">
            <Shield className="h-6 w-6 text-primary" aria-hidden="true" />
            <span className="text-lg font-bold">ALDECI</span>
          </div>
          <p className="text-muted-foreground text-sm">
            Onboarding — Step {step} of {STEPS.length}
          </p>
        </header>

        <div className="mb-6">
          <Progress value={progressPct} className="h-1 mb-5" />
          <div className="flex justify-center">
            <StepIndicator currentStep={step} />
          </div>
        </div>

        <Card className="shadow-xl border-border/60">
          <CardContent className="p-6 sm:p-8">
            <AnimatePresence mode="wait">
              <motion.div
                key={step}
                initial={{ opacity: 0, x: 24 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -24 }}
                transition={{ duration: 0.2, ease: "easeInOut" }}
              >
                {step === 1 && (
                  <StepCloudAccount
                    data={cloud}
                    onChange={(next) => setCloud((s) => ({ ...s, ...next }))}
                    onSubmitted={() => goNext()}
                    onSkip={goNext}
                  />
                )}
                {step === 2 && (
                  <StepSourceRepo
                    data={source}
                    onChange={(next) => setSource((s) => ({ ...s, ...next }))}
                    onSubmitted={() => goNext()}
                    onSkip={goNext}
                  />
                )}
                {step === 3 && (
                  <StepFirstScan
                    iacContent={iacContent}
                    onIacContentChange={setIacContent}
                    onScanned={() => goNext()}
                    onSkip={goNext}
                  />
                )}
                {step === 4 && <StepDashboard onGo={goDashboard} />}
              </motion.div>
            </AnimatePresence>
          </CardContent>

          <div className="px-6 sm:px-8 pb-6 flex items-center justify-between border-t border-border/40 pt-4">
            <Button
              variant="outline"
              onClick={goBack}
              disabled={step === 1}
              className="gap-2"
            >
              <ChevronLeft className="h-4 w-4" />
              Back
            </Button>
            <span className="text-xs text-muted-foreground">
              {STEPS[step - 1]?.title}
            </span>
          </div>
        </Card>
      </div>
    </main>
  );
}
