/**
 * ImportPage — /import
 * Founder-P0 (Multica #4003): repo URL import + .zip upload, real API calls only.
 */
import { useState } from "react";
import { Upload, GitBranch, CheckCircle, AlertCircle, Loader2, FolderOpen } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/shared/page-header";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface ImportJob {
  job_id: string;
  status: string;
  repo_url?: string;
  filename?: string;
  message: string;
  submitted_at: string;
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------
async function postJson<T>(path: string, body: unknown): Promise<T> {
  const token = getStoredAuthToken() || import.meta.env.VITE_API_KEY || "";
  const res = await fetch(buildApiUrl(path), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "X-API-Key": token } : {}),
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(detail?.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}

async function postFormData<T>(path: string, formData: FormData): Promise<T> {
  const token = getStoredAuthToken() || import.meta.env.VITE_API_KEY || "";
  const res = await fetch(buildApiUrl(path), {
    method: "POST",
    headers: {
      ...(token ? { "X-API-Key": token } : {}),
    },
    body: formData,
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(detail?.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------
function StatusBadge({ status }: { status: string }) {
  const variants: Record<string, { label: string; variant: "default" | "secondary" | "destructive" | "outline" }> = {
    queued: { label: "Queued", variant: "secondary" },
    processing: { label: "Processing", variant: "default" },
    done: { label: "Done", variant: "default" },
    failed: { label: "Failed", variant: "destructive" },
  };
  const cfg = variants[status] ?? { label: status, variant: "outline" };
  return <Badge variant={cfg.variant}>{cfg.label}</Badge>;
}

function JobRow({ job }: { job: ImportJob }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-border p-3 text-sm">
      <CheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-green-500" />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate font-mono text-xs text-muted-foreground">
            {job.repo_url ?? job.filename ?? job.job_id}
          </span>
          <StatusBadge status={job.status} />
        </div>
        <p className="mt-1 text-xs text-muted-foreground">{job.message}</p>
        <p className="mt-0.5 text-xs text-muted-foreground/60">{job.submitted_at}</p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Repo URL tab
// ---------------------------------------------------------------------------
function RepoTab({ onJob }: { onJob: (j: ImportJob) => void }) {
  const [url, setUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const orgId = getStoredOrgId() || "default";

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!url.trim()) return;
    setLoading(true);
    try {
      const job = await postJson<ImportJob>("/api/v1/import/repo", {
        repo_url: url.trim(),
        branch: branch.trim() || "main",
        org_id: orgId,
        scanners: ["sast", "secrets", "supply_chain"],
      });
      onJob({ ...job, submitted_at: new Date().toISOString() });
      setUrl("");
      setBranch("main");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-1.5">
        <Label htmlFor="repo-url">Repository URL</Label>
        <Input
          id="repo-url"
          placeholder="https://github.com/org/repo"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={loading}
          required
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="branch">Branch</Label>
        <Input
          id="branch"
          placeholder="main"
          value={branch}
          onChange={(e) => setBranch(e.target.value)}
          disabled={loading}
        />
      </div>
      {error && (
        <div className="flex items-center gap-2 rounded-md bg-destructive/10 p-2 text-xs text-destructive">
          <AlertCircle className="h-3.5 w-3.5 shrink-0" />
          {error}
        </div>
      )}
      <Button type="submit" disabled={loading || !url.trim()} className="w-full">
        {loading ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Queuing scan…
          </>
        ) : (
          <>
            <GitBranch className="mr-2 h-4 w-4" />
            Start scan
          </>
        )}
      </Button>
      <p className="text-center text-xs text-muted-foreground">
        Runs SAST + secrets + supply-chain scanners. Results in{" "}
        <span className="font-medium">Discover &rsaquo; Code Scanning</span>.
      </p>
    </form>
  );
}

// ---------------------------------------------------------------------------
// ZIP upload tab
// ---------------------------------------------------------------------------
function UploadTab({ onJob }: { onJob: (j: ImportJob) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const orgId = getStoredOrgId() || "default";

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!file) return;
    setLoading(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("org_id", orgId);
      const job = await postFormData<ImportJob>("/api/v1/import/upload", fd);
      onJob({ ...job, submitted_at: new Date().toISOString() });
      setFile(null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-1.5">
        <Label htmlFor="zip-file">Source archive (.zip, max 100 MB)</Label>
        <label
          htmlFor="zip-file"
          className="flex cursor-pointer flex-col items-center gap-2 rounded-lg border-2 border-dashed border-border p-6 hover:border-primary/50 transition-colors"
        >
          <FolderOpen className="h-8 w-8 text-muted-foreground" />
          <span className="text-sm text-muted-foreground">
            {file ? file.name : "Click to select or drag and drop"}
          </span>
          <input
            id="zip-file"
            type="file"
            accept=".zip"
            className="sr-only"
            disabled={loading}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) setFile(f);
            }}
          />
        </label>
      </div>
      {error && (
        <div className="flex items-center gap-2 rounded-md bg-destructive/10 p-2 text-xs text-destructive">
          <AlertCircle className="h-3.5 w-3.5 shrink-0" />
          {error}
        </div>
      )}
      <Button type="submit" disabled={loading || !file} className="w-full">
        {loading ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Uploading…
          </>
        ) : (
          <>
            <Upload className="mr-2 h-4 w-4" />
            Upload and scan
          </>
        )}
      </Button>
      <p className="text-center text-xs text-muted-foreground">
        Runs SAST + secrets scanners on extracted files. Results in{" "}
        <span className="font-medium">Discover &rsaquo; Code Scanning</span>.
      </p>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
type Tab = "repo" | "upload";

export default function ImportPage() {
  const [tab, setTab] = useState<Tab>("repo");
  const [jobs, setJobs] = useState<ImportJob[]>([]);

  function addJob(j: ImportJob) {
    setJobs((prev) => [j, ...prev].slice(0, 20));
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Import Repository"
        description="Scan a GitHub/GitLab URL or upload a .zip archive. Results appear in Discover."
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Input card */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex gap-2">
              <button
                onClick={() => setTab("repo")}
                className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  tab === "repo"
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                <GitBranch className="mr-1.5 inline h-3.5 w-3.5" />
                Git URL
              </button>
              <button
                onClick={() => setTab("upload")}
                className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  tab === "upload"
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                <Upload className="mr-1.5 inline h-3.5 w-3.5" />
                Upload .zip
              </button>
            </div>
          </CardHeader>
          <CardContent>
            {tab === "repo" ? <RepoTab onJob={addJob} /> : <UploadTab onJob={addJob} />}
          </CardContent>
        </Card>

        {/* Recent imports */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent Imports</CardTitle>
            <CardDescription>Submitted this session</CardDescription>
          </CardHeader>
          <CardContent>
            {jobs.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-8 text-center text-sm text-muted-foreground">
                <Upload className="h-8 w-8 opacity-30" />
                <p>No imports yet. Submit a repo URL or zip above.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {jobs.map((j) => (
                  <JobRow key={j.job_id} job={j} />
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
