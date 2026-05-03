// FOLDED into UpgradePathsHub (binary-fp tab) 2026-05-02 — preserve for git history
/**
 * Binary Fingerprint Dashboard
 *
 * Upload binary/library → extract unique fingerprint → correlate with known
 * vulnerable binaries even when version metadata is missing.
 * Route: /binary-fingerprint  (now redirects to /remediate/upgrade?tab=binary-fp)
 * API: GET /api/v1/binary-fp/stats; POST /api/v1/binary-fp/fingerprint
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Fingerprint, Upload, RefreshCw, Package, AlertTriangle, Hash } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Stats {
  total_fingerprints?: number;
  unique_binaries?: number;
  vulnerable_matches?: number;
  latest_scan?: string;
}

interface Match {
  name?: string;
  confidence?: number;
  cve?: string;
  severity?: string;
  version?: string;
}

interface FingerprintResult {
  filename?: string;
  sha256?: string;
  ssdeep?: string;
  size_bytes?: number;
  type?: string;
  matches?: Match[];
  vulnerable?: boolean;
  error?: string;
}

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    ...opts,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
      ...(opts.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function formatBytes(n?: number) {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function severityColor(s?: string) {
  const k = (s ?? "").toLowerCase();
  if (k === "critical") return "border-red-500/30 text-red-300 bg-red-500/10";
  if (k === "high")     return "border-orange-500/30 text-orange-300 bg-orange-500/10";
  if (k === "medium")   return "border-yellow-500/30 text-yellow-300 bg-yellow-500/10";
  return "border-green-500/30 text-green-300 bg-green-500/10";
}

export default function BinaryFingerprintDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<FingerprintResult | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const s = await apiFetch<Stats>("/api/v1/binary-fp/stats");
      setStats(s);
    } catch (e) { setErr((e as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const fileToBase64 = (f: File) => new Promise<string>((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => {
      const data = r.result as string;
      const idx = data.indexOf(",");
      resolve(idx >= 0 ? data.slice(idx + 1) : data);
    };
    r.onerror = () => reject(r.error);
    r.readAsDataURL(f);
  });

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setResult(null);
    try {
      const content_b64 = await fileToBase64(file);
      const r = await apiFetch<FingerprintResult>("/api/v1/binary-fp/fingerprint", {
        method: "POST",
        body: JSON.stringify({
          filename: file.name,
          content_b64,
          size_bytes: file.size,
        }),
      });
      setResult(r);
      await load();
    } catch (e) {
      setResult({ error: (e as Error).message });
    } finally { setUploading(false); }
  };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Binary Fingerprint"
        description="Identify binaries and libraries by content — catch vulnerable components even when versions are stripped"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Fingerprints" value={stats?.total_fingerprints ?? 0} icon={Fingerprint} />
        <KpiCard title="Unique Binaries" value={stats?.unique_binaries ?? 0} icon={Package} />
        <KpiCard title="Vulnerable Matches" value={stats?.vulnerable_matches ?? 0} icon={AlertTriangle} trend="down" />
        <KpiCard title="Latest Scan" value={stats?.latest_scan ? new Date(stats.latest_scan).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—"} icon={Hash} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Upload className="h-4 w-4" /> Upload Binary</CardTitle>
          <CardDescription className="text-xs">Fingerprint a binary to identify it and correlate with known vulnerabilities</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <label className="flex-1 cursor-pointer rounded border border-dashed border-border bg-muted/20 px-3 py-2 text-center text-xs hover:bg-muted/40 transition-colors">
              <input
                type="file"
                className="hidden"
                onChange={e => { const f = e.target.files?.[0] ?? null; setFile(f); setResult(null); }}
              />
              {file ? (
                <span className="font-mono">{file.name} · {formatBytes(file.size)}</span>
              ) : (
                <span className="text-muted-foreground">Click to select a binary file</span>
              )}
            </label>
            <Button size="sm" onClick={handleUpload} disabled={uploading || !file}>
              <Upload className={cn("h-4 w-4 mr-2", uploading && "animate-pulse")} />
              Fingerprint
            </Button>
          </div>

          {result?.error && (
            <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-xs font-mono text-red-400">{result.error}</div>
          )}

          {result && !result.error && (
            <div className="rounded border border-border/50 bg-muted/20 p-3 space-y-3">
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 text-[11px] font-mono">
                <div><span className="text-muted-foreground">File:</span> {result.filename ?? "—"}</div>
                <div><span className="text-muted-foreground">Type:</span> {result.type ?? "—"}</div>
                <div className="truncate"><span className="text-muted-foreground">SHA-256:</span> {result.sha256 ?? "—"}</div>
                <div><span className="text-muted-foreground">Size:</span> {formatBytes(result.size_bytes)}</div>
                {result.ssdeep && <div className="col-span-full truncate"><span className="text-muted-foreground">ssdeep:</span> {result.ssdeep}</div>}
              </div>

              <div>
                <div className="mb-2 flex items-center justify-between text-xs">
                  <span className="font-medium">Matches</span>
                  {result.vulnerable && (
                    <Badge className="text-[10px] border border-red-500/30 text-red-300 bg-red-500/10">Vulnerable</Badge>
                  )}
                </div>
                {(result.matches ?? []).length === 0 ? (
                  <div className="rounded border border-dashed border-border/50 p-3 text-xs text-muted-foreground text-center">
                    No matches — binary appears unique or clean.
                  </div>
                ) : (
                  <div className="space-y-1">
                    {(result.matches ?? []).map((m, i) => (
                      <div key={i} className="flex items-center justify-between rounded bg-muted/30 px-2 py-1.5 text-[11px]">
                        <div className="flex items-center gap-2 font-mono">
                          <span>{m.name ?? "—"}</span>
                          {m.version && <span className="text-muted-foreground">v{m.version}</span>}
                          {m.cve && <span className="text-red-400">{m.cve}</span>}
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-muted-foreground">{((m.confidence ?? 0) * 100).toFixed(0)}%</span>
                          {m.severity && <Badge className={cn("text-[10px] border capitalize", severityColor(m.severity))}>{m.severity}</Badge>}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {err && <ErrorState message={err} onRetry={load} />}
        </CardContent>
      </Card>
    </motion.div>
  );
}
