/**
 * HooksPolicyPanel — PolicyAuthoringHub "hooks-policy" tab
 *
 * Wired to real backend:
 *   GET /api/v1/policy-enforcement/hooks/policy  → current hook policy JSON
 *   PUT /api/v1/policy-enforcement/hooks/policy  → save edited policy
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { FileEdit, Save, RefreshCw, AlertTriangle, CheckCircle2 } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    ...options,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
      "Content-Type": "application/json",
      ...(options?.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function HooksPolicyPanel() {
  const [policyJson, setPolicyJson] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveOk, setSaveOk] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const raw = await apiFetch<unknown>("/api/v1/policy-enforcement/hooks/policy");
      setPolicyJson(JSON.stringify(raw, null, 2));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load hook policy");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleChange = (val: string) => {
    setPolicyJson(val);
    setSaveOk(false);
    setSaveError(null);
    try {
      JSON.parse(val);
      setParseError(null);
    } catch {
      setParseError("Invalid JSON");
    }
  };

  const handleSave = async () => {
    if (parseError) return;
    setSaving(true);
    setSaveError(null);
    setSaveOk(false);
    try {
      await apiFetch("/api/v1/policy-enforcement/hooks/policy", {
        method: "PUT",
        body: policyJson,
      });
      setSaveOk(true);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-5"
    >
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <FileEdit className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Hooks Policy Editor</span>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={load} className="gap-1.5">
            <RefreshCw className="h-3.5 w-3.5" /> Reload
          </Button>
          <Button
            size="sm"
            onClick={handleSave}
            disabled={saving || !!parseError}
            className="gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white"
          >
            <Save className="h-3.5 w-3.5" />
            {saving ? "Saving…" : "Save Policy"}
          </Button>
        </div>
      </div>

      {parseError && (
        <div className="flex items-center gap-2 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-destructive text-xs">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          {parseError}
        </div>
      )}

      {saveError && (
        <div className="flex items-center gap-2 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-destructive text-xs">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          {saveError}
        </div>
      )}

      {saveOk && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-emerald-400 text-xs">
          <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
          Hook policy saved successfully.
        </div>
      )}

      <div className="rounded-lg border border-border overflow-hidden">
        <div className="bg-muted/30 border-b border-border px-3 py-2 flex items-center gap-2">
          <span className="text-xs text-muted-foreground font-mono">hooks-policy.json</span>
          <span className="ml-auto text-[10px] text-muted-foreground">
            PUT /api/v1/policy-enforcement/hooks/policy
          </span>
        </div>
        <textarea
          value={policyJson}
          onChange={e => handleChange(e.target.value)}
          spellCheck={false}
          className="w-full min-h-[480px] bg-background font-mono text-xs text-foreground p-4 resize-y outline-none focus:ring-1 focus:ring-indigo-500/50"
        />
      </div>
    </motion.div>
  );
}
