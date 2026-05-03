/**
 * Connector Mapping UI — define field mappings for a connector
 * Route: /connectors/mapping
 * API: POST /api/v1/connectors/mapping
 * Multica id: 6f32a3e2
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Plug, Save, Plus, Trash2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface MappingRow {
  source: string;
  target: string;
  transform?: string;
}

interface MappingResp {
  mapping_id?: string;
  status?: string;
  detail?: string;
}

async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    method: "POST",
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (res.status === 501) return { detail: "Coming soon" } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function ConnectorMappingUI() {
  const [connector, setConnector] = useState("");
  const [rows, setRows] = useState<MappingRow[]>([{ source: "", target: "" }]);
  const [resp, setResp] = useState<MappingResp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const update = (i: number, patch: Partial<MappingRow>) => {
    setRows(rs => rs.map((r, idx) => idx === i ? { ...r, ...patch } : r));
  };

  const submit = async () => {
    if (!connector.trim()) return;
    setLoading(true);
    setErr(null);
    setResp(null);
    try {
      const r = await apiPost<MappingResp>("/api/v1/connectors/mapping", {
        connector,
        mapping: rows.filter(r => r.source && r.target),
      });
      setResp(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!resp?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Connector Field Mapping"
        description="Map connector input fields to ALdeci canonical schema — transform, rename, drop"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Plug className="h-4 w-4" /> Mapping</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">POST /api/v1/connectors/mapping</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-xs">Connector ID</Label>
            <Input value={connector} onChange={e => setConnector(e.target.value)} placeholder="snyk-cli" className="text-sm font-mono" />
          </div>

          <div className="space-y-2">
            <Label className="text-xs">Field Map</Label>
            {rows.map((r, i) => (
              <div key={i} className="grid grid-cols-12 gap-2">
                <Input value={r.source} onChange={e => update(i, { source: e.target.value })} placeholder="source.field" className="col-span-4 text-xs font-mono" />
                <Input value={r.target} onChange={e => update(i, { target: e.target.value })} placeholder="target.field" className="col-span-4 text-xs font-mono" />
                <Input value={r.transform ?? ""} onChange={e => update(i, { transform: e.target.value })} placeholder="lowercase|uppercase|…" className="col-span-3 text-xs font-mono" />
                <Button variant="ghost" size="sm" className="col-span-1" onClick={() => setRows(rs => rs.filter((_, idx) => idx !== i))}><Trash2 className="h-3 w-3" /></Button>
              </div>
            ))}
            <Button variant="outline" size="sm" onClick={() => setRows(rs => [...rs, { source: "", target: "" }])}><Plus className="h-3 w-3 mr-1" /> Add field</Button>
          </div>

          <Button onClick={submit} disabled={loading || !connector.trim()} size="sm"><Save className="h-4 w-4 mr-2" /> {loading ? "Saving…" : "Save Mapping"}</Button>

          {err && <ErrorState message={err} onRetry={submit} />}
          {resp && (
            <div className="rounded-md border p-3 text-xs space-y-1">
              {resp.detail && <Badge variant="secondary">{resp.detail}</Badge>}
              {resp.mapping_id && <div><span className="text-muted-foreground">Mapping ID:</span> <span className="font-mono">{resp.mapping_id}</span></div>}
              {resp.status && <div><span className="text-muted-foreground">Status:</span> <span className="font-mono">{resp.status}</span></div>}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
