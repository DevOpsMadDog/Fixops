/**
 * DPOPrivacyHub — Data Protection Officer unified hero
 *
 * Serves P28 DPO persona with 4 DPO-specific operational tabs.
 *
 *   tab           | endpoint(s)
 *   --------------|------------------------------------------------------------
 *   dsrs          | /api/v1/privacy/dsrs, /api/v1/privacy/stats
 *   dpia          | /api/v1/privacy-impact/assessments, /api/v1/privacy-impact/summary
 *   cross-border  | EmptyState (no route exists yet — registry coming soon)
 *   discovery     | /api/v1/data-discovery/datastores, /api/v1/data-discovery/stats
 *
 * Route: /comply/dpo
 * Persona: P28 Data Protection Officer
 */

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Inbox,
  FileSearch2,
  Globe,
  Database,
  AlertCircle,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
} from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getStoredAuthToken } from "@/lib/api";

// ─── API fetch helper ────────────────────────────────────────────────────────

const BASE = "/api/v1";

async function apiFetch<T>(path: string): Promise<T> {
  const token = getStoredAuthToken();
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "X-API-Key": token } : {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ─── Types ───────────────────────────────────────────────────────────────────

interface DSR {
  id: string;
  requester: string;
  type: string;
  received: string;
  due: string;
  status: string;
  fulfilled_by?: string;
}

interface DPIA {
  id: string;
  title: string;
  risk_score?: number;
  status: string;
  due_date?: string;
  created_at?: string;
}

interface Datastore {
  id: string;
  name: string;
  location?: string;
  sensitivity_tier?: string;
  record_count?: number;
  data_types?: string[];
}

// ─── Tab config ──────────────────────────────────────────────────────────────

type TabKey = "dsrs" | "dpia" | "cross-border" | "discovery";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "dsrs",
    label: "DSR Queue",
    icon: Inbox,
    description: "Data Subject Request queue — track access, deletion, portability, and objection requests with SLA status.",
  },
  {
    key: "dpia",
    label: "DPIA",
    icon: FileSearch2,
    description: "Data Protection Impact Assessments — risk scores, regulatory status, and due dates.",
  },
  {
    key: "cross-border",
    label: "Cross-Border Transfers",
    icon: Globe,
    description: "Cross-border transfer registry — recipient country, legal mechanism, data categories, and last review.",
  },
  {
    key: "discovery",
    label: "PII/PHI Discovery",
    icon: Database,
    description: "PII/PHI inventory by datastore — sensitivity tier, record counts, and data categories.",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));
function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

// ─── Shared helpers ──────────────────────────────────────────────────────────

function statusBadge(status: string) {
  const s = (status ?? "").toLowerCase();
  if (s === "completed" || s === "fulfilled" || s === "approved")
    return <Badge className="bg-green-600/20 text-green-400 border-green-700">{status}</Badge>;
  if (s === "overdue" || s === "rejected" || s === "high")
    return <Badge className="bg-red-600/20 text-red-400 border-red-700">{status}</Badge>;
  if (s === "pending" || s === "in_progress" || s === "medium")
    return <Badge className="bg-amber-600/20 text-amber-400 border-amber-700">{status}</Badge>;
  return <Badge variant="outline">{status}</Badge>;
}

function riskBadge(score: number | undefined) {
  if (score == null) return <span className="text-muted-foreground">—</span>;
  if (score >= 7) return <Badge className="bg-red-600/20 text-red-400 border-red-700">{score}/10</Badge>;
  if (score >= 4) return <Badge className="bg-amber-600/20 text-amber-400 border-amber-700">{score}/10</Badge>;
  return <Badge className="bg-green-600/20 text-green-400 border-green-700">{score}/10</Badge>;
}

function fmtDate(d: string | undefined) {
  if (!d) return "—";
  try { return new Date(d).toLocaleDateString(); } catch { return d; }
}

function LoadingRow({ cols }: { cols: number }) {
  return (
    <TableRow>
      <TableCell colSpan={cols} className="text-center py-8 text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin inline mr-2" />Loading…
      </TableCell>
    </TableRow>
  );
}

function ErrorRow({ cols, msg }: { cols: number; msg: string }) {
  return (
    <TableRow>
      <TableCell colSpan={cols} className="text-center py-8 text-destructive">
        <AlertCircle className="h-4 w-4 inline mr-2" />{msg}
      </TableCell>
    </TableRow>
  );
}

function EmptyRow({ cols, label }: { cols: number; label: string }) {
  return (
    <TableRow>
      <TableCell colSpan={cols} className="text-center py-8 text-muted-foreground">
        {label}
      </TableCell>
    </TableRow>
  );
}

// ─── DSR Tab ─────────────────────────────────────────────────────────────────

function DSRPanel() {
  const [dsrs, setDsrs] = useState<DSR[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    apiFetch<{ items?: DSR[]; dsrs?: DSR[] }>("/privacy/dsrs")
      .then(d => setDsrs(d.items ?? d.dsrs ?? []))
      .catch(e => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  const overdue = dsrs.filter(d => d.status?.toLowerCase() === "overdue").length;
  const pending = dsrs.filter(d => d.status?.toLowerCase() === "pending").length;
  const done = dsrs.filter(d => ["completed", "fulfilled"].includes(d.status?.toLowerCase())).length;

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Overdue", value: overdue, icon: XCircle, color: "text-red-400" },
          { label: "Pending", value: pending, icon: Clock, color: "text-amber-400" },
          { label: "Fulfilled", value: done, icon: CheckCircle2, color: "text-green-400" },
        ].map(m => (
          <Card key={m.label} className="bg-muted/30 border-border">
            <CardContent className="flex items-center gap-3 p-4">
              <m.icon className={`h-5 w-5 ${m.color}`} />
              <div>
                <p className="text-xs text-muted-foreground">{m.label}</p>
                <p className="text-xl font-semibold">{loading ? "—" : m.value}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Requester</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Received</TableHead>
              <TableHead>Due</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Fulfilled By</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? <LoadingRow cols={6} /> :
             error ? <ErrorRow cols={6} msg={error} /> :
             dsrs.length === 0 ? <EmptyRow cols={6} label="No data subject requests found." /> :
             dsrs.map(r => (
               <TableRow key={r.id}>
                 <TableCell className="font-medium">{r.requester ?? "—"}</TableCell>
                 <TableCell>{r.type ?? "—"}</TableCell>
                 <TableCell>{fmtDate(r.received)}</TableCell>
                 <TableCell>{fmtDate(r.due)}</TableCell>
                 <TableCell>{statusBadge(r.status)}</TableCell>
                 <TableCell className="text-muted-foreground">{r.fulfilled_by ?? "—"}</TableCell>
               </TableRow>
             ))
            }
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

// ─── DPIA Tab ────────────────────────────────────────────────────────────────

function DPIAPanel() {
  const [items, setItems] = useState<DPIA[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    apiFetch<{ items?: DPIA[]; assessments?: DPIA[] }>("/privacy-impact/assessments")
      .then(d => setItems(d.items ?? d.assessments ?? []))
      .catch(e => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-lg border border-border overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Assessment</TableHead>
              <TableHead>Risk Score</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Due Date</TableHead>
              <TableHead>Created</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? <LoadingRow cols={5} /> :
             error ? <ErrorRow cols={5} msg={error} /> :
             items.length === 0 ? <EmptyRow cols={5} label="No DPIA assessments found." /> :
             items.map(a => (
               <TableRow key={a.id}>
                 <TableCell className="font-medium">{a.title ?? a.id}</TableCell>
                 <TableCell>{riskBadge(a.risk_score)}</TableCell>
                 <TableCell>{statusBadge(a.status)}</TableCell>
                 <TableCell>{fmtDate(a.due_date)}</TableCell>
                 <TableCell className="text-muted-foreground">{fmtDate(a.created_at)}</TableCell>
               </TableRow>
             ))
            }
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

// ─── Cross-Border Tab ────────────────────────────────────────────────────────

function CrossBorderPanel() {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3 text-muted-foreground">
      <Globe className="h-10 w-10 opacity-40" />
      <p className="text-sm font-medium">Cross-border transfer registry coming soon</p>
      <p className="text-xs max-w-sm text-center">
        The cross-border transfer registry will track recipient countries, legal mechanisms
        (SCCs, BCRs, adequacy decisions), data categories, and review dates.
      </p>
    </div>
  );
}

// ─── Discovery Tab ───────────────────────────────────────────────────────────

function DiscoveryPanel() {
  const [stores, setStores] = useState<Datastore[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    apiFetch<{ items?: Datastore[]; datastores?: Datastore[] }>("/data-discovery/datastores")
      .then(d => setStores(d.items ?? d.datastores ?? []))
      .catch(e => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  function tierBadge(tier: string | undefined) {
    const t = (tier ?? "").toLowerCase();
    if (t === "critical" || t === "high")
      return <Badge className="bg-red-600/20 text-red-400 border-red-700">{tier}</Badge>;
    if (t === "medium")
      return <Badge className="bg-amber-600/20 text-amber-400 border-amber-700">{tier}</Badge>;
    if (t === "low")
      return <Badge className="bg-green-600/20 text-green-400 border-green-700">{tier}</Badge>;
    return <Badge variant="outline">{tier ?? "—"}</Badge>;
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-lg border border-border overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Datastore</TableHead>
              <TableHead>Location</TableHead>
              <TableHead>Sensitivity</TableHead>
              <TableHead className="text-right">Record Count</TableHead>
              <TableHead>Data Categories</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? <LoadingRow cols={5} /> :
             error ? <ErrorRow cols={5} msg={error} /> :
             stores.length === 0 ? <EmptyRow cols={5} label="No datastores discovered yet." /> :
             stores.map(s => (
               <TableRow key={s.id}>
                 <TableCell className="font-medium">{s.name ?? s.id}</TableCell>
                 <TableCell className="text-muted-foreground">{s.location ?? "—"}</TableCell>
                 <TableCell>{tierBadge(s.sensitivity_tier)}</TableCell>
                 <TableCell className="text-right font-mono text-sm">
                   {s.record_count != null ? s.record_count.toLocaleString() : "—"}
                 </TableCell>
                 <TableCell className="text-muted-foreground text-xs">
                   {Array.isArray(s.data_types) && s.data_types.length > 0
                     ? s.data_types.slice(0, 3).join(", ") + (s.data_types.length > 3 ? ` +${s.data_types.length - 3}` : "")
                     : "—"}
                 </TableCell>
               </TableRow>
             ))
            }
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

// ─── Hub ─────────────────────────────────────────────────────────────────────

export default function DPOPrivacyHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab")) ? (params.get("tab") as TabKey) : "dsrs";
  const [tab, setTab] = useState<TabKey>(initial);

  useEffect(() => {
    const urlTab = params.get("tab");
    if (urlTab !== tab) {
      if (isTabKey(urlTab)) {
        setTab(urlTab);
      } else {
        const next = new URLSearchParams(params.toString());
        next.set("tab", tab);
        setParams(next, { replace: true });
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, params.toString()]);

  const activeMeta = useMemo(() => TABS.find(t => t.key === tab) ?? TABS[0], [tab]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="DPO Privacy Center"
        description="Data Protection Officer workspace — DSR queue, DPIA management, cross-border transfers, and PII/PHI inventory."
        badge={activeMeta.label}
      />

      <Tabs value={tab} onValueChange={v => setTab(v as TabKey)} className="w-full">
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="text-xs gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <p className="text-xs text-muted-foreground mt-2 mb-1">{activeMeta.description}</p>

        <TabsContent value="dsrs"><DSRPanel /></TabsContent>
        <TabsContent value="dpia"><DPIAPanel /></TabsContent>
        <TabsContent value="cross-border"><CrossBorderPanel /></TabsContent>
        <TabsContent value="discovery"><DiscoveryPanel /></TabsContent>
      </Tabs>
    </motion.div>
  );
}
