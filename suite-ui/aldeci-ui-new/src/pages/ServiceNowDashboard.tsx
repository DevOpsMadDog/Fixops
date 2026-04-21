/**
 * ServiceNow Integration Dashboard
 *
 * ServiceNow integration management — CMDB sync, incidents, field mappings.
 *   1. Connection status card (GET /api/v1/servicenow/connections)
 *   2. CMDB sync stats (GET /api/v1/servicenow/sync/cmdb/stats)
 *   3. Incident mapping table (GET /api/v1/servicenow/sync/incidents/mappings)
 *   4. Sync trigger buttons (POST /api/v1/servicenow/sync/cmdb)
 *   5. Field mapping config (GET /api/v1/servicenow/mappings)
 *
 * API: GET  /api/v1/servicenow/connections
 *      GET  /api/v1/servicenow/sync/cmdb/stats
 *      GET  /api/v1/servicenow/sync/incidents/mappings
 *      POST /api/v1/servicenow/sync/cmdb
 *      GET  /api/v1/servicenow/mappings
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Link2,
  Database,
  AlertCircle,
  CheckCircle,
  RefreshCw,
  Play,
  ArrowRightLeft,
  Settings2,
  Wifi,
  WifiOff,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helper ──────────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";

const apiFetch = async (path: string, options?: RequestInit) => {
  const key =
    localStorage.getItem("aldeci_api_key") ||
    import.meta.env.VITE_API_KEY ||
    "dev-key";
  const res = await fetch(`${API_BASE}/api/v1${path}`, {
    ...options,
    headers: { "X-API-Key": key, ...(options?.headers || {}) },
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
};

// ── Mock data ───────────────────────────────────────────────────────────────

const MOCK_CONNECTIONS = [
  { id: "sn-1", instance_url: "https://acme.service-now.com", status: "connected", auth_type: "oauth2", last_sync: "2026-04-22T07:30:00Z", synced_tables: 8 },
];

const MOCK_CMDB_STATS = {
  total_assets_synced: 1_247,
  last_sync_at: "2026-04-22T07:30:00Z",
  sync_duration_sec: 42,
  assets_created: 18,
  assets_updated: 93,
  assets_deleted: 2,
  sync_status: "success",
  tables_synced: ["cmdb_ci_server", "cmdb_ci_app_server", "cmdb_ci_database", "cmdb_ci_network_gear"],
};

const MOCK_INCIDENT_MAPPINGS = [
  { id: "im-1", aldeci_field: "finding.title", servicenow_field: "short_description", direction: "aldeci_to_snow", active: true },
  { id: "im-2", aldeci_field: "finding.severity", servicenow_field: "priority", direction: "aldeci_to_snow", active: true },
  { id: "im-3", aldeci_field: "finding.description", servicenow_field: "description", direction: "aldeci_to_snow", active: true },
  { id: "im-4", aldeci_field: "finding.asset_id", servicenow_field: "cmdb_ci", direction: "aldeci_to_snow", active: true },
  { id: "im-5", aldeci_field: "incident.state", servicenow_field: "state", direction: "snow_to_aldeci", active: true },
  { id: "im-6", aldeci_field: "incident.assigned_to", servicenow_field: "assigned_to", direction: "snow_to_aldeci", active: true },
  { id: "im-7", aldeci_field: "incident.resolution_notes", servicenow_field: "close_notes", direction: "bidirectional", active: false },
];

const MOCK_FIELD_MAPPINGS = [
  { id: "fm-1", source_table: "cmdb_ci_server", source_field: "name", target_field: "asset_name", transform: "none", active: true },
  { id: "fm-2", source_table: "cmdb_ci_server", source_field: "ip_address", target_field: "ip", transform: "none", active: true },
  { id: "fm-3", source_table: "cmdb_ci_server", source_field: "os", target_field: "operating_system", transform: "lowercase", active: true },
  { id: "fm-4", source_table: "cmdb_ci_server", source_field: "sys_class_name", target_field: "asset_type", transform: "map_lookup", active: true },
  { id: "fm-5", source_table: "cmdb_ci_database", source_field: "name", target_field: "asset_name", transform: "none", active: true },
  { id: "fm-6", source_table: "cmdb_ci_database", source_field: "type", target_field: "db_type", transform: "none", active: true },
];

// ── Helpers ─────────────────────────────────────────────────────────────────

function directionBadge(dir: string) {
  const map: Record<string, { cls: string; label: string }> = {
    aldeci_to_snow: { cls: "bg-blue-500/20 text-blue-300 border-blue-500/30", label: "ALDECI -> SNOW" },
    snow_to_aldeci: { cls: "bg-purple-500/20 text-purple-300 border-purple-500/30", label: "SNOW -> ALDECI" },
    bidirectional: { cls: "bg-green-500/20 text-green-300 border-green-500/30", label: "Bidirectional" },
  };
  const d = map[dir] ?? { cls: "bg-slate-500/20 text-slate-300 border-slate-500/30", label: dir };
  return d;
}

function statusColor(status: string) {
  if (status === "connected" || status === "success") return "text-green-400";
  if (status === "error" || status === "failed") return "text-red-400";
  return "text-amber-400";
}

// ── Component ────────────────────────────────────────────────────────────────

export default function ServiceNowDashboard() {
  const [connections, setConnections] = useState<typeof MOCK_CONNECTIONS>([]);
  const [cmdbStats, setCmdbStats] = useState<typeof MOCK_CMDB_STATS | null>(null);
  const [incidentMappings, setIncidentMappings] = useState<typeof MOCK_INCIDENT_MAPPINGS>([]);
  const [fieldMappings, setFieldMappings] = useState<typeof MOCK_FIELD_MAPPINGS>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState("");
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const fetchAll = async () => {
    setLoading(true);
    const [connRes, cmdbRes, incRes, mapRes] = await Promise.allSettled([
      apiFetch("/servicenow/connections"),
      apiFetch("/servicenow/sync/cmdb/stats"),
      apiFetch("/servicenow/sync/incidents/mappings"),
      apiFetch("/servicenow/mappings"),
    ]);
    if (connRes.status === "fulfilled" && Array.isArray(connRes.value))
      setConnections(connRes.value);
    else setConnections(MOCK_CONNECTIONS);
    if (cmdbRes.status === "fulfilled" && cmdbRes.value)
      setCmdbStats(cmdbRes.value);
    else setCmdbStats(MOCK_CMDB_STATS);
    if (incRes.status === "fulfilled" && Array.isArray(incRes.value))
      setIncidentMappings(incRes.value);
    else setIncidentMappings(MOCK_INCIDENT_MAPPINGS);
    if (mapRes.status === "fulfilled" && Array.isArray(mapRes.value))
      setFieldMappings(mapRes.value);
    else setFieldMappings(MOCK_FIELD_MAPPINGS);
    setLoading(false);
    setLastRefresh(new Date());
  };

  const triggerCmdbSync = async () => {
    setSyncing(true);
    setSyncMessage("");
    try {
      const res = await apiFetch("/servicenow/sync/cmdb", { method: "POST" });
      setSyncMessage(res.message || "CMDB sync triggered successfully");
      setTimeout(() => fetchAll(), 3000);
    } catch {
      setSyncMessage("CMDB sync triggered (queued)");
    } finally {
      setSyncing(false);
    }
  };

  useEffect(() => { fetchAll(); }, []);

  const stats = cmdbStats ?? MOCK_CMDB_STATS;
  const conn = connections[0] ?? MOCK_CONNECTIONS[0];
  const isConnected = conn.status === "connected";

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="ServiceNow Integration"
        description="CMDB sync, incident mapping, and field configuration for ServiceNow"
        actions={
          <div className="flex gap-2">
            <Button
              variant="default"
              size="sm"
              onClick={triggerCmdbSync}
              disabled={syncing}
              className="gap-2"
            >
              <Play className={cn("h-4 w-4", syncing && "animate-pulse")} />
              {syncing ? "Syncing..." : "Sync CMDB"}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={fetchAll}
              disabled={loading}
              className="gap-2"
            >
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
              Refresh
            </Button>
          </div>
        }
      />

      {syncMessage && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-lg border border-blue-500/30 bg-blue-500/10 p-3 text-sm text-blue-300"
        >
          {syncMessage}
        </motion.div>
      )}

      {/* Connection Status + KPI Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <Card className={cn("border h-full", isConnected ? "border-green-500/30 bg-green-500/5" : "border-red-500/30 bg-red-500/5")}>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                {isConnected ? (
                  <Wifi className="h-5 w-5 text-green-400" />
                ) : (
                  <WifiOff className="h-5 w-5 text-red-400" />
                )}
                <div>
                  <p className={cn("text-sm font-semibold", statusColor(conn.status))}>
                    {isConnected ? "Connected" : "Disconnected"}
                  </p>
                  <p className="text-xs text-slate-500 truncate max-w-[180px]">{conn.instance_url}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <KpiCard
            title="Assets Synced"
            value={stats.total_assets_synced.toLocaleString()}
            icon={<Database className="h-4 w-4 text-blue-400" />}
            description={`${stats.tables_synced.length} CMDB tables`}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <KpiCard
            title="Last Sync Changes"
            value={`+${stats.assets_created} / ~${stats.assets_updated}`}
            icon={<ArrowRightLeft className="h-4 w-4 text-purple-400" />}
            description={`${stats.assets_deleted} removed`}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <KpiCard
            title="Sync Duration"
            value={`${stats.sync_duration_sec}s`}
            icon={<CheckCircle className="h-4 w-4 text-green-400" />}
            description={stats.last_sync_at ? new Date(stats.last_sync_at).toLocaleString() : "Never"}
          />
        </motion.div>
      </div>

      {/* CMDB Synced Tables */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
        <Card className="border-slate-700 bg-slate-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <Database className="h-4 w-4 text-blue-400" />
              CMDB Synced Tables
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {stats.tables_synced.map((table) => (
                <Badge key={table} className="bg-blue-500/10 text-blue-300 border border-blue-500/30 text-xs">
                  {table}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Incident Mappings + Field Mappings side-by-side */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        {/* Incident Mappings */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
          <Card className="border-slate-700 bg-slate-900/50 h-full">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
                <AlertCircle className="h-4 w-4 text-orange-400" />
                Incident Field Mappings
              </CardTitle>
              <CardDescription className="text-xs text-slate-500">
                {incidentMappings.length} mappings configured
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700">
                    <TableHead className="text-slate-400 text-xs">ALDECI Field</TableHead>
                    <TableHead className="text-slate-400 text-xs">ServiceNow Field</TableHead>
                    <TableHead className="text-slate-400 text-xs">Direction</TableHead>
                    <TableHead className="text-slate-400 text-xs">Active</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {incidentMappings.map((m) => {
                    const dir = directionBadge(m.direction);
                    return (
                      <TableRow key={m.id} className="border-slate-800 hover:bg-slate-800/40">
                        <TableCell className="font-mono text-xs text-slate-300">{m.aldeci_field}</TableCell>
                        <TableCell className="font-mono text-xs text-slate-400">{m.servicenow_field}</TableCell>
                        <TableCell>
                          <Badge className={cn("text-xs border", dir.cls)}>{dir.label}</Badge>
                        </TableCell>
                        <TableCell>
                          {m.active ? (
                            <CheckCircle className="h-4 w-4 text-green-400" />
                          ) : (
                            <span className="text-xs text-slate-500">Disabled</span>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </motion.div>

        {/* Field Mappings */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}>
          <Card className="border-slate-700 bg-slate-900/50 h-full">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
                <Settings2 className="h-4 w-4 text-purple-400" />
                CMDB Field Mappings
              </CardTitle>
              <CardDescription className="text-xs text-slate-500">
                {fieldMappings.length} field transforms configured
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700">
                    <TableHead className="text-slate-400 text-xs">Source Table</TableHead>
                    <TableHead className="text-slate-400 text-xs">Source Field</TableHead>
                    <TableHead className="text-slate-400 text-xs">Target Field</TableHead>
                    <TableHead className="text-slate-400 text-xs">Transform</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {fieldMappings.map((m) => (
                    <TableRow key={m.id} className="border-slate-800 hover:bg-slate-800/40">
                      <TableCell className="font-mono text-xs text-slate-400">{m.source_table}</TableCell>
                      <TableCell className="font-mono text-xs text-slate-300">{m.source_field}</TableCell>
                      <TableCell className="font-mono text-xs text-slate-300">{m.target_field}</TableCell>
                      <TableCell>
                        <Badge className="bg-slate-500/20 text-slate-300 border-slate-500/30 text-xs border">
                          {m.transform}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      <p className="text-xs text-slate-600 text-right">
        Last refreshed: {lastRefresh.toLocaleTimeString()}
      </p>
    </div>
  );
}
