/**
 * WebhookEventsTable
 *
 * Renders real webhook events fetched from GET /api/v1/webhooks/
 * (SQLite-backed, org-scoped).  Used in WebhookIngestionHub "catalogue" tab.
 */

import { useEffect, useState, useCallback } from "react";
import { RefreshCw, Inbox } from "lucide-react";
import { webhooksApi } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface WebhookEvent {
  id: number;
  event_id: string;
  source: string;
  event_type: string;
  actor_email: string | null;
  ip_address: string | null;
  outcome: string | null;
  received_at: string;
}

interface ApiResponse {
  org_id: string;
  items: WebhookEvent[];
  count: number;
}

function statusVariant(outcome: string | null): "default" | "secondary" | "destructive" | "outline" {
  if (!outcome) return "secondary";
  const o = outcome.toLowerCase();
  if (o === "success" || o === "allow") return "default";
  if (o === "deny" || o === "failure" || o === "failed") return "destructive";
  return "outline";
}

function formatTs(raw: string): string {
  try {
    return new Date(raw).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return raw;
  }
}

export function WebhookEventsTable({ orgId = "default" }: { orgId?: string }) {
  const [events, setEvents] = useState<WebhookEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [total, setTotal] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await webhooksApi.list({ org_id: orgId, limit: 100 });
      const body = res.data as ApiResponse;
      setEvents(Array.isArray(body.items) ? body.items : []);
      setTotal(typeof body.count === "number" ? body.count : 0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load webhook events";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading) {
    return (
      <div className="space-y-2 mt-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-9 w-full rounded" />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="mt-4 rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
        {error}
        <Button variant="ghost" size="sm" className="ml-3" onClick={() => void load()}>
          Retry
        </Button>
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="mt-8 flex flex-col items-center gap-3 text-muted-foreground">
        <Inbox className="h-10 w-10 opacity-40" />
        <p className="text-sm">No webhook events received yet.</p>
        <p className="text-xs opacity-70">
          Send a webhook to <code className="font-mono">/api/v1/webhooks/&#123;source&#125;</code> to see events here.
        </p>
      </div>
    );
  }

  return (
    <div className="mt-4 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Showing {events.length} of {total} events
        </p>
        <Button variant="ghost" size="sm" onClick={() => void load()} className="gap-1.5 text-xs">
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </Button>
      </div>

      <div className="rounded-md border border-border overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="bg-muted/30">
              <TableHead className="text-xs font-semibold w-32">Source</TableHead>
              <TableHead className="text-xs font-semibold">Event Type</TableHead>
              <TableHead className="text-xs font-semibold w-40">Timestamp</TableHead>
              <TableHead className="text-xs font-semibold w-24">Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {events.map((ev) => (
              <TableRow key={ev.id} className="hover:bg-muted/20 transition-colors">
                <TableCell className="text-xs font-mono text-muted-foreground">
                  {ev.source || "—"}
                </TableCell>
                <TableCell className="text-xs">
                  {ev.event_type}
                </TableCell>
                <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                  {formatTs(ev.received_at)}
                </TableCell>
                <TableCell>
                  <Badge
                    variant={statusVariant(ev.outcome)}
                    className="text-[10px] px-1.5 py-0"
                  >
                    {ev.outcome ?? "received"}
                  </Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
