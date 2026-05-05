import { useState, useRef, useEffect } from "react";
import { Bell, X, AlertTriangle, Info, CheckCircle, Clock } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import api from "@/lib/api";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

interface Alert {
  alert_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: string;
  created_at: string;
  description?: string;
}

interface AlertsResponse {
  alerts: Alert[];
  total: number;
}

const SEVERITY_CONFIG: Record<
  string,
  { icon: typeof AlertTriangle; color: string; bg: string }
> = {
  critical: { icon: AlertTriangle, color: "text-red-400", bg: "bg-red-500/10" },
  high: { icon: AlertTriangle, color: "text-orange-400", bg: "bg-orange-500/10" },
  medium: { icon: Info, color: "text-yellow-400", bg: "bg-yellow-500/10" },
  low: { icon: Info, color: "text-blue-400", bg: "bg-blue-500/10" },
  info: { icon: CheckCircle, color: "text-emerald-400", bg: "bg-emerald-500/10" },
};

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function NotificationBell() {
  const [open, setOpen] = useState(false);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const dropdownRef = useRef<HTMLDivElement>(null);

  const { data, isLoading, dataUpdatedAt } = useQuery<AlertsResponse>({
    queryKey: ["notifications", "alert-triage"],
    queryFn: async () => {
      const { data } = await api.get(`/api/v1/alert-triage/alerts`, {
        params: { org_id: "default", limit: 5 },
      });
      return data;
    },
    refetchInterval: 30_000,
    retry: false,
  });

  const allAlerts: Alert[] = data?.alerts ?? [];
  const visible = allAlerts.filter((a) => !dismissed.has(a.alert_id));
  const unreadCount = visible.length;

  // Close dropdown on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  // Show toast on new alerts after first load
  const prevCount = useRef<number | null>(null);
  useEffect(() => {
    if (unreadCount > 0 && prevCount.current !== null && unreadCount > prevCount.current) {
      // Dynamically import toast to avoid circular deps
      import("sonner").then(({ toast }) => {
        toast.info(`${unreadCount - (prevCount.current ?? 0)} new alert(s) detected`, {
          description: "Check the notification bell for details.",
        });
      });
    }
    prevCount.current = unreadCount;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dataUpdatedAt]);

  return (
    <div className="relative" ref={dropdownRef}>
      <Button
        variant="ghost"
        size="icon"
        onClick={() => setOpen((o) => !o)}
        className={cn("relative", open && "bg-primary/10 text-primary")}
        aria-label="Notifications"
      >
        <Bell className="h-4 w-4" />
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white leading-none">
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </Button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-80 rounded-xl border border-border bg-card shadow-xl z-50 overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <span className="text-sm font-semibold text-foreground">Notifications</span>
            <div className="flex items-center gap-2">
              {unreadCount > 0 && (
                <button
                  onClick={() => {
                    const ids = new Set([...dismissed, ...visible.map((a) => a.alert_id)]);
                    setDismissed(ids);
                  }}
                  className="text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  Clear all
                </button>
              )}
              <button onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground">
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Body */}
          <div className="max-h-80 overflow-y-auto">
            {isLoading ? (
              <div className="flex flex-col gap-2 p-4">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-14 rounded-lg bg-muted/40 animate-pulse" />
                ))}
              </div>
            ) : visible.length === 0 ? (
              <div className="flex flex-col items-center justify-center gap-2 py-10 text-muted-foreground">
                <CheckCircle className="h-7 w-7 opacity-40" />
                <span className="text-sm">All clear — no alerts</span>
              </div>
            ) : (
              <ul className="divide-y divide-border">
                {visible.map((alert) => {
                  const cfg = SEVERITY_CONFIG[alert.severity] ?? SEVERITY_CONFIG.info;
                  const Icon = cfg.icon;
                  return (
                    <li
                      key={alert.alert_id}
                      className={cn("flex items-start gap-3 px-4 py-3 hover:bg-muted/30 transition-colors", cfg.bg)}
                    >
                      <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", cfg.color)} />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium text-foreground truncate">{alert.title}</p>
                        {alert.description && (
                          <p className="text-[11px] text-muted-foreground truncate mt-0.5">{alert.description}</p>
                        )}
                        <div className="mt-1 flex items-center gap-1.5 text-[10px] text-muted-foreground">
                          <Clock className="h-3 w-3" />
                          <span>{timeAgo(alert.created_at)}</span>
                          <span className="capitalize rounded-sm bg-muted px-1">{alert.severity}</span>
                        </div>
                      </div>
                      <button
                        onClick={() => setDismissed((s) => new Set([...s, alert.alert_id]))}
                        className="mt-0.5 text-muted-foreground hover:text-foreground shrink-0"
                        aria-label="Dismiss"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          {/* Footer */}
          <div className="border-t border-border px-4 py-2.5">
            <a
              href="#/mission-control/soc"
              onClick={() => setOpen(false)}
              className="block text-center text-xs text-primary hover:underline"
            >
              View all in SOC Alert Triage
            </a>
          </div>
        </div>
      )}
    </div>
  );
}
