/**
 * HealthCardWidget — 5 subsystem traffic lights from /api/v1/system/health
 * Mounted in CISODashboard top-right corner
 *
 * Shows: Pipeline, Database, Connectors, Feeds, Queue with status colors
 * Status: HEALTHY (green), DEGRADED (yellow), CRITICAL (red), UNKNOWN (gray)
 */

import { useEffect, useState } from "react";
import { Activity } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface SubsystemHealth {
  name: string;
  status: "healthy" | "degraded" | "critical" | "unknown";
  response_ms: number;
  error?: string;
}

interface SystemHealthReport {
  overall_status: "healthy" | "degraded" | "critical" | "unknown";
  subsystems: SubsystemHealth[];
}

export function HealthCardWidget() {
  const [health, setHealth] = useState<SystemHealthReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const res = await fetch(buildApiUrl("/api/v1/system/health"), {
          headers: {
            "X-API-Key": getStoredAuthToken(),
            "X-Org-ID": getStoredOrgId(),
            "Content-Type": "application/json",
          },
        });
        if (!res.ok) {
          setError("Failed to fetch health");
          setLoading(false);
          return;
        }
        const data = (await res.json()) as SystemHealthReport;
        setHealth(data);
        setError(null);
      } catch (err) {
        setError("Error loading health status");
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchHealth();
    const interval = setInterval(fetchHealth, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <Card className="w-full">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            System Health
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-5">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-12" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error || !health) {
    return (
      <Card className="w-full">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            System Health
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-xs text-muted-foreground">{error || "No health data"}</div>
        </CardContent>
      </Card>
    );
  }

  const statusColor = (status: string) => {
    switch (status) {
      case "healthy":
        return "bg-green-500/20 border-green-500/40 text-green-300";
      case "degraded":
        return "bg-yellow-500/20 border-yellow-500/40 text-yellow-300";
      case "critical":
        return "bg-red-500/20 border-red-500/40 text-red-300";
      default:
        return "bg-slate-500/20 border-slate-500/40 text-slate-300";
    }
  };

  const statusDot = (status: string) => {
    switch (status) {
      case "healthy":
        return "bg-green-500";
      case "degraded":
        return "bg-yellow-500";
      case "critical":
        return "bg-red-500";
      default:
        return "bg-slate-500";
    }
  };

  return (
    <Card className="w-full">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <Activity className="h-4 w-4 text-primary" />
          System Health
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-5">
          {health.subsystems.map((subsys) => (
            <div
              key={subsys.name}
              className={cn(
                "flex flex-col items-center gap-2 p-3 rounded-lg border transition-colors",
                statusColor(subsys.status)
              )}
            >
              <div className="flex items-center gap-1.5 w-full justify-center">
                <div className={cn("h-2 w-2 rounded-full", statusDot(subsys.status))} />
                <span className="text-[11px] font-semibold capitalize truncate">
                  {subsys.name}
                </span>
              </div>
              <span className="text-[10px] text-muted-foreground">
                {subsys.response_ms.toFixed(0)}ms
              </span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
