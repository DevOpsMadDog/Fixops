import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import {
  Shield, Bug, Eye, Zap, FileCheck, AlertTriangle, CheckCircle2,
  Upload, Play, Settings, Clock, ArrowRight,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../ui/card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Skeleton } from '../ui/skeleton';
import { api } from '../../lib/api';

interface ActivityEvent {
  id: string;
  type: string;
  action: string;
  timestamp: string;
  severity?: string;
  details?: string;
  user?: string;
  resource_type?: string;
}

const eventIcons: Record<string, React.ElementType> = {
  scan: Shield,
  finding: Bug,
  remediation: Zap,
  compliance: FileCheck,
  alert: AlertTriangle,
  upload: Upload,
  pipeline: Play,
  config: Settings,
  verify: Eye,
  resolve: CheckCircle2,
};

const eventColors: Record<string, string> = {
  scan: 'text-cyan-400 bg-cyan-500/10',
  finding: 'text-amber-400 bg-amber-500/10',
  remediation: 'text-emerald-400 bg-emerald-500/10',
  compliance: 'text-violet-400 bg-violet-500/10',
  alert: 'text-red-400 bg-red-500/10',
  upload: 'text-blue-400 bg-blue-500/10',
  pipeline: 'text-indigo-400 bg-indigo-500/10',
  config: 'text-gray-400 bg-gray-500/10',
  verify: 'text-orange-400 bg-orange-500/10',
  resolve: 'text-green-400 bg-green-500/10',
};

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function getEventType(event: Record<string, unknown>): string {
  const action = String(event.action || event.event_type || event.type || '').toLowerCase();
  if (action.includes('scan')) return 'scan';
  if (action.includes('find') || action.includes('vuln')) return 'finding';
  if (action.includes('remed') || action.includes('fix')) return 'remediation';
  if (action.includes('comply') || action.includes('evidence') || action.includes('compliance')) return 'compliance';
  if (action.includes('alert') || action.includes('critical')) return 'alert';
  if (action.includes('upload') || action.includes('ingest')) return 'upload';
  if (action.includes('pipeline') || action.includes('brain')) return 'pipeline';
  if (action.includes('config') || action.includes('setting')) return 'config';
  if (action.includes('verify') || action.includes('mpte')) return 'verify';
  if (action.includes('resolve') || action.includes('close')) return 'resolve';
  return 'config';
}

interface RecentActivityTimelineProps {
  compact?: boolean;
  limit?: number;
}

export default function RecentActivityTimeline({ compact = false, limit = 8 }: RecentActivityTimelineProps) {
  const navigate = useNavigate();

  const { data: events, isLoading } = useQuery({
    queryKey: ['recent-activity', limit],
    queryFn: async () => {
      const res = await api.get('/api/v1/audit/logs', { params: { limit } });
      const items = res.data?.items || res.data || [];
      return (items as Record<string, unknown>[]).map((e, i) => ({
        id: String(e.id || `evt-${i}`),
        type: getEventType(e),
        action: String(e.action || e.event || e.message || 'System Event'),
        timestamp: String(e.timestamp || e.created_at || new Date().toISOString()),
        severity: String(e.severity || e.level || 'info'),
        details: String(e.details || e.description || e.resource || ''),
        user: String(e.user || e.actor || 'system'),
        resource_type: String(e.resource_type || ''),
      } as ActivityEvent));
    },
    refetchInterval: 30_000,
    retry: 1,
  });

  if (isLoading) {
    return (
      <Card className="glass-card backdrop-blur-md bg-gray-900/40 border-gray-700/40">
        <CardHeader className={compact ? 'pb-2' : ''}>
          <CardTitle className="text-base flex items-center gap-2">
            <Clock className="w-4 h-4 text-primary" />
            Recent Activity
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {Array.from({ length: compact ? 4 : 6 }).map((_, i) => (
            <div key={i} className="flex items-start gap-3">
              <Skeleton className="w-8 h-8 rounded-lg flex-shrink-0" />
              <div className="flex-1 space-y-1.5">
                <Skeleton className="h-4 w-48" />
                <Skeleton className="h-3 w-32" />
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    );
  }

  const displayEvents = events || [];

  return (
    <Card className="glass-card backdrop-blur-md bg-gray-900/40 border-gray-700/40 hover:border-primary/20 transition-all duration-300">
      <CardHeader className={compact ? 'pb-2' : ''}>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-base flex items-center gap-2">
              <Clock className="w-4 h-4 text-primary" />
              Recent Activity
            </CardTitle>
            {!compact && <CardDescription>Latest security events from audit trail</CardDescription>}
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="text-xs text-muted-foreground hover:text-foreground"
            onClick={() => navigate('/evidence/audit-trail')}
            aria-label="View all activity"
          >
            View all
            <ArrowRight className="w-3 h-3 ml-1" />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {displayEvents.length === 0 ? (
          <div className="text-center py-8">
            <Clock className="w-10 h-10 mx-auto text-muted-foreground/20 mb-3" />
            <p className="text-sm text-muted-foreground">No recent activity</p>
            <p className="text-xs text-muted-foreground/60 mt-1">Events will appear as you use the platform</p>
          </div>
        ) : (
          <div className="relative">
            {/* Timeline line */}
            <div className="absolute left-4 top-4 bottom-4 w-px bg-border/40" />

            <div className="space-y-1">
              {displayEvents.map((event, i) => {
                const Icon = eventIcons[event.type] || Clock;
                const colors = eventColors[event.type] || 'text-gray-400 bg-gray-500/10';
                const [textColor, bgColor] = colors.split(' ');

                return (
                  <motion.div
                    key={event.id}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.04, ease: [0.16, 1, 0.3, 1] }}
                    className="relative flex items-start gap-3 pl-1 py-2 rounded-lg hover:bg-muted/20 transition-colors group"
                  >
                    {/* Icon */}
                    <div className={`relative z-10 w-8 h-8 rounded-lg ${bgColor} flex items-center justify-center flex-shrink-0`}>
                      <Icon className={`w-4 h-4 ${textColor}`} />
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm text-foreground truncate">{event.action}</p>
                        {event.severity && event.severity !== 'info' && (
                          <Badge
                            variant={event.severity === 'critical' ? 'destructive' : 'outline'}
                            className="text-[9px] px-1 py-0 h-3.5"
                          >
                            {event.severity}
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        {event.details && (
                          <span className="text-xs text-muted-foreground truncate max-w-[200px]">
                            {event.details}
                          </span>
                        )}
                        <span className="text-[10px] text-muted-foreground/50 flex-shrink-0">
                          {timeAgo(event.timestamp)}
                        </span>
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
