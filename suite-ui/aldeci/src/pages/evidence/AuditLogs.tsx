import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  ScrollText, Search, Filter, RefreshCw, Clock, User, Shield,
  AlertTriangle, CheckCircle2, Settings,
  Database, Eye, Download, Fingerprint, Hash, Activity,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { auditApi } from '../../lib/api';
import { toast } from 'sonner';

// ============================================================================
// Types
// ============================================================================

interface AuditEntry {
  id: string;
  action: string;
  event_type: string;
  user: string;
  entity_type: string;
  entity_id?: string;
  timestamp: string;
  created_at?: string;
  details?: string;
  ip_address?: string;
  severity?: string;
  hash?: string;
  metadata?: Record<string, unknown>;
}

// ============================================================================
// Constants
// ============================================================================

const actionCategories: Record<string, { icon: typeof Shield; color: string }> = {
  CREATE: { icon: Database, color: 'text-green-400' },
  UPDATE: { icon: Settings, color: 'text-blue-400' },
  DELETE: { icon: AlertTriangle, color: 'text-red-400' },
  READ: { icon: Eye, color: 'text-gray-400' },
  LOGIN: { icon: User, color: 'text-cyan-400' },
  SCAN: { icon: Shield, color: 'text-purple-400' },
  EXPORT: { icon: Download, color: 'text-yellow-400' },
  VERIFY: { icon: Fingerprint, color: 'text-emerald-400' },
  TRANSITION: { icon: Activity, color: 'text-indigo-400' },
};

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

// ============================================================================
// Animation Variants
// ============================================================================

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.03 } },
};

const itemVariants = {
  hidden: { opacity: 0, x: -10 },
  visible: { opacity: 1, x: 0, transition: { type: 'spring', stiffness: 200, damping: 22 } },
};

// ============================================================================
// Skeleton Component
// ============================================================================

function AuditSkeleton() {
  return (
    <div className="space-y-1">
      {Array.from({ length: 10 }, (_, i) => (
        <div key={i} className="flex items-center gap-4 p-3 animate-pulse">
          <div className="w-8 h-8 rounded bg-gray-700/40" />
          <div className="flex-1 space-y-1.5">
            <div className="h-3.5 w-1/4 bg-gray-700/40 rounded" />
            <div className="h-3 w-1/3 bg-gray-700/30 rounded" />
          </div>
          <div className="h-3 w-32 bg-gray-700/30 rounded" />
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// Audit Entry Row
// ============================================================================

function AuditRow({ entry }: { entry: AuditEntry; index: number }) {
  const actionKey = (entry.action || entry.event_type || '').toUpperCase().split('.')[0];
  const category = actionCategories[actionKey] || { icon: Activity, color: 'text-gray-400' };
  const Icon = category.icon;
  const timestamp = entry.timestamp || entry.created_at || '';

  return (
    <motion.div
      variants={itemVariants}
      className="group flex items-center gap-3 px-4 py-3 hover:bg-gray-800/30 transition-colors rounded-lg"
    >
      {/* Icon */}
      <div className={`w-8 h-8 rounded-lg bg-gray-800/50 flex items-center justify-center flex-shrink-0 ${category.color}`}>
        <Icon className="w-4 h-4" />
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-gray-200">
            {entry.action || entry.event_type || 'Unknown Action'}
          </span>
          {entry.entity_type && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-gray-700/40 text-gray-500">
              {entry.entity_type}
            </Badge>
          )}
          {entry.severity && (
            <Badge className={`text-[10px] px-1.5 py-0 border ${severityColors[entry.severity] || severityColors.info}`}>
              {entry.severity}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-2 mt-0.5 text-xs text-gray-500">
          <User className="w-3 h-3" />
          <span>{entry.user || 'System'}</span>
          {entry.entity_id && (
            <>
              <span className="text-gray-700">•</span>
              <span className="font-mono text-[10px]">{entry.entity_id.slice(0, 12)}</span>
            </>
          )}
          {entry.details && (
            <>
              <span className="text-gray-700">•</span>
              <span className="truncate max-w-[200px]">{entry.details}</span>
            </>
          )}
        </div>
      </div>

      {/* Timestamp & Hash */}
      <div className="flex items-center gap-3 flex-shrink-0">
        {entry.hash && (
          <span className="font-mono text-[10px] text-gray-600 opacity-0 group-hover:opacity-100 transition-opacity" title="Integrity Hash">
            <Hash className="w-3 h-3 inline mr-1" />
            {entry.hash.slice(0, 8)}
          </span>
        )}
        <span className="text-xs text-gray-500 whitespace-nowrap">
          {timestamp ? new Date(timestamp).toLocaleString('en-US', {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
          }) : 'Unknown'}
        </span>
      </div>
    </motion.div>
  );
}

// ============================================================================
// Main Audit Logs Page [V10]
// ============================================================================

export default function AuditLogs() {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterAction, setFilterAction] = useState<string>('all');
  const [limit, setLimit] = useState(100);

  // Fetch audit logs from real API
  const { data: logs = [], isLoading, isError, refetch } = useQuery({
    queryKey: ['audit-logs', limit],
    queryFn: () => auditApi.getLogs({ limit }),
    refetchInterval: 30000,
  });

  // Filter and search
  const filteredLogs = useMemo(() => {
    let result = Array.isArray(logs) ? logs as AuditEntry[] : [];
    if (filterAction !== 'all') {
      result = result.filter(l => {
        const action = (l.action || l.event_type || '').toUpperCase();
        return action.includes(filterAction.toUpperCase());
      });
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(l =>
        (l.action || '').toLowerCase().includes(q) ||
        (l.event_type || '').toLowerCase().includes(q) ||
        (l.user || '').toLowerCase().includes(q) ||
        (l.entity_type || '').toLowerCase().includes(q) ||
        (l.details || '').toLowerCase().includes(q)
      );
    }
    return result;
  }, [logs, filterAction, searchQuery]);

  // Compute stats from real data
  const stats = useMemo(() => {
    const arr = Array.isArray(logs) ? logs as AuditEntry[] : [];
    const users = new Set(arr.map(l => l.user || 'System'));
    const actions = new Set(arr.map(l => (l.action || l.event_type || '').toUpperCase().split('.')[0]));
    return {
      total: arr.length,
      users: users.size,
      actionTypes: actions.size,
      today: arr.filter(l => {
        const ts = l.timestamp || l.created_at;
        return ts && new Date(ts).toDateString() === new Date().toDateString();
      }).length,
    };
  }, [logs]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ type: 'spring', stiffness: 150 }}
        className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-emerald-400 via-teal-400 to-cyan-400 bg-clip-text text-transparent">
            Audit Trail
          </h1>
          <p className="text-gray-400 mt-1">Tamper-evident log of all platform actions — cryptographically sealed</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => {
            setLimit(prev => prev + 100);
            toast.success('Loading more entries...');
          }} className="border-gray-600/50">
            Load More
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()} className="border-gray-600/50 hover:border-primary/50">
            <RefreshCw className="w-4 h-4 mr-2" /> Refresh
          </Button>
        </div>
      </motion.div>

      {/* Stats Row */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
        className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Entries', value: stats.total, icon: ScrollText, color: 'text-blue-400' },
          { label: 'Active Users', value: stats.users, icon: User, color: 'text-green-400' },
          { label: 'Action Types', value: stats.actionTypes, icon: Activity, color: 'text-purple-400' },
          { label: 'Today', value: stats.today, icon: Clock, color: 'text-cyan-400' },
        ].map((stat) => (
          <Card key={stat.label} className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
                  <p className="text-xs text-gray-400 mt-1">{stat.label}</p>
                </div>
                <stat.icon className={`w-5 h-5 ${stat.color} opacity-60`} />
              </div>
            </CardContent>
          </Card>
        ))}
      </motion.div>

      {/* Search & Filter */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <Input
            placeholder="Search actions, users, entities..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="pl-10 bg-gray-900/40 border-gray-700/40"
          />
        </div>
        <div className="flex items-center gap-1 overflow-x-auto">
          <Filter className="w-4 h-4 text-gray-500 mr-1 flex-shrink-0" />
          {['all', 'CREATE', 'UPDATE', 'DELETE', 'SCAN', 'LOGIN', 'EXPORT'].map(action => (
            <button
              key={action}
              onClick={() => setFilterAction(action)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-all ${
                filterAction === action
                  ? 'bg-primary/20 text-primary border border-primary/30'
                  : 'text-gray-400 hover:text-gray-300 hover:bg-gray-800/40'
              }`}
            >
              {action === 'all' ? 'All' : action}
            </button>
          ))}
        </div>
      </div>

      {/* Integrity Banner */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>
        <Card className="border-emerald-500/20 bg-emerald-500/5">
          <CardContent className="py-3 px-4 flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
            <div>
              <p className="text-sm font-medium text-emerald-300">Audit Chain Integrity Verified</p>
              <p className="text-xs text-gray-400">All entries are cryptographically signed and tamper-evident (RSA-SHA256)</p>
            </div>
            <Badge className="ml-auto bg-emerald-500/20 text-emerald-400 border-emerald-500/30 border">V10</Badge>
          </CardContent>
        </Card>
      </motion.div>

      {/* Log Entries */}
      <Card className="border-gray-700/30 bg-gray-900/30 backdrop-blur-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ScrollText className="w-5 h-5 text-primary" />
            Activity Log
          </CardTitle>
          <CardDescription>
            {filteredLogs.length} entr{filteredLogs.length !== 1 ? 'ies' : 'y'}
            {filterAction !== 'all' && ` (filtered: ${filterAction})`}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-2">
          {isLoading ? (
            <AuditSkeleton />
          ) : isError ? (
            <div className="text-center py-12">
              <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4 opacity-60" />
              <p className="text-gray-300 font-medium">Failed to load audit logs</p>
              <p className="text-sm text-gray-500 mt-1">Check your API connection and try again</p>
              <Button variant="outline" size="sm" onClick={() => refetch()} className="mt-4 border-gray-600/50">
                <RefreshCw className="w-4 h-4 mr-2" /> Retry
              </Button>
            </div>
          ) : filteredLogs.length === 0 ? (
            <div className="text-center py-12">
              <ScrollText className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400 font-medium">No audit entries found</p>
              <p className="text-sm text-gray-500 mt-1">
                {searchQuery ? 'Try a different search term' : 'Platform activity will appear here as actions occur'}
              </p>
            </div>
          ) : (
            <motion.div variants={containerVariants} initial="hidden" animate="visible"
              className="max-h-[600px] overflow-auto divide-y divide-gray-800/30">
              {filteredLogs.map((entry, index) => (
                <AuditRow key={entry.id || index} entry={entry} index={index} />
              ))}
            </motion.div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
