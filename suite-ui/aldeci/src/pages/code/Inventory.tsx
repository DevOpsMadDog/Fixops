import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Box,
  Search,
  Server,
  Globe,
  Database,
  Shield,
  Code2,
  AlertTriangle,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
import { api } from '../../lib/api';

// ─── Interfaces ────────────────────────────────────────────────────────────────

interface Application {
  id: string;
  name: string;
  type?: string;
  language?: string;
  risk_score?: number;
  vulnerability_count?: number;
  last_scan?: string;
  status?: string;
  team?: string;
  environment?: string;
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

const typeIcon = (type: string) => {
  switch (type?.toLowerCase()) {
    case 'service':
      return Server;
    case 'web':
    case 'webapp':
      return Globe;
    case 'api':
      return Database;
    case 'library':
      return Code2;
    default:
      return Box;
  }
};

const riskColor = (score: number): string => {
  if (score >= 70) return 'text-red-400';
  if (score >= 40) return 'text-yellow-400';
  return 'text-green-400';
};

const riskLabel = (score: number): string => {
  if (score >= 70) return 'High';
  if (score >= 40) return 'Medium';
  return 'Low';
};

const formatDate = (iso?: string): string => {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return iso;
  }
};

// ─── Skeleton ──────────────────────────────────────────────────────────────────

function InventorySkeleton() {
  return (
    <div className="space-y-3">
      {Array.from({ length: 6 }, (_, i) => (
        <div
          key={i}
          className="flex items-center gap-4 p-4 rounded-lg border border-gray-700/30 animate-pulse"
        >
          <div className="h-10 w-10 bg-gray-700/40 rounded-lg" />
          <div className="flex-1 space-y-2">
            <div className="h-4 w-40 bg-gray-700/40 rounded" />
            <div className="h-3 w-24 bg-gray-700/30 rounded" />
          </div>
          <div className="h-6 w-16 bg-gray-700/30 rounded" />
          <div className="h-6 w-16 bg-gray-700/30 rounded" />
        </div>
      ))}
    </div>
  );
}

// ─── Animation Variants ────────────────────────────────────────────────────────

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.04 } },
};

const itemVariants = {
  hidden: { opacity: 0, x: -10 },
  visible: {
    opacity: 1,
    x: 0,
    transition: { type: 'spring' as const, stiffness: 200, damping: 22 },
  },
};

// ─── Stat Card ─────────────────────────────────────────────────────────────────

interface StatCardProps {
  label: string;
  value: number;
  icon: React.ElementType;
  accent?: string;
}

function StatCard({ label, value, icon: Icon, accent = 'text-cyan-400' }: StatCardProps) {
  return (
    <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
      <CardContent className="p-4 flex items-center gap-3">
        <div className={`p-2 rounded-lg bg-gray-800/60 ${accent}`}>
          <Icon className="h-4 w-4" />
        </div>
        <div>
          <p className="text-2xl font-bold text-gray-100">{value}</p>
          <p className="text-xs text-gray-400">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────────

const TYPES = ['all', 'service', 'api', 'web', 'library'];

export default function Inventory() {
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');

  const { data: appsRaw, isLoading } = useQuery({
    queryKey: ['inventory-apps'],
    queryFn: async () => {
      try {
        const res = await api.get('/api/v1/inventory/applications');
        return res.data?.applications || res.data?.items || res.data || [];
      } catch (err) {
        toast.error('Failed to load asset inventory');
        throw err;
      }
    },
  });

  const apps = useMemo(() => {
    let list = (appsRaw || []) as Application[];
    if (typeFilter !== 'all') {
      list = list.filter((a) => a.type?.toLowerCase() === typeFilter);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (a) =>
          a.name.toLowerCase().includes(q) ||
          (a.type || '').toLowerCase().includes(q) ||
          (a.language || '').toLowerCase().includes(q)
      );
    }
    return list;
  }, [appsRaw, searchQuery, typeFilter]);

  const allApps = (appsRaw || []) as Application[];
  const totalServices = allApps.filter(
    (a) => a.type?.toLowerCase() === 'service' || a.type?.toLowerCase() === 'api'
  ).length;
  const highRisk = allApps.filter((a) => (a.risk_score ?? 0) >= 70).length;
  const vulnerable = allApps.filter((a) => (a.vulnerability_count ?? 0) > 0).length;

  return (
    <div className="p-6 space-y-6 min-h-screen bg-gray-950/50">
      {/* ── Header ── */}
      <motion.div
        initial={{ opacity: 0, y: -12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="space-y-1"
      >
        <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 via-blue-400 to-indigo-400 bg-clip-text text-transparent">
          Asset Inventory
        </h1>
        <p className="text-gray-400 text-sm">
          Track applications, services, and their security posture
        </p>
      </motion.div>

      {/* ── Stats Row ── */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
        className="grid grid-cols-2 md:grid-cols-4 gap-4"
      >
        <StatCard label="Total Apps" value={allApps.length} icon={Box} accent="text-cyan-400" />
        <StatCard label="Services / APIs" value={totalServices} icon={Server} accent="text-blue-400" />
        <StatCard label="High Risk" value={highRisk} icon={AlertTriangle} accent="text-red-400" />
        <StatCard label="Vulnerable" value={vulnerable} icon={Shield} accent="text-orange-400" />
      </motion.div>

      {/* ── Filters ── */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3, delay: 0.15 }}
        className="flex flex-col sm:flex-row gap-3"
      >
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
          <Input
            placeholder="Search by name, type, or language..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 bg-gray-900/60 border-gray-700/40 text-gray-100 placeholder:text-gray-500 focus:border-cyan-500/50"
          />
        </div>
        <div className="flex gap-2 flex-wrap">
          {TYPES.map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                typeFilter === t
                  ? 'bg-primary/20 text-primary border border-primary/30'
                  : 'text-gray-400 hover:text-gray-300 border border-gray-700/30'
              }`}
            >
              {t === 'all' ? 'All' : t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>
      </motion.div>

      {/* ── App List ── */}
      <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
        <CardHeader className="pb-3">
          <CardTitle className="text-gray-100 text-base font-semibold">
            Applications
            <span className="ml-2 text-xs font-normal text-gray-500">
              {isLoading ? '…' : `${apps.length} result${apps.length !== 1 ? 's' : ''}`}
            </span>
          </CardTitle>
          <CardDescription className="text-gray-500 text-xs">
            Showing {typeFilter === 'all' ? 'all types' : typeFilter}
            {searchQuery ? ` matching "${searchQuery}"` : ''}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <InventorySkeleton />
          ) : apps.length === 0 ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex flex-col items-center justify-center py-16 text-gray-500"
            >
              <Box className="h-12 w-12 mb-3 opacity-30" />
              <p className="font-medium">No applications found</p>
              <p className="text-xs mt-1">Try adjusting your search or filter</p>
            </motion.div>
          ) : (
            <motion.div
              variants={containerVariants}
              initial="hidden"
              animate="visible"
              className="space-y-2"
            >
              {apps.map((app) => {
                const TypeIcon = typeIcon(app.type ?? '');
                const score = app.risk_score ?? 0;
                const vulnCount = app.vulnerability_count ?? 0;

                return (
                  <motion.div
                    key={app.id}
                    variants={itemVariants}
                    className="flex items-center gap-4 p-4 rounded-lg border border-gray-700/30 bg-gray-800/20 hover:bg-gray-800/40 transition-colors group"
                  >
                    {/* Type Icon */}
                    <div className="flex-shrink-0 h-10 w-10 rounded-lg bg-gray-800/60 flex items-center justify-center border border-gray-700/30 group-hover:border-cyan-500/20 transition-colors">
                      <TypeIcon className="h-5 w-5 text-gray-400 group-hover:text-cyan-400 transition-colors" />
                    </div>

                    {/* Name + meta */}
                    <div className="flex-1 min-w-0">
                      <p className="font-semibold text-gray-100 truncate">{app.name}</p>
                      <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                        {app.team && (
                          <span className="text-xs text-gray-500">{app.team}</span>
                        )}
                        {app.environment && (
                          <Badge
                            variant="outline"
                            className="text-[10px] h-4 border-gray-600/40 text-gray-400 px-1.5"
                          >
                            {app.environment}
                          </Badge>
                        )}
                        {app.last_scan && (
                          <span className="text-[10px] text-gray-600">
                            Scanned {formatDate(app.last_scan)}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Badges */}
                    <div className="flex items-center gap-2 flex-shrink-0 flex-wrap justify-end">
                      {app.type && (
                        <Badge
                          variant="outline"
                          className="text-xs border-gray-600/40 text-gray-300 capitalize"
                        >
                          {app.type}
                        </Badge>
                      )}
                      {app.language && (
                        <Badge
                          variant="outline"
                          className="text-xs border-blue-500/20 text-blue-400 bg-blue-500/5"
                        >
                          {app.language}
                        </Badge>
                      )}
                      {score > 0 && (
                        <div className="flex items-center gap-1">
                          <Shield className={`h-3.5 w-3.5 ${riskColor(score)}`} />
                          <span className={`text-xs font-medium ${riskColor(score)}`}>
                            {riskLabel(score)} ({score})
                          </span>
                        </div>
                      )}
                      {vulnCount > 0 && (
                        <Badge className="text-xs bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20">
                          <AlertTriangle className="h-3 w-3 mr-1" />
                          {vulnCount} vuln{vulnCount !== 1 ? 's' : ''}
                        </Badge>
                      )}
                    </div>
                  </motion.div>
                );
              })}
            </motion.div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
