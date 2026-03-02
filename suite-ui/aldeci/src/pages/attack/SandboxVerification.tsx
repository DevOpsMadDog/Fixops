import { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Play,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Terminal,
  Hash,
  Clock,
  BarChart3,
  RefreshCw,
  Wifi,
  WifiOff,
  Copy,
  ChevronDown,
  ChevronUp,
  Activity,
  Lock,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { sandboxApi } from '../../lib/api';
import { toast } from 'sonner';

// ─── Types ────────────────────────────────────────────────────────────────────

type Language = 'python' | 'bash' | 'nodejs' | 'curl' | 'go';

type VerdictType = 'EXPLOITABLE' | 'NOT_EXPLOITABLE' | 'INCONCLUSIVE';

interface VerificationResult {
  id?: string;
  verdict: VerdictType;
  confidence: number;
  evidence_hash?: string;
  output?: string;
  logs?: string;
  execution_time?: number;
  cve_id?: string;
  language?: string;
  timestamp?: string;
  error?: string;
  indicators_matched?: string[];
}

interface SandboxStats {
  total_verifications?: number;
  exploitable_count?: number;
  not_exploitable_count?: number;
  inconclusive_count?: number;
  success_rate?: number;
  average_execution_time?: number;
  uptime_seconds?: number;
  uptime_percentage?: number;
}

interface SandboxHealth {
  status?: string;
  docker_available?: boolean;
  sandbox_ready?: boolean;
  version?: string;
  container_limit?: number;
  active_containers?: number;
}

interface ResultItem {
  id: string;
  verdict: VerdictType;
  confidence: number;
  cve_id?: string;
  language?: string;
  timestamp?: string;
  execution_time?: number;
  evidence_hash?: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const LANGUAGES: { id: Language; label: string; placeholder: string }[] = [
  {
    id: 'python',
    label: 'Python',
    placeholder:
      'import requests\n\n# PoC for CVE-XXXX-XXXXX\ntarget = "http://target.example.com"\n\nresponse = requests.get(f"{target}/vulnerable-endpoint")\nif response.status_code == 200 and "error" in response.text:\n    print("[+] Target is VULNERABLE")\nelse:\n    print("[-] Target does not appear vulnerable")',
  },
  {
    id: 'bash',
    label: 'Bash',
    placeholder:
      '#!/bin/bash\n# PoC for CVE-XXXX-XXXXX\nTARGET="${TARGET_URL:-http://target.example.com}"\n\nRESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/test")\nif [ "$RESPONSE" = "200" ]; then\n  echo "[+] Endpoint reachable"\nfi',
  },
  {
    id: 'nodejs',
    label: 'Node.js',
    placeholder:
      "const https = require('https');\n\n// PoC for CVE-XXXX-XXXXX\nconst target = process.env.TARGET_URL || 'http://target.example.com';\n\nfetch(`${target}/api/endpoint`)\n  .then(r => r.text())\n  .then(body => {\n    if (body.includes('sensitive')) {\n      console.log('[+] Data exposed - VULNERABLE');\n    }\n  });",
  },
  {
    id: 'curl',
    label: 'curl',
    placeholder:
      '#!/bin/bash\n# PoC via curl for CVE-XXXX-XXXXX\nTARGET="${TARGET_URL:-http://target.example.com}"\n\n# Test for vulnerability\ncurl -v \\\n  -H "X-Custom-Header: ../../../../etc/passwd" \\\n  "$TARGET/api/v1/resource" 2>&1 | grep -i "root:"',
  },
  {
    id: 'go',
    label: 'Go',
    placeholder:
      'package main\n\nimport (\n\t"fmt"\n\t"net/http"\n\t"os"\n)\n\nfunc main() {\n\ttarget := os.Getenv("TARGET_URL")\n\tif target == "" {\n\t\ttarget = "http://target.example.com"\n\t}\n\tresp, err := http.Get(target + "/vulnerable")\n\tif err != nil {\n\t\tfmt.Println("[-] Connection failed:", err)\n\t\treturn\n\t}\n\tdefer resp.Body.Close()\n\tfmt.Printf("[+] Status: %d\\n", resp.StatusCode)\n}',
  },
];

const VERDICT_CONFIG: Record<
  VerdictType,
  { label: string; color: string; icon: React.ElementType; bg: string }
> = {
  EXPLOITABLE: {
    label: 'EXPLOITABLE',
    color: 'text-red-400',
    icon: XCircle,
    bg: 'bg-red-500/10 border-red-500/30',
  },
  NOT_EXPLOITABLE: {
    label: 'NOT EXPLOITABLE',
    color: 'text-green-400',
    icon: CheckCircle2,
    bg: 'bg-green-500/10 border-green-500/30',
  },
  INCONCLUSIVE: {
    label: 'INCONCLUSIVE',
    color: 'text-yellow-400',
    icon: AlertTriangle,
    bg: 'bg-yellow-500/10 border-yellow-500/30',
  },
};

// ─── Helper Components ────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  accent: string;
}) {
  return (
    <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
      <CardContent className="p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-gray-500 uppercase tracking-wider">{label}</span>
          <Icon className={`w-4 h-4 ${accent}`} />
        </div>
        <div className={`text-2xl font-bold ${accent}`}>{value}</div>
      </CardContent>
    </Card>
  );
}

function VerdictBadge({ verdict }: { verdict: VerdictType }) {
  const cfg = VERDICT_CONFIG[verdict];
  const Icon = cfg.icon;
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-sm font-semibold ${cfg.bg} ${cfg.color}`}
    >
      <Icon className="w-4 h-4" />
      {cfg.label}
    </span>
  );
}

function CopyButton({ text }: { text: string }) {
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => toast.success('Copied to clipboard'));
  }, [text]);
  return (
    <button
      onClick={handleCopy}
      className="p-1 hover:text-gray-200 text-gray-500 transition-colors"
      title="Copy"
    >
      <Copy className="w-3.5 h-3.5" />
    </button>
  );
}

// ─── Results Panel ────────────────────────────────────────────────────────────

function VerificationResultPanel({ result }: { result: VerificationResult }) {
  const [logsExpanded, setLogsExpanded] = useState(false);
  const cfg = VERDICT_CONFIG[result.verdict] ?? VERDICT_CONFIG.INCONCLUSIVE;

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.3 }}
      className={`rounded-xl border p-5 space-y-4 ${cfg.bg}`}
    >
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3 justify-between">
        <VerdictBadge verdict={result.verdict} />
        {result.cve_id && (
          <Badge variant="outline" className="border-gray-600 text-gray-300 font-mono">
            {result.cve_id}
          </Badge>
        )}
        {result.execution_time !== undefined && (
          <span className="text-xs text-gray-500 flex items-center gap-1">
            <Clock className="w-3 h-3" />
            {result.execution_time.toFixed(2)}s
          </span>
        )}
      </div>

      {/* Confidence */}
      <div className="space-y-1.5">
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">Confidence</span>
          <span className={`font-semibold ${cfg.color}`}>{Math.round(result.confidence * 100)}%</span>
        </div>
        <Progress
          value={result.confidence * 100}
          className="h-2 bg-gray-800"
        />
      </div>

      {/* Indicators */}
      {result.indicators_matched && result.indicators_matched.length > 0 && (
        <div className="space-y-1">
          <div className="text-xs text-gray-500 uppercase tracking-wider">Indicators Matched</div>
          <div className="flex flex-wrap gap-1.5">
            {result.indicators_matched.map((ind) => (
              <span
                key={ind}
                className="px-2 py-0.5 bg-gray-800/60 border border-gray-700/40 rounded text-xs text-gray-300 font-mono"
              >
                {ind}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Evidence Hash (V10 compliance) */}
      {result.evidence_hash && (
        <div className="bg-gray-950/60 rounded-lg border border-gray-700/30 p-3">
          <div className="flex items-center gap-2 mb-1">
            <Hash className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-xs text-gray-400 uppercase tracking-wider">Evidence Hash (V10)</span>
            <CopyButton text={result.evidence_hash} />
          </div>
          <code className="text-xs font-mono text-purple-300 break-all">{result.evidence_hash}</code>
        </div>
      )}

      {/* Execution Output / Logs */}
      {(result.output || result.logs) && (
        <div className="space-y-1.5">
          <button
            onClick={() => setLogsExpanded((v) => !v)}
            className="flex items-center gap-2 text-xs text-gray-400 hover:text-gray-200 transition-colors"
          >
            <Terminal className="w-3.5 h-3.5" />
            Execution Output
            {logsExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
          <AnimatePresence>
            {logsExpanded && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <pre className="bg-gray-950 border border-gray-800/60 rounded-lg p-3 text-xs font-mono text-green-300 whitespace-pre-wrap overflow-auto max-h-64">
                  {result.output ?? result.logs}
                </pre>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* Error */}
      {result.error && (
        <div className="bg-red-950/30 border border-red-800/40 rounded-lg p-3">
          <p className="text-xs text-red-400 font-mono">{result.error}</p>
        </div>
      )}
    </motion.div>
  );
}

// ─── Results Table Row ────────────────────────────────────────────────────────

function ResultRow({
  item,
  index,
}: {
  item: ResultItem;
  index: number;
}) {
  const cfg = VERDICT_CONFIG[item.verdict] ?? VERDICT_CONFIG.INCONCLUSIVE;
  const Icon = cfg.icon;

  return (
    <motion.tr
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.04 }}
      className="border-b border-gray-800/40 hover:bg-gray-800/20 transition-colors"
    >
      <td className="py-3 px-4">
        <span className={`inline-flex items-center gap-1 text-xs font-semibold ${cfg.color}`}>
          <Icon className="w-3.5 h-3.5" />
          {cfg.label}
        </span>
      </td>
      <td className="py-3 px-4">
        <div className="flex items-center gap-2">
          <Progress value={item.confidence * 100} className="h-1.5 w-20 bg-gray-800" />
          <span className="text-xs text-gray-400">{Math.round(item.confidence * 100)}%</span>
        </div>
      </td>
      <td className="py-3 px-4 text-xs font-mono text-gray-400">
        {item.cve_id ?? '—'}
      </td>
      <td className="py-3 px-4">
        {item.language && (
          <Badge variant="outline" className="border-gray-700 text-gray-400 text-xs">
            {item.language}
          </Badge>
        )}
      </td>
      <td className="py-3 px-4 text-xs text-gray-500">
        {item.execution_time !== undefined ? `${item.execution_time.toFixed(2)}s` : '—'}
      </td>
      <td className="py-3 px-4 text-xs text-gray-500">
        {item.timestamp ? new Date(item.timestamp).toLocaleString() : '—'}
      </td>
    </motion.tr>
  );
}

// ─── Stats Tab ────────────────────────────────────────────────────────────────

function StatsTab({ stats }: { stats: SandboxStats | undefined }) {
  if (!stats) {
    return (
      <div className="flex items-center justify-center h-48 text-gray-600">
        <BarChart3 className="w-8 h-8 mr-3" />
        No statistics available
      </div>
    );
  }

  const total = stats.total_verifications ?? 0;
  const exploitable = stats.exploitable_count ?? 0;
  const notExploitable = stats.not_exploitable_count ?? 0;
  const inconclusive = stats.inconclusive_count ?? 0;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Total Verifications" value={total} icon={Activity} accent="text-purple-400" />
        <StatCard label="Exploitable Found" value={exploitable} icon={XCircle} accent="text-red-400" />
        <StatCard
          label="Not Exploitable"
          value={notExploitable}
          icon={CheckCircle2}
          accent="text-green-400"
        />
        <StatCard
          label="Inconclusive"
          value={inconclusive}
          icon={AlertTriangle}
          accent="text-yellow-400"
        />
      </div>

      {/* Distribution bar */}
      {total > 0 && (
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardHeader>
            <CardTitle className="text-sm text-gray-400">Result Distribution</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {[
              { label: 'Exploitable', count: exploitable, color: 'bg-red-500', accent: 'text-red-400' },
              { label: 'Not Exploitable', count: notExploitable, color: 'bg-green-500', accent: 'text-green-400' },
              { label: 'Inconclusive', count: inconclusive, color: 'bg-yellow-500', accent: 'text-yellow-400' },
            ].map(({ label, count, color, accent }) => (
              <div key={label} className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-gray-400">{label}</span>
                  <span className={accent}>
                    {count} ({total > 0 ? Math.round((count / total) * 100) : 0}%)
                  </span>
                </div>
                <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                  <motion.div
                    className={`h-full rounded-full ${color}`}
                    initial={{ width: 0 }}
                    animate={{ width: `${total > 0 ? (count / total) * 100 : 0}%` }}
                    transition={{ duration: 0.8, ease: 'easeOut' }}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardContent className="p-4">
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">Success Rate</div>
            <div className="text-3xl font-bold text-purple-400">
              {stats.success_rate !== undefined ? `${Math.round(stats.success_rate * 100)}%` : '—'}
            </div>
          </CardContent>
        </Card>
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardContent className="p-4">
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">Avg Execution Time</div>
            <div className="text-3xl font-bold text-pink-400">
              {stats.average_execution_time !== undefined
                ? `${stats.average_execution_time.toFixed(1)}s`
                : '—'}
            </div>
          </CardContent>
        </Card>
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardContent className="p-4">
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">Sandbox Uptime</div>
            <div className="text-3xl font-bold text-green-400">
              {stats.uptime_percentage !== undefined
                ? `${stats.uptime_percentage.toFixed(1)}%`
                : '—'}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SandboxVerification() {
  const queryClient = useQueryClient();

  // Form state
  const [language, setLanguage] = useState<Language>('python');
  const [code, setCode] = useState('');
  const [cveId, setCveId] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [timeoutSeconds, setTimeoutSeconds] = useState(30);
  const [requiresNetwork, setRequiresNetwork] = useState(false);
  const [latestResult, setLatestResult] = useState<VerificationResult | null>(null);

  // Queries
  const { data: healthData, isLoading: healthLoading } = useQuery<SandboxHealth>({
    queryKey: ['sandbox-health'],
    queryFn: sandboxApi.health,
    refetchInterval: 30_000,
    retry: false,
  });

  const { data: statsData, isLoading: statsLoading } = useQuery<SandboxStats>({
    queryKey: ['sandbox-stats'],
    queryFn: sandboxApi.getStats,
    refetchInterval: 60_000,
    retry: false,
  });

  const {
    data: resultsData,
    isLoading: resultsLoading,
    refetch: refetchResults,
  } = useQuery<ResultItem[]>({
    queryKey: ['sandbox-results'],
    queryFn: sandboxApi.getResults,
    refetchInterval: 30_000,
    retry: false,
  });

  // Mutation
  const verifyMutation = useMutation({
    mutationFn: sandboxApi.verifyPoC,
    onSuccess: (data: VerificationResult) => {
      setLatestResult(data);
      queryClient.invalidateQueries({ queryKey: ['sandbox-results'] });
      queryClient.invalidateQueries({ queryKey: ['sandbox-stats'] });
      const verdict = data.verdict ?? 'INCONCLUSIVE';
      if (verdict === 'EXPLOITABLE') {
        toast.error('Verdict: EXPLOITABLE — sandbox confirmed the PoC works', {
          duration: 6000,
        });
      } else if (verdict === 'NOT_EXPLOITABLE') {
        toast.success('Verdict: NOT EXPLOITABLE — PoC did not succeed', { duration: 5000 });
      } else {
        toast.warning('Verdict: INCONCLUSIVE — manual review required', { duration: 5000 });
      }
    },
    onError: (err: Error) => {
      toast.error(`Verification failed: ${err.message ?? 'Unknown error'}`);
    },
  });

  const handleVerify = useCallback(() => {
    if (!code.trim()) {
      toast.error('Please enter a PoC script before verifying');
      return;
    }
    setLatestResult(null);
    verifyMutation.mutate({
      language,
      code,
      cve_id: cveId.trim() || undefined,
      target_url: targetUrl.trim() || undefined,
      timeout_seconds: timeoutSeconds,
      requires_network: requiresNetwork,
    });
  }, [code, language, cveId, targetUrl, timeoutSeconds, requiresNetwork, verifyMutation]);

  const currentLang = LANGUAGES.find((l) => l.id === language)!;

  // Derived health state
  const sandboxReady =
    !healthLoading &&
    healthData != null &&
    (healthData.sandbox_ready !== false) &&
    (healthData.status === 'healthy' || healthData.docker_available === true);

  const results: ResultItem[] = Array.isArray(resultsData) ? resultsData : [];

  return (
    <div className="min-h-screen bg-gray-900/80 p-6 space-y-6">
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: -12 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-purple-400 via-pink-400 to-red-400 bg-clip-text text-transparent">
            Sandbox Verification
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            V5 — MPTE: Verify PoC exploits in an isolated Docker sandbox environment
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Docker health indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-gray-700/40 bg-gray-900/60 text-sm">
            {healthLoading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin text-gray-400" />
            ) : sandboxReady ? (
              <span className="w-2.5 h-2.5 rounded-full bg-green-500 shadow-[0_0_6px_2px_rgba(34,197,94,0.4)] animate-pulse" />
            ) : (
              <span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_6px_2px_rgba(239,68,68,0.4)]" />
            )}
            <span className={sandboxReady ? 'text-green-400' : 'text-red-400'}>
              Docker {sandboxReady ? 'Ready' : healthLoading ? 'Checking…' : 'Unavailable'}
            </span>
            {healthData?.active_containers !== undefined && (
              <span className="text-gray-500 text-xs">
                ({healthData.active_containers}/{healthData.container_limit ?? '?'} containers)
              </span>
            )}
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              refetchResults();
              queryClient.invalidateQueries({ queryKey: ['sandbox-stats'] });
              queryClient.invalidateQueries({ queryKey: ['sandbox-health'] });
            }}
            className="border-gray-700 text-gray-400 hover:text-gray-200"
          >
            <RefreshCw className="w-4 h-4 mr-1.5" />
            Refresh
          </Button>
        </div>
      </motion.div>

      {/* ── Stats Row ──────────────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-2 gap-3 sm:grid-cols-4"
      >
        <StatCard
          label="Total Verifications"
          value={statsLoading ? '…' : (statsData?.total_verifications ?? 0)}
          icon={Activity}
          accent="text-purple-400"
        />
        <StatCard
          label="Exploitable Found"
          value={statsLoading ? '…' : (statsData?.exploitable_count ?? 0)}
          icon={XCircle}
          accent="text-red-400"
        />
        <StatCard
          label="Avg Confidence"
          value={
            statsLoading
              ? '…'
              : statsData?.success_rate !== undefined
              ? `${Math.round(statsData.success_rate * 100)}%`
              : '—'
          }
          icon={BarChart3}
          accent="text-pink-400"
        />
        <StatCard
          label="Sandbox Uptime"
          value={
            statsLoading
              ? '…'
              : statsData?.uptime_percentage !== undefined
              ? `${statsData.uptime_percentage.toFixed(1)}%`
              : '—'
          }
          icon={Shield}
          accent="text-green-400"
        />
      </motion.div>

      {/* ── Main Tabs ──────────────────────────────────────────────────── */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.15 }}>
        <Tabs defaultValue="verify">
          <TabsList className="bg-gray-900/60 border border-gray-700/40 mb-6">
            <TabsTrigger value="verify" className="data-[state=active]:bg-purple-500/20 data-[state=active]:text-purple-300">
              <Play className="w-4 h-4 mr-2" />
              Verify PoC
            </TabsTrigger>
            <TabsTrigger value="results" className="data-[state=active]:bg-purple-500/20 data-[state=active]:text-purple-300">
              <Terminal className="w-4 h-4 mr-2" />
              Results
              {results.length > 0 && (
                <span className="ml-2 px-1.5 py-0.5 bg-purple-500/20 text-purple-300 rounded text-xs">
                  {results.length}
                </span>
              )}
            </TabsTrigger>
            <TabsTrigger value="stats" className="data-[state=active]:bg-purple-500/20 data-[state=active]:text-purple-300">
              <BarChart3 className="w-4 h-4 mr-2" />
              Stats
            </TabsTrigger>
          </TabsList>

          {/* ── Verify Tab ─────────────────────────────────────────────── */}
          <TabsContent value="verify" className="space-y-5 mt-0">
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardHeader>
                <CardTitle className="text-base text-gray-200 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-purple-400" />
                  PoC Script Editor
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-5">
                {/* Language Selector */}
                <div className="flex gap-1 flex-wrap">
                  {LANGUAGES.map((lang) => (
                    <button
                      key={lang.id}
                      onClick={() => setLanguage(lang.id)}
                      className={`px-3 py-1.5 rounded-md text-sm font-medium transition-all ${
                        language === lang.id
                          ? 'bg-purple-500/25 text-purple-300 border border-purple-500/40 shadow-sm'
                          : 'bg-gray-800/40 text-gray-500 border border-gray-700/30 hover:text-gray-300 hover:bg-gray-800/70'
                      }`}
                    >
                      {lang.label}
                    </button>
                  ))}
                </div>

                {/* Code Editor */}
                <div className="relative">
                  <div className="absolute top-3 right-3 z-10 flex items-center gap-1">
                    <Badge variant="outline" className="border-gray-700 text-gray-500 text-xs">
                      {currentLang.label}
                    </Badge>
                    {code && <CopyButton text={code} />}
                  </div>
                  <Textarea
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    placeholder={currentLang.placeholder}
                    rows={14}
                    className="font-mono text-sm bg-gray-950 border-gray-700/50 text-green-300 placeholder:text-gray-700 resize-y min-h-[14rem] focus:border-purple-500/50 focus:ring-purple-500/20"
                    spellCheck={false}
                  />
                </div>

                {/* Config Inputs */}
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <label className="text-xs text-gray-500 uppercase tracking-wider">CVE ID</label>
                    <Input
                      value={cveId}
                      onChange={(e) => setCveId(e.target.value)}
                      placeholder="CVE-2024-XXXXX"
                      className="bg-gray-900/60 border-gray-700/50 text-gray-200 font-mono placeholder:text-gray-700 focus:border-purple-500/50"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs text-gray-500 uppercase tracking-wider">Target URL</label>
                    <Input
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="https://target.example.com"
                      className="bg-gray-900/60 border-gray-700/50 text-gray-200 font-mono placeholder:text-gray-700 focus:border-purple-500/50"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs text-gray-500 uppercase tracking-wider">
                      Timeout (seconds)
                    </label>
                    <Input
                      type="number"
                      min={5}
                      max={300}
                      value={timeoutSeconds}
                      onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
                      className="bg-gray-900/60 border-gray-700/50 text-gray-200 focus:border-purple-500/50"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs text-gray-500 uppercase tracking-wider">
                      Network Access
                    </label>
                    <button
                      onClick={() => setRequiresNetwork((v) => !v)}
                      className={`flex items-center gap-2 px-4 py-2 rounded-md border transition-all text-sm w-full ${
                        requiresNetwork
                          ? 'bg-orange-500/15 border-orange-500/40 text-orange-300'
                          : 'bg-gray-800/40 border-gray-700/40 text-gray-500 hover:text-gray-300'
                      }`}
                    >
                      {requiresNetwork ? (
                        <Wifi className="w-4 h-4" />
                      ) : (
                        <WifiOff className="w-4 h-4" />
                      )}
                      {requiresNetwork ? 'Network Enabled (outbound allowed)' : 'Network Disabled (isolated)'}
                    </button>
                  </div>
                </div>

                {/* Verify Button */}
                <div className="flex items-center gap-4">
                  <Button
                    onClick={handleVerify}
                    disabled={verifyMutation.isPending || !code.trim() || !sandboxReady}
                    className="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white font-semibold px-6 disabled:opacity-50"
                  >
                    {verifyMutation.isPending ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Running in Sandbox…
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 mr-2" />
                        Verify PoC
                      </>
                    )}
                  </Button>

                  {!sandboxReady && !healthLoading && (
                    <p className="text-xs text-red-400 flex items-center gap-1">
                      <XCircle className="w-3.5 h-3.5" />
                      Sandbox unavailable — Docker may not be running
                    </p>
                  )}

                  {verifyMutation.isPending && (
                    <p className="text-xs text-gray-500 animate-pulse">
                      Executing in isolated container… ({timeoutSeconds}s timeout)
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Result Panel */}
            <AnimatePresence mode="wait">
              {latestResult && (
                <div key="result-panel">
                  <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                    <Hash className="w-4 h-4 text-purple-400" />
                    Verification Result
                  </h3>
                  <VerificationResultPanel result={latestResult} />
                </div>
              )}
            </AnimatePresence>
          </TabsContent>

          {/* ── Results Tab ────────────────────────────────────────────── */}
          <TabsContent value="results" className="mt-0">
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="text-base text-gray-200 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-purple-400" />
                  Recent Verifications
                </CardTitle>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => refetchResults()}
                  className="border-gray-700 text-gray-400 hover:text-gray-200"
                >
                  <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
                  Refresh
                </Button>
              </CardHeader>
              <CardContent>
                {resultsLoading ? (
                  <div className="flex items-center justify-center h-32 text-gray-600">
                    <Loader2 className="w-6 h-6 animate-spin mr-3" />
                    Loading results…
                  </div>
                ) : results.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-40 text-gray-600 gap-2">
                    <Terminal className="w-8 h-8" />
                    <p className="text-sm">No verifications yet. Run your first PoC above.</p>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-gray-800/60">
                          <th className="text-left py-2 px-4 text-xs text-gray-500 uppercase tracking-wider font-medium">
                            Verdict
                          </th>
                          <th className="text-left py-2 px-4 text-xs text-gray-500 uppercase tracking-wider font-medium">
                            Confidence
                          </th>
                          <th className="text-left py-2 px-4 text-xs text-gray-500 uppercase tracking-wider font-medium">
                            CVE
                          </th>
                          <th className="text-left py-2 px-4 text-xs text-gray-500 uppercase tracking-wider font-medium">
                            Language
                          </th>
                          <th className="text-left py-2 px-4 text-xs text-gray-500 uppercase tracking-wider font-medium">
                            Duration
                          </th>
                          <th className="text-left py-2 px-4 text-xs text-gray-500 uppercase tracking-wider font-medium">
                            Timestamp
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {results.map((item, i) => (
                          <ResultRow key={item.id ?? i} item={item} index={i} />
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ── Stats Tab ──────────────────────────────────────────────── */}
          <TabsContent value="stats" className="mt-0">
            {statsLoading ? (
              <div className="flex items-center justify-center h-48 text-gray-600">
                <Loader2 className="w-6 h-6 animate-spin mr-3" />
                Loading statistics…
              </div>
            ) : (
              <StatsTab stats={statsData} />
            )}
          </TabsContent>
        </Tabs>
      </motion.div>
    </div>
  );
}
