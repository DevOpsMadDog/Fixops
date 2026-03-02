import { useState, useCallback, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Upload, FileText, CheckCircle2, AlertCircle, Loader2, RefreshCw,
  Shield, Code, Globe, Box, Cloud, Database, Activity, Cpu,
  BarChart3, Zap, ChevronRight, X, ArrowRight, Layers,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { scannerIngestApi } from '../../lib/api';
import { toast } from 'sonner';

// ============================================================================
// Types
// ============================================================================

interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface UploadResult {
  scanner_type: string;
  confidence: number;
  findings_count: number;
  severity_breakdown: SeverityBreakdown;
  pipeline_job_id?: string;
  file_name: string;
  file_size: number;
  ingested_at: string;
}

interface SupportedScanner {
  id: string;
  name: string;
  category: 'SAST' | 'DAST' | 'SCA' | 'Infra' | 'Cloud';
  formats: string[];
  description?: string;
}

interface IngestStats {
  total_uploads: number;
  total_findings_parsed: number;
  scanners_supported: number;
  recent_uploads: RecentUpload[];
}

interface RecentUpload {
  id: string;
  file_name: string;
  scanner_type: string;
  findings_count: number;
  uploaded_at: string;
  status: 'processed' | 'pending' | 'failed';
}

// ============================================================================
// Constants
// ============================================================================

const APPLE_EASE = [0.16, 1, 0.3, 1] as const;

const CATEGORY_META: Record<
  SupportedScanner['category'],
  { icon: typeof Shield; color: string; gradient: string }
> = {
  SAST: { icon: Code, color: 'text-blue-400', gradient: 'from-blue-500 to-cyan-500' },
  DAST: { icon: Globe, color: 'text-purple-400', gradient: 'from-purple-500 to-pink-500' },
  SCA: { icon: Box, color: 'text-teal-400', gradient: 'from-teal-500 to-emerald-500' },
  Infra: { icon: Layers, color: 'text-orange-400', gradient: 'from-orange-500 to-red-500' },
  Cloud: { icon: Cloud, color: 'text-sky-400', gradient: 'from-sky-500 to-blue-500' },
};

const SEVERITY_CONFIG = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20', bar: 'bg-red-500', label: 'Critical' },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20', bar: 'bg-orange-500', label: 'High' },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20', bar: 'bg-yellow-500', label: 'Medium' },
  low: { color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20', bar: 'bg-blue-500', label: 'Low' },
  info: { color: 'text-gray-400', bg: 'bg-gray-500/10 border-gray-500/20', bar: 'bg-gray-500', label: 'Info' },
} as const;

// ============================================================================
// Animation Variants
// ============================================================================

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.07 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 18, scale: 0.96 },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: { ease: APPLE_EASE, duration: 0.55 },
  },
};

const fadeSlide = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { ease: APPLE_EASE, duration: 0.45 } },
  exit: { opacity: 0, y: -8, transition: { duration: 0.25 } },
};

// ============================================================================
// Helper — format bytes
// ============================================================================

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ============================================================================
// Skeleton loader
// ============================================================================

function SkeletonCard() {
  return (
    <div className="rounded-xl border border-gray-700/30 bg-gray-900/40 p-4 animate-pulse">
      <div className="h-3 bg-gray-700/50 rounded w-1/3 mb-3" />
      <div className="h-5 bg-gray-700/40 rounded w-2/3 mb-2" />
      <div className="h-3 bg-gray-700/30 rounded w-1/2" />
    </div>
  );
}

// ============================================================================
// Stat Card
// ============================================================================

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: string | number;
  icon: typeof Shield;
  color: string;
}) {
  return (
    <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
      <CardContent className="p-4 flex items-center justify-between">
        <div>
          <p className={`text-2xl font-bold ${color}`}>{value}</p>
          <p className="text-xs text-gray-400 mt-0.5">{label}</p>
        </div>
        <Icon className={`w-5 h-5 ${color} opacity-50`} />
      </CardContent>
    </Card>
  );
}

// ============================================================================
// Detection Result Panel
// ============================================================================

function DetectionPanel({ result }: { result: UploadResult }) {
  const total = result.findings_count || 1;
  const sev = result.severity_breakdown;
  const sevKeys = ['critical', 'high', 'medium', 'low', 'info'] as const;

  return (
    <motion.div variants={fadeSlide} initial="hidden" animate="visible" exit="exit">
      <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md overflow-hidden">
        {/* Gradient top bar */}
        <div className="h-0.5 bg-gradient-to-r from-blue-400 via-purple-400 to-cyan-400" />

        <CardContent className="p-5 space-y-5">
          {/* Scanner + confidence */}
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-widest mb-1">Detected Scanner</p>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0" />
                <span className="text-lg font-semibold text-gray-100">{result.scanner_type}</span>
              </div>
            </div>
            <div className="text-right">
              <p className="text-xs text-gray-500 uppercase tracking-widest mb-1">Confidence</p>
              <div className="flex items-center gap-2">
                <Progress
                  value={Math.round(result.confidence * 100)}
                  className="w-24 h-2 bg-gray-700/50"
                />
                <span className="text-sm font-bold text-green-400">
                  {Math.round(result.confidence * 100)}%
                </span>
              </div>
            </div>
          </div>

          {/* Findings summary */}
          <div className="flex items-center gap-3 p-3 rounded-lg border border-gray-700/30 bg-gray-800/30">
            <BarChart3 className="w-5 h-5 text-primary opacity-70 flex-shrink-0" />
            <div>
              <p className="text-2xl font-bold text-gray-100">{result.findings_count.toLocaleString()}</p>
              <p className="text-xs text-gray-400">Findings parsed from {result.file_name}</p>
            </div>
          </div>

          {/* Severity breakdown */}
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-widest mb-3">Severity Breakdown</p>
            <div className="space-y-2">
              {sevKeys.map(key => {
                const count = sev?.[key] ?? 0;
                const pct = total > 0 ? (count / total) * 100 : 0;
                const cfg = SEVERITY_CONFIG[key];
                return (
                  <div key={key} className="flex items-center gap-3">
                    <span className={`text-xs font-medium w-14 flex-shrink-0 ${cfg.color}`}>
                      {cfg.label}
                    </span>
                    <div className="flex-1 h-1.5 rounded-full bg-gray-700/50 overflow-hidden">
                      <motion.div
                        className={`h-full rounded-full ${cfg.bar}`}
                        initial={{ width: 0 }}
                        animate={{ width: `${pct}%` }}
                        transition={{ ease: APPLE_EASE, duration: 0.7, delay: 0.1 }}
                      />
                    </div>
                    <span className={`text-xs font-bold w-8 text-right ${cfg.color}`}>{count}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {result.pipeline_job_id && (
            <div className="flex items-center gap-2 p-2 rounded-lg border border-green-500/20 bg-green-500/5">
              <Cpu className="w-4 h-4 text-green-400 flex-shrink-0" />
              <span className="text-xs text-green-400">
                Pipeline job <code className="font-mono">{result.pipeline_job_id}</code> queued
              </span>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ============================================================================
// Supported Scanner Card
// ============================================================================

function ScannerChip({ scanner }: { scanner: SupportedScanner }) {
  const meta = CATEGORY_META[scanner.category];
  const Icon = meta.icon;

  return (
    <motion.div variants={itemVariants} whileHover={{ scale: 1.03, y: -2 }} transition={{ type: 'spring', stiffness: 320 }}>
      <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md hover:border-gray-600/50 transition-all duration-200 overflow-hidden h-full">
        <div className={`h-0.5 bg-gradient-to-r ${meta.gradient}`} />
        <CardContent className="p-3">
          <div className="flex items-start gap-2">
            <div className={`w-7 h-7 rounded-md bg-gradient-to-br ${meta.gradient} bg-opacity-20 flex items-center justify-center flex-shrink-0 mt-0.5`}>
              <Icon className="w-3.5 h-3.5 text-white" />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-semibold text-gray-200 truncate">{scanner.name}</p>
              <p className={`text-[10px] font-medium uppercase tracking-wide ${meta.color}`}>{scanner.category}</p>
              {scanner.formats && scanner.formats.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {scanner.formats.slice(0, 3).map(fmt => (
                    <span key={fmt} className="text-[10px] text-gray-500 bg-gray-800/60 border border-gray-700/40 rounded px-1.5 py-0.5 font-mono">
                      {fmt}
                    </span>
                  ))}
                  {scanner.formats.length > 3 && (
                    <span className="text-[10px] text-gray-600">+{scanner.formats.length - 3}</span>
                  )}
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ============================================================================
// Recent Upload Row
// ============================================================================

function RecentUploadRow({ upload }: { upload: RecentUpload }) {
  const statusConfig = {
    processed: { color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/20', label: 'Processed' },
    pending: { color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20', label: 'Pending' },
    failed: { color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20', label: 'Failed' },
  }[upload.status];

  const relativeTime = (() => {
    const diff = Date.now() - new Date(upload.uploaded_at).getTime();
    const mins = Math.floor(diff / 60_000);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  })();

  return (
    <div className="flex items-center gap-4 p-3 rounded-lg border border-gray-700/20 bg-gray-800/20 hover:bg-gray-800/40 transition-colors">
      <FileText className="w-4 h-4 text-gray-500 flex-shrink-0" />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-gray-200 truncate">{upload.file_name}</p>
        <p className="text-xs text-gray-500">{upload.scanner_type} · {relativeTime}</p>
      </div>
      <div className="flex items-center gap-3 flex-shrink-0">
        <span className="text-sm font-bold text-gray-300">{upload.findings_count}</span>
        <Badge className={`border text-[10px] px-2 ${statusConfig.bg} ${statusConfig.color}`}>
          {statusConfig.label}
        </Badge>
      </div>
    </div>
  );
}

// ============================================================================
// Upload Drop Zone
// ============================================================================

function DropZone({
  onFile,
  file,
  onClear,
}: {
  onFile: (f: File) => void;
  file: File | null;
  onClear: () => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const dropped = e.dataTransfer.files[0];
      if (dropped) onFile(dropped);
    },
    [onFile]
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selected = e.target.files?.[0];
      if (selected) onFile(selected);
    },
    [onFile]
  );

  if (file) {
    return (
      <motion.div
        variants={fadeSlide}
        initial="hidden"
        animate="visible"
        className="flex items-center gap-4 p-4 rounded-xl border border-blue-500/30 bg-blue-500/5"
      >
        <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center flex-shrink-0">
          <FileText className="w-5 h-5 text-blue-400" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-gray-200 truncate">{file.name}</p>
          <p className="text-xs text-gray-400">{formatBytes(file.size)} · ready to upload</p>
        </div>
        <button
          onClick={onClear}
          className="w-7 h-7 rounded-full bg-gray-700/50 hover:bg-gray-700 flex items-center justify-center transition-colors"
          aria-label="Clear file"
        >
          <X className="w-3.5 h-3.5 text-gray-400" />
        </button>
      </motion.div>
    );
  }

  return (
    <motion.div
      onDragOver={e => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
      animate={dragging ? { scale: 1.01 } : { scale: 1 }}
      transition={{ type: 'spring', stiffness: 300 }}
      className={`relative flex flex-col items-center justify-center gap-4 p-10 rounded-xl border-2 border-dashed cursor-pointer transition-all duration-200
        ${dragging
          ? 'border-blue-500/60 bg-blue-500/5'
          : 'border-gray-600/40 bg-gray-900/30 hover:border-gray-500/60 hover:bg-gray-800/30'
        }`}
    >
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        accept=".xml,.json,.csv,.sarif,.html,.txt"
        onChange={handleChange}
      />

      <motion.div
        animate={dragging ? { y: -4, scale: 1.1 } : { y: 0, scale: 1 }}
        transition={{ type: 'spring', stiffness: 250 }}
        className="w-14 h-14 rounded-2xl bg-gray-800/60 border border-gray-700/40 flex items-center justify-center"
      >
        <Upload className={`w-7 h-7 ${dragging ? 'text-blue-400' : 'text-gray-500'} transition-colors`} />
      </motion.div>

      <div className="text-center">
        <p className={`text-sm font-medium ${dragging ? 'text-blue-300' : 'text-gray-300'} transition-colors`}>
          {dragging ? 'Drop your scanner report here' : 'Drag & drop scanner report'}
        </p>
        <p className="text-xs text-gray-500 mt-1">
          or <span className="text-blue-400 underline underline-offset-2">browse files</span> · XML, JSON, SARIF, CSV, HTML
        </p>
      </div>

      {dragging && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="absolute inset-0 rounded-xl border-2 border-blue-500/40 pointer-events-none"
        />
      )}
    </motion.div>
  );
}

// ============================================================================
// Main Page Component
// ============================================================================

export default function ScannerIngestUpload() {
  // Upload zone state
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [pushingPipeline, setPushingPipeline] = useState(false);
  const [uploadResult, setUploadResult] = useState<UploadResult | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // Supported scanners state
  const [supportedScanners, setSupportedScanners] = useState<SupportedScanner[]>([]);
  const [scannersLoading, setScannersLoading] = useState(true);
  const [scannersError, setScannersError] = useState<string | null>(null);

  // Stats state
  const [stats, setStats] = useState<IngestStats | null>(null);
  const [statsLoading, setStatsLoading] = useState(true);

  // Active tab
  const [activeTab, setActiveTab] = useState<'upload' | 'supported'>('upload');

  // ── Fetch stats ─────────────────────────────────────────────────────────────

  const fetchStats = useCallback(async () => {
    setStatsLoading(true);
    try {
      const data = await scannerIngestApi.stats() as IngestStats;
      setStats(data);
    } catch {
      // Stats are best-effort; don't block UI
    } finally {
      setStatsLoading(false);
    }
  }, []);

  // ── Fetch supported scanners ─────────────────────────────────────────────────

  const fetchSupported = useCallback(async () => {
    setScannersLoading(true);
    setScannersError(null);
    try {
      const data = await scannerIngestApi.supported() as SupportedScanner[] | { scanners: SupportedScanner[] };
      const list = Array.isArray(data) ? data : (data as { scanners: SupportedScanner[] }).scanners ?? [];
      setSupportedScanners(list);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to load supported scanners';
      setScannersError(msg);
    } finally {
      setScannersLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    fetchSupported();
  }, [fetchStats, fetchSupported]);

  // ── Handle file selection ────────────────────────────────────────────────────

  const handleFile = useCallback((f: File) => {
    setFile(f);
    setUploadResult(null);
    setUploadError(null);
  }, []);

  const handleClear = useCallback(() => {
    setFile(null);
    setUploadResult(null);
    setUploadError(null);
  }, []);

  // ── Upload ───────────────────────────────────────────────────────────────────

  const handleUpload = useCallback(async () => {
    if (!file) return;
    setUploading(true);
    setUploadResult(null);
    setUploadError(null);

    try {
      const data = await scannerIngestApi.upload(file) as UploadResult;
      setUploadResult({
        ...data,
        file_name: file.name,
        file_size: file.size,
      });
      toast.success(`Upload complete — ${data.findings_count ?? 0} findings parsed from ${data.scanner_type ?? 'unknown scanner'}`);
      // Refresh stats after upload
      fetchStats();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Upload failed';
      setUploadError(msg);
      toast.error(`Upload failed: ${msg}`);
    } finally {
      setUploading(false);
    }
  }, [file, fetchStats]);

  // ── Push to pipeline ─────────────────────────────────────────────────────────

  const handlePushToPipeline = useCallback(async () => {
    if (!uploadResult) return;
    setPushingPipeline(true);

    try {
      // Detect & enrich through the brain pipeline
      await scannerIngestApi.detect({
        scanner_type: uploadResult.scanner_type,
        findings_count: uploadResult.findings_count,
        severity_breakdown: uploadResult.severity_breakdown,
        pipeline_job_id: uploadResult.pipeline_job_id,
      });
      toast.success('Findings pushed to brain pipeline — triage in progress');
      setUploadResult(prev =>
        prev ? { ...prev, pipeline_job_id: prev.pipeline_job_id ?? `job-${Date.now()}` } : prev
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Pipeline push failed';
      toast.error(`Pipeline push failed: ${msg}`);
    } finally {
      setPushingPipeline(false);
    }
  }, [uploadResult]);

  // ── Group scanners by category ───────────────────────────────────────────────

  const groupedScanners = supportedScanners.reduce<Record<string, SupportedScanner[]>>(
    (acc, scanner) => {
      const cat = scanner.category ?? 'Other';
      if (!acc[cat]) acc[cat] = [];
      acc[cat].push(scanner);
      return acc;
    },
    {}
  );

  const categoryOrder: Array<SupportedScanner['category']> = ['SAST', 'DAST', 'SCA', 'Infra', 'Cloud'];

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* ── Header ─────────────────────────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: -18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ ease: APPLE_EASE, duration: 0.55 }}
        className="flex items-start justify-between gap-4 flex-wrap"
      >
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-cyan-400 bg-clip-text text-transparent">
            Scanner Ingest
          </h1>
          <p className="text-gray-400 mt-1 text-sm">
            Upload 3rd-party scanner reports and push findings through the CTEM+ brain pipeline
          </p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <Badge className="bg-purple-500/15 text-purple-300 border-purple-500/30 border px-3 py-1">
            <Database className="w-3.5 h-3.5 mr-1.5" />
            25 Normalizers
          </Badge>
          <Button
            variant="outline"
            size="sm"
            onClick={() => { fetchStats(); fetchSupported(); }}
            className="border-gray-600/50 hover:border-primary/50"
          >
            <RefreshCw className="w-4 h-4 mr-1.5" /> Refresh
          </Button>
        </div>
      </motion.div>

      {/* ── Stats Row ──────────────────────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ ease: APPLE_EASE, duration: 0.5, delay: 0.1 }}
        className="grid grid-cols-2 md:grid-cols-3 gap-4"
      >
        {statsLoading ? (
          Array.from({ length: 3 }).map((_, i) => <SkeletonCard key={i} />)
        ) : (
          <>
            <StatCard
              label="Total Uploads"
              value={stats?.total_uploads?.toLocaleString() ?? '—'}
              icon={Upload}
              color="text-blue-400"
            />
            <StatCard
              label="Findings Parsed"
              value={stats?.total_findings_parsed?.toLocaleString() ?? '—'}
              icon={Activity}
              color="text-orange-400"
            />
            <StatCard
              label="Scanners Supported"
              value={stats?.scanners_supported ?? (supportedScanners.length || '—')}
              icon={Shield}
              color="text-green-400"
            />
          </>
        )}
      </motion.div>

      {/* ── Tabs ───────────────────────────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ ease: APPLE_EASE, duration: 0.5, delay: 0.18 }}
      >
        <Tabs value={activeTab} onValueChange={v => setActiveTab(v as 'upload' | 'supported')}>
          <TabsList className="bg-gray-900/60 border border-gray-700/40 mb-5">
            <TabsTrigger value="upload" className="data-[state=active]:bg-gray-800">
              <Upload className="w-4 h-4 mr-2" /> Upload Zone
            </TabsTrigger>
            <TabsTrigger value="supported" className="data-[state=active]:bg-gray-800">
              <Shield className="w-4 h-4 mr-2" /> Supported Scanners
              {supportedScanners.length > 0 && (
                <Badge className="ml-2 bg-gray-700/60 text-gray-300 border-gray-600/40 border text-[10px] px-1.5">
                  {supportedScanners.length}
                </Badge>
              )}
            </TabsTrigger>
          </TabsList>

          {/* ── Upload Zone tab ─────────────────────────────────────────────────── */}
          <TabsContent value="upload" className="space-y-5 mt-0">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              {/* Left — Drop Zone + Actions */}
              <div className="space-y-4">
                <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Upload className="w-4 h-4 text-primary" />
                      Upload Scanner Report
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <DropZone file={file} onFile={handleFile} onClear={handleClear} />

                    {/* Error state */}
                    <AnimatePresence>
                      {uploadError && (
                        <motion.div
                          variants={fadeSlide}
                          initial="hidden"
                          animate="visible"
                          exit="exit"
                          className="flex items-start gap-3 p-3 rounded-lg border border-red-500/30 bg-red-500/5"
                        >
                          <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                          <div className="flex-1">
                            <p className="text-sm text-red-300 font-medium">Upload failed</p>
                            <p className="text-xs text-red-400/70 mt-0.5">{uploadError}</p>
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={handleUpload}
                            className="h-7 px-2 text-red-400 hover:text-red-300 hover:bg-red-500/10"
                          >
                            <RefreshCw className="w-3.5 h-3.5 mr-1" /> Retry
                          </Button>
                        </motion.div>
                      )}
                    </AnimatePresence>

                    {/* Upload action */}
                    <div className="flex gap-3">
                      <Button
                        className="flex-1 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white border-0"
                        disabled={!file || uploading}
                        onClick={handleUpload}
                      >
                        {uploading ? (
                          <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Uploading…</>
                        ) : (
                          <><Upload className="w-4 h-4 mr-2" /> Upload Report</>
                        )}
                      </Button>

                      <Button
                        variant="outline"
                        className={`flex-1 border-gray-700/50 transition-all ${
                          uploadResult && !pushingPipeline
                            ? 'hover:border-green-500/50 hover:bg-green-500/5 text-green-300'
                            : 'text-gray-400 cursor-not-allowed'
                        }`}
                        disabled={!uploadResult || pushingPipeline}
                        onClick={handlePushToPipeline}
                      >
                        {pushingPipeline ? (
                          <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Pushing…</>
                        ) : (
                          <><Zap className="w-4 h-4 mr-2" /> Push to Pipeline</>
                        )}
                      </Button>
                    </div>

                    {/* Pipeline push state hint */}
                    <AnimatePresence>
                      {!uploadResult && !uploading && (
                        <motion.p
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          exit={{ opacity: 0 }}
                          className="text-[11px] text-gray-600 text-center"
                        >
                          Upload a report first to enable pipeline push
                        </motion.p>
                      )}
                    </AnimatePresence>
                  </CardContent>
                </Card>
              </div>

              {/* Right — Detection Result */}
              <div>
                <AnimatePresence mode="wait">
                  {uploading && (
                    <motion.div
                      key="uploading"
                      variants={fadeSlide}
                      initial="hidden"
                      animate="visible"
                      exit="exit"
                    >
                      <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md h-full">
                        <CardContent className="flex flex-col items-center justify-center gap-4 py-16">
                          <div className="relative">
                            <Loader2 className="w-10 h-10 text-blue-400 animate-spin" />
                            <div className="absolute inset-0 blur-lg bg-blue-500/20 rounded-full" />
                          </div>
                          <div className="text-center">
                            <p className="text-sm font-medium text-gray-300">Processing report…</p>
                            <p className="text-xs text-gray-500 mt-1">Auto-detecting scanner format</p>
                          </div>
                        </CardContent>
                      </Card>
                    </motion.div>
                  )}

                  {!uploading && uploadResult && (
                    <motion.div key="result" variants={fadeSlide} initial="hidden" animate="visible" exit="exit">
                      <DetectionPanel result={uploadResult} />
                    </motion.div>
                  )}

                  {!uploading && !uploadResult && !uploadError && (
                    <motion.div
                      key="empty"
                      variants={fadeSlide}
                      initial="hidden"
                      animate="visible"
                      exit="exit"
                    >
                      <Card className="border-gray-700/20 bg-gray-900/20 backdrop-blur-md h-full">
                        <CardContent className="flex flex-col items-center justify-center gap-4 py-16">
                          <div className="w-16 h-16 rounded-2xl bg-gray-800/60 border border-gray-700/30 flex items-center justify-center">
                            <FileText className="w-8 h-8 text-gray-600" />
                          </div>
                          <div className="text-center">
                            <p className="text-sm font-medium text-gray-400">No report uploaded yet</p>
                            <p className="text-xs text-gray-600 mt-1">
                              Upload a scanner report to see auto-detection results
                            </p>
                          </div>
                          <div className="flex items-center gap-1 text-xs text-gray-600">
                            <ChevronRight className="w-3.5 h-3.5" />
                            <span>Supports ZAP, Burp, Nessus, SARIF, and 22 more formats</span>
                          </div>
                        </CardContent>
                      </Card>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>

            {/* Recent Uploads */}
            {stats?.recent_uploads && stats.recent_uploads.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ ease: APPLE_EASE, duration: 0.45, delay: 0.15 }}
              >
                <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Activity className="w-4 h-4 text-primary" />
                      Recent Uploads
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {stats.recent_uploads.map(upload => (
                      <RecentUploadRow key={upload.id} upload={upload} />
                    ))}
                  </CardContent>
                </Card>
              </motion.div>
            )}
          </TabsContent>

          {/* ── Supported Scanners tab ───────────────────────────────────────────── */}
          <TabsContent value="supported" className="mt-0">
            {scannersLoading ? (
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                {Array.from({ length: 12 }).map((_, i) => <SkeletonCard key={i} />)}
              </div>
            ) : scannersError ? (
              <motion.div
                variants={fadeSlide}
                initial="hidden"
                animate="visible"
                className="flex flex-col items-center justify-center gap-4 py-20"
              >
                <AlertCircle className="w-10 h-10 text-red-400" />
                <div className="text-center">
                  <p className="text-sm font-medium text-red-300">Failed to load scanners</p>
                  <p className="text-xs text-gray-500 mt-1">{scannersError}</p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={fetchSupported}
                  className="border-gray-600/50 hover:border-red-500/50"
                >
                  <RefreshCw className="w-4 h-4 mr-2" /> Retry
                </Button>
              </motion.div>
            ) : supportedScanners.length === 0 ? (
              <motion.div
                variants={fadeSlide}
                initial="hidden"
                animate="visible"
                className="flex flex-col items-center justify-center gap-4 py-20"
              >
                <Shield className="w-10 h-10 text-gray-600" />
                <p className="text-sm text-gray-400">No scanner data available</p>
              </motion.div>
            ) : (
              <div className="space-y-6">
                {categoryOrder
                  .filter(cat => groupedScanners[cat]?.length)
                  .map(category => {
                    const meta = CATEGORY_META[category];
                    const CategoryIcon = meta.icon;
                    const scanners = groupedScanners[category];
                    return (
                      <motion.section
                        key={category}
                        initial={{ opacity: 0, y: 12 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ ease: APPLE_EASE, duration: 0.45 }}
                      >
                        {/* Category heading */}
                        <div className="flex items-center gap-2 mb-3">
                          <div className={`w-6 h-6 rounded-md bg-gradient-to-br ${meta.gradient} flex items-center justify-center`}>
                            <CategoryIcon className="w-3.5 h-3.5 text-white" />
                          </div>
                          <h3 className={`text-sm font-semibold ${meta.color}`}>{category}</h3>
                          <Badge className="bg-gray-800/60 text-gray-400 border-gray-700/40 border text-[10px] px-1.5">
                            {scanners.length}
                          </Badge>
                          <div className="flex-1 h-px bg-gray-700/30" />
                        </div>

                        <motion.div
                          variants={containerVariants}
                          initial="hidden"
                          animate="visible"
                          className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3"
                        >
                          {scanners.map(scanner => (
                            <ScannerChip key={scanner.id ?? scanner.name} scanner={scanner} />
                          ))}
                        </motion.div>
                      </motion.section>
                    );
                  })}

                {/* Remaining categories not in our order */}
                {Object.entries(groupedScanners)
                  .filter(([cat]) => !categoryOrder.includes(cat as SupportedScanner['category']))
                  .map(([cat, scanners]) => (
                    <motion.section
                      key={cat}
                      initial={{ opacity: 0, y: 12 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ ease: APPLE_EASE, duration: 0.45 }}
                    >
                      <div className="flex items-center gap-2 mb-3">
                        <Database className="w-4 h-4 text-gray-400" />
                        <h3 className="text-sm font-semibold text-gray-400">{cat}</h3>
                        <Badge className="bg-gray-800/60 text-gray-400 border-gray-700/40 border text-[10px] px-1.5">
                          {scanners.length}
                        </Badge>
                        <div className="flex-1 h-px bg-gray-700/30" />
                      </div>
                      <motion.div
                        variants={containerVariants}
                        initial="hidden"
                        animate="visible"
                        className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3"
                      >
                        {scanners.map(scanner => (
                          <ScannerChip key={scanner.id ?? scanner.name} scanner={scanner} />
                        ))}
                      </motion.div>
                    </motion.section>
                  ))}

                {/* Footer CTA */}
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.4 }}
                  className="flex items-center justify-between p-4 rounded-xl border border-gray-700/20 bg-gray-900/20"
                >
                  <div className="flex items-center gap-3">
                    <ArrowRight className="w-4 h-4 text-primary" />
                    <p className="text-sm text-gray-400">
                      Have a scanner format not listed? Switch to{' '}
                      <button
                        onClick={() => setActiveTab('upload')}
                        className="text-blue-400 underline underline-offset-2 hover:text-blue-300 transition-colors"
                      >
                        Upload Zone
                      </button>{' '}
                      — auto-detection will attempt to parse it.
                    </p>
                  </div>
                </motion.div>
              </div>
            )}
          </TabsContent>
        </Tabs>
      </motion.div>
    </div>
  );
}
