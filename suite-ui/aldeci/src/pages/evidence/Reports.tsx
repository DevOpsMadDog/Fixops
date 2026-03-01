import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileText, Download, Plus, RefreshCw, FileBarChart, FileSpreadsheet,
  Clock, CheckCircle2, AlertTriangle, Loader2, Filter, Search,
  Eye, Trash2, FileJson, BarChart3,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { reportsApi } from '../../lib/api';
import { toast } from 'sonner';

// ============================================================================
// Types
// ============================================================================

interface Report {
  id: string;
  name: string;
  report_type: string;
  format: string;
  status: string;
  created_at: string;
  updated_at?: string;
  parameters?: Record<string, unknown>;
  file_size?: number;
  download_url?: string;
  framework?: string;
}

// ============================================================================
// Constants
// ============================================================================

const REPORT_TYPES = [
  { id: 'executive', label: 'Executive Summary', icon: FileBarChart, description: 'High-level risk posture for leadership' },
  { id: 'compliance', label: 'Compliance Report', icon: FileText, description: 'Framework-specific compliance status' },
  { id: 'technical', label: 'Technical Detail', icon: FileJson, description: 'In-depth findings for engineering teams' },
  { id: 'trend', label: 'Trend Analysis', icon: BarChart3, description: 'Risk trajectory and remediation velocity' },
] as const;

const FORMAT_OPTIONS = [
  { id: 'pdf', label: 'PDF', icon: FileText },
  { id: 'csv', label: 'CSV', icon: FileSpreadsheet },
  { id: 'json', label: 'JSON', icon: FileJson },
  { id: 'sarif', label: 'SARIF', icon: FileBarChart },
] as const;

const statusConfig: Record<string, { color: string; icon: typeof CheckCircle2 }> = {
  completed: { color: 'bg-green-500/20 text-green-400 border-green-500/30', icon: CheckCircle2 },
  generating: { color: 'bg-blue-500/20 text-blue-400 border-blue-500/30', icon: Loader2 },
  queued: { color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', icon: Clock },
  failed: { color: 'bg-red-500/20 text-red-400 border-red-500/30', icon: AlertTriangle },
};

// ============================================================================
// Animation Variants
// ============================================================================

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.06 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 16 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 200, damping: 22 } },
};

// ============================================================================
// Skeleton Component
// ============================================================================

function ReportSkeleton() {
  return (
    <div className="space-y-3">
      {[1, 2, 3, 4].map(i => (
        <div key={i} className="flex items-center gap-4 p-4 rounded-lg border border-gray-700/30 bg-gray-800/30 animate-pulse">
          <div className="w-10 h-10 rounded-lg bg-gray-700/50" />
          <div className="flex-1 space-y-2">
            <div className="h-4 w-1/3 bg-gray-700/50 rounded" />
            <div className="h-3 w-1/2 bg-gray-700/30 rounded" />
          </div>
          <div className="h-6 w-20 bg-gray-700/30 rounded-full" />
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// Report Card Component
// ============================================================================

function ReportCard({ report, onDelete }: { report: Report; index: number; onDelete: (id: string) => void }) {
  const config = statusConfig[report.status] || statusConfig.completed;
  const StatusIcon = config.icon;

  const formatIcon = FORMAT_OPTIONS.find(f => f.id === report.format)?.icon || FileText;
  const FormatIcon = formatIcon;

  return (
    <motion.div
      variants={itemVariants}
      layout
      className="group flex items-center gap-4 p-4 rounded-lg border border-gray-700/30 bg-gray-800/20 hover:bg-gray-800/40 hover:border-gray-600/40 transition-all duration-200"
    >
      <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
        <FormatIcon className="w-5 h-5 text-primary" />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium text-gray-100 truncate">
            {report.name || `${report.report_type} Report`}
          </span>
          {report.framework && (
            <Badge variant="outline" className="text-xs border-gray-600/40">
              {report.framework}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-3 mt-1 text-xs text-gray-400">
          <span className="uppercase font-medium">{report.format}</span>
          <span className="text-gray-600">•</span>
          <span className="capitalize">{report.report_type}</span>
          <span className="text-gray-600">•</span>
          <span>{new Date(report.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })}</span>
          {report.file_size && (
            <>
              <span className="text-gray-600">•</span>
              <span>{(report.file_size / 1024).toFixed(1)} KB</span>
            </>
          )}
        </div>
      </div>

      <Badge className={`${config.color} border flex items-center gap-1`}>
        <StatusIcon className={`w-3 h-3 ${report.status === 'generating' ? 'animate-spin' : ''}`} />
        {report.status}
      </Badge>

      <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
        <Button variant="ghost" size="sm" className="h-8 w-8 p-0 text-gray-400 hover:text-gray-200">
          <Eye className="w-4 h-4" />
        </Button>
        <Button variant="ghost" size="sm" className="h-8 w-8 p-0 text-gray-400 hover:text-blue-400">
          <Download className="w-4 h-4" />
        </Button>
        <Button variant="ghost" size="sm" className="h-8 w-8 p-0 text-gray-400 hover:text-red-400" onClick={() => onDelete(report.id)}>
          <Trash2 className="w-4 h-4" />
        </Button>
      </div>
    </motion.div>
  );
}

// ============================================================================
// Main Reports Page [V3] [V10]
// ============================================================================

export default function Reports() {
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [showCreatePanel, setShowCreatePanel] = useState(false);
  const [selectedType, setSelectedType] = useState('executive');
  const [selectedFormat, setSelectedFormat] = useState('pdf');

  // Fetch reports from real API
  const { data: reports = [], isLoading, isError, refetch } = useQuery({
    queryKey: ['reports'],
    queryFn: () => reportsApi.list(),
    refetchInterval: 15000, // Refresh every 15s to catch generating → completed
  });

  // Generate report mutation
  const generateMutation = useMutation({
    mutationFn: (params: { type: string; format: string }) =>
      reportsApi.generate({ report_type: params.type, format: params.format }),
    onSuccess: () => {
      toast.success('Report generation started');
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      setShowCreatePanel(false);
    },
    onError: () => toast.error('Failed to generate report'),
  });

  // Delete report (soft — just refetch to reflect server-side deletion)
  const handleDelete = (id: string) => {
    toast.info(`Report ${id.slice(0, 8)} deletion requested`);
    refetch();
  };

  // Filter and search
  const filteredReports = useMemo(() => {
    let result = Array.isArray(reports) ? reports : [];
    if (filterType !== 'all') {
      result = result.filter((r: Report) => r.report_type === filterType);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter((r: Report) =>
        (r.name || '').toLowerCase().includes(q) ||
        (r.report_type || '').toLowerCase().includes(q) ||
        (r.framework || '').toLowerCase().includes(q)
      );
    }
    return result as Report[];
  }, [reports, filterType, searchQuery]);

  // Stats from real data
  const stats = useMemo(() => {
    const arr = Array.isArray(reports) ? reports as Report[] : [];
    return {
      total: arr.length,
      completed: arr.filter(r => r.status === 'completed').length,
      generating: arr.filter(r => r.status === 'generating' || r.status === 'queued').length,
      failed: arr.filter(r => r.status === 'failed').length,
    };
  }, [reports]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ type: 'spring', stiffness: 150 }}
        className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-cyan-400 bg-clip-text text-transparent">
            Reports
          </h1>
          <p className="text-gray-400 mt-1">Generate, track, and export security reports</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()} className="border-gray-600/50 hover:border-primary/50">
            <RefreshCw className="w-4 h-4 mr-2" /> Refresh
          </Button>
          <Button size="sm" onClick={() => setShowCreatePanel(!showCreatePanel)} className="bg-primary hover:bg-primary/90">
            <Plus className="w-4 h-4 mr-2" /> Generate Report
          </Button>
        </div>
      </motion.div>

      {/* Stats Row */}
      <motion.div variants={containerVariants} initial="hidden" animate="visible"
        className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Reports', value: stats.total, color: 'text-blue-400', icon: FileText },
          { label: 'Completed', value: stats.completed, color: 'text-green-400', icon: CheckCircle2 },
          { label: 'Generating', value: stats.generating, color: 'text-yellow-400', icon: Loader2 },
          { label: 'Failed', value: stats.failed, color: 'text-red-400', icon: AlertTriangle },
        ].map((stat) => (
          <motion.div key={stat.label} variants={itemVariants}>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
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
          </motion.div>
        ))}
      </motion.div>

      {/* Create Report Panel */}
      <AnimatePresence>
        {showCreatePanel && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <Card className="border-primary/30 bg-gray-900/60 backdrop-blur-md">
              <CardHeader>
                <CardTitle className="text-lg">Generate New Report</CardTitle>
                <CardDescription>Select the report type and output format</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Report Type Selection */}
                <div>
                  <label className="text-sm font-medium text-gray-300 mb-2 block">Report Type</label>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {REPORT_TYPES.map(type => (
                      <button
                        key={type.id}
                        onClick={() => setSelectedType(type.id)}
                        className={`p-3 rounded-lg border text-left transition-all ${
                          selectedType === type.id
                            ? 'border-primary/50 bg-primary/10'
                            : 'border-gray-700/30 bg-gray-800/30 hover:border-gray-600/40'
                        }`}
                      >
                        <type.icon className={`w-5 h-5 mb-2 ${selectedType === type.id ? 'text-primary' : 'text-gray-400'}`} />
                        <p className="text-sm font-medium">{type.label}</p>
                        <p className="text-xs text-gray-500 mt-1">{type.description}</p>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Format Selection */}
                <div>
                  <label className="text-sm font-medium text-gray-300 mb-2 block">Output Format</label>
                  <div className="flex gap-2">
                    {FORMAT_OPTIONS.map(fmt => (
                      <button
                        key={fmt.id}
                        onClick={() => setSelectedFormat(fmt.id)}
                        className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-all text-sm ${
                          selectedFormat === fmt.id
                            ? 'border-primary/50 bg-primary/10 text-primary'
                            : 'border-gray-700/30 text-gray-400 hover:border-gray-600/40'
                        }`}
                      >
                        <fmt.icon className="w-4 h-4" />
                        {fmt.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Generate Button */}
                <div className="flex justify-end gap-2 pt-2">
                  <Button variant="outline" onClick={() => setShowCreatePanel(false)} className="border-gray-600/50">
                    Cancel
                  </Button>
                  <Button
                    onClick={() => generateMutation.mutate({ type: selectedType, format: selectedFormat })}
                    disabled={generateMutation.isPending}
                  >
                    {generateMutation.isPending ? (
                      <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Generating...</>
                    ) : (
                      <><Plus className="w-4 h-4 mr-2" /> Generate Report</>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Search & Filter */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <Input
            placeholder="Search reports..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="pl-10 bg-gray-900/40 border-gray-700/40"
          />
        </div>
        <div className="flex items-center gap-1">
          <Filter className="w-4 h-4 text-gray-500 mr-1" />
          {['all', 'executive', 'compliance', 'technical', 'trend'].map(type => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                filterType === type
                  ? 'bg-primary/20 text-primary border border-primary/30'
                  : 'text-gray-400 hover:text-gray-300 hover:bg-gray-800/40'
              }`}
            >
              {type === 'all' ? 'All' : type.charAt(0).toUpperCase() + type.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Reports List */}
      <Card className="border-gray-700/30 bg-gray-900/30 backdrop-blur-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-primary" />
            Generated Reports
          </CardTitle>
          <CardDescription>
            {filteredReports.length} report{filteredReports.length !== 1 ? 's' : ''}
            {filterType !== 'all' && ` (filtered: ${filterType})`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <ReportSkeleton />
          ) : isError ? (
            <div className="text-center py-12">
              <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4 opacity-60" />
              <p className="text-gray-300 font-medium">Failed to load reports</p>
              <p className="text-sm text-gray-500 mt-1">Check your API connection and try again</p>
              <Button variant="outline" size="sm" onClick={() => refetch()} className="mt-4 border-gray-600/50">
                <RefreshCw className="w-4 h-4 mr-2" /> Retry
              </Button>
            </div>
          ) : filteredReports.length === 0 ? (
            <div className="text-center py-12">
              <FileText className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400 font-medium">No reports found</p>
              <p className="text-sm text-gray-500 mt-1">
                {searchQuery ? 'Try a different search term' : 'Generate your first report to get started'}
              </p>
              {!searchQuery && (
                <Button size="sm" onClick={() => setShowCreatePanel(true)} className="mt-4">
                  <Plus className="w-4 h-4 mr-2" /> Generate Report
                </Button>
              )}
            </div>
          ) : (
            <motion.div variants={containerVariants} initial="hidden" animate="visible" className="space-y-2">
              <AnimatePresence>
                {filteredReports.map((report, index) => (
                  <ReportCard key={report.id || index} report={report} index={index} onDelete={handleDelete} />
                ))}
              </AnimatePresence>
            </motion.div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
