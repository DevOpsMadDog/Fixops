import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Code,
  Search,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  GitBranch,
  FileCode,
  Bug,
  ShieldAlert,
  ArrowUpRight,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { ingestApi, inventoryApi, dedupApi } from '../../lib/api';
import { toast } from 'sonner';

export default function CodeScanning() {
  const [scanUrl, setScanUrl] = useState('');
  const queryClient = useQueryClient();

  // Fetch scan results
  const { data: scanResults, isLoading: resultsLoading } = useQuery({
    queryKey: ['code-scan-results'],
    queryFn: () => inventoryApi.getApplications(),
    retry: false,
  });

  // Fetch deduplication stats
  const { data: dedupStats } = useQuery({
    queryKey: ['dedup-stats'],
    queryFn: () => dedupApi.getStats(),
    retry: false,
  });

  // Scan mutation
  const scanMutation = useMutation({
    mutationFn: async (url: string) => {
      // Create a mock file from the URL for the ingestSARIF call
      const blob = new Blob([JSON.stringify({ source: url, type: 'repository' })], { type: 'application/json' });
      const file = new File([blob], 'scan-request.json', { type: 'application/json' });
      return await ingestApi.ingestSARIF(file);
    },
    onSuccess: () => {
      toast.success('Scan initiated successfully');
      queryClient.invalidateQueries({ queryKey: ['code-scan-results'] });
      setScanUrl('');
    },
    onError: (error: any) => {
      toast.error(`Scan failed: ${error.message || 'Unknown error'}`);
    },
  });

  const handleScan = () => {
    if (!scanUrl.trim()) {
      toast.error('Please enter a repository URL');
      return;
    }
    scanMutation.mutate(scanUrl);
  };

  // Stats from data
  const findings = (scanResults as any)?.assets || [];
  const criticalCount = findings.filter((f: any) => f.severity === 'critical').length;
  const highCount = findings.filter((f: any) => f.severity === 'high').length;
  const mediumCount = findings.filter((f: any) => f.severity === 'medium').length;

  const getSeverityBadge = (severity: string) => {
    const styles: Record<string, string> = {
      critical: 'bg-red-500/20 text-red-400 border-red-500/30',
      high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    };
    return styles[severity] || styles.info;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center">
              <Code className="w-5 h-5 text-white" />
            </div>
            Code Scanning
          </h1>
          <p className="text-muted-foreground mt-1">
            Static analysis and vulnerability detection for your codebase
          </p>
        </div>
      </div>

      {/* Scan Input */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <GitBranch className="w-5 h-5" />
            Scan Repository
          </CardTitle>
          <CardDescription>
            Enter a Git repository URL to scan for vulnerabilities
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3">
            <Input
              placeholder="https://github.com/org/repo"
              value={scanUrl}
              onChange={(e) => setScanUrl(e.target.value)}
              className="flex-1"
            />
            <Button 
              onClick={handleScan} 
              disabled={scanMutation.isPending}
              className="gap-2"
            >
              {scanMutation.isPending ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  Scan
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="glass-card border-red-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-red-400">{criticalCount}</p>
                  <p className="text-xs text-muted-foreground">Critical</p>
                </div>
                <ShieldAlert className="w-8 h-8 text-red-400/50" />
              </div>
            </CardContent>
          </Card>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <Card className="glass-card border-orange-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-orange-400">{highCount}</p>
                  <p className="text-xs text-muted-foreground">High</p>
                </div>
                <AlertTriangle className="w-8 h-8 text-orange-400/50" />
              </div>
            </CardContent>
          </Card>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <Card className="glass-card border-yellow-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-yellow-400">{mediumCount}</p>
                  <p className="text-xs text-muted-foreground">Medium</p>
                </div>
                <Bug className="w-8 h-8 text-yellow-400/50" />
              </div>
            </CardContent>
          </Card>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
          <Card className="glass-card border-green-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-green-400">{(dedupStats as any)?.deduplicated || 0}</p>
                  <p className="text-xs text-muted-foreground">Deduplicated</p>
                </div>
                <CheckCircle2 className="w-8 h-8 text-green-400/50" />
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Findings List */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileCode className="w-5 h-5" />
            Findings
          </CardTitle>
          <CardDescription>
            {resultsLoading ? 'Loading...' : `${findings.length} findings across your codebase`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {resultsLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
            </div>
          ) : findings.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Code className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No findings yet</p>
              <p className="text-sm">Scan a repository to find vulnerabilities</p>
            </div>
          ) : (
            <div className="space-y-3">
              {findings.slice(0, 20).map((finding: any, index: number) => (
                <motion.div
                  key={finding.id || index}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors cursor-pointer group"
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <Badge className={getSeverityBadge(finding.severity || 'info')}>
                      {(finding.severity || 'info').toUpperCase()}
                    </Badge>
                    <div className="min-w-0 flex-1">
                      <p className="font-medium truncate">{finding.name || finding.title || finding.id}</p>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        {finding.file && <span className="truncate">{finding.file}</span>}
                        {finding.line && <span>Line {finding.line}</span>}
                        {finding.cve_id && (
                          <Badge variant="outline" className="text-[10px]">{finding.cve_id}</Badge>
                        )}
                      </div>
                    </div>
                  </div>
                  <ArrowUpRight className="w-4 h-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                </motion.div>
              ))}
              {findings.length > 20 && (
                <p className="text-center text-sm text-muted-foreground pt-4">
                  Showing 20 of {findings.length} findings
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
