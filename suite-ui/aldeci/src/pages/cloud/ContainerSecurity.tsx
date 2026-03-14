import { useEffect, useState, useCallback, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { motion } from 'framer-motion';
import {
  Box, Shield, AlertTriangle, Search, RefreshCw,
  Layers, CheckCircle2, XCircle, Clock, Eye,
  ChevronDown, ChevronUp, Server,
} from 'lucide-react';
import { api, containerScanApi } from '../../lib/api';
import { toast } from 'sonner';

// ============================================================================
// Types [V7]
// ============================================================================

interface ContainerImage {
  image: string;
  name?: string;
  tag?: string;
  size?: string;
  os?: string;
  status?: string;
  vuln_count?: number;
  critical_count?: number;
  high_count?: number;
  last_scanned?: string;
  layers?: number;
  digest?: string;
}

interface ContainerVuln {
  cve_id?: string;
  id?: string;
  severity: string;
  package?: string;
  component?: string;
  installed_version?: string;
  fix_version?: string;
  description?: string;
  epss_score?: number;
  exploitable?: boolean;
}

// ============================================================================
// Constants
// ============================================================================

const severityConfig: Record<string, { bg: string; text: string; border: string; icon: typeof AlertTriangle }> = {
  critical: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30', icon: XCircle },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30', icon: AlertTriangle },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30', icon: AlertTriangle },
  low: { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500/30', icon: Shield },
  info: { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500/30', icon: Eye },
};

const containerV = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.05 } },
};
const itemV = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 200, damping: 22 } },
};

// ============================================================================
// Skeleton
// ============================================================================

function ContainerSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div className="space-y-2">
          <Skeleton className="h-9 w-80" />
          <Skeleton className="h-4 w-96" />
        </div>
        <div className="flex gap-2">
          <Skeleton className="h-10 w-32" />
          <Skeleton className="h-10 w-24" />
        </div>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[1, 2, 3, 4, 5].map(i => (
          <Card key={i} className="border-border/50 bg-card/50">
            <CardContent className="pt-4 pb-3">
              <Skeleton className="h-8 w-14 mb-2" />
              <Skeleton className="h-3 w-20" />
            </CardContent>
          </Card>
        ))}
      </div>
      <Skeleton className="h-10 w-64" />
      <Card className="border-border/50">
        <CardContent className="pt-6">
          <div className="space-y-3">
            {[1, 2, 3, 4].map(i => (
              <Skeleton key={i} className="h-24 w-full rounded-lg" />
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// Container Image Card
// ============================================================================

function ImageCard({ img, index }: { img: ContainerImage; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const riskScore = Math.min(((img.vuln_count || 0) / 50) * 100, 100);
  const riskColor = riskScore > 70 ? 'text-red-400' : riskScore > 40 ? 'text-yellow-400' : 'text-green-400';
  const statusBg = img.status === 'scanned'
    ? 'bg-green-500/20 text-green-400 border-green-500/30'
    : img.status === 'scanning'
    ? 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    : 'bg-gray-500/20 text-gray-400 border-gray-500/30';

  return (
    <motion.div variants={itemV}>
      <div
        className="p-4 border border-border/30 rounded-lg bg-card/20 hover:bg-card/40 transition-all cursor-pointer"
        onClick={() => setExpanded(!expanded)}
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        aria-label={`Container image ${img.image || img.name || `image-${index}`}`}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpanded(!expanded); }}}
      >
        <div className="flex justify-between items-start">
          <div className="flex items-start gap-3">
            <div className="mt-1">
              <Box className="w-5 h-5 text-sky-400" />
            </div>
            <div>
              <div className="font-mono font-semibold text-foreground">
                {img.image || img.name || `image-${index}`}
              </div>
              <div className="flex items-center gap-3 text-xs text-muted-foreground mt-1">
                <span>Tag: <span className="text-foreground">{img.tag || 'latest'}</span></span>
                <span>Size: <span className="text-foreground">{img.size || 'N/A'}</span></span>
                <span>OS: <span className="text-foreground">{img.os || 'linux'}</span></span>
                {img.layers && <span>Layers: <span className="text-foreground">{img.layers}</span></span>}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {(img.vuln_count || 0) > 0 && (
              <Badge className="bg-red-500/20 text-red-400 border border-red-500/30">
                {img.vuln_count} vulns
              </Badge>
            )}
            {(img.critical_count || 0) > 0 && (
              <Badge className="bg-red-600/30 text-red-300 border border-red-600/40">
                {img.critical_count} CRIT
              </Badge>
            )}
            <Badge className={`border ${statusBg}`}>{img.status || 'pending'}</Badge>
            {expanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
          </div>
        </div>

        {/* Risk bar */}
        <div className="mt-3 flex items-center gap-3">
          <span className="text-xs text-muted-foreground w-20">Risk Score:</span>
          <div className="flex-1 bg-gray-800/50 rounded-full h-2 overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${riskScore}%` }}
              transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
              className={`h-full rounded-full ${
                riskScore > 70 ? 'bg-red-500' : riskScore > 40 ? 'bg-yellow-500' : 'bg-green-500'
              }`}
            />
          </div>
          <span className={`text-xs font-mono font-bold ${riskColor}`}>{Math.round(riskScore)}</span>
        </div>

        {/* Expanded details */}
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            transition={{ duration: 0.3 }}
            className="mt-4 pt-3 border-t border-border/20 space-y-2"
          >
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              <div className="p-2 rounded bg-gray-800/30">
                <span className="text-muted-foreground">Digest</span>
                <p className="font-mono text-foreground truncate">{img.digest || 'sha256:...'}</p>
              </div>
              <div className="p-2 rounded bg-gray-800/30">
                <span className="text-muted-foreground">Last Scanned</span>
                <p className="text-foreground">{img.last_scanned ? new Date(img.last_scanned).toLocaleString() : 'Never'}</p>
              </div>
              <div className="p-2 rounded bg-gray-800/30">
                <span className="text-muted-foreground">Critical</span>
                <p className="text-red-400 font-bold">{img.critical_count || 0}</p>
              </div>
              <div className="p-2 rounded bg-gray-800/30">
                <span className="text-muted-foreground">High</span>
                <p className="text-orange-400 font-bold">{img.high_count || 0}</p>
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </motion.div>
  );
}

// ============================================================================
// Vulnerability Row
// ============================================================================

function VulnRow({ vuln }: { vuln: ContainerVuln }) {
  const sev = severityConfig[vuln.severity] || severityConfig.info;
  const SevIcon = sev.icon;

  return (
    <motion.div variants={itemV}
      className="flex items-center justify-between p-3 border border-border/30 rounded-lg bg-card/10 hover:bg-card/30 transition-colors"
    >
      <div className="flex items-center gap-3">
        <SevIcon className={`w-4 h-4 ${sev.text}`} aria-hidden="true" />
        <Badge className={`border ${sev.bg} ${sev.text} ${sev.border}`}>
          {vuln.severity?.toUpperCase()}
        </Badge>
        <div>
          <span className="font-mono text-sm text-foreground">{vuln.cve_id || vuln.id || 'N/A'}</span>
          <p className="text-xs text-muted-foreground">
            {vuln.package || vuln.component || 'Unknown'} {vuln.installed_version ? `v${vuln.installed_version}` : ''}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-4 text-xs">
        {vuln.epss_score != null && (
          <div className="flex items-center gap-1.5">
            <span className="text-muted-foreground">EPSS:</span>
            <span className={`font-mono ${vuln.epss_score > 0.5 ? 'text-red-400' : 'text-foreground'}`}>
              {(vuln.epss_score * 100).toFixed(1)}%
            </span>
          </div>
        )}
        {vuln.exploitable && (
          <Badge className="bg-red-600/20 text-red-300 border border-red-600/30 text-[10px]">
            EXPLOITABLE
          </Badge>
        )}
        <span className={`text-muted-foreground ${vuln.fix_version ? '' : 'text-red-400/60'}`}>
          {vuln.fix_version ? `Fix: ${vuln.fix_version}` : 'No fix available'}
        </span>
      </div>
    </motion.div>
  );
}

// ============================================================================
// Main Component [V7]
// ============================================================================

const ContainerSecurity = () => {
  const [images, setImages] = useState<ContainerImage[]>([]);
  const [vulns, setVulns] = useState<ContainerVuln[]>([]);
  const [scannerStatus, setScannerStatus] = useState<{ status?: string; containers?: ContainerImage[] } | null>(null);
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [statusRes, vulnsRes] = await Promise.all([
        containerScanApi.getStatus().catch((e) => { console.error('[Container] status fetch failed:', e?.message); return { containers: [], status: 'unknown' }; }),
        api.get('/api/v1/vulns/discovered').catch((e) => { console.error('[Container] vulns fetch failed:', e?.message); return { data: { vulnerabilities: [] } }; }),
      ]);
      const statusData = typeof statusRes === 'object' && statusRes !== null ? statusRes as { status?: string; containers?: ContainerImage[] } : {};
      setScannerStatus(statusData);
      setImages(statusData.containers || []);
      const vulnData = (vulnsRes as { data?: { vulnerabilities?: ContainerVuln[]; findings?: ContainerVuln[] } }).data || vulnsRes as { vulnerabilities?: ContainerVuln[]; findings?: ContainerVuln[] };
      setVulns(vulnData.vulnerabilities || vulnData.findings || []);
    } catch (e) {
      console.error('Container fetch error', e);
      toast.error('Failed to fetch container data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleScan = async () => {
    setScanning(true);
    try {
      await containerScanApi.scanImage({ image: 'all' });
      toast.success('Container scan initiated across all images');
      // Re-fetch after a brief delay to let scan start
      setTimeout(() => fetchData(), 1500);
    } catch (e) {
      toast.error(`Scan failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    } finally {
      setScanning(false);
    }
  };

  // Compute stats
  const stats = useMemo(() => {
    const critical = vulns.filter(v => v.severity === 'critical').length;
    const high = vulns.filter(v => v.severity === 'high').length;
    const medium = vulns.filter(v => v.severity === 'medium').length;
    const low = vulns.filter(v => v.severity === 'low').length;
    const fixable = vulns.filter(v => v.fix_version).length;
    return { critical, high, medium, low, fixable, total: vulns.length };
  }, [vulns]);

  // Filter vulnerabilities
  const filteredVulns = useMemo(() => {
    let filtered = vulns;
    if (severityFilter !== 'all') {
      filtered = filtered.filter(v => v.severity === severityFilter);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(v =>
        (v.cve_id || v.id || '').toLowerCase().includes(q) ||
        (v.package || v.component || '').toLowerCase().includes(q) ||
        (v.description || '').toLowerCase().includes(q)
      );
    }
    return filtered;
  }, [vulns, severityFilter, searchQuery]);

  if (loading) return <ContainerSkeleton />;

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ type: 'spring', stiffness: 200, damping: 22 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-sky-400 to-blue-500 bg-clip-text text-transparent">
            Container & VM Security
          </h1>
          <p className="text-muted-foreground mt-1">
            Scan Docker/OCI container images for vulnerabilities, misconfigurations, and supply chain risks
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={fetchData} aria-label="Refresh data">
            <RefreshCw className="w-4 h-4 mr-2" /> Refresh
          </Button>
          <Button onClick={handleScan} disabled={scanning} aria-label="Scan all container images">
            {scanning ? (
              <><RefreshCw className="w-4 h-4 mr-2 animate-spin" /> Scanning...</>
            ) : (
              <><Shield className="w-4 h-4 mr-2" /> Scan Images</>
            )}
          </Button>
        </div>
      </motion.div>

      {/* Scanner Status Badge */}
      {scannerStatus && (
        <div className="flex items-center gap-3">
          <Badge className={`border px-3 py-1 ${
            scannerStatus?.status === 'healthy'
              ? 'bg-green-500/20 text-green-400 border-green-500/30'
              : 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
          }`}>
            <Server className="w-3.5 h-3.5 mr-1.5" />
            Container Scanner: {String(scannerStatus?.status || 'ready')}
          </Badge>
          <Badge className="bg-primary/20 text-primary border-primary/30 border px-3 py-1">
            <Layers className="w-3.5 h-3.5 mr-1.5" /> V7 Native Scanner
          </Badge>
        </div>
      )}

      {/* Stats Row */}
      <motion.div variants={containerV} initial="hidden" animate="visible"
        className="grid grid-cols-2 md:grid-cols-6 gap-3">
        {[
          { label: 'Images', value: images.length, color: 'text-sky-400', icon: Box },
          { label: 'Total Vulns', value: stats.total, color: 'text-yellow-400', icon: AlertTriangle },
          { label: 'Critical', value: stats.critical, color: 'text-red-400', icon: XCircle },
          { label: 'High', value: stats.high, color: 'text-orange-400', icon: AlertTriangle },
          { label: 'Fixable', value: stats.fixable, color: 'text-green-400', icon: CheckCircle2 },
          { label: 'Fix Rate', value: stats.total ? `${Math.round((stats.fixable / stats.total) * 100)}%` : '0%', color: 'text-cyan-400', icon: Clock },
        ].map((s) => (
          <motion.div key={s.label} variants={itemV}>
            <Card className="border-border/50 bg-card/50">
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center justify-between">
                  <div>
                    <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                    <div className="text-xs text-muted-foreground">{s.label}</div>
                  </div>
                  <s.icon className={`w-5 h-5 ${s.color} opacity-50`} aria-hidden="true" />
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </motion.div>

      {/* Severity Distribution Bar */}
      {stats.total > 0 && (
        <Card className="border-border/50 bg-card/30">
          <CardContent className="py-4">
            <div className="flex items-center gap-3 mb-2">
              <span className="text-sm text-muted-foreground">Severity Distribution</span>
            </div>
            <div className="flex h-3 rounded-full overflow-hidden bg-gray-800/50">
              {stats.critical > 0 && (
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${(stats.critical / stats.total) * 100}%` }}
                  transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
                  className="bg-red-500 h-full"
                  title={`Critical: ${stats.critical}`}
                />
              )}
              {stats.high > 0 && (
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${(stats.high / stats.total) * 100}%` }}
                  transition={{ duration: 0.6, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
                  className="bg-orange-500 h-full"
                  title={`High: ${stats.high}`}
                />
              )}
              {stats.medium > 0 && (
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${(stats.medium / stats.total) * 100}%` }}
                  transition={{ duration: 0.6, delay: 0.2, ease: [0.16, 1, 0.3, 1] }}
                  className="bg-yellow-500 h-full"
                  title={`Medium: ${stats.medium}`}
                />
              )}
              {stats.low > 0 && (
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${(stats.low / stats.total) * 100}%` }}
                  transition={{ duration: 0.6, delay: 0.3, ease: [0.16, 1, 0.3, 1] }}
                  className="bg-blue-500 h-full"
                  title={`Low: ${stats.low}`}
                />
              )}
            </div>
            <div className="flex gap-4 mt-2 text-xs text-muted-foreground">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> Critical: {stats.critical}</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500" /> High: {stats.high}</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-yellow-500" /> Medium: {stats.medium}</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500" /> Low: {stats.low}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <Tabs defaultValue="images" className="space-y-4">
        <TabsList>
          <TabsTrigger value="images">
            <Box className="w-4 h-4 mr-1.5" /> Images ({images.length})
          </TabsTrigger>
          <TabsTrigger value="vulns">
            <AlertTriangle className="w-4 h-4 mr-1.5" /> Vulnerabilities ({vulns.length})
          </TabsTrigger>
        </TabsList>

        {/* Images Tab */}
        <TabsContent value="images">
          <Card className="border-border/50 bg-card/20">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Box className="w-5 h-5 text-sky-400" />
                Container Images
              </CardTitle>
              <CardDescription>Scanned images with vulnerability assessment</CardDescription>
            </CardHeader>
            <CardContent>
              {images.length === 0 ? (
                <div className="text-center py-16">
                  <Box className="w-16 h-16 text-muted-foreground/30 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-foreground mb-2">No container images found</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Click "Scan Images" to discover and scan container images in your registry.
                  </p>
                  <Button onClick={handleScan} disabled={scanning}>
                    <Shield className="w-4 h-4 mr-2" /> Start Scanning
                  </Button>
                </div>
              ) : (
                <motion.div variants={containerV} initial="hidden" animate="visible" className="space-y-3">
                  {images.map((img, i) => (
                    <ImageCard key={img.image || img.name || i} img={img} index={i} />
                  ))}
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Vulnerabilities Tab */}
        <TabsContent value="vulns">
          <Card className="border-border/50 bg-card/20">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5 text-orange-400" />
                    Container Vulnerabilities
                  </CardTitle>
                  <CardDescription>{filteredVulns.length} of {vulns.length} vulnerabilities shown</CardDescription>
                </div>
                <div className="flex gap-2 items-center">
                  {/* Severity filter */}
                  <div className="flex gap-1">
                    {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
                      <button
                        key={sev}
                        onClick={() => setSeverityFilter(sev)}
                        className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                          severityFilter === sev
                            ? sev === 'all' ? 'bg-primary/20 text-primary' :
                              `${(severityConfig[sev] || severityConfig.info).bg} ${(severityConfig[sev] || severityConfig.info).text}`
                            : 'text-muted-foreground hover:text-foreground'
                        }`}
                        aria-label={`Filter by ${sev} severity`}
                        aria-pressed={severityFilter === sev}
                      >
                        {sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {/* Search */}
              <div className="relative max-w-sm mb-4">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" aria-hidden="true" />
                <Input
                  placeholder="Search CVE, package..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  className="pl-10 bg-gray-900/40 border-gray-700/40"
                  aria-label="Search vulnerabilities"
                />
              </div>

              {filteredVulns.length === 0 ? (
                <div className="text-center py-12">
                  <CheckCircle2 className="w-12 h-12 text-green-500/40 mx-auto mb-4" />
                  <p className="text-muted-foreground">
                    {vulns.length === 0 ? 'No vulnerabilities found.' : 'No matches for current filter.'}
                  </p>
                </div>
              ) : (
                <motion.div variants={containerV} initial="hidden" animate="visible" className="space-y-2">
                  {filteredVulns.slice(0, 50).map((v, i) => (
                    <VulnRow key={v.cve_id || v.id || i} vuln={v} />
                  ))}
                  {filteredVulns.length > 50 && (
                    <p className="text-center text-sm text-muted-foreground py-2">
                      Showing 50 of {filteredVulns.length} vulnerabilities
                    </p>
                  )}
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ContainerSecurity;
