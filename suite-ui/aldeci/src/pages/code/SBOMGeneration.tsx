import { useEffect, useState, useCallback, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { motion } from 'framer-motion';
import {
  FileText, Package, Shield, Download,
  Search, AlertTriangle, CheckCircle2, FileCode, Scale,
  Layers, Clock,
} from 'lucide-react';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// ============================================================================
// Types [V7]
// ============================================================================

interface SBOMRecord {
  id?: string;
  project_name?: string;
  version?: string;
  format?: string;
  component_count?: number;
  created_at?: string;
  status?: string;
  hash?: string;
}

interface DependencyRecord {
  name?: string;
  package?: string;
  version?: string;
  license?: string;
  vulnerabilities?: number;
  ecosystem?: string;
  direct?: boolean;
  risk_level?: string;
}

interface LicenseRecord {
  name?: string;
  spdx_id?: string;
  risk?: string;
  packages_count?: number;
  category?: string;
  osi_approved?: boolean;
}

// ============================================================================
// Constants
// ============================================================================

const riskColors: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30' },
  high: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30' },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  low: { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30' },
  none: { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500/30' },
};

const containerV = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.04 } },
};
const itemV = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 200, damping: 22 } },
};

// ============================================================================
// Skeleton
// ============================================================================

function SBOMSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div className="space-y-2">
          <Skeleton className="h-9 w-80" />
          <Skeleton className="h-4 w-[28rem]" />
        </div>
        <div className="flex gap-2">
          <Skeleton className="h-10 w-40" />
          <Skeleton className="h-10 w-36" />
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
            {[1, 2, 3].map(i => (
              <Skeleton key={i} className="h-20 w-full rounded-lg" />
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// Main Component [V7]
// ============================================================================

const SBOMGeneration = () => {
  const [sboms, setSboms] = useState<SBOMRecord[]>([]);
  const [licenses, setLicenses] = useState<LicenseRecord[]>([]);
  const [dependencies, setDependencies] = useState<DependencyRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [sbomRes, licenseRes, depRes] = await Promise.all([
        api.get('/api/v1/inventory/applications', { params: { include_sbom: true } }).catch(() => ({ data: { sboms: [], items: [] } })),
        api.get('/api/v1/inventory/assets', { params: { type: 'license' } }).catch(() => ({ data: { licenses: [], items: [] } })),
        api.get('/api/v1/inventory/assets', { params: { type: 'dependency' } }).catch(() => ({ data: { dependencies: [], items: [] } })),
      ]);
      setSboms(sbomRes.data?.sboms || sbomRes.data?.items || []);
      setLicenses(licenseRes.data?.licenses || licenseRes.data?.items || licenseRes.data || []);
      setDependencies(depRes.data?.dependencies || depRes.data?.items || depRes.data || []);
    } catch (e) {
      console.error('SBOM fetch error', e);
      toast.error('Failed to load SBOM data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleGenerate = async (format: string) => {
    setGenerating(true);
    try {
      await api.post('/api/v1/inventory/applications', { format, project_name: 'ALdeci', version: '2.0.0' });
      toast.success(`${format.toUpperCase()} SBOM generated successfully`);
      await fetchData();
    } catch (e) {
      toast.error(`Failed to generate SBOM: ${e instanceof Error ? e.message : 'Unknown error'}`);
    } finally {
      setGenerating(false);
    }
  };

  // Compute stats
  const stats = useMemo(() => {
    const highRiskLicenses = licenses.filter(l => l.risk === 'high' || l.risk === 'critical').length;
    const vulnDeps = dependencies.filter(d => (d.vulnerabilities || 0) > 0).length;
    const directDeps = dependencies.filter(d => d.direct).length;
    return {
      sbomCount: sboms.length,
      depCount: dependencies.length,
      licenseCount: licenses.length,
      highRiskLicenses,
      vulnDeps,
      directDeps,
    };
  }, [sboms, dependencies, licenses]);

  // Filter dependencies
  const filteredDeps = useMemo(() => {
    if (!searchQuery) return dependencies;
    const q = searchQuery.toLowerCase();
    return dependencies.filter(d =>
      (d.name || d.package || '').toLowerCase().includes(q) ||
      (d.license || '').toLowerCase().includes(q) ||
      (d.ecosystem || '').toLowerCase().includes(q)
    );
  }, [dependencies, searchQuery]);

  if (loading) return <SBOMSkeleton />;

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
          <h1 className="text-3xl font-bold bg-gradient-to-r from-teal-400 to-cyan-500 bg-clip-text text-transparent">
            SBOM & License Management
          </h1>
          <p className="text-muted-foreground mt-1">
            Software Bill of Materials generation (CycloneDX / SPDX) & license compliance tracking
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => handleGenerate('cyclonedx')} disabled={generating}
            aria-label="Generate CycloneDX SBOM">
            <FileCode className="w-4 h-4 mr-2" />
            {generating ? 'Generating...' : 'CycloneDX'}
          </Button>
          <Button onClick={() => handleGenerate('spdx')} disabled={generating}
            aria-label="Generate SPDX SBOM">
            <FileText className="w-4 h-4 mr-2" />
            {generating ? 'Generating...' : 'SPDX'}
          </Button>
        </div>
      </motion.div>

      {/* Pillar Badge */}
      <div className="flex items-center gap-3">
        <Badge className="bg-primary/20 text-primary border-primary/30 border px-3 py-1">
          <Layers className="w-3.5 h-3.5 mr-1.5" /> V7 Supply Chain
        </Badge>
      </div>

      {/* Stats Row */}
      <motion.div variants={containerV} initial="hidden" animate="visible"
        className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'SBOMs Generated', value: stats.sbomCount, color: 'text-blue-400', icon: FileText },
          { label: 'Dependencies', value: stats.depCount, color: 'text-purple-400', icon: Package },
          { label: 'Licenses Found', value: stats.licenseCount, color: 'text-green-400', icon: Scale },
          { label: 'Vulnerable Deps', value: stats.vulnDeps, color: stats.vulnDeps > 0 ? 'text-red-400' : 'text-green-400', icon: AlertTriangle },
          { label: 'License Risks', value: stats.highRiskLicenses, color: stats.highRiskLicenses > 0 ? 'text-orange-400' : 'text-green-400', icon: Shield },
        ].map(s => (
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

      {/* License Risk Distribution */}
      {stats.licenseCount > 0 && (
        <Card className="border-border/50 bg-card/30">
          <CardContent className="py-4">
            <div className="flex items-center gap-3 mb-2">
              <Scale className="w-4 h-4 text-muted-foreground" aria-hidden="true" />
              <span className="text-sm text-muted-foreground">License Risk Distribution</span>
            </div>
            <div className="flex h-3 rounded-full overflow-hidden bg-gray-800/50">
              {['high', 'medium', 'low'].map((risk, idx) => {
                const count = licenses.filter(l => l.risk === risk).length;
                if (count === 0) return null;
                const colors = { high: 'bg-red-500', medium: 'bg-yellow-500', low: 'bg-green-500' };
                return (
                  <motion.div
                    key={risk}
                    initial={{ width: 0 }}
                    animate={{ width: `${(count / stats.licenseCount) * 100}%` }}
                    transition={{ duration: 0.6, delay: idx * 0.1, ease: [0.16, 1, 0.3, 1] }}
                    className={`${colors[risk as keyof typeof colors]} h-full`}
                    title={`${risk}: ${count}`}
                  />
                );
              })}
            </div>
            <div className="flex gap-4 mt-2 text-xs text-muted-foreground">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> High: {licenses.filter(l => l.risk === 'high').length}</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-yellow-500" /> Medium: {licenses.filter(l => l.risk === 'medium').length}</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-green-500" /> Low: {licenses.filter(l => l.risk === 'low').length}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <Tabs defaultValue="sboms" className="space-y-4">
        <TabsList>
          <TabsTrigger value="sboms">
            <FileText className="w-4 h-4 mr-1.5" /> SBOMs ({sboms.length})
          </TabsTrigger>
          <TabsTrigger value="dependencies">
            <Package className="w-4 h-4 mr-1.5" /> Dependencies ({dependencies.length})
          </TabsTrigger>
          <TabsTrigger value="licenses">
            <Scale className="w-4 h-4 mr-1.5" /> Licenses ({licenses.length})
          </TabsTrigger>
        </TabsList>

        {/* SBOMs Tab */}
        <TabsContent value="sboms">
          <Card className="border-border/50 bg-card/20">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-teal-400" />
                Generated SBOMs
              </CardTitle>
              <CardDescription>Software Bill of Materials in CycloneDX and SPDX formats</CardDescription>
            </CardHeader>
            <CardContent>
              {sboms.length === 0 ? (
                <div className="text-center py-16">
                  <FileText className="w-16 h-16 text-muted-foreground/30 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-foreground mb-2">No SBOMs generated yet</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Generate a CycloneDX or SPDX SBOM for your project to track components and dependencies.
                  </p>
                  <div className="flex justify-center gap-2">
                    <Button variant="outline" onClick={() => handleGenerate('cyclonedx')} disabled={generating}>
                      <FileCode className="w-4 h-4 mr-2" /> CycloneDX
                    </Button>
                    <Button onClick={() => handleGenerate('spdx')} disabled={generating}>
                      <FileText className="w-4 h-4 mr-2" /> SPDX
                    </Button>
                  </div>
                </div>
              ) : (
                <motion.div variants={containerV} initial="hidden" animate="visible" className="space-y-3">
                  {sboms.map((s, i) => (
                    <motion.div key={s.id || i} variants={itemV}
                      className="p-4 border border-border/30 rounded-lg bg-card/20 hover:bg-card/40 transition-all flex justify-between items-center">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-teal-500/20 flex items-center justify-center">
                          <FileText className="w-5 h-5 text-teal-400" />
                        </div>
                        <div>
                          <div className="font-semibold text-foreground">{s.project_name || 'Project'} v{s.version || '1.0'}</div>
                          <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                            <span>Format: <span className="text-foreground">{(s.format || 'CycloneDX').toUpperCase()}</span></span>
                            <span>Components: <span className="text-foreground">{s.component_count || 0}</span></span>
                            {s.created_at && (
                              <span className="flex items-center gap-1">
                                <Clock className="w-3 h-3" />
                                {new Date(s.created_at).toLocaleDateString()}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={s.status === 'complete' ? 'bg-green-500/20 text-green-400' : 'bg-blue-500/20 text-blue-400'}>
                          {s.status || 'complete'}
                        </Badge>
                        <Button size="sm" variant="outline" aria-label={`Download ${s.project_name} SBOM`}>
                          <Download className="w-4 h-4 mr-1.5" /> Download
                        </Button>
                      </div>
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Dependencies Tab */}
        <TabsContent value="dependencies">
          <Card className="border-border/50 bg-card/20">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Package className="w-5 h-5 text-purple-400" />
                    Project Dependencies
                  </CardTitle>
                  <CardDescription>{filteredDeps.length} of {dependencies.length} dependencies shown</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {/* Search */}
              <div className="relative max-w-sm mb-4">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" aria-hidden="true" />
                <Input
                  placeholder="Search packages, licenses..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  className="pl-10 bg-gray-900/40 border-gray-700/40"
                  aria-label="Search dependencies"
                />
              </div>

              {filteredDeps.length === 0 ? (
                <div className="text-center py-12">
                  <Package className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
                  <p className="text-muted-foreground">
                    {dependencies.length === 0 ? 'No dependencies found. Generate an SBOM first.' : 'No matching dependencies.'}
                  </p>
                </div>
              ) : (
                <motion.div variants={containerV} initial="hidden" animate="visible" className="space-y-2">
                  {filteredDeps.slice(0, 40).map((d, i) => {
                    return (
                      <motion.div key={i} variants={itemV}
                        className="flex items-center justify-between p-3 border border-border/30 rounded-lg bg-card/10 hover:bg-card/30 transition-colors">
                        <div className="flex items-center gap-3">
                          <Package className="w-4 h-4 text-muted-foreground" aria-hidden="true" />
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-sm text-foreground">{d.name || d.package || 'Unknown'}</span>
                              <Badge variant="outline" className="text-[10px]">{d.version || 'latest'}</Badge>
                              {d.direct && <Badge className="bg-blue-500/20 text-blue-400 text-[10px]">Direct</Badge>}
                            </div>
                            <div className="flex items-center gap-2 mt-0.5 text-xs text-muted-foreground">
                              {d.ecosystem && <span>{d.ecosystem}</span>}
                              {d.license && <span>License: {d.license}</span>}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          {(d.vulnerabilities || 0) > 0 && (
                            <Badge className="bg-red-500/20 text-red-400 border border-red-500/30">
                              <AlertTriangle className="w-3 h-3 mr-1" /> {d.vulnerabilities} vulns
                            </Badge>
                          )}
                          {(d.vulnerabilities || 0) === 0 && (
                            <Badge className="bg-green-500/20 text-green-400 border border-green-500/30">
                              <CheckCircle2 className="w-3 h-3 mr-1" /> Clean
                            </Badge>
                          )}
                        </div>
                      </motion.div>
                    );
                  })}
                  {filteredDeps.length > 40 && (
                    <p className="text-center text-sm text-muted-foreground py-2">
                      Showing 40 of {filteredDeps.length} dependencies
                    </p>
                  )}
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Licenses Tab */}
        <TabsContent value="licenses">
          <Card className="border-border/50 bg-card/20">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Scale className="w-5 h-5 text-green-400" />
                License Compliance
              </CardTitle>
              <CardDescription>License risk assessment and compliance tracking</CardDescription>
            </CardHeader>
            <CardContent>
              {licenses.length === 0 ? (
                <div className="text-center py-12">
                  <Scale className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
                  <p className="text-muted-foreground">No license data available. Generate an SBOM to scan for licenses.</p>
                </div>
              ) : (
                <motion.div variants={containerV} initial="hidden" animate="visible" className="space-y-2">
                  {licenses.slice(0, 30).map((l, i) => {
                    const risk = riskColors[l.risk || 'low'] || riskColors.none;
                    return (
                      <motion.div key={i} variants={itemV}
                        className="flex items-center justify-between p-3 border border-border/30 rounded-lg bg-card/10 hover:bg-card/30 transition-colors">
                        <div className="flex items-center gap-3">
                          <Scale className="w-4 h-4 text-muted-foreground" aria-hidden="true" />
                          <div>
                            <span className="font-medium text-foreground">{l.name || l.spdx_id || 'Unknown'}</span>
                            <div className="flex items-center gap-2 mt-0.5 text-xs text-muted-foreground">
                              <span>{l.packages_count || 0} packages</span>
                              {l.category && <span>{l.category}</span>}
                              {l.osi_approved && (
                                <span className="flex items-center gap-1 text-green-400">
                                  <CheckCircle2 className="w-3 h-3" /> OSI Approved
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <Badge className={`border ${risk.bg} ${risk.text} ${risk.border}`}>
                          {(l.risk || 'low')} risk
                        </Badge>
                      </motion.div>
                    );
                  })}
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SBOMGeneration;
