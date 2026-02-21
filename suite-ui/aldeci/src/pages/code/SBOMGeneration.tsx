import { useEffect, useState, useCallback } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { motion } from 'framer-motion';
import { api } from '../../lib/api';

const SBOMGeneration = () => {
  const [sboms, setSboms] = useState<any[]>([]);
  const [licenses, setLicenses] = useState<any[]>([]);
  const [dependencies, setDependencies] = useState<any[]>([]);
  const [, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [sbomRes, licenseRes, depRes] = await Promise.all([
        api.get('/api/v1/inventory/applications', { params: { include_sbom: true } }).catch(() => ({ data: { sboms: [] } })),
        api.get('/api/v1/inventory/assets', { params: { type: 'license' } }).catch(() => ({ data: { licenses: [] } })),
        api.get('/api/v1/inventory/assets', { params: { type: 'dependency' } }).catch(() => ({ data: { dependencies: [] } })),
      ]);
      setSboms(sbomRes.data?.sboms || []);
      setLicenses(licenseRes.data?.licenses || licenseRes.data || []);
      setDependencies(depRes.data?.dependencies || depRes.data || []);
    } catch (e) { console.error('SBOM fetch error', e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleGenerate = async (format: string) => {
    setGenerating(true);
    try {
      await api.post('/api/v1/inventory/applications', { format, project_name: 'FixOps', version: '1.0.0' });
      await fetchData();
    } catch (e) { console.error('Generate SBOM error', e); }
    finally { setGenerating(false); }
  };

  const riskColor = (risk: string) => {
    switch (risk) {
      case 'high': return 'bg-red-500/20 text-red-400';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400';
      case 'low': return 'bg-green-500/20 text-green-400';
      default: return 'bg-gray-500/20 text-gray-400';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-teal-400 to-cyan-500 bg-clip-text text-transparent">SBOM & License Management</h1>
          <p className="text-muted-foreground mt-1">Software Bill of Materials generation (CycloneDX / SPDX) & license compliance</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => handleGenerate('cyclonedx')} disabled={generating}>Generate CycloneDX</Button>
          <Button onClick={() => handleGenerate('spdx')} disabled={generating}>Generate SPDX</Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'SBOMs Generated', value: sboms.length, color: 'text-blue-400' },
          { label: 'Dependencies', value: dependencies.length, color: 'text-purple-400' },
          { label: 'Licenses Found', value: licenses.length, color: 'text-green-400' },
          { label: 'License Risks', value: licenses.filter((l: any) => l.risk === 'high').length, color: 'text-red-400' },
        ].map((s, i) => (
          <motion.div key={i} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}>
            <Card className="border-border/50 bg-card/50">
              <CardContent className="pt-4 pb-3">
                <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-xs text-muted-foreground">{s.label}</div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      <Tabs defaultValue="sboms" className="space-y-4">
        <TabsList>
          <TabsTrigger value="sboms">SBOMs ({sboms.length})</TabsTrigger>
          <TabsTrigger value="dependencies">Dependencies ({dependencies.length})</TabsTrigger>
          <TabsTrigger value="licenses">Licenses ({licenses.length})</TabsTrigger>
        </TabsList>
        <TabsContent value="sboms">
          <Card className="border-border/50"><CardContent className="pt-6">
            <div className="space-y-3">{sboms.map((s: any, i: number) => (
              <div key={i} className="p-4 border border-border/30 rounded-lg flex justify-between items-center">
                <div>
                  <div className="font-semibold text-foreground">{s.project_name || 'SBOM'} v{s.version || '1.0'}</div>
                  <div className="text-xs text-muted-foreground">Format: {s.format || 'CycloneDX'} • Components: {s.component_count || 0} • {s.created_at ? new Date(s.created_at).toLocaleDateString() : 'N/A'}</div>
                </div>
                <Button size="sm" variant="outline">Download</Button>
              </div>
            ))}{sboms.length === 0 && <div className="text-center py-8 text-muted-foreground">No SBOMs generated yet. Click "Generate" to create one.</div>}</div>
          </CardContent></Card>
        </TabsContent>
        <TabsContent value="dependencies">
          <Card className="border-border/50"><CardContent className="pt-6">
            <div className="space-y-2">{dependencies.slice(0, 30).map((d: any, i: number) => (
              <div key={i} className="flex items-center justify-between p-3 border border-border/30 rounded-lg">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-foreground">{d.name || d.package}</span>
                  <Badge variant="outline">{d.version || 'latest'}</Badge>
                </div>
                <div className="flex items-center gap-2">
                  {d.vulnerabilities > 0 && <Badge className="bg-red-500/20 text-red-400">{d.vulnerabilities} vulns</Badge>}
                  <span className="text-xs text-muted-foreground">{d.license || 'Unknown'}</span>
                </div>
              </div>
            ))}{dependencies.length === 0 && <div className="text-center py-8 text-muted-foreground">No dependencies found.</div>}</div>
          </CardContent></Card>
        </TabsContent>
        <TabsContent value="licenses">
          <Card className="border-border/50"><CardContent className="pt-6">
            <div className="space-y-2">{licenses.slice(0, 30).map((l: any, i: number) => (
              <div key={i} className="flex items-center justify-between p-3 border border-border/30 rounded-lg">
                <div>
                  <span className="font-medium text-foreground">{l.name || l.spdx_id || 'Unknown'}</span>
                  <span className="text-xs text-muted-foreground ml-2">({l.packages_count || 0} packages)</span>
                </div>
                <Badge className={riskColor(l.risk || 'low')}>{l.risk || 'low'} risk</Badge>
              </div>
            ))}{licenses.length === 0 && <div className="text-center py-8 text-muted-foreground">No license data available.</div>}</div>
          </CardContent></Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SBOMGeneration;

