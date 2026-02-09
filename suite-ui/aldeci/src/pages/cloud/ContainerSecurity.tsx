import { useEffect, useState, useCallback } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { motion } from 'framer-motion';
import { api } from '../../lib/api';

const severityColor = (s: string) => {
  switch (s) {
    case 'critical': return 'bg-red-500/20 text-red-400';
    case 'high': return 'bg-orange-500/20 text-orange-400';
    case 'medium': return 'bg-yellow-500/20 text-yellow-400';
    case 'low': return 'bg-blue-500/20 text-blue-400';
    default: return 'bg-gray-500/20 text-gray-400';
  }
};

const ContainerSecurity = () => {
  const [images, setImages] = useState<any[]>([]);
  const [vulns, setVulns] = useState<any[]>([]);
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [imagesRes, vulnsRes] = await Promise.all([
        api.get('/api/v1/container/status').catch(() => ({ data: { containers: [] } })),
        api.get('/api/v1/vulns/discovered').catch(() => ({ data: { vulnerabilities: [] } })),
      ]);
      setImages(imagesRes.data?.containers || imagesRes.data || []);
      setVulns(vulnsRes.data?.vulnerabilities || vulnsRes.data || []);
    } catch (e) { console.error('Container fetch error', e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleScan = async () => {
    setScanning(true);
    try {
      await api.post('/api/v1/container/scan/image', { image: 'all' }).catch(() => {});
      await fetchData();
    } catch (e) { console.error('Scan error', e); }
    finally { setScanning(false); }
  };

  const criticalCount = vulns.filter((v: any) => v.severity === 'critical').length;
  const highCount = vulns.filter((v: any) => v.severity === 'high').length;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-sky-400 to-blue-500 bg-clip-text text-transparent">Container & VM Security</h1>
          <p className="text-muted-foreground mt-1">Scan Docker/OCI container images and virtual machines for vulnerabilities</p>
        </div>
        <Button onClick={handleScan} disabled={scanning}>{scanning ? 'Scanning...' : '🔍 Scan Images'}</Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Container Images', value: images.length, color: 'text-blue-400' },
          { label: 'Total Vulns', value: vulns.length, color: 'text-yellow-400' },
          { label: 'Critical', value: criticalCount, color: 'text-red-400' },
          { label: 'High', value: highCount, color: 'text-orange-400' },
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

      <Tabs defaultValue="images" className="space-y-4">
        <TabsList>
          <TabsTrigger value="images">Images ({images.length})</TabsTrigger>
          <TabsTrigger value="vulns">Vulnerabilities ({vulns.length})</TabsTrigger>
        </TabsList>
        <TabsContent value="images">
          <Card className="border-border/50"><CardContent className="pt-6">
            {loading ? <div className="text-center py-8 text-muted-foreground">Loading...</div> : (
            <div className="space-y-3">{images.map((img: any, i: number) => (
              <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.03 }}
                className="p-4 border border-border/30 rounded-lg">
                <div className="flex justify-between items-start">
                  <div>
                    <div className="font-mono font-semibold text-foreground">{img.image || img.name || `image-${i}`}</div>
                    <div className="text-xs text-muted-foreground mt-1">Tag: {img.tag || 'latest'} • Size: {img.size || 'N/A'} • OS: {img.os || 'linux'}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    {img.vuln_count > 0 && <Badge className="bg-red-500/20 text-red-400">{img.vuln_count} vulns</Badge>}
                    <Badge className={img.status === 'scanned' ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}>{img.status || 'pending'}</Badge>
                  </div>
                </div>
                {img.vuln_count > 0 && (
                  <div className="mt-2 flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">Risk:</span>
                    <Progress value={Math.min((img.vuln_count / 50) * 100, 100)} className="flex-1 h-2" />
                  </div>
                )}
              </motion.div>
            ))}{images.length === 0 && <div className="text-center py-12 text-muted-foreground">No container images found. Click "Scan Images" to start.</div>}</div>)}
          </CardContent></Card>
        </TabsContent>
        <TabsContent value="vulns">
          <Card className="border-border/50"><CardContent className="pt-6">
            <div className="space-y-2">{vulns.slice(0, 30).map((v: any, i: number) => (
              <div key={i} className="flex items-center justify-between p-3 border border-border/30 rounded-lg">
                <div className="flex items-center gap-3">
                  <Badge className={severityColor(v.severity)}>{v.severity}</Badge>
                  <div>
                    <span className="font-mono text-sm text-foreground">{v.cve_id || v.id || 'N/A'}</span>
                    <p className="text-xs text-muted-foreground">{v.package || v.component || 'Unknown package'} {v.installed_version || ''}</p>
                  </div>
                </div>
                <span className="text-xs text-muted-foreground">{v.fix_version ? `Fix: ${v.fix_version}` : 'No fix'}</span>
              </div>
            ))}{vulns.length === 0 && <div className="text-center py-8 text-muted-foreground">No vulnerabilities found.</div>}</div>
          </CardContent></Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ContainerSecurity;

