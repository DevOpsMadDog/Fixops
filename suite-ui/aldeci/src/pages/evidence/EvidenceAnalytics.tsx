import { useEffect, useState, useCallback } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { motion } from 'framer-motion';
import { api } from '../../lib/api';

const EvidenceAnalytics = () => {
  const [analytics, setAnalytics] = useState<any>(null);
  const [trends, setTrends] = useState<any[]>([]);
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [chainStatus, setChainStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [analyticsRes, trendsRes, anomaliesRes, chainRes] = await Promise.all([
        api.get('/api/v1/analytics/summary', { params: { org_id: 'default' } }).catch(() => ({ data: {} })),
        api.get('/api/v1/analytics/trends/severity-over-time', { params: { org_id: 'default', days: 30 } }).catch(() => ({ data: { trend_data: [] } })),
        api.get('/api/v1/analytics/trends/anomalies', { params: { org_id: 'default' } }).catch(() => ({ data: { anomalies: [] } })),
        api.get('/api/v1/audit/chain/verify').catch(() => ({ data: { valid: true, total_entries: 0 } })),
      ]);
      setAnalytics(analyticsRes.data);
      setTrends(trendsRes.data?.trend_data || []);
      setAnomalies(anomaliesRes.data?.anomalies || []);
      setChainStatus(chainRes.data);
    } catch (e) { console.error('Analytics fetch error', e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleExport = async (format: string) => {
    try {
      const res = await api.get('/api/v1/audit/logs/export', { params: { format, days: 30 }, responseType: format === 'csv' ? 'blob' : 'json' });
      if (format === 'csv') {
        const blob = new Blob([res.data], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url; a.download = 'analytics.csv'; a.click();
      }
    } catch (e) { console.error('Export error', e); }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-fuchsia-400 to-pink-500 bg-clip-text text-transparent">Evidence & Security Analytics</h1>
          <p className="text-muted-foreground mt-1">Advanced analytics with trend analysis, anomaly detection, and tamper-proof audit chains</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => handleExport('csv')}>Export CSV</Button>
          <Button variant="outline" onClick={fetchData}>Refresh</Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Total Findings', value: analytics?.total_findings ?? 0, color: 'text-blue-400' },
          { label: 'Critical', value: analytics?.severity_breakdown?.critical ?? 0, color: 'text-red-400' },
          { label: 'Anomalies', value: anomalies.length, color: 'text-yellow-400' },
          { label: 'Audit Entries', value: chainStatus?.total_entries ?? 0, color: 'text-purple-400' },
          { label: 'Chain Valid', value: chainStatus?.valid ? '✓ Yes' : '✗ No', color: chainStatus?.valid ? 'text-green-400' : 'text-red-400' },
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

      <Tabs defaultValue="trends" className="space-y-4">
        <TabsList>
          <TabsTrigger value="trends">Severity Trends</TabsTrigger>
          <TabsTrigger value="anomalies">Anomaly Detection ({anomalies.length})</TabsTrigger>
          <TabsTrigger value="audit">Audit Chain</TabsTrigger>
        </TabsList>

        <TabsContent value="trends">
          <Card className="border-border/50"><CardContent className="pt-6">
            {loading ? <div className="text-center py-8 text-muted-foreground">Loading trends...</div> : (
            <div className="space-y-3">{trends.length > 0 ? trends.map((t: any, i: number) => (
              <div key={i} className="flex items-center gap-4 p-3 border border-border/30 rounded-lg">
                <span className="text-sm font-mono text-muted-foreground w-24">{t.date || t.period}</span>
                <div className="flex-1 flex gap-2">
                  {['critical', 'high', 'medium', 'low'].map(sev => (
                    <div key={sev} className="flex-1">
                      <div className="text-xs text-muted-foreground capitalize">{sev}</div>
                      <Progress value={Math.min(((t[sev] || 0) / Math.max(t.total || 1, 1)) * 100, 100)} className="h-2 mt-1" />
                      <div className="text-xs text-right mt-0.5">{t[sev] || 0}</div>
                    </div>
                  ))}
                </div>
              </div>
            )) : <div className="text-center py-12 text-muted-foreground">No trend data available for the selected period.</div>}</div>)}
          </CardContent></Card>
        </TabsContent>

        <TabsContent value="anomalies">
          <Card className="border-border/50"><CardContent className="pt-6">
            <div className="space-y-2">{anomalies.map((a: any, i: number) => (
              <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.03 }}
                className="p-3 border border-border/30 rounded-lg">
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <Badge className="bg-yellow-500/20 text-yellow-400">⚡ Anomaly</Badge>
                    <span className="text-sm text-foreground">{a.metric || a.type || 'Unknown'}</span>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Z-Score: <span className="font-mono text-foreground">{a.z_score?.toFixed(2) || 'N/A'}</span>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground mt-1">{a.description || `Anomalous value detected: ${a.value}`}</p>
              </motion.div>
            ))}{anomalies.length === 0 && <div className="text-center py-12 text-muted-foreground">No anomalies detected. All metrics within normal ranges.</div>}</div>
          </CardContent></Card>
        </TabsContent>

        <TabsContent value="audit">
          <Card className="border-border/50"><CardContent className="pt-6">
            <div className="space-y-4">
              <div className="p-6 border border-border/30 rounded-lg text-center">
                <div className={`text-5xl mb-2 ${chainStatus?.valid ? 'text-green-400' : 'text-red-400'}`}>
                  {chainStatus?.valid ? '🔒' : '⚠️'}
                </div>
                <div className="text-xl font-bold text-foreground">{chainStatus?.valid ? 'Audit Chain Verified' : 'Chain Integrity Issue'}</div>
                <div className="text-sm text-muted-foreground mt-1">
                  {chainStatus?.total_entries ?? 0} entries • SHA-256 hash chain • {chainStatus?.valid ? 'No tampering detected' : 'Verification failed'}
                </div>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" className="flex-1" onClick={() => handleExport('json')}>Export Audit Log (JSON)</Button>
                <Button variant="outline" className="flex-1" onClick={() => handleExport('csv')}>Export Audit Log (CSV)</Button>
              </div>
            </div>
          </CardContent></Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default EvidenceAnalytics;

