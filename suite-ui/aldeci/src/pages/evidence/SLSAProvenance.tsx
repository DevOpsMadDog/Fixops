import { useEffect, useState, useCallback } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { motion } from 'framer-motion';
import { api } from '../../lib/api';

const levelColor = (level: number) => {
  if (level >= 3) return 'bg-green-500/20 text-green-400';
  if (level >= 2) return 'bg-yellow-500/20 text-yellow-400';
  if (level >= 1) return 'bg-orange-500/20 text-orange-400';
  return 'bg-red-500/20 text-red-400';
};

const SLSAProvenance = () => {
  const [attestations, setAttestations] = useState<any[]>([]);
  const [bundles, setBundles] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [attRes, bundleRes, statsRes] = await Promise.all([
        api.get('/api/v1/provenance/').catch(() => ({ data: { attestations: [] } })),
        api.get('/api/v1/evidence/', { params: { org_id: 'default', limit: 20 } }).catch(() => ({ data: { bundles: [] } })),
        api.get('/api/v1/evidence/stats').catch(() => ({ data: {} })),
      ]);
      setAttestations(attRes.data?.attestations || attRes.data || []);
      setBundles(bundleRes.data?.bundles || bundleRes.data || []);
      setStats(statsRes.data);
    } catch (e) { console.error('Provenance fetch error', e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-400 to-violet-500 bg-clip-text text-transparent">SLSA Provenance & Attestations</h1>
          <p className="text-muted-foreground mt-1">SLSA v1 supply chain provenance, in-toto attestations, and WORM-compliant storage</p>
        </div>
        <Button variant="outline" onClick={fetchData}>Refresh</Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Attestations', value: attestations.length, color: 'text-indigo-400' },
          { label: 'Evidence Bundles', value: bundles.length, color: 'text-purple-400' },
          { label: 'WORM Stored', value: stats?.worm_count ?? bundles.length, color: 'text-green-400' },
          { label: 'Verified', value: stats?.verified_count ?? 0, color: 'text-cyan-400' },
          { label: 'Avg SLSA Level', value: stats?.avg_slsa_level?.toFixed(1) ?? 'N/A', color: 'text-yellow-400' },
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

      <Tabs defaultValue="attestations" className="space-y-4">
        <TabsList>
          <TabsTrigger value="attestations">Attestations ({attestations.length})</TabsTrigger>
          <TabsTrigger value="bundles">Evidence Bundles ({bundles.length})</TabsTrigger>
          <TabsTrigger value="slsa">SLSA Levels</TabsTrigger>
        </TabsList>
        <TabsContent value="attestations">
          <Card className="border-border/50"><CardContent className="pt-6">
            {loading ? <div className="text-center py-8 text-muted-foreground">Loading...</div> : (
            <div className="space-y-3">{attestations.slice(0, 20).map((att: any, i: number) => (
              <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.03 }}
                className="p-4 border border-border/30 rounded-lg">
                <div className="flex justify-between items-start">
                  <div>
                    <div className="font-semibold text-foreground">{att.subject || att.artifact || `attestation-${i}`}</div>
                    <div className="text-xs text-muted-foreground mt-1">Type: {att.predicate_type || 'in-toto'} • Builder: {att.builder_id || 'N/A'}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={levelColor(att.slsa_level || 0)}>SLSA L{att.slsa_level || 0}</Badge>
                    {att.verified && <Badge className="bg-green-500/20 text-green-400">✓ Verified</Badge>}
                  </div>
                </div>
              </motion.div>
            ))}{attestations.length === 0 && <div className="text-center py-12 text-muted-foreground">No attestations found.</div>}</div>)}
          </CardContent></Card>
        </TabsContent>
        <TabsContent value="bundles">
          <Card className="border-border/50"><CardContent className="pt-6">
            <div className="space-y-3">{bundles.slice(0, 20).map((b: any, i: number) => (
              <div key={i} className="p-4 border border-border/30 rounded-lg flex justify-between items-center">
                <div>
                  <div className="font-semibold text-foreground">{b.name || b.bundle_id || `bundle-${i}`}</div>
                  <div className="text-xs text-muted-foreground">Items: {b.item_count || 0} • Size: {b.size || 'N/A'} • {b.created_at ? new Date(b.created_at).toLocaleDateString() : ''}</div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge className={b.worm_locked ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}>{b.worm_locked ? '🔒 WORM' : 'Mutable'}</Badge>
                  <Badge variant="outline">{b.storage_backend || 'local'}</Badge>
                </div>
              </div>
            ))}{bundles.length === 0 && <div className="text-center py-12 text-muted-foreground">No evidence bundles.</div>}</div>
          </CardContent></Card>
        </TabsContent>
        <TabsContent value="slsa">
          <Card className="border-border/50"><CardContent className="pt-6">
            <div className="space-y-4">
              {[
                { level: 0, name: 'No Guarantees', desc: 'No SLSA level achieved' },
                { level: 1, name: 'Build Process Documented', desc: 'Documentation of the build process exists' },
                { level: 2, name: 'Hosted Build Platform', desc: 'Build runs on hosted platform with signed provenance' },
                { level: 3, name: 'Hardened Builds', desc: 'Source and build platform integrity verified' },
              ].map(sl => {
                const count = attestations.filter((a: any) => (a.slsa_level || 0) >= sl.level).length;
                return (
                  <div key={sl.level} className="flex items-center gap-4 p-3 border border-border/30 rounded-lg">
                    <Badge className={`w-24 justify-center ${levelColor(sl.level)}`}>SLSA L{sl.level}</Badge>
                    <div className="flex-1">
                      <div className="text-sm font-medium text-foreground">{sl.name}</div>
                      <div className="text-xs text-muted-foreground">{sl.desc}</div>
                    </div>
                    <Progress value={attestations.length ? (count / attestations.length) * 100 : 0} className="w-32 h-2" />
                    <span className="text-sm w-10 text-right text-muted-foreground">{count}</span>
                  </div>
                );
              })}
            </div>
          </CardContent></Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SLSAProvenance;

