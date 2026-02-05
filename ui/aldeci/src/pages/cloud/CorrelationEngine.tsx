import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const CorrelationEngine = () => {
  const [clusters, setClusters] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchClusters = async () => {
    setLoading(true);
    try {
      const data = await api.cloud.correlation.getClusters();
      setClusters(data);
    } catch (error) {
      console.error('Failed to fetch clusters', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchClusters();
  }, []);

  const handleProcess = async () => {
    await api.cloud.correlation.processFinding({ action: 'trigger_deduplication' });
    fetchClusters();
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
         <h1 className="text-3xl font-bold">Correlation & Deduplication</h1>
         <Button onClick={handleProcess}>Run Correlation</Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card>
          <CardHeader><CardTitle>Total Clusters</CardTitle></CardHeader>
          <CardContent className="text-4xl font-bold">{clusters.length}</CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Reduction Rate</CardTitle></CardHeader>
          <CardContent className="text-4xl font-bold">~40%</CardContent>
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader><CardTitle>Active Clusters</CardTitle></CardHeader>
        <CardContent>
           {loading ? <div>Loading clusters...</div> : (
             <div className="space-y-4">
               {clusters.map((cluster: any) => (
                 <div key={cluster.id} className="p-4 border rounded-lg flex items-center justify-between">
                    <div>
                      <div className="font-bold">{cluster.canonical_cve || 'Grouped Issue'}</div>
                      <div className="text-sm text-muted-foreground">{cluster.finding_count} findings merged</div>
                    </div>
                    <div className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-xs">
                      {cluster.status}
                    </div>
                 </div>
               ))}
               {clusters.length === 0 && <div className="text-muted-foreground">No clustered findings.</div>}
             </div>
           )}
        </CardContent>
      </Card>
    </div>
  );
};

export default CorrelationEngine;
