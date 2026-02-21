import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import api from '../../lib/api';

const ThreatFeeds = () => {
  const [epss, setEpss] = useState([]);
  const [kev, setKev] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [epssData, kevData] = await Promise.all([
          api.cloud.feeds.getEPSS(),
          api.cloud.feeds.getKEV()
        ]);
        setEpss(epssData || []);
        setKev(kevData || []);
      } catch (error) {
        console.error('Failed to fetch feeds', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">Threat Intelligence Feeds</h1>
      
      <Tabs defaultValue="epss">
        <TabsList>
          <TabsTrigger value="epss">EPSS Scores</TabsTrigger>
          <TabsTrigger value="kev">CISA KEV</TabsTrigger>
        </TabsList>
        
        <TabsContent value="epss" className="space-y-4">
          <Card>
            <CardHeader><CardTitle>Exploit Prediction Scoring System</CardTitle></CardHeader>
            <CardContent>
              {loading ? <div>Loading...</div> : (
                <div className="grid gap-2">
                  {/* Mock rendering if array is empty or simple list */}
                  {Array.isArray(epss) && epss.length > 0 ? epss.map((item: any) => (
                    <div key={item.cve} className="p-2 border-b flex justify-between">
                      <span>{item.cve}</span>
                      <span className="font-mono">{(item.score * 100).toFixed(2)}%</span>
                    </div>
                  )) : <div className="text-muted-foreground">No EPSS data loaded.</div>}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="kev" className="space-y-4">
           <Card>
            <CardHeader><CardTitle>Known Exploited Vulnerabilities</CardTitle></CardHeader>
            <CardContent>
               {loading ? <div>Loading...</div> : (
                <div className="grid gap-2">
                   {Array.isArray(kev) && kev.length > 0 ? kev.map((item: any) => (
                    <div key={item.cveID} className="p-2 border-b">
                      <div className="font-semibold">{item.cveID}</div>
                      <div className="text-sm text-gray-500">{item.vulnerabilityName}</div>
                    </div>
                  )) : <div className="text-muted-foreground">No KEV entries found.</div>}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ThreatFeeds;
