import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const IaCScanning = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await api.code.iac.list();
        setScans(data);
      } catch (error) {
        console.error('Failed to fetch IaC scans', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const handleScan = async () => {
    try {
      await api.cloud.cspm.scan('# Full IaC scan request');
      // Refresh list
      const data = await api.code.iac.list();
      setScans(data);
    } catch (error) {
      console.error('Scan failed', error);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">IaC Scanning</h1>
        <Button onClick={handleScan}>Trigger Scan</Button>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Recent Scans</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div>Loading...</div>
          ) : (
            <div className="space-y-2">
               {scans.map((scan: any) => (
                <div key={scan.id} className="flex justify-between p-3 border rounded">
                  <span>{scan.filename || scan.id}</span>
                  <span className={`px-2 py-1 rounded text-xs ${scan.status === 'secure' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                    {scan.status}
                  </span>
                </div>
              ))}
              {scans.length === 0 && <div className="text-muted-foreground">No past scans found.</div>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default IaCScanning;
