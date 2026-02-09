import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import api from '../../lib/api';

const SystemHealth = () => {
  const [health, setHealth] = useState<any>(null);
  const [version, setVersion] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [healthData, versionData] = await Promise.all([
          api.settings.system.health(),
          api.settings.system.version()
        ]);
        setHealth(healthData);
        setVersion(versionData);
      } catch (error) {
        console.error('Failed to fetch system data', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">System Health</h1>

      {loading ? <div>Loading...</div> : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card>
              <CardContent className="pt-6">
                <div className="text-sm text-muted-foreground">Status</div>
                <div className={`text-3xl font-bold ${health?.status === 'healthy' ? 'text-green-600' : 'text-red-600'}`}>
                  {health?.status?.toUpperCase() || 'UNKNOWN'}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-sm text-muted-foreground">Version</div>
                <div className="text-3xl font-bold">{version?.version || 'N/A'}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-sm text-muted-foreground">Uptime</div>
                <div className="text-3xl font-bold">{health?.uptime || 'N/A'}</div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader><CardTitle>Service Status</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-4">
                {health?.services ? Object.entries(health.services).map(([name, status]: any) => (
                  <div key={name} className="flex justify-between items-center p-3 border rounded-lg">
                    <span className="font-medium">{name}</span>
                    <span className={`px-3 py-1 rounded-full text-xs ${status === 'healthy' || status === 'up' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                      {status}
                    </span>
                  </div>
                )) : (
                  <div className="text-muted-foreground">No service details available</div>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>System Details</CardTitle></CardHeader>
            <CardContent>
              <pre className="text-xs bg-gray-50 p-4 rounded overflow-auto">
                {JSON.stringify({ health, version }, null, 2)}
              </pre>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
};

export default SystemHealth;
