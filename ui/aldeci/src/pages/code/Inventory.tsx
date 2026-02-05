import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import api from '../../lib/api';

const Inventory = () => {
  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await api.code.inventory.getApplications();
        setApps(data);
      } catch (error) {
        console.error('Failed to fetch inventory', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Asset Inventory</h1>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Applications ({apps.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
             <div>Loading assets...</div>
          ) : (
            <div className="space-y-4">
              {apps.map((app: any) => (
                <div key={app.id || Math.random()} className="p-4 border rounded-lg flex justify-between">
                  <span>{app.name || 'Unnamed App'}</span>
                  <span className="text-muted-foreground">{app.type || 'Service'}</span>
                </div>
              ))}
              {apps.length === 0 && <div className="text-center text-muted-foreground">No applications found.</div>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Inventory;
