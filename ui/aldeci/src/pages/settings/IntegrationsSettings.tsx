import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const IntegrationsSettings = () => {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIntegrations();
  }, []);

  const fetchIntegrations = async () => {
    setLoading(true);
    try {
      const data = await api.settings.integrations.list();
      setIntegrations(data || []);
    } catch (error) {
      console.error('Failed to fetch integrations', error);
    } finally {
      setLoading(false);
    }
  };

  const handleTest = async (id: string) => {
    try {
      const result = await api.settings.integrations.test(id);
      alert(`Test result: ${result.success ? 'SUCCESS' : 'FAILED'}`);
    } catch (error) {
      console.error('Test failed', error);
    }
  };

  const integrationTypes = [
    { id: 'jira', name: 'Jira', icon: '📋', status: 'connected' },
    { id: 'servicenow', name: 'ServiceNow', icon: '🎫', status: 'available' },
    { id: 'gitlab', name: 'GitLab', icon: '🦊', status: 'available' },
    { id: 'github', name: 'GitHub', icon: '🐙', status: 'available' },
    { id: 'azure-devops', name: 'Azure DevOps', icon: '☁️', status: 'available' },
    { id: 'slack', name: 'Slack', icon: '💬', status: 'connected' },
    { id: 'confluence', name: 'Confluence', icon: '📝', status: 'connected' },
  ];

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">Integrations</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {integrationTypes.map((integration) => (
          <Card key={integration.id}>
            <CardContent className="pt-6">
              <div className="flex items-center gap-4 mb-4">
                <div className="text-4xl">{integration.icon}</div>
                <div>
                  <div className="font-bold">{integration.name}</div>
                  <span className={`text-xs px-2 py-1 rounded ${integration.status === 'connected' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
                    {integration.status}
                  </span>
                </div>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" className="flex-1">Configure</Button>
                {integration.status === 'connected' && (
                  <Button variant="outline" size="sm" onClick={() => handleTest(integration.id)}>Test</Button>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader><CardTitle>Configured Integrations</CardTitle></CardHeader>
        <CardContent>
          {loading ? <div>Loading...</div> : (
            <div className="space-y-4">
              {integrations.map((int: any) => (
                <div key={int.id} className="p-4 border rounded-lg flex justify-between items-center">
                  <div>
                    <div className="font-bold">{int.name || int.type}</div>
                    <div className="text-sm text-muted-foreground">{int.url || int.endpoint}</div>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => handleTest(int.id)}>Test</Button>
                    <Button variant="outline" size="sm">Edit</Button>
                  </div>
                </div>
              ))}
              {integrations.length === 0 && <div className="text-muted-foreground">No integrations configured yet.</div>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default IntegrationsSettings;
