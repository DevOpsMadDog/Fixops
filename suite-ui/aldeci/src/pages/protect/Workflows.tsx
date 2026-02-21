import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const Workflows = () => {
  const [workflows, setWorkflows] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchWorkflows();
  }, []);

  const fetchWorkflows = async () => {
    setLoading(true);
    try {
      const data = await api.protect.workflows.list();
      setWorkflows(data || []);
    } catch (error) {
      console.error('Failed to fetch workflows', error);
    } finally {
      setLoading(false);
    }
  };

  const handleExecute = async (id: string) => {
    try {
      await api.protect.workflows.execute(id);
      fetchWorkflows();
    } catch (error) {
      console.error('Failed to execute workflow', error);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Automation Workflows</h1>
        <Button>Create Workflow</Button>
      </div>

      <Card>
        <CardHeader><CardTitle>Configured Workflows</CardTitle></CardHeader>
        <CardContent>
          {loading ? <div>Loading...</div> : (
            <div className="space-y-4">
              {workflows.map((wf: any) => (
                <div key={wf.id} className="p-4 border rounded-lg flex justify-between items-center">
                  <div>
                    <div className="font-bold">{wf.name}</div>
                    <div className="text-sm text-muted-foreground">{wf.description || 'No description'}</div>
                    <div className="text-xs mt-1">Trigger: {wf.trigger}</div>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className={`px-2 py-1 rounded text-xs ${wf.enabled ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
                      {wf.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                    <Button variant="outline" size="sm" onClick={() => handleExecute(wf.id)}>Run</Button>
                  </div>
                </div>
              ))}
              {workflows.length === 0 && <div className="text-center text-muted-foreground py-8">No workflows configured.</div>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Workflows;
