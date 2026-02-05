import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const Policies = () => {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchPolicies();
  }, []);

  const fetchPolicies = async () => {
    setLoading(true);
    try {
      const data = await api.ai.policies.list();
      setPolicies(data || []);
    } catch (error) {
      console.error('Failed to fetch policies', error);
    } finally {
      setLoading(false);
    }
  };

  const handleValidate = async (id: string) => {
    try {
      await api.ai.policies.validate(id);
      fetchPolicies();
    } catch (error) {
      console.error('Validation failed', error);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Policy Engine</h1>
        <Button>Create Policy</Button>
      </div>

      <Card>
        <CardHeader><CardTitle>Security Policies</CardTitle></CardHeader>
        <CardContent>
          {loading ? <div>Loading...</div> : (
            <div className="space-y-4">
              {policies.map((policy: any) => (
                <div key={policy.id} className="p-4 border rounded-lg">
                  <div className="flex justify-between items-start">
                    <div>
                      <div className="font-bold">{policy.name}</div>
                      <div className="text-sm text-muted-foreground">{policy.description || 'No description'}</div>
                      <div className="text-xs mt-2">
                        {policy.rules?.length || 0} rules
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className={`px-2 py-1 rounded text-xs ${policy.enabled ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
                        {policy.enabled ? 'Active' : 'Inactive'}
                      </span>
                      <Button variant="outline" size="sm" onClick={() => handleValidate(policy.id)}>Validate</Button>
                    </div>
                  </div>
                </div>
              ))}
              {policies.length === 0 && <div className="text-center text-muted-foreground py-8">No policies defined.</div>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Policies;
