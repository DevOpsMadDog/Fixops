import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const EvidenceBundles = () => {
  const [bundles, setBundles] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchBundles();
  }, []);

  const fetchBundles = async () => {
    setLoading(true);
    try {
      const data = await api.evidence.bundles.list();
      setBundles(data || []);
    } catch (error) {
      console.error('Failed to fetch bundles', error);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (bundleId: string) => {
    try {
      const result = await api.evidence.bundles.verify(bundleId);
      alert(`Verification: ${result.valid ? 'VALID' : 'INVALID'}`);
    } catch (error) {
      console.error('Verification failed', error);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Evidence Bundles</h1>
        <Button onClick={fetchBundles}>Refresh</Button>
      </div>

      <Card>
        <CardHeader><CardTitle>Available Bundles</CardTitle></CardHeader>
        <CardContent>
          {loading ? <div>Loading...</div> : (
            <div className="space-y-4">
              {bundles.map((bundle: any) => (
                <div key={bundle.id || bundle.release} className="p-4 border rounded-lg flex justify-between items-center">
                  <div>
                    <div className="font-bold">{bundle.release || bundle.id}</div>
                    <div className="text-sm text-muted-foreground">{bundle.created_at}</div>
                    <div className="text-xs mt-1">
                      {bundle.signed ? '🔐 Signed' : '⚠️ Unsigned'} | 
                      {bundle.slsa_level ? ` SLSA L${bundle.slsa_level}` : ' No SLSA'}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => handleVerify(bundle.id || bundle.release)}>
                      Verify
                    </Button>
                    <Button variant="outline" size="sm">Download</Button>
                  </div>
                </div>
              ))}
              {bundles.length === 0 && <div className="text-center text-muted-foreground py-8">No evidence bundles found.</div>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default EvidenceBundles;
