import { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import api from '../../lib/api';

const AlgorithmicLab = () => {
  const [cveIds, setCveIds] = useState('');
  const [monteCarloResult, setMonteCarloResult] = useState<any>(null);
  const [causalResult, setCausalResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const runMonteCarlo = async () => {
    if (!cveIds) return;
    setLoading(true);
    try {
      const ids = cveIds.split(',').map(s => s.trim());
      const result = await api.ai.labs.monteCarloQuantify({ cve_ids: ids, simulations: 10000 });
      setMonteCarloResult(result);
    } catch (error) {
      console.error('Monte Carlo failed', error);
    } finally {
      setLoading(false);
    }
  };

  const runCausal = async () => {
    if (!cveIds) return;
    setLoading(true);
    try {
      const ids = cveIds.split(',').map(s => s.trim());
      const result = await api.ai.labs.causalAnalyze({ finding_ids: ids });
      setCausalResult(result);
    } catch (error) {
      console.error('Causal analysis failed', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">Algorithmic Lab</h1>
      <p className="text-muted-foreground">Advanced risk quantification using Monte Carlo FAIR and Causal Inference</p>

      <Card>
        <CardHeader><CardTitle>Input CVE/Finding IDs</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <input
            type="text"
            value={cveIds}
            onChange={(e) => setCveIds(e.target.value)}
            placeholder="CVE-2024-1234, CVE-2024-5678"
            className="w-full px-4 py-2 border rounded-lg"
          />
          <div className="flex gap-4">
            <button onClick={runMonteCarlo} disabled={loading} className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">
              Run Monte Carlo FAIR
            </button>
            <button onClick={runCausal} disabled={loading} className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50">
              Run Causal Analysis
            </button>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {monteCarloResult && (
          <Card>
            <CardHeader><CardTitle>Monte Carlo FAIR Results</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-sm text-muted-foreground">Expected Loss</div>
                    <div className="text-2xl font-bold">${monteCarloResult.expected_loss?.toLocaleString() || 'N/A'}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground">95th Percentile</div>
                    <div className="text-2xl font-bold">${monteCarloResult.p95?.toLocaleString() || 'N/A'}</div>
                  </div>
                </div>
                <pre className="text-xs bg-gray-50 p-2 rounded overflow-auto max-h-48">
                  {JSON.stringify(monteCarloResult, null, 2)}
                </pre>
              </div>
            </CardContent>
          </Card>
        )}

        {causalResult && (
          <Card>
            <CardHeader><CardTitle>Causal Inference Results</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-4">
                {causalResult.root_causes && (
                  <div>
                    <div className="text-sm text-muted-foreground mb-2">Root Causes</div>
                    <div className="space-y-2">
                      {causalResult.root_causes.map((cause: any, idx: number) => (
                        <div key={idx} className="p-2 bg-purple-50 rounded text-sm">
                          {cause.name || cause} - Impact: {cause.impact || 'Unknown'}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <pre className="text-xs bg-gray-50 p-2 rounded overflow-auto max-h-48">
                  {JSON.stringify(causalResult, null, 2)}
                </pre>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

export default AlgorithmicLab;
