import { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const Reachability = () => {
  const [cveId, setCveId] = useState('');
  const [repository, setRepository] = useState('https://github.com/example/repo');
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async () => {
    if (!cveId) return;
    setLoading(true);
    try {
      const data = await api.attack.reachability.analyze({ cve_id: cveId, repository });
      setResults(data);
    } catch (error) {
      console.error('Reachability analysis failed', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchExisting = async () => {
    if (!cveId) return;
    try {
      const data = await api.attack.reachability.getResults(cveId);
      setResults(data);
    } catch (error) {
      console.error('No existing results', error);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">Reachability Analysis</h1>
      <p className="text-muted-foreground">Determine if a CVE is reachable from your network perimeter</p>

      <Card>
        <CardHeader><CardTitle>Analyze CVE Reachability</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-4">
            <input
              type="text"
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              placeholder="CVE ID (e.g., CVE-2024-1234)"
              className="flex-1 px-4 py-2 border rounded-lg"
            />
            <input
              type="text"
              value={repository}
              onChange={(e) => setRepository(e.target.value)}
              placeholder="Repository URL"
              className="flex-1 px-4 py-2 border rounded-lg"
            />
            <Button onClick={handleAnalyze} disabled={loading || !cveId}>
              {loading ? 'Analyzing...' : 'Analyze'}
            </Button>
            <Button variant="outline" onClick={fetchExisting} disabled={!cveId}>
              Get Cached Results
            </Button>
          </div>
        </CardContent>
      </Card>

      {results && (
        <Card>
          <CardHeader><CardTitle>Results for {cveId}</CardTitle></CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-6">
              <div>
                <div className="text-sm text-muted-foreground">Reachable</div>
                <div className={`text-2xl font-bold ${results.reachable ? 'text-red-600' : 'text-green-600'}`}>
                  {results.reachable ? 'YES' : 'NO'}
                </div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Confidence</div>
                <div className="text-2xl font-bold">{results.confidence || 'N/A'}%</div>
              </div>
            </div>
            {results.paths && results.paths.length > 0 && (
              <div className="mt-6">
                <h4 className="font-semibold mb-2">Attack Paths</h4>
                <div className="space-y-2">
                  {results.paths.map((path: any, idx: number) => (
                    <div key={idx} className="p-3 bg-gray-50 rounded text-sm font-mono">
                      {path.join(' → ')}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default Reachability;
