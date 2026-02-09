import { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const Predictions = () => {
  const [cveIds, setCveIds] = useState('');
  const [trajectory, setTrajectory] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const runPrediction = async () => {
    if (!cveIds) return;
    setLoading(true);
    try {
      const ids = cveIds.split(',').map(s => s.trim());
      const result = await api.ai.predictions.riskTrajectory({ cve_ids: ids });
      setTrajectory(result);
    } catch (error) {
      console.error('Prediction failed', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">Risk Predictions</h1>
      <p className="text-muted-foreground">Markov Chain and Bayesian Network predictions for risk trajectory</p>

      <Card>
        <CardHeader><CardTitle>Predict Risk Trajectory</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <input
            type="text"
            value={cveIds}
            onChange={(e) => setCveIds(e.target.value)}
            placeholder="Enter CVE IDs (comma-separated)"
            className="w-full px-4 py-2 border rounded-lg"
          />
          <Button onClick={runPrediction} disabled={loading || !cveIds}>
            {loading ? 'Predicting...' : 'Run Prediction'}
          </Button>
        </CardContent>
      </Card>

      {trajectory && (
        <Card>
          <CardHeader><CardTitle>Trajectory Results</CardTitle></CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-6 mb-6">
              <div>
                <div className="text-sm text-muted-foreground">Current Risk</div>
                <div className="text-3xl font-bold">{trajectory.current_risk?.toFixed(2) || 'N/A'}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground">30-Day Forecast</div>
                <div className="text-3xl font-bold">{trajectory.forecast_30d?.toFixed(2) || 'N/A'}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Trend</div>
                <div className={`text-3xl font-bold ${trajectory.trend === 'increasing' ? 'text-red-600' : trajectory.trend === 'decreasing' ? 'text-green-600' : 'text-yellow-600'}`}>
                  {trajectory.trend || 'Stable'}
                </div>
              </div>
            </div>
            <pre className="text-xs bg-gray-50 p-4 rounded overflow-auto max-h-64">
              {JSON.stringify(trajectory, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default Predictions;
