import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { toast } from 'sonner';
import api from '../../lib/api';

interface PentestRequest {
  id: string;
  finding_id?: string;
  target_url?: string;
  target?: string;
  name?: string;
  vulnerability_type?: string;
  test_case?: string;
  priority: string;
  status: string;
  created_at?: string;
  started_at?: string;
  completed_at?: string;
  requested_by?: string;
  severity_found?: string;
  findings_count?: number;
}

interface PentestResult {
  id: string;
  request_id: string;
  finding_id?: string;
  exploitability: string;
  exploit_successful?: boolean;
  evidence: string;
  risk_score?: number;
  confidence_score?: number;
  steps_taken?: string[];
}

const MPTEConsole = () => {
  const [requests, setRequests] = useState<PentestRequest[]>([]);
  const [results, setResults] = useState<PentestResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [target, setTarget] = useState('');
  const [summary, setSummary] = useState<Record<string, number>>({});

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [reqData, resData] = await Promise.all([
        api.attack.mpte.getRequests(),
        api.attack.mpte.getResults()
      ]);
      
      // Handle both response formats: {items: [...]} or {requests: [...]} or direct array
      const reqItems = reqData?.items || reqData?.requests || (Array.isArray(reqData) ? reqData : []);
      const resItems = resData?.items || resData?.results || (Array.isArray(resData) ? resData : []);
      
      setRequests(reqItems);
      setResults(resItems);
      
      // Set summary if available
      if (reqData?.summary) {
        setSummary(reqData.summary);
      }
    } catch (error) {
      console.error('Failed to fetch MPTE data', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateRequest = async () => {
    if (!target) return;
    try {
      const result = await api.attack.mpte.createRequest({
        finding_id: `finding-${Date.now()}`,
        target_url: target,
        vulnerability_type: 'general',
        test_case: 'automated-pentest',
        priority: 'high'
      });
      toast.success(`Pentest request created: ${result?.id?.slice(0, 8) || 'OK'}`);
      setTarget('');
      fetchData();
    } catch (error: any) {
      const msg = error?.response?.data?.detail || error?.message || 'Unknown error';
      toast.error(`Failed to create request: ${msg}`);
      console.error('Failed to create request', error);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'completed': return 'bg-green-500/20 text-green-400 dark:text-green-300';
      case 'running':
      case 'in_progress': return 'bg-blue-500/20 text-blue-400 dark:text-blue-300';
      case 'pending': return 'bg-yellow-500/20 text-yellow-400 dark:text-yellow-300';
      case 'failed':
      case 'cancelled': return 'bg-red-500/20 text-red-400 dark:text-red-300';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getExploitabilityColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'confirmed':
      case 'exploitable': return 'bg-red-500/20 text-red-400 dark:text-red-300';
      case 'likely': return 'bg-orange-500/20 text-orange-400 dark:text-orange-300';
      case 'possible': return 'bg-yellow-500/20 text-yellow-400 dark:text-yellow-300';
      case 'not_exploitable': return 'bg-green-500/20 text-green-400 dark:text-green-300';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">🔐 MPTE Console</h1>
        <Button variant="outline" onClick={fetchData}>Refresh</Button>
      </div>

      {/* Summary Stats */}
      {Object.keys(summary).length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <Card>
            <CardContent className="pt-4 text-center">
              <div className="text-2xl font-bold">{summary.total || 0}</div>
              <div className="text-sm text-muted-foreground">Total</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <div className="text-2xl font-bold text-yellow-600">{summary.pending || 0}</div>
              <div className="text-sm text-muted-foreground">Pending</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <div className="text-2xl font-bold text-blue-600">{summary.in_progress || 0}</div>
              <div className="text-sm text-muted-foreground">In Progress</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <div className="text-2xl font-bold text-green-600">{summary.completed || 0}</div>
              <div className="text-sm text-muted-foreground">Completed</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <div className="text-2xl font-bold text-purple-600">{summary.scheduled || 0}</div>
              <div className="text-sm text-muted-foreground">Scheduled</div>
            </CardContent>
          </Card>
        </div>
      )}

      <Card>
        <CardHeader><CardTitle>New Pentest Request</CardTitle></CardHeader>
        <CardContent className="flex gap-4">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Target URL or IP (e.g., https://app.example.com)"
            className="flex-1 px-4 py-2 border rounded-lg bg-background text-foreground"
          />
          <Button onClick={handleCreateRequest} disabled={!target.trim()}>
            Create Request
          </Button>
        </CardContent>
      </Card>

      <Tabs defaultValue="requests">
        <TabsList>
          <TabsTrigger value="requests">Requests ({requests.length})</TabsTrigger>
          <TabsTrigger value="results">Results ({results.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="requests" className="space-y-4 mt-4">
          {loading ? (
            <div className="flex justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary"></div>
            </div>
          ) : requests.map((req) => (
            <Card key={req.id}>
              <CardContent className="p-4">
                <div className="flex justify-between items-start">
                  <div className="space-y-1">
                    <div className="font-bold text-lg">{req.name || req.target_url || req.target}</div>
                    {req.vulnerability_type && (
                      <div className="text-sm text-muted-foreground">Type: {req.vulnerability_type}</div>
                    )}
                    <div className="flex gap-2 text-xs">
                      <span className="px-2 py-0.5 bg-muted text-muted-foreground rounded">Priority: {req.priority}</span>
                      {req.finding_id && <span className="px-2 py-0.5 bg-blue-500/10 text-blue-400 rounded">Finding: {req.finding_id}</span>}
                      {req.requested_by && <span className="px-2 py-0.5 bg-purple-500/10 text-purple-400 rounded">{req.requested_by}</span>}
                    </div>
                    {req.created_at && (
                      <div className="text-xs text-muted-foreground">
                        Created: {new Date(req.created_at).toLocaleString()}
                      </div>
                    )}
                  </div>
                  <div className="text-right space-y-2">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(req.status)}`}>
                      {req.status?.replace('_', ' ').toUpperCase()}
                    </span>
                    {req.findings_count !== undefined && req.findings_count > 0 && (
                      <div className="text-sm">
                        <span className="font-medium">{req.findings_count}</span> findings
                        {req.severity_found && (
                          <span className={`ml-2 px-2 py-0.5 rounded text-xs ${
                            req.severity_found === 'critical' ? 'bg-red-500/20 text-red-400' :
                            req.severity_found === 'high' ? 'bg-orange-500/20 text-orange-400' :
                            'bg-yellow-500/20 text-yellow-400'
                          }`}>{req.severity_found}</span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
          {requests.length === 0 && !loading && (
            <div className="text-muted-foreground text-center py-12">
              <div className="text-4xl mb-4">🔍</div>
              <p>No pentest requests yet.</p>
              <p className="text-sm">Create a new request to start penetration testing.</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="results" className="space-y-4 mt-4">
          {loading ? (
            <div className="flex justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary"></div>
            </div>
          ) : results.map((res) => (
            <Card key={res.id}>
              <CardContent className="p-4">
                <div className="flex justify-between items-start">
                  <div className="space-y-2">
                    <div className="font-bold">Request: {res.request_id}</div>
                    {res.finding_id && (
                      <div className="text-sm text-muted-foreground">Finding: {res.finding_id}</div>
                    )}
                    <span className={`inline-block px-3 py-1 rounded-full text-xs font-medium ${getExploitabilityColor(res.exploitability)}`}>
                      {res.exploitability?.replace('_', ' ').toUpperCase()}
                    </span>
                    {res.exploit_successful !== undefined && (
                      <span className={`ml-2 px-2 py-0.5 rounded text-xs ${res.exploit_successful ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
                        {res.exploit_successful ? '⚠️ Exploit Successful' : '✅ Not Exploited'}
                      </span>
                    )}
                  </div>
                  <div className="text-right">
                    {res.risk_score !== undefined && (
                      <div className="text-2xl font-mono font-bold">{res.risk_score}</div>
                    )}
                    {res.confidence_score !== undefined && (
                      <div className="text-xs text-muted-foreground">
                        Confidence: {(res.confidence_score * 100).toFixed(0)}%
                      </div>
                    )}
                  </div>
                </div>
                {res.steps_taken && res.steps_taken.length > 0 && (
                  <div className="mt-3">
                    <div className="text-xs font-medium mb-1">Steps Taken:</div>
                    <ul className="text-xs text-muted-foreground list-disc list-inside">
                      {res.steps_taken.map((step, i) => <li key={i}>{step}</li>)}
                    </ul>
                  </div>
                )}
                {res.evidence && (
                  <details className="mt-3">
                    <summary className="text-xs font-medium cursor-pointer">View Evidence</summary>
                    <pre className="mt-2 text-xs bg-muted p-3 rounded overflow-auto max-h-48 text-foreground">
                      {res.evidence}
                    </pre>
                  </details>
                )}
              </CardContent>
            </Card>
          ))}
          {results.length === 0 && !loading && (
            <div className="text-muted-foreground text-center py-12">
              <div className="text-4xl mb-4">📋</div>
              <p>No results available yet.</p>
              <p className="text-sm">Results will appear here once pentest requests are completed.</p>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default MPTEConsole;
