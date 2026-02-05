import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import api from '../../lib/api';

const AuditLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const data = await api.evidence.audit.getLogs({ limit: 100 });
        setLogs(data || []);
      } catch (error) {
        console.error('Failed to fetch audit logs', error);
      } finally {
        setLoading(false);
      }
    };
    fetchLogs();
  }, []);

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">Audit Trail</h1>

      <Card>
        <CardHeader><CardTitle>Recent Activity</CardTitle></CardHeader>
        <CardContent>
          {loading ? <div>Loading...</div> : (
            <div className="space-y-2 max-h-[600px] overflow-auto">
              {logs.map((log: any, idx: number) => (
                <div key={log.id || idx} className="p-3 border-b flex justify-between items-start">
                  <div>
                    <div className="font-semibold text-sm">{log.action || log.event_type}</div>
                    <div className="text-xs text-muted-foreground">{log.user || 'System'} • {log.entity_type}</div>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {new Date(log.timestamp || log.created_at).toLocaleString()}
                  </div>
                </div>
              ))}
              {logs.length === 0 && <div className="text-muted-foreground py-8 text-center">No audit logs found.</div>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default AuditLogs;
