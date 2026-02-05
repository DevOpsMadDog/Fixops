import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const Reports = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    setLoading(true);
    try {
      const data = await api.evidence.reports.list();
      setReports(data || []);
    } catch (error) {
      console.error('Failed to fetch reports', error);
    } finally {
      setLoading(false);
    }
  };

  const generateReport = async (type: string, format: string) => {
    setGenerating(true);
    try {
      await api.evidence.reports.generate({ type, format });
      fetchReports();
    } catch (error) {
      console.error('Failed to generate report', error);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Reports</h1>
        <div className="flex gap-2">
          <Button onClick={() => generateReport('executive', 'pdf')} disabled={generating}>
            Generate Executive PDF
          </Button>
          <Button variant="outline" onClick={() => generateReport('detailed', 'csv')} disabled={generating}>
            Export CSV
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader><CardTitle>Generated Reports</CardTitle></CardHeader>
        <CardContent>
          {loading ? <div>Loading...</div> : (
            <div className="space-y-4">
              {reports.map((report: any) => (
                <div key={report.id} className="p-4 border rounded-lg flex justify-between items-center">
                  <div>
                    <div className="font-bold">{report.name || report.type}</div>
                    <div className="text-sm text-muted-foreground">{report.format?.toUpperCase()} • {report.created_at}</div>
                  </div>
                  <Button variant="outline" size="sm">Download</Button>
                </div>
              ))}
              {reports.length === 0 && <div className="text-center text-muted-foreground py-8">No reports generated yet.</div>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Reports;
