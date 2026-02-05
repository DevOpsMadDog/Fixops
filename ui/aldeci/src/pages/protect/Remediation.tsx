import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const Remediation = () => {
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchTasks();
  }, []);

  const fetchTasks = async () => {
    setLoading(true);
    try {
      const data = await api.protect.remediation.getTasks();
      setTasks(data || []);
    } catch (error) {
      console.error('Failed to fetch tasks', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'bg-red-100 text-red-800';
      case 'in_progress': return 'bg-yellow-100 text-yellow-800';
      case 'resolved': return 'bg-green-100 text-green-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Remediation Center</h1>
        <Button onClick={fetchTasks}>Refresh</Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-4xl font-bold">{tasks.length}</div>
            <div className="text-sm text-muted-foreground">Total Tasks</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-4xl font-bold text-red-600">
              {tasks.filter((t: any) => t.status === 'open').length}
            </div>
            <div className="text-sm text-muted-foreground">Open</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-4xl font-bold text-yellow-600">
              {tasks.filter((t: any) => t.status === 'in_progress').length}
            </div>
            <div className="text-sm text-muted-foreground">In Progress</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-4xl font-bold text-green-600">
              {tasks.filter((t: any) => t.status === 'resolved').length}
            </div>
            <div className="text-sm text-muted-foreground">Resolved</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle>All Tasks</CardTitle></CardHeader>
        <CardContent>
          {loading ? <div>Loading...</div> : (
            <div className="space-y-4">
              {tasks.map((task: any) => (
                <div key={task.id} className="p-4 border rounded-lg">
                  <div className="flex justify-between items-start">
                    <div>
                      <div className="font-bold">{task.title || task.cve_id || 'Untitled Task'}</div>
                      <div className="text-sm text-muted-foreground">{task.description || 'No description'}</div>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-xs ${getStatusColor(task.status)}`}>
                      {task.status}
                    </span>
                  </div>
                  {task.assignee && <div className="mt-2 text-sm">Assigned to: {task.assignee}</div>}
                </div>
              ))}
              {tasks.length === 0 && <div className="text-center text-muted-foreground py-8">No remediation tasks found.</div>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Remediation;
