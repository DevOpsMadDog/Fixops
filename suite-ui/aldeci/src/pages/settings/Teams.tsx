import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const Teams = () => {
  const [teams, setTeams] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchTeams = async () => {
      try {
        const data = await api.settings.access.teams();
        setTeams(data || []);
      } catch (error) {
        console.error('Failed to fetch teams', error);
      } finally {
        setLoading(false);
      }
    };
    fetchTeams();
  }, []);

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Team Management</h1>
        <Button>Create Team</Button>
      </div>

      <Card>
        <CardHeader><CardTitle>Teams</CardTitle></CardHeader>
        <CardContent>
          {loading ? <div>Loading...</div> : (
            <div className="space-y-4">
              {teams.map((team: any) => (
                <div key={team.id} className="p-4 border rounded-lg flex justify-between items-center">
                  <div>
                    <div className="font-bold">{team.name}</div>
                    <div className="text-sm text-muted-foreground">{team.description || 'No description'}</div>
                    <div className="text-xs mt-1">{team.member_count || 0} members</div>
                  </div>
                  <Button variant="outline" size="sm">Manage</Button>
                </div>
              ))}
              {teams.length === 0 && <div className="text-center text-muted-foreground py-8">No teams found.</div>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Teams;
