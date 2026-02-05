import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const Users = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const data = await api.settings.access.users();
        setUsers(data || []);
      } catch (error) {
        console.error('Failed to fetch users', error);
      } finally {
        setLoading(false);
      }
    };
    fetchUsers();
  }, []);

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">User Management</h1>
        <Button>Add User</Button>
      </div>

      <Card>
        <CardHeader><CardTitle>Users</CardTitle></CardHeader>
        <CardContent>
          {loading ? <div>Loading...</div> : (
            <div className="space-y-4">
              {users.map((user: any) => (
                <div key={user.id} className="p-4 border rounded-lg flex justify-between items-center">
                  <div>
                    <div className="font-bold">{user.name || user.email}</div>
                    <div className="text-sm text-muted-foreground">{user.email}</div>
                    <div className="text-xs mt-1">{user.role}</div>
                  </div>
                  <Button variant="outline" size="sm">Edit</Button>
                </div>
              ))}
              {users.length === 0 && <div className="text-center text-muted-foreground py-8">No users found.</div>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Users;
