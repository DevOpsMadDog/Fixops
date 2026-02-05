import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import api from '../../lib/api';

const Collaboration = () => {
  const [comments, setComments] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [commentsData, notifData] = await Promise.all([
          api.protect.collaboration.getComments(),
          api.protect.collaboration.getNotifications()
        ]);
        setComments(commentsData || []);
        setNotifications(notifData || []);
      } catch (error) {
        console.error('Failed to fetch collaboration data', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">Collaboration Hub</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader><CardTitle>Recent Comments</CardTitle></CardHeader>
          <CardContent>
            {loading ? <div>Loading...</div> : (
              <div className="space-y-4 max-h-96 overflow-auto">
                {comments.map((comment: any, idx: number) => (
                  <div key={comment.id || idx} className="p-3 bg-gray-50 rounded-lg">
                    <div className="text-sm font-semibold">{comment.author || 'Anonymous'}</div>
                    <div className="text-sm">{comment.content}</div>
                    <div className="text-xs text-muted-foreground mt-1">{comment.entity_type}: {comment.entity_id}</div>
                  </div>
                ))}
                {comments.length === 0 && <div className="text-muted-foreground">No comments yet.</div>}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Pending Notifications</CardTitle></CardHeader>
          <CardContent>
            {loading ? <div>Loading...</div> : (
              <div className="space-y-4 max-h-96 overflow-auto">
                {notifications.map((notif: any, idx: number) => (
                  <div key={notif.id || idx} className="p-3 border-l-4 border-blue-500 bg-blue-50 rounded-r-lg">
                    <div className="text-sm font-semibold">{notif.type || 'Notification'}</div>
                    <div className="text-sm">{notif.message || notif.content}</div>
                  </div>
                ))}
                {notifications.length === 0 && <div className="text-muted-foreground">No pending notifications.</div>}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Collaboration;
