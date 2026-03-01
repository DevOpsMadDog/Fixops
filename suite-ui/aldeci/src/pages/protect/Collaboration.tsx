import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { MessageSquare, Bell, Users2, Search, Send, Clock, AlertCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { toast } from 'sonner';
import { api } from '../../lib/api';

// ─── Interfaces ────────────────────────────────────────────────────────────────

interface Comment {
  id: string;
  author: string;
  content: string;
  entity_type?: string;
  entity_id?: string;
  created_at?: string;
}

interface Notification {
  id: string;
  type: string;
  message: string;
  content?: string;
  severity?: string;
  read?: boolean;
  created_at?: string;
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function relativeTime(ts?: string): string {
  if (!ts) return '';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function severityBorderClass(severity?: string): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'border-l-red-500';
    case 'high':     return 'border-l-orange-500';
    case 'warning':  return 'border-l-yellow-500';
    default:         return 'border-l-blue-500';
  }
}

// ─── Skeleton ──────────────────────────────────────────────────────────────────

function CollabSkeleton() {
  return (
    <div className="space-y-3">
      {Array.from({ length: 5 }, (_, i) => (
        <div key={i} className="p-4 rounded-lg border border-gray-700/30 animate-pulse">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 bg-gray-700/40 rounded-full" />
            <div className="space-y-2 flex-1">
              <div className="h-4 w-32 bg-gray-700/40 rounded" />
              <div className="h-3 w-full bg-gray-700/30 rounded" />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Animation Variants ────────────────────────────────────────────────────────

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.03 },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { type: 'spring', stiffness: 260, damping: 22 },
  },
};

// ─── Main Component ────────────────────────────────────────────────────────────

export default function Collaboration() {
  const [commentSearch, setCommentSearch] = useState('');

  // Queries
  const { data: commentsRaw, isLoading: commentsLoading } = useQuery({
    queryKey: ['collaboration-comments'],
    queryFn: async () => {
      const res = await api.get('/api/v1/collaboration/comments');
      return (res.data?.items || res.data || []) as Comment[];
    },
  });

  const { data: notifsRaw, isLoading: notifsLoading } = useQuery({
    queryKey: ['collaboration-notifications'],
    queryFn: async () => {
      const res = await api.get('/api/v1/collaboration/notifications');
      return (res.data?.items || res.data || []) as Notification[];
    },
  });

  const comments: Comment[] = commentsRaw ?? [];
  const notifications: Notification[] = notifsRaw ?? [];

  // Derived
  const filteredComments = useMemo(() => {
    const q = commentSearch.toLowerCase().trim();
    if (!q) return comments;
    return comments.filter(
      (c) =>
        c.author?.toLowerCase().includes(q) ||
        c.content?.toLowerCase().includes(q) ||
        c.entity_type?.toLowerCase().includes(q),
    );
  }, [comments, commentSearch]);

  const unreadCount = useMemo(
    () => notifications.filter((n) => n.read === false).length,
    [notifications],
  );

  const handleReply = (comment: Comment) => {
    toast.info(`Reply to ${comment.author} — coming soon`);
  };

  return (
    <div className="p-6 space-y-6 min-h-screen">
      {/* ── Header ── */}
      <motion.div
        initial={{ opacity: 0, y: -16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="space-y-1"
      >
        <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 via-indigo-400 to-purple-400 bg-clip-text text-transparent">
          Collaboration Hub
        </h1>
        <p className="text-sm text-gray-400">
          Team comments, notifications, and activity feed
        </p>
      </motion.div>

      {/* ── Stats Row ── */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1, duration: 0.35 }}
        className="grid grid-cols-3 gap-4"
      >
        {[
          { label: 'Comments', value: comments.length, icon: MessageSquare, color: 'text-blue-400' },
          { label: 'Notifications', value: notifications.length, icon: Bell, color: 'text-indigo-400' },
          { label: 'Unread', value: unreadCount, icon: AlertCircle, color: 'text-purple-400' },
        ].map(({ label, value, icon: Icon, color }) => (
          <Card
            key={label}
            className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md"
          >
            <CardContent className="flex items-center gap-3 p-4">
              <Icon className={`h-5 w-5 shrink-0 ${color}`} />
              <div>
                <p className="text-2xl font-bold text-white">{value}</p>
                <p className="text-xs text-gray-400">{label}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </motion.div>

      {/* ── Tabs ── */}
      <Tabs defaultValue="comments" className="space-y-4">
        <TabsList className="bg-gray-800/50 border border-gray-700/40">
          <TabsTrigger value="comments" className="data-[state=active]:bg-gray-700/60">
            <MessageSquare className="h-4 w-4 mr-2" />
            Comments
          </TabsTrigger>
          <TabsTrigger value="notifications" className="data-[state=active]:bg-gray-700/60">
            <Bell className="h-4 w-4 mr-2" />
            Notifications
            {unreadCount > 0 && (
              <Badge className="ml-2 bg-purple-600 text-white text-xs px-1.5 py-0">
                {unreadCount}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        {/* ── Comments Tab ── */}
        <TabsContent value="comments" className="space-y-4">
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardHeader className="pb-3">
              <CardTitle className="text-white flex items-center gap-2">
                <Users2 className="h-5 w-5 text-blue-400" />
                Recent Comments
              </CardTitle>
              <CardDescription className="text-gray-400">
                Team annotations and discussion threads
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Search */}
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
                <Input
                  placeholder="Search comments..."
                  value={commentSearch}
                  onChange={(e) => setCommentSearch(e.target.value)}
                  className="pl-9 bg-gray-800/40 border-gray-700/40 text-gray-200 placeholder:text-gray-500 focus-visible:ring-blue-500/40"
                />
              </div>

              {/* List */}
              {commentsLoading ? (
                <CollabSkeleton />
              ) : filteredComments.length === 0 ? (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="flex flex-col items-center gap-3 py-12 text-gray-500"
                >
                  <MessageSquare className="h-10 w-10 opacity-40" />
                  <p className="text-sm">
                    {commentSearch ? 'No comments match your search.' : 'No comments yet.'}
                  </p>
                </motion.div>
              ) : (
                <motion.div
                  variants={containerVariants}
                  initial="hidden"
                  animate="visible"
                  className="space-y-3 max-h-[480px] overflow-y-auto pr-1"
                >
                  <AnimatePresence>
                    {filteredComments.map((comment) => (
                      <motion.div
                        key={comment.id}
                        variants={itemVariants}
                        layout
                        className="p-4 bg-gray-800/20 border border-gray-700/30 rounded-lg group"
                      >
                        <div className="flex items-start gap-3">
                          {/* Avatar placeholder */}
                          <div className="h-8 w-8 rounded-full bg-gradient-to-br from-blue-500/30 to-indigo-500/30 border border-blue-500/20 flex items-center justify-center shrink-0">
                            <span className="text-xs font-semibold text-blue-300">
                              {(comment.author ?? 'A').charAt(0).toUpperCase()}
                            </span>
                          </div>

                          <div className="flex-1 min-w-0 space-y-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-sm font-semibold text-gray-200">
                                {comment.author || 'Anonymous'}
                              </span>
                              {comment.entity_type && (
                                <Badge
                                  variant="outline"
                                  className="text-xs border-gray-600 text-gray-400"
                                >
                                  {comment.entity_type}
                                </Badge>
                              )}
                              {comment.created_at && (
                                <span className="flex items-center gap-1 text-xs text-gray-500 ml-auto">
                                  <Clock className="h-3 w-3" />
                                  {relativeTime(comment.created_at)}
                                </span>
                              )}
                            </div>

                            <p className="text-sm text-gray-300 leading-relaxed">
                              {comment.content}
                            </p>

                            {comment.entity_id && (
                              <p className="text-xs text-gray-500">
                                Entity: {comment.entity_id}
                              </p>
                            )}
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex justify-end mt-2 opacity-0 group-hover:opacity-100 transition-opacity">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs text-gray-400 hover:text-blue-400 hover:bg-blue-500/10"
                            onClick={() => handleReply(comment)}
                          >
                            <Send className="h-3 w-3 mr-1" />
                            Reply
                          </Button>
                        </div>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Notifications Tab ── */}
        <TabsContent value="notifications" className="space-y-4">
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardHeader className="pb-3">
              <CardTitle className="text-white flex items-center gap-2">
                <Bell className="h-5 w-5 text-indigo-400" />
                Notifications
              </CardTitle>
              <CardDescription className="text-gray-400">
                System alerts and team activity updates
              </CardDescription>
            </CardHeader>
            <CardContent>
              {notifsLoading ? (
                <CollabSkeleton />
              ) : notifications.length === 0 ? (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="flex flex-col items-center gap-3 py-12 text-gray-500"
                >
                  <Bell className="h-10 w-10 opacity-40" />
                  <p className="text-sm">No notifications.</p>
                </motion.div>
              ) : (
                <motion.div
                  variants={containerVariants}
                  initial="hidden"
                  animate="visible"
                  className="space-y-3 max-h-[480px] overflow-y-auto pr-1"
                >
                  <AnimatePresence>
                    {notifications.map((notif) => (
                      <motion.div
                        key={notif.id}
                        variants={itemVariants}
                        layout
                        className={`p-4 bg-gray-800/20 border border-gray-700/30 border-l-4 ${severityBorderClass(notif.severity)} rounded-r-lg`}
                      >
                        <div className="flex items-start gap-3">
                          {/* Unread dot */}
                          {notif.read === false && (
                            <span className="mt-1.5 h-2 w-2 rounded-full bg-blue-400 shrink-0" />
                          )}

                          <div className="flex-1 min-w-0 space-y-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <Badge
                                variant="outline"
                                className="text-xs border-gray-600 text-gray-300 capitalize"
                              >
                                {notif.type || 'info'}
                              </Badge>
                              {notif.severity && (
                                <Badge
                                  variant="outline"
                                  className={`text-xs capitalize ${
                                    notif.severity === 'critical'
                                      ? 'border-red-500/40 text-red-400'
                                      : notif.severity === 'high'
                                      ? 'border-orange-500/40 text-orange-400'
                                      : notif.severity === 'warning'
                                      ? 'border-yellow-500/40 text-yellow-400'
                                      : 'border-blue-500/40 text-blue-400'
                                  }`}
                                >
                                  {notif.severity}
                                </Badge>
                              )}
                              {notif.created_at && (
                                <span className="flex items-center gap-1 text-xs text-gray-500 ml-auto">
                                  <Clock className="h-3 w-3" />
                                  {relativeTime(notif.created_at)}
                                </span>
                              )}
                            </div>

                            <p className="text-sm text-gray-300 leading-relaxed">
                              {notif.message || notif.content}
                            </p>
                          </div>
                        </div>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
