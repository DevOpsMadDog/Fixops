import { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import {
  Bell, AlertTriangle, CheckCircle2, Info, XCircle, X, CheckCheck,
  Trash2, ExternalLink, Shield, Activity, Clock,
} from 'lucide-react';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { ScrollArea } from './ui/scroll-area';
import { useNotificationsStore, AppNotification } from '../stores';
import { api } from '../lib/api';

// Notification type config
const typeConfig: Record<AppNotification['type'], { icon: React.ElementType; color: string; bg: string }> = {
  info: { icon: Info, color: 'text-blue-400', bg: 'bg-blue-500/10' },
  warning: { icon: AlertTriangle, color: 'text-amber-400', bg: 'bg-amber-500/10' },
  error: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/10' },
  success: { icon: CheckCircle2, color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
};

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export default function NotificationCenter() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<'all' | 'unread'>('all');
  const panelRef = useRef<HTMLDivElement>(null);
  const {
    notifications, unreadCount, addNotification,
    markRead, markAllRead, dismiss, clearAll,
  } = useNotificationsStore();

  // Fetch real alerts from audit logs and nerve center on mount
  const fetchAlerts = useCallback(async () => {
    try {
      const [auditRes, pulseRes] = await Promise.all([
        api.get('/api/v1/audit/logs', { params: { limit: 10 } }).catch(() => ({ data: null })),
        api.get('/api/v1/nerve-center/pulse').catch(() => ({ data: null })),
      ]);

      // Convert audit logs to notifications
      const logs = auditRes.data?.items || auditRes.data || [];
      if (Array.isArray(logs) && logs.length > 0) {
        const existingIds = new Set(notifications.map(n => n.title));
        for (const log of logs.slice(0, 5)) {
          const logObj = log as Record<string, unknown>;
          const title = String(logObj.action || logObj.event || logObj.message || 'System Event');
          if (!existingIds.has(title)) {
            const severity = String(logObj.severity || logObj.level || 'info').toLowerCase();
            const type: AppNotification['type'] =
              severity === 'critical' || severity === 'error' ? 'error' :
              severity === 'warning' || severity === 'high' ? 'warning' :
              severity === 'success' ? 'success' : 'info';
            addNotification({
              type,
              title,
              message: String(logObj.details || logObj.description || logObj.resource || ''),
              link: logObj.resource_type === 'finding' ? '/intelligence' : undefined,
            });
          }
        }
      }

      // Convert pulse data to notification
      const pulse = pulseRes.data;
      if (pulse && typeof pulse === 'object') {
        const pulseObj = pulse as Record<string, unknown>;
        const activeAlerts = Number(pulseObj.active_alerts || pulseObj.alert_count || 0);
        if (activeAlerts > 0) {
          const existingIds = new Set(notifications.map(n => n.title));
          const alertTitle = `${activeAlerts} active alert${activeAlerts > 1 ? 's' : ''} detected`;
          if (!existingIds.has(alertTitle)) {
            addNotification({
              type: activeAlerts > 5 ? 'error' : 'warning',
              title: alertTitle,
              message: 'View Nerve Center for details',
              link: '/nerve-center',
            });
          }
        }
      }
    } catch {
      // Silently handle — notifications are supplementary
    }
  }, [addNotification, notifications]);

  // Fetch on first open
  useEffect(() => {
    if (open && notifications.length === 0) {
      fetchAlerts();
    }
  }, [open, notifications.length, fetchAlerts]);

  // Click outside to close
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    if (open) document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const filtered = tab === 'unread' ? notifications.filter(n => !n.read) : notifications;

  return (
    <div className="relative" ref={panelRef}>
      {/* Bell Button */}
      <Button
        variant="ghost"
        size="icon"
        className="relative h-9 w-9"
        onClick={() => setOpen(prev => !prev)}
        aria-label={`Notifications${unreadCount > 0 ? ` (${unreadCount} unread)` : ''}`}
        aria-expanded={open}
      >
        <Bell className="w-5 h-5" />
        <AnimatePresence>
          {unreadCount > 0 && (
            <motion.span
              key="badge"
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0 }}
              className="absolute -top-1 -right-1 bg-red-500 text-white text-[10px] font-bold rounded-full min-w-[16px] h-4 flex items-center justify-center px-0.5"
            >
              {unreadCount > 99 ? '99+' : unreadCount}
            </motion.span>
          )}
        </AnimatePresence>
      </Button>

      {/* Dropdown Panel */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -8, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.96 }}
            transition={{ duration: 0.15, ease: [0.16, 1, 0.3, 1] }}
            className="absolute right-0 top-full mt-2 w-[400px] bg-popover border border-border rounded-xl shadow-2xl shadow-black/20 z-50 overflow-hidden"
          >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-primary" />
                <h3 className="font-semibold text-sm">Notifications</h3>
                {unreadCount > 0 && (
                  <Badge variant="destructive" className="text-[10px] px-1.5 py-0 h-4">
                    {unreadCount} new
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-1">
                {unreadCount > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 px-2 text-xs text-muted-foreground"
                    onClick={markAllRead}
                    aria-label="Mark all as read"
                  >
                    <CheckCheck className="w-3.5 h-3.5 mr-1" />
                    Read all
                  </Button>
                )}
                {notifications.length > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 px-2 text-xs text-muted-foreground"
                    onClick={clearAll}
                    aria-label="Clear all notifications"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </Button>
                )}
              </div>
            </div>

            {/* Tab Switcher */}
            <div className="flex gap-1 px-3 pt-2">
              {(['all', 'unread'] as const).map(t => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`px-3 py-1 text-xs font-medium rounded-md transition-colors ${
                    tab === t
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
                  }`}
                >
                  {t === 'all' ? 'All' : `Unread (${unreadCount})`}
                </button>
              ))}
            </div>

            {/* Notification List */}
            <ScrollArea className="max-h-[400px]">
              <div className="p-2 space-y-0.5">
                {filtered.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <Bell className="w-10 h-10 text-muted-foreground/20 mb-3" />
                    <p className="text-sm text-muted-foreground">
                      {tab === 'unread' ? 'No unread notifications' : 'No notifications yet'}
                    </p>
                    <p className="text-xs text-muted-foreground/60 mt-1">
                      Security alerts and system events will appear here
                    </p>
                  </div>
                ) : (
                  filtered.map((notification, i) => {
                    const config = typeConfig[notification.type];
                    const Icon = config.icon;

                    return (
                      <motion.div
                        key={notification.id}
                        initial={{ opacity: 0, x: -8 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.03 }}
                        className={`group flex gap-3 p-3 rounded-lg cursor-pointer transition-colors ${
                          notification.read
                            ? 'hover:bg-muted/30'
                            : 'bg-primary/5 hover:bg-primary/10'
                        }`}
                        onClick={() => {
                          markRead(notification.id);
                          if (notification.link) {
                            navigate(notification.link);
                            setOpen(false);
                          }
                        }}
                      >
                        {/* Icon */}
                        <div className={`flex-shrink-0 w-8 h-8 rounded-lg ${config.bg} flex items-center justify-center mt-0.5`}>
                          <Icon className={`w-4 h-4 ${config.color}`} />
                        </div>

                        {/* Content */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-start justify-between gap-2">
                            <p className={`text-sm leading-tight ${notification.read ? 'text-muted-foreground' : 'text-foreground font-medium'}`}>
                              {notification.title}
                            </p>
                            <button
                              onClick={(e) => { e.stopPropagation(); dismiss(notification.id); }}
                              className="opacity-0 group-hover:opacity-100 transition-opacity"
                              aria-label="Dismiss notification"
                            >
                              <X className="w-3.5 h-3.5 text-muted-foreground hover:text-foreground" />
                            </button>
                          </div>
                          {notification.message && (
                            <p className="text-xs text-muted-foreground mt-0.5 truncate">
                              {notification.message}
                            </p>
                          )}
                          <div className="flex items-center gap-2 mt-1">
                            <span className="flex items-center gap-1 text-[10px] text-muted-foreground/70">
                              <Clock className="w-2.5 h-2.5" />
                              {timeAgo(notification.timestamp)}
                            </span>
                            {notification.link && (
                              <span className="flex items-center gap-0.5 text-[10px] text-primary/60">
                                <ExternalLink className="w-2.5 h-2.5" />
                                View
                              </span>
                            )}
                            {!notification.read && (
                              <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                            )}
                          </div>
                        </div>
                      </motion.div>
                    );
                  })
                )}
              </div>
            </ScrollArea>

            {/* Footer */}
            {notifications.length > 0 && (
              <div className="border-t border-border px-4 py-2">
                <Button
                  variant="ghost"
                  size="sm"
                  className="w-full h-8 text-xs text-muted-foreground hover:text-foreground"
                  onClick={() => { navigate('/evidence/audit-trail'); setOpen(false); }}
                >
                  <Activity className="w-3.5 h-3.5 mr-1.5" />
                  View all activity
                </Button>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
