import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import {
  Settings, LogOut, Shield, Key, HelpCircle,
  ChevronRight, Moon, Sun,
} from 'lucide-react';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { useAuthStore, useUIStore } from '../stores';

export default function UserMenu() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const { user, logout } = useAuthStore();
  const { theme, setTheme } = useUIStore();

  // Click outside to close
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    if (open) document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const displayName = user?.name || 'Security Analyst';
  const displayEmail = user?.email || 'analyst@aldeci.io';
  const displayRole = user?.role || 'admin';
  const initials = displayName
    .split(' ')
    .map(p => p[0])
    .join('')
    .toUpperCase()
    .slice(0, 2);

  const roleColors: Record<string, string> = {
    admin: 'border-red-500/40 text-red-400 bg-red-500/10',
    analyst: 'border-blue-500/40 text-blue-400 bg-blue-500/10',
    viewer: 'border-gray-500/40 text-gray-400 bg-gray-500/10',
  };

  const menuItems = [
    { label: 'Settings', icon: Settings, path: '/settings', shortcut: '⌘,' },
    { label: 'API Keys', icon: Key, path: '/settings', shortcut: undefined },
    { label: 'System Health', icon: Shield, path: '/settings/system-health', shortcut: undefined },
    { label: 'Help & Docs', icon: HelpCircle, path: undefined, shortcut: '?' },
  ];

  const handleThemeChange = (newTheme: 'dark' | 'light') => {
    setTheme(newTheme);
    document.documentElement.classList.toggle('dark', newTheme === 'dark');
    document.documentElement.classList.toggle('light', newTheme === 'light');
  };

  return (
    <div className="relative" ref={menuRef}>
      {/* Avatar Button */}
      <Button
        variant="ghost"
        size="icon"
        className="h-9 w-9 rounded-full"
        onClick={() => setOpen(prev => !prev)}
        aria-label="User menu"
        aria-expanded={open}
      >
        <div className="w-7 h-7 rounded-full bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center text-[10px] font-bold text-white">
          {initials}
        </div>
      </Button>

      {/* Dropdown Menu */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -8, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.96 }}
            transition={{ duration: 0.15, ease: [0.16, 1, 0.3, 1] }}
            className="absolute right-0 top-full mt-2 w-[280px] bg-popover border border-border rounded-xl shadow-2xl shadow-black/20 z-50 overflow-hidden"
          >
            {/* Profile Section */}
            <div className="px-4 py-3 border-b border-border">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center text-sm font-bold text-white flex-shrink-0">
                  {initials}
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">{displayName}</p>
                  <p className="text-xs text-muted-foreground truncate">{displayEmail}</p>
                </div>
              </div>
              <div className="mt-2 flex items-center gap-2">
                <Badge variant="outline" className={`text-[10px] px-1.5 py-0 h-4 ${roleColors[displayRole] || ''}`}>
                  {displayRole}
                </Badge>
                <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4 border-emerald-500/40 text-emerald-400 bg-emerald-500/10">
                  Active
                </Badge>
              </div>
            </div>

            {/* Theme Switcher */}
            <div className="px-3 py-2 border-b border-border">
              <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1.5 px-1">Appearance</p>
              <div className="flex gap-1 bg-muted/30 rounded-lg p-1">
                {[
                  { key: 'dark' as const, icon: Moon, label: 'Dark' },
                  { key: 'light' as const, icon: Sun, label: 'Light' },
                ].map(opt => (
                  <button
                    key={opt.key}
                    onClick={() => handleThemeChange(opt.key)}
                    className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-md text-xs transition-colors ${
                      theme === opt.key
                        ? 'bg-background text-foreground shadow-sm'
                        : 'text-muted-foreground hover:text-foreground'
                    }`}
                  >
                    <opt.icon className="w-3.5 h-3.5" />
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Menu Items */}
            <div className="py-1 px-1">
              {menuItems.map(item => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.label}
                    onClick={() => {
                      if (item.path) {
                        navigate(item.path);
                        setOpen(false);
                      }
                    }}
                    className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors group"
                  >
                    <Icon className="w-4 h-4" />
                    <span className="flex-1 text-left">{item.label}</span>
                    {item.shortcut ? (
                      <kbd className="text-[10px] font-mono text-muted-foreground/50 bg-muted/50 px-1.5 py-0.5 rounded border border-border/50">
                        {item.shortcut}
                      </kbd>
                    ) : (
                      <ChevronRight className="w-3 h-3 opacity-0 group-hover:opacity-50 transition-opacity" />
                    )}
                  </button>
                );
              })}
            </div>

            {/* Logout */}
            <div className="border-t border-border p-1">
              <button
                onClick={() => {
                  logout();
                  setOpen(false);
                  navigate('/');
                }}
                className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors"
              >
                <LogOut className="w-4 h-4" />
                <span>Sign out</span>
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
