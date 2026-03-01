import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { User, Shield, UserPlus, Search, Mail, Clock, Crown, Key } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
import { api } from '../../lib/api';

interface UserAccount {
  id: string;
  name?: string;
  email: string;
  role: string;
  status?: string;
  last_login?: string;
  created_at?: string;
  avatar_url?: string;
  two_factor_enabled?: boolean;
}

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.03 } },
};

const itemVariants = {
  hidden: { opacity: 0, x: -10 },
  visible: { opacity: 1, x: 0, transition: { type: 'spring', stiffness: 200, damping: 22 } },
};

const roleBadge = (role: string) => {
  switch (role?.toLowerCase()) {
    case 'admin':     return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
    case 'security':  return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    case 'developer': return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'viewer':    return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    default:          return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
};

const avatarColor = (role: string) => {
  switch (role?.toLowerCase()) {
    case 'admin':     return 'bg-purple-500/30 text-purple-300';
    case 'security':  return 'bg-blue-500/30 text-blue-300';
    case 'developer': return 'bg-green-500/30 text-green-300';
    default:          return 'bg-gray-600/40 text-gray-300';
  }
};

function relativeTime(iso?: string): string {
  if (!iso) return 'Never';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1)   return 'Just now';
  if (mins < 60)  return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)   return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30)  return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

function UsersSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 6 }, (_, i) => (
        <div key={i} className="flex items-center gap-4 p-4 animate-pulse">
          <div className="h-10 w-10 bg-gray-700/40 rounded-full" />
          <div className="flex-1 space-y-2">
            <div className="h-4 w-40 bg-gray-700/40 rounded" />
            <div className="h-3 w-56 bg-gray-700/30 rounded" />
          </div>
          <div className="h-6 w-16 bg-gray-700/30 rounded" />
        </div>
      ))}
    </div>
  );
}

const ROLES = ['all', 'admin', 'security', 'developer', 'viewer'] as const;

export default function Users() {
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState<string>('all');

  const { data: usersRaw, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      const res = await api.get('/api/v1/users');
      return res.data?.items || res.data || [];
    },
  });

  const users = useMemo(() => {
    let list = (usersRaw || []) as UserAccount[];
    if (roleFilter !== 'all') {
      list = list.filter(u => u.role === roleFilter);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      list = list.filter(u =>
        (u.name || '').toLowerCase().includes(q) ||
        u.email.toLowerCase().includes(q) ||
        u.role.toLowerCase().includes(q)
      );
    }
    return list;
  }, [usersRaw, searchQuery, roleFilter]);

  const allUsers = (usersRaw || []) as UserAccount[];
  const totalUsers     = allUsers.length;
  const activeUsers    = allUsers.filter(u => (u.status || 'active') === 'active').length;
  const adminUsers     = allUsers.filter(u => u.role?.toLowerCase() === 'admin').length;
  const twoFAEnabled   = allUsers.filter(u => u.two_factor_enabled).length;

  const stats = [
    { label: 'Total Users',  value: totalUsers,   icon: User,   color: 'text-blue-400'   },
    { label: 'Active',       value: activeUsers,  icon: Shield, color: 'text-green-400'  },
    { label: 'Admins',       value: adminUsers,   icon: Crown,  color: 'text-purple-400' },
    { label: '2FA Enabled',  value: twoFAEnabled, icon: Key,    color: 'text-cyan-400'   },
  ];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 via-cyan-400 to-teal-400 bg-clip-text text-transparent">
            User Management
          </h1>
          <p className="text-gray-400 mt-1 text-sm">
            Manage user accounts, roles, and access permissions
          </p>
        </div>
        <Button
          className="flex items-center gap-2 bg-primary/20 border border-primary/30 text-primary hover:bg-primary/30 transition-all"
          onClick={() => toast.info('Add user flow coming soon')}
        >
          <UserPlus className="h-4 w-4" />
          Add User
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {stats.map(({ label, value, icon: Icon, color }) => (
          <Card key={label} className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardContent className="p-4 flex items-center gap-3">
              <div className={`p-2 rounded-lg bg-gray-800/60`}>
                <Icon className={`h-4 w-4 ${color}`} />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-100">{value}</p>
                <p className="text-xs text-gray-500">{label}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* User List Card */}
      <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
        <CardHeader className="pb-4">
          <div className="flex flex-col sm:flex-row sm:items-center gap-3 justify-between">
            <div>
              <CardTitle className="text-gray-100 text-base">All Users</CardTitle>
              <CardDescription className="text-gray-500 text-xs mt-0.5">
                {users.length} user{users.length !== 1 ? 's' : ''} shown
              </CardDescription>
            </div>
            {/* Search */}
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
              <Input
                placeholder="Search users..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="pl-8 bg-gray-800/60 border-gray-700/40 text-gray-200 placeholder-gray-600 text-sm h-8 focus:border-blue-500/50"
              />
            </div>
          </div>

          {/* Role filter */}
          <div className="flex gap-2 flex-wrap mt-2">
            {ROLES.map(role => (
              <button
                key={role}
                onClick={() => setRoleFilter(role)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  roleFilter === role
                    ? 'bg-primary/20 text-primary border border-primary/30'
                    : 'text-gray-400 hover:text-gray-300 border border-gray-700/30'
                }`}
              >
                {role.charAt(0).toUpperCase() + role.slice(1)}
              </button>
            ))}
          </div>
        </CardHeader>

        <CardContent className="pt-0">
          {isLoading ? (
            <UsersSkeleton />
          ) : users.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-gray-500">
              <User className="h-10 w-10 mb-3 text-gray-600" />
              <p className="text-sm font-medium">No users found</p>
              <p className="text-xs mt-1">Try adjusting your search or filter</p>
            </div>
          ) : (
            <motion.div
              variants={containerVariants}
              initial="hidden"
              animate="visible"
              className="space-y-1"
            >
              {users.map(user => {
                const initials = (user.name || user.email).charAt(0).toUpperCase();
                const isActive = (user.status || 'active') === 'active';

                return (
                  <motion.div
                    key={user.id}
                    variants={itemVariants}
                    className="flex items-center gap-4 p-3 rounded-xl hover:bg-gray-800/40 transition-colors group"
                  >
                    {/* Avatar */}
                    <div className={`h-10 w-10 rounded-full flex items-center justify-center text-sm font-semibold shrink-0 ${avatarColor(user.role)}`}>
                      {initials}
                    </div>

                    {/* Name + Email */}
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-gray-100 text-sm truncate">
                        {user.name || user.email}
                      </p>
                      <p className="text-gray-400 text-xs flex items-center gap-1 truncate mt-0.5">
                        <Mail className="h-3 w-3 shrink-0" />
                        {user.email}
                      </p>
                    </div>

                    {/* Role Badge */}
                    <Badge
                      variant="outline"
                      className={`text-xs border shrink-0 ${roleBadge(user.role)}`}
                    >
                      {user.role || 'viewer'}
                    </Badge>

                    {/* 2FA */}
                    {user.two_factor_enabled && (
                      <Badge
                        variant="outline"
                        className="text-xs border bg-green-500/10 text-green-400 border-green-500/30 flex items-center gap-1 shrink-0"
                      >
                        <Key className="h-3 w-3" />
                        2FA
                      </Badge>
                    )}

                    {/* Status dot */}
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span
                        className={`h-2 w-2 rounded-full ${isActive ? 'bg-green-500' : 'bg-red-500'}`}
                        title={isActive ? 'Active' : 'Inactive'}
                      />
                    </div>

                    {/* Last login */}
                    <div className="hidden md:flex items-center gap-1 text-xs text-gray-500 shrink-0">
                      <Clock className="h-3 w-3" />
                      {relativeTime(user.last_login)}
                    </div>
                  </motion.div>
                );
              })}
            </motion.div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
