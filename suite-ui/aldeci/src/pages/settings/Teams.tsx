import { useState, useMemo } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Users2, Shield, UserPlus, Search, Settings2, Crown } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
import { api } from '../../lib/api';

interface Team {
  id: string;
  name: string;
  description?: string;
  member_count?: number;
  role?: string;
  created_at?: string;
  lead?: string;
  permissions?: string[];
}

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.05 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 200, damping: 22 } },
};

const roleBadgeColor = (role: string): string => {
  switch (role?.toLowerCase()) {
    case 'admin':     return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
    case 'security':  return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    case 'developer': return 'bg-green-500/20 text-green-400 border-green-500/30';
    default:          return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
};

function TeamsSkeleton() {
  return (
    <div className="space-y-3">
      {Array.from({ length: 4 }, (_, i) => (
        <div key={i} className="p-4 rounded-lg border border-gray-700/30 bg-gray-800/20 animate-pulse">
          <div className="flex items-center justify-between">
            <div className="space-y-2">
              <div className="h-5 w-40 bg-gray-700/40 rounded" />
              <div className="h-3 w-60 bg-gray-700/30 rounded" />
            </div>
            <div className="h-8 w-20 bg-gray-700/30 rounded" />
          </div>
        </div>
      ))}
    </div>
  );
}

export default function Teams() {
  const [searchQuery, setSearchQuery] = useState('');

  const { data: teamsRaw, isLoading } = useQuery({
    queryKey: ['teams'],
    queryFn: async () => {
      const res = await api.get('/api/v1/teams');
      return res.data?.items || res.data || [];
    },
  });

  const teams = useMemo(() => {
    const list = (teamsRaw || []) as Team[];
    if (!searchQuery) return list;
    const q = searchQuery.toLowerCase();
    return list.filter(t =>
      t.name?.toLowerCase().includes(q) ||
      t.description?.toLowerCase().includes(q)
    );
  }, [teamsRaw, searchQuery]);

  const createTeam = useMutation({
    mutationFn: async () => {
      await api.post('/api/v1/teams', { name: `Team ${Date.now()}`, description: 'New team' });
    },
    onSuccess: () => { toast.success('Team created'); },
    onError: () => toast.error('Failed to create team'),
  });

  const totalMembers = useMemo(
    () => teams.reduce((sum, t) => sum + (t.member_count ?? 0), 0),
    [teams]
  );

  const adminTeams = useMemo(
    () => teams.filter(t => t.role?.toLowerCase() === 'admin').length,
    [teams]
  );

  return (
    <div className="p-6 space-y-6 min-h-screen bg-gray-950 text-gray-100">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-violet-400 via-purple-400 to-indigo-400 bg-clip-text text-transparent">
            Team Management
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Manage security teams, roles, and access permissions
          </p>
        </div>
        <Button
          onClick={() => createTeam.mutate()}
          disabled={createTeam.isPending}
          className="bg-violet-600 hover:bg-violet-700 text-white"
        >
          <UserPlus className="w-4 h-4 mr-2" />
          Create Team
        </Button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4">
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardContent className="flex items-center gap-3 p-4">
            <div className="p-2 rounded-lg bg-violet-500/20">
              <Users2 className="w-5 h-5 text-violet-400" />
            </div>
            <div>
              <p className="text-xs text-gray-400 uppercase tracking-wide">Total Teams</p>
              <p className="text-2xl font-bold text-gray-100">{teams.length}</p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardContent className="flex items-center gap-3 p-4">
            <div className="p-2 rounded-lg bg-blue-500/20">
              <Shield className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-xs text-gray-400 uppercase tracking-wide">Total Members</p>
              <p className="text-2xl font-bold text-gray-100">{totalMembers}</p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardContent className="flex items-center gap-3 p-4">
            <div className="p-2 rounded-lg bg-purple-500/20">
              <Crown className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-xs text-gray-400 uppercase tracking-wide">Admin Teams</p>
              <p className="text-2xl font-bold text-gray-100">{adminTeams}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
        <Input
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          placeholder="Search teams by name or description..."
          className="pl-10 bg-gray-900/40 border-gray-700/40 text-gray-100 placeholder:text-gray-500 focus:border-violet-500/60"
        />
      </div>

      {/* Team list */}
      <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
        <CardHeader>
          <CardTitle className="text-gray-100 flex items-center gap-2">
            <Users2 className="w-5 h-5 text-violet-400" />
            Teams
          </CardTitle>
          <CardDescription className="text-gray-400">
            {teams.length} team{teams.length !== 1 ? 's' : ''} found
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <TeamsSkeleton />
          ) : teams.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Users2 className="w-12 h-12 text-gray-600 mb-4" />
              <p className="text-gray-400 text-lg font-medium">No teams found</p>
              <p className="text-gray-500 text-sm mt-1">
                {searchQuery ? 'Try adjusting your search query.' : 'Create your first team to get started.'}
              </p>
            </div>
          ) : (
            <motion.div
              className="space-y-3"
              variants={containerVariants}
              initial="hidden"
              animate="visible"
            >
              {teams.map(team => (
                <motion.div
                  key={team.id}
                  variants={itemVariants}
                  className="p-4 rounded-lg border border-gray-700/30 bg-gray-800/20 hover:bg-gray-800/40 transition-colors"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-gray-100 truncate">{team.name}</span>
                        {team.role && (
                          <Badge className={`text-xs border ${roleBadgeColor(team.role)}`}>
                            {team.role}
                          </Badge>
                        )}
                        {team.member_count !== undefined && (
                          <Badge className="text-xs bg-gray-700/40 text-gray-300 border-gray-600/40">
                            {team.member_count} member{team.member_count !== 1 ? 's' : ''}
                          </Badge>
                        )}
                      </div>

                      {team.description && (
                        <p className="text-gray-400 text-sm truncate">{team.description}</p>
                      )}

                      <div className="flex items-center gap-4 text-xs text-gray-500">
                        {team.lead && (
                          <span className="flex items-center gap-1">
                            <Crown className="w-3 h-3 text-yellow-500/70" />
                            {team.lead}
                          </span>
                        )}
                        {team.created_at && (
                          <span>
                            Created {new Date(team.created_at).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                    </div>

                    <Button
                      variant="outline"
                      size="sm"
                      className="shrink-0 border-gray-600/50 text-gray-300 hover:border-violet-500/50 hover:text-violet-400 hover:bg-violet-500/10"
                    >
                      <Settings2 className="w-3.5 h-3.5 mr-1.5" />
                      Manage
                    </Button>
                  </div>
                </motion.div>
              ))}
            </motion.div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
