'use client'

import { useState, useEffect, useMemo } from 'react'
import { Users, Search, Plus, Edit2, Trash2, UserPlus, UserMinus, Shield, Mail, Calendar, Loader2, RefreshCw, WifiOff } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'
import { useTeams } from '@fixops/api-client'

const DEMO_TEAMS = [
  {
    id: '1',
    name: 'Security Team',
    description: 'Security analysts and incident responders',
    member_count: 8,
    lead: 'Sarah Chen',
    created_at: '2024-01-10T10:00:00Z',
    members: [
      { id: '1', name: 'Sarah Chen', email: 'sarah.chen@fixops.io', role: 'Team Lead' },
      { id: '2', name: 'Emily Rodriguez', email: 'emily.rodriguez@fixops.io', role: 'Senior Analyst' },
      { id: '3', name: 'Anna Patel', email: 'anna.patel@fixops.io', role: 'Analyst' },
      { id: '4', name: 'Admin User', email: 'admin@fixops.io', role: 'Member' },
    ],
  },
  {
    id: '2',
    name: 'Platform Team',
    description: 'Infrastructure and platform engineering',
    member_count: 12,
    lead: 'John Doe',
    created_at: '2024-01-15T14:30:00Z',
    members: [
      { id: '5', name: 'John Doe', email: 'john.doe@fixops.io', role: 'Team Lead' },
      { id: '6', name: 'Admin User', email: 'admin@fixops.io', role: 'Member' },
    ],
  },
  {
    id: '3',
    name: 'Backend Team',
    description: 'Backend services and API development',
    member_count: 15,
    lead: 'Michael Kim',
    created_at: '2024-02-01T09:00:00Z',
    members: [
      { id: '7', name: 'Michael Kim', email: 'michael.kim@fixops.io', role: 'Team Lead' },
      { id: '8', name: 'John Doe', email: 'john.doe@fixops.io', role: 'Senior Engineer' },
      { id: '9', name: 'David Brown', email: 'david.brown@fixops.io', role: 'Engineer' },
    ],
  },
  {
    id: '4',
    name: 'Frontend Team',
    description: 'Web and mobile UI development',
    member_count: 10,
    lead: 'Lisa Wang',
    created_at: '2024-02-10T11:20:00Z',
    members: [
      { id: '10', name: 'Lisa Wang', email: 'lisa.wang@fixops.io', role: 'Team Lead' },
      { id: '11', name: 'Michael Kim', email: 'michael.kim@fixops.io', role: 'Engineer' },
    ],
  },
  {
    id: '5',
    name: 'Compliance Team',
    description: 'Compliance and audit management',
    member_count: 5,
    lead: 'Anna Patel',
    created_at: '2024-03-05T13:45:00Z',
    members: [
      { id: '12', name: 'Anna Patel', email: 'anna.patel@fixops.io', role: 'Team Lead' },
      { id: '13', name: 'Lisa Wang', email: 'lisa.wang@fixops.io', role: 'Auditor' },
    ],
  },
  {
    id: '6',
    name: 'Data Team',
    description: 'Data engineering and analytics',
    member_count: 7,
    lead: 'David Brown',
    created_at: '2024-03-20T15:10:00Z',
    members: [
      { id: '14', name: 'David Brown', email: 'david.brown@fixops.io', role: 'Team Lead' },
    ],
  },
]

export default function TeamsPage() {
  const { demoEnabled } = useDemoModeContext()
  const { data: apiData, loading: apiLoading, error: apiError, refetch } = useTeams()
  
  // Transform API data to match our UI format, or use demo data
  const teamsData = useMemo(() => {
    if (demoEnabled || !apiData?.items) {
      return DEMO_TEAMS
    }
    return apiData.items.map(team => ({
      id: team.id,
      name: team.name,
      description: team.description || '',
      member_count: team.member_count || 0,
      lead: 'Team Lead',
      created_at: team.created_at,
      members: [] as Array<{ id: string; name: string; email: string; role: string }>,
    }))
  }, [demoEnabled, apiData])

  const [teams, setTeams] = useState(DEMO_TEAMS)
  const [filteredTeams, setFilteredTeams] = useState(DEMO_TEAMS)
  const [selectedTeam, setSelectedTeam] = useState<typeof DEMO_TEAMS[0] | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showAddMemberModal, setShowAddMemberModal] = useState(false)

  // Update teams when data source changes
  useEffect(() => {
    setTeams(teamsData)
    setFilteredTeams(teamsData)
  }, [teamsData])

  const formatDate = (isoString: string) => {
    const date = new Date(isoString)
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  }

  const applyFilters = () => {
    let filtered = [...teams]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(team =>
        team.name.toLowerCase().includes(query) ||
        team.description.toLowerCase().includes(query) ||
        team.lead.toLowerCase().includes(query)
      )
    }

    setFilteredTeams(filtered)
  }

  useState(() => {
    applyFilters()
  })

  const summary = {
    total: teams.length,
    total_members: teams.reduce((sum, t) => sum + t.member_count, 0),
    avg_size: Math.round(teams.reduce((sum, t) => sum + t.member_count, 0) / teams.length),
    largest: Math.max(...teams.map(t => t.member_count)),
  }

  return (
    <AppShell activeApp="teams">
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        {/* Left Sidebar - Stats */}
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          {/* Header */}
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center gap-3 mb-4">
              <Users size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">Team Management</h2>
            </div>
            <p className="text-xs text-slate-500">Manage teams and memberships</p>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Teams</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Members</div>
                <div className="text-xl font-semibold text-green-500">{summary.total_members}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Avg Size</div>
                <div className="text-xl font-semibold text-blue-500">{summary.avg_size}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Largest</div>
                <div className="text-xl font-semibold text-orange-500">{summary.largest}</div>
              </div>
            </div>
          </div>

          {/* Team List */}
          <div className="p-4 flex-1 overflow-auto">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
              All Teams
            </div>
            <div className="space-y-2">
              {teams.map((team) => (
                <button
                  key={team.id}
                  onClick={() => setSelectedTeam(team)}
                  className={`w-full p-3 rounded-md text-sm font-medium text-left transition-all ${
                    selectedTeam?.id === team.id
                      ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                      : 'text-slate-400 hover:bg-white/5'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span>{team.name}</span>
                    <span className="text-xs">{team.member_count}</span>
                  </div>
                  <div className="text-xs text-slate-500">{team.lead}</div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 flex flex-col">
          {/* Top Bar */}
          <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
                        <div className="flex items-center justify-between mb-4">
                          <div>
                            <h1 className="text-2xl font-semibold mb-1">Teams</h1>
                            <p className="text-sm text-slate-500 flex items-center gap-2">
                              {apiLoading && !demoEnabled ? (
                                <><Loader2 size={14} className="animate-spin" /> Loading...</>
                              ) : (
                                <>Showing {filteredTeams.length} team{filteredTeams.length !== 1 ? 's' : ''}</>
                              )}
                              {!demoEnabled && apiError && (
                                <span className="text-amber-400 flex items-center gap-1">
                                  <WifiOff size={12} /> Using cached data
                                </span>
                              )}
                            </p>
                          </div>
                          <div className="flex items-center gap-2">
                            {!demoEnabled && (
                              <button
                                onClick={() => refetch()}
                                disabled={apiLoading}
                                className="p-2 hover:bg-white/10 rounded-md transition-colors disabled:opacity-50"
                                title="Refresh data"
                              >
                                <RefreshCw size={16} className={apiLoading ? 'animate-spin' : ''} />
                              </button>
                            )}
                            <button
                              onClick={() => setShowCreateModal(true)}
                              className="px-4 py-2 bg-[#6B5AED] hover:bg-[#5B4ADD] rounded-md text-white text-sm font-medium transition-all flex items-center gap-2"
                            >
                              <Plus size={16} />
                              Create Team
                            </button>
                          </div>
                        </div>

            {/* Search Bar */}
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by name, description, or lead..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); applyFilters(); }}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>
          </div>

          {/* Teams Grid */}
          <div className="flex-1 overflow-auto p-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
              {filteredTeams.map((team) => (
                <div
                  key={team.id}
                  onClick={() => setSelectedTeam(team)}
                  className="bg-white/2 border border-white/5 rounded-lg p-5 hover:bg-white/5 hover:border-[#6B5AED]/30 cursor-pointer transition-all"
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-[#6B5AED]/20 flex items-center justify-center">
                        <Users size={20} className="text-[#6B5AED]" />
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-white">{team.name}</h3>
                        <p className="text-xs text-slate-400">{team.member_count} members</p>
                      </div>
                    </div>
                  </div>

                  {/* Description */}
                  <p className="text-sm text-slate-300 mb-4">{team.description}</p>

                  {/* Team Lead */}
                  <div className="p-3 bg-white/5 rounded-lg mb-3">
                    <div className="text-xs text-slate-400 mb-1">Team Lead</div>
                    <div className="text-sm text-white font-medium flex items-center gap-2">
                      <Shield size={14} className="text-[#6B5AED]" />
                      {team.lead}
                    </div>
                  </div>

                  {/* Footer */}
                  <div className="flex items-center justify-between pt-3 border-t border-white/5">
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      <Calendar size={12} />
                      Created {formatDate(team.created_at)}
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        setSelectedTeam(team)
                        setShowAddMemberModal(true)
                      }}
                      className="text-xs text-[#6B5AED] hover:underline flex items-center gap-1"
                    >
                      <UserPlus size={12} />
                      Add Member
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Team Detail Drawer */}
        {selectedTeam && !showAddMemberModal && (
          <div
            onClick={() => setSelectedTeam(null)}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end"
          >
            <div
              onClick={(e) => e.stopPropagation()}
              className="w-[600px] h-full bg-[#1e293b] border-l border-white/10 flex flex-col animate-slide-in overflow-auto"
            >
              {/* Drawer Header */}
              <div className="p-6 border-b border-white/10 sticky top-0 bg-[#1e293b] z-10">
                <div className="flex justify-between items-start mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-12 h-12 rounded-lg bg-[#6B5AED]/20 flex items-center justify-center">
                      <Users size={24} className="text-[#6B5AED]" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold">{selectedTeam.name}</h3>
                      <p className="text-sm text-slate-400">{selectedTeam.description}</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedTeam(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="flex gap-2">
                  <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium bg-[#6B5AED]/10 text-[#6B5AED]">
                    <Users size={14} />
                    {selectedTeam.member_count} members
                  </span>
                  <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium bg-white/5 text-slate-300">
                    <Shield size={14} />
                    {selectedTeam.lead}
                  </span>
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Team Information */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Team Information</h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Team ID</span>
                      <span className="text-sm text-white font-mono">{selectedTeam.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Created</span>
                      <span className="text-sm text-white">{formatDate(selectedTeam.created_at)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Total Members</span>
                      <span className="text-sm text-white">{selectedTeam.member_count}</span>
                    </div>
                  </div>
                </div>

                {/* Members */}
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-sm font-semibold text-slate-300">Members</h4>
                    <button
                      onClick={() => setShowAddMemberModal(true)}
                      className="text-xs text-[#6B5AED] hover:underline flex items-center gap-1"
                    >
                      <UserPlus size={12} />
                      Add Member
                    </button>
                  </div>
                  <div className="space-y-2">
                    {selectedTeam.members.map((member) => (
                      <div key={member.id} className="p-3 bg-white/5 rounded-lg flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-full bg-[#6B5AED]/20 flex items-center justify-center">
                            <span className="text-xs font-semibold text-[#6B5AED]">
                              {member.name.split(' ').map(n => n[0]).join('')}
                            </span>
                          </div>
                          <div>
                            <div className="text-sm text-white font-medium">{member.name}</div>
                            <div className="text-xs text-slate-400 flex items-center gap-1">
                              <Mail size={10} />
                              {member.email}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-slate-400">{member.role}</span>
                          <button
                            onClick={() => {
                              if (confirm(`Remove ${member.name} from ${selectedTeam.name}?`)) {
                              }
                            }}
                            className="p-1 hover:bg-red-500/10 rounded transition-colors"
                            title="Remove member"
                          >
                            <UserMinus size={14} className="text-red-400" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Actions</h4>
                  <div className="space-y-2">
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Edit2 size={16} />
                      Edit Team Details
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Shield size={16} />
                      Change Team Lead
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors flex items-center gap-2">
                      <Users size={16} />
                      View Team Activity
                    </button>
                    <button className="w-full p-3 bg-red-500/10 hover:bg-red-500/20 rounded-lg text-sm text-left text-red-400 transition-colors flex items-center gap-2">
                      <Trash2 size={16} />
                      Delete Team
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  )
}
