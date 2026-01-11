'use client'

import { useState, useEffect, useMemo } from 'react'
import { Users, Search, Plus, Edit2, Trash2, Shield, Mail, CheckCircle, XCircle, Clock, Key, UserPlus, Filter, User, Loader2, RefreshCw, WifiOff } from 'lucide-react'
import { AppShell, useDemoModeContext } from '@fixops/ui'
import { useUsers } from '@fixops/api-client'

const DEMO_USERS = [
  {
    id: '1',
    email: 'admin@fixops.io',
    first_name: 'Admin',
    last_name: 'User',
    role: 'admin',
    status: 'active',
    created_at: '2024-01-15T10:00:00Z',
    last_login: '2024-11-22T08:30:00Z',
    teams: ['Security Team', 'Platform Team'],
  },
  {
    id: '2',
    email: 'sarah.chen@fixops.io',
    first_name: 'Sarah',
    last_name: 'Chen',
    role: 'security_analyst',
    status: 'active',
    created_at: '2024-02-20T14:30:00Z',
    last_login: '2024-11-22T09:15:00Z',
    teams: ['Security Team'],
  },
  {
    id: '3',
    email: 'john.doe@fixops.io',
    first_name: 'John',
    last_name: 'Doe',
    role: 'developer',
    status: 'active',
    created_at: '2024-03-10T09:00:00Z',
    last_login: '2024-11-21T16:45:00Z',
    teams: ['Backend Team', 'Platform Team'],
  },
  {
    id: '4',
    email: 'emily.rodriguez@fixops.io',
    first_name: 'Emily',
    last_name: 'Rodriguez',
    role: 'security_analyst',
    status: 'active',
    created_at: '2024-04-05T11:20:00Z',
    last_login: '2024-11-22T07:00:00Z',
    teams: ['Security Team'],
  },
  {
    id: '5',
    email: 'michael.kim@fixops.io',
    first_name: 'Michael',
    last_name: 'Kim',
    role: 'developer',
    status: 'inactive',
    created_at: '2024-05-12T13:45:00Z',
    last_login: '2024-10-15T10:30:00Z',
    teams: ['Frontend Team'],
  },
  {
    id: '6',
    email: 'lisa.wang@fixops.io',
    first_name: 'Lisa',
    last_name: 'Wang',
    role: 'viewer',
    status: 'active',
    created_at: '2024-06-18T15:10:00Z',
    last_login: '2024-11-22T06:20:00Z',
    teams: ['Compliance Team'],
  },
  {
    id: '7',
    email: 'david.brown@fixops.io',
    first_name: 'David',
    last_name: 'Brown',
    role: 'developer',
    status: 'suspended',
    created_at: '2024-07-22T08:30:00Z',
    last_login: '2024-09-10T14:00:00Z',
    teams: ['Backend Team'],
  },
  {
    id: '8',
    email: 'anna.patel@fixops.io',
    first_name: 'Anna',
    last_name: 'Patel',
    role: 'security_analyst',
    status: 'active',
    created_at: '2024-08-30T10:15:00Z',
    last_login: '2024-11-21T18:30:00Z',
    teams: ['Security Team', 'Compliance Team'],
  },
]

export default function UsersPage() {
  const { demoEnabled } = useDemoModeContext()
  const { data: apiData, loading: apiLoading, error: apiError, refetch } = useUsers()
  
  // Transform API data to match our UI format, or use demo data
  const usersData = useMemo(() => {
    if (demoEnabled || !apiData?.items) {
      return DEMO_USERS
    }
    return apiData.items.map(user => ({
      id: user.id,
      email: user.email,
      first_name: user.name?.split(' ')[0] || 'Unknown',
      last_name: user.name?.split(' ').slice(1).join(' ') || '',
      role: user.role || 'viewer',
      status: user.status || 'active',
      created_at: user.created_at,
      last_login: user.last_login,
      teams: [] as string[],
    }))
  }, [demoEnabled, apiData])

  const [users, setUsers] = useState(DEMO_USERS)
  const [filteredUsers, setFilteredUsers] = useState(DEMO_USERS)
  const [selectedUser, setSelectedUser] = useState<typeof DEMO_USERS[0] | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [roleFilter, setRoleFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)

  // Update users when data source changes
  useEffect(() => {
    setUsers(usersData)
    setFilteredUsers(usersData)
  }, [usersData])

  const getRoleColor = (role: string) => {
    const colors = {
      admin: '#dc2626',
      security_analyst: '#f97316',
      developer: '#3b82f6',
      viewer: '#10b981',
    }
    return colors[role as keyof typeof colors] || colors.viewer
  }

  const getStatusColor = (status: string) => {
    const colors = {
      active: '#10b981',
      inactive: '#6b7280',
      suspended: '#dc2626',
    }
    return colors[status as keyof typeof colors] || colors.inactive
  }

  const formatDate = (isoString: string) => {
    const date = new Date(isoString)
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  }

  const formatDateTime = (isoString: string) => {
    const date = new Date(isoString)
    return date.toLocaleString('en-US', { 
      month: 'short', 
      day: 'numeric', 
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const applyFilters = () => {
    let filtered = [...users]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(user =>
        user.email.toLowerCase().includes(query) ||
        user.first_name.toLowerCase().includes(query) ||
        user.last_name.toLowerCase().includes(query)
      )
    }

    if (roleFilter !== 'all') {
      filtered = filtered.filter(user => user.role === roleFilter)
    }

    if (statusFilter !== 'all') {
      filtered = filtered.filter(user => user.status === statusFilter)
    }

    setFilteredUsers(filtered)
  }

  useState(() => {
    applyFilters()
  })

  const summary = {
    total: users.length,
    active: users.filter(u => u.status === 'active').length,
    inactive: users.filter(u => u.status === 'inactive').length,
    suspended: users.filter(u => u.status === 'suspended').length,
    admins: users.filter(u => u.role === 'admin').length,
    analysts: users.filter(u => u.role === 'security_analyst').length,
    developers: users.filter(u => u.role === 'developer').length,
    viewers: users.filter(u => u.role === 'viewer').length,
  }

  return (
    <AppShell activeApp="users">
      <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
        {/* Left Sidebar - Filters */}
        <div className="w-72 bg-[#0f172a]/80 border-r border-white/10 flex flex-col sticky top-0 h-screen">
          {/* Header */}
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center gap-3 mb-4">
              <Users size={24} className="text-[#6B5AED]" />
              <h2 className="text-lg font-semibold">User Management</h2>
            </div>
            <p className="text-xs text-slate-500">Manage users, roles, and access</p>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-white/10">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Total Users</div>
                <div className="text-xl font-semibold text-[#6B5AED]">{summary.total}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Active</div>
                <div className="text-xl font-semibold text-green-500">{summary.active}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Admins</div>
                <div className="text-xl font-semibold text-red-500">{summary.admins}</div>
              </div>
              <div className="p-3 bg-white/5 rounded-md">
                <div className="text-slate-500 mb-1">Analysts</div>
                <div className="text-xl font-semibold text-orange-500">{summary.analysts}</div>
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="p-4 flex-1 overflow-auto">
            <div className="mb-6">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Role
              </div>
              <div className="space-y-2">
                {['all', 'admin', 'security_analyst', 'developer', 'viewer'].map((role) => (
                  <button
                    key={role}
                    onClick={() => { setRoleFilter(role); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      roleFilter === role
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{role.replace('_', ' ')}</span>
                    {role !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({users.filter(u => u.role === role).length})
                      </span>
                    )}
                    {role === 'all' && (
                      <span className="ml-2 text-xs">({users.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Filter size={12} />
                Filter by Status
              </div>
              <div className="space-y-2">
                {['all', 'active', 'inactive', 'suspended'].map((status) => (
                  <button
                    key={status}
                    onClick={() => { setStatusFilter(status); applyFilters(); }}
                    className={`w-full p-2.5 rounded-md text-sm font-medium text-left transition-all ${
                      statusFilter === status
                        ? 'bg-[#6B5AED]/10 text-[#6B5AED] border border-[#6B5AED]/30'
                        : 'text-slate-400 hover:bg-white/5'
                    }`}
                  >
                    <span className="capitalize">{status}</span>
                    {status !== 'all' && (
                      <span className="ml-2 text-xs">
                        ({users.filter(u => u.status === status).length})
                      </span>
                    )}
                    {status === 'all' && (
                      <span className="ml-2 text-xs">({users.length})</span>
                    )}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 flex flex-col">
          {/* Top Bar */}
          <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
                        <div className="flex items-center justify-between mb-4">
                          <div>
                            <h1 className="text-2xl font-semibold mb-1">Users</h1>
                            <p className="text-sm text-slate-500 flex items-center gap-2">
                              {apiLoading && !demoEnabled ? (
                                <><Loader2 size={14} className="animate-spin" /> Loading...</>
                              ) : (
                                <>Showing {filteredUsers.length} user{filteredUsers.length !== 1 ? 's' : ''}</>
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
                              Create User
                            </button>
                          </div>
                        </div>

            {/* Search Bar */}
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by name or email..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); applyFilters(); }}
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#6B5AED]/50"
              />
            </div>
          </div>

          {/* Users Table */}
          <div className="flex-1 overflow-auto p-6">
            <div className="bg-white/2 rounded-lg border border-white/5 overflow-hidden">
              <table className="w-full">
                <thead className="bg-white/5 border-b border-white/10">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">User</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Role</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Teams</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Last Login</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {filteredUsers.map((user) => (
                    <tr
                      key={user.id}
                      onClick={() => setSelectedUser(user)}
                      className="hover:bg-white/5 cursor-pointer transition-colors"
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-full bg-[#6B5AED]/20 flex items-center justify-center">
                            <span className="text-sm font-semibold text-[#6B5AED]">
                              {user.first_name[0]}{user.last_name[0]}
                            </span>
                          </div>
                          <div>
                            <div className="text-sm font-medium text-white">
                              {user.first_name} {user.last_name}
                            </div>
                            <div className="text-xs text-slate-400 flex items-center gap-1">
                              <Mail size={12} />
                              {user.email}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                          style={{ 
                            backgroundColor: `${getRoleColor(user.role)}20`,
                            color: getRoleColor(user.role)
                          }}
                        >
                          <Shield size={12} />
                          {user.role.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
                          style={{ 
                            backgroundColor: `${getStatusColor(user.status)}20`,
                            color: getStatusColor(user.status)
                          }}
                        >
                          {user.status === 'active' && <CheckCircle size={12} />}
                          {user.status === 'inactive' && <Clock size={12} />}
                          {user.status === 'suspended' && <XCircle size={12} />}
                          {user.status}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {user.teams.slice(0, 2).map((team, idx) => (
                            <span key={idx} className="px-2 py-1 bg-white/5 rounded text-xs text-slate-300">
                              {team}
                            </span>
                          ))}
                          {user.teams.length > 2 && (
                            <span className="px-2 py-1 bg-white/5 rounded text-xs text-slate-400">
                              +{user.teams.length - 2}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-sm text-slate-300">{formatDateTime(user.last_login)}</div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              setSelectedUser(user)
                              setShowEditModal(true)
                            }}
                            className="p-1.5 hover:bg-white/10 rounded transition-colors"
                            title="Edit user"
                          >
                            <Edit2 size={14} className="text-slate-400" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              if (confirm(`Delete user ${user.first_name} ${user.last_name}?`)) {
                                setUsers(users.filter(u => u.id !== user.id))
                                applyFilters()
                              }
                            }}
                            className="p-1.5 hover:bg-red-500/10 rounded transition-colors"
                            title="Delete user"
                          >
                            <Trash2 size={14} className="text-red-400" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* User Detail Drawer */}
        {selectedUser && !showEditModal && (
          <div
            onClick={() => setSelectedUser(null)}
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
                    <div className="w-12 h-12 rounded-full bg-[#6B5AED]/20 flex items-center justify-center">
                      <span className="text-lg font-semibold text-[#6B5AED]">
                        {selectedUser.first_name[0]}{selectedUser.last_name[0]}
                      </span>
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold">{selectedUser.first_name} {selectedUser.last_name}</h3>
                      <p className="text-sm text-slate-400">{selectedUser.email}</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedUser(null)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="flex gap-2">
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getRoleColor(selectedUser.role)}20`,
                      color: getRoleColor(selectedUser.role)
                    }}
                  >
                    <Shield size={14} />
                    {selectedUser.role.replace('_', ' ')}
                  </span>
                  <span
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium"
                    style={{ 
                      backgroundColor: `${getStatusColor(selectedUser.status)}20`,
                      color: getStatusColor(selectedUser.status)
                    }}
                  >
                    {selectedUser.status === 'active' && <CheckCircle size={14} />}
                    {selectedUser.status === 'inactive' && <Clock size={14} />}
                    {selectedUser.status === 'suspended' && <XCircle size={14} />}
                    {selectedUser.status}
                  </span>
                </div>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 p-6 space-y-6">
                {/* Account Information */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <User size={16} />
                    Account Information
                  </h4>
                  <div className="space-y-3 bg-white/5 rounded-lg p-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">User ID</span>
                      <span className="text-sm text-white font-mono">{selectedUser.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Created</span>
                      <span className="text-sm text-white">{formatDate(selectedUser.created_at)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-slate-400">Last Login</span>
                      <span className="text-sm text-white">{formatDateTime(selectedUser.last_login)}</span>
                    </div>
                  </div>
                </div>

                {/* Teams */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <Users size={16} />
                    Team Memberships
                  </h4>
                  <div className="space-y-2">
                    {selectedUser.teams.map((team, idx) => (
                      <div key={idx} className="p-3 bg-white/5 rounded-lg flex items-center justify-between">
                        <span className="text-sm text-white">{team}</span>
                        <button className="text-xs text-slate-400 hover:text-white transition-colors">
                          Remove
                        </button>
                      </div>
                    ))}
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg flex items-center justify-center gap-2 text-sm text-[#6B5AED] transition-colors">
                      <UserPlus size={16} />
                      Add to Team
                    </button>
                  </div>
                </div>

                {/* Actions */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <Key size={16} />
                    Actions
                  </h4>
                  <div className="space-y-2">
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors">
                      Reset Password
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors">
                      Generate API Key
                    </button>
                    <button className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-lg text-sm text-left text-white transition-colors">
                      View Activity Log
                    </button>
                    {selectedUser.status === 'active' && (
                      <button className="w-full p-3 bg-red-500/10 hover:bg-red-500/20 rounded-lg text-sm text-left text-red-400 transition-colors">
                        Suspend User
                      </button>
                    )}
                    {selectedUser.status === 'suspended' && (
                      <button className="w-full p-3 bg-green-500/10 hover:bg-green-500/20 rounded-lg text-sm text-left text-green-400 transition-colors">
                        Reactivate User
                      </button>
                    )}
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
