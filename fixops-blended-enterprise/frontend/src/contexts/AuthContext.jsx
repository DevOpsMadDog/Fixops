import React, { createContext, useContext, useState, useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import api from '../utils/api'

const AuthContext = createContext(null)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const queryClient = useQueryClient()

  // Check if auth bypass is enabled (support both Vite and React App env vars)
  const bypassAuth = import.meta.env.VITE_BYPASS_AUTH === 'true' || 
                     import.meta.env.REACT_APP_BYPASS_AUTH === 'true'

  // Debug logging
  console.log('🔍 Auth Debug:', {
    VITE_BYPASS_AUTH: import.meta.env.VITE_BYPASS_AUTH,
    REACT_APP_BYPASS_AUTH: import.meta.env.REACT_APP_BYPASS_AUTH,
    bypassAuth,
    isAuthenticated,
    isLoading,
    user: user?.username || 'none'
  })

  // Check for existing token on mount
  useEffect(() => {
    if (bypassAuth) {
      // Bypass authentication - create mock user
      const mockUser = {
        id: 'admin-user-001',
        email: 'admin@fixops.dev',
        username: 'admin',
        first_name: 'System',
        last_name: 'Administrator',
        roles: ['admin', 'security_analyst', 'compliance_officer'],
        full_name: 'System Administrator'
      }
      
      setUser(mockUser)
      setIsAuthenticated(true)
      setIsLoading(false)
      
      console.log('🔓 Authentication bypassed - Demo mode enabled')
      return
    }

    checkAuthStatus()
  }, [bypassAuth])

  const checkAuthStatus = async () => {
    const token = localStorage.getItem('access_token')
    
    if (!token) {
      setIsLoading(false)
      return
    }

    try {
      // Validate token by fetching user info
      const response = await api.get('/auth/me')
      setUser(response.data)
      setIsAuthenticated(true)
      
      // Set default authorization header
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`
    } catch (error) {
      // Token is invalid, remove it
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      delete api.defaults.headers.common['Authorization']
      
      console.error('Token validation failed:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const login = async (credentials) => {
    if (bypassAuth) {
      // Simulate successful login
      const mockUser = {
        id: 'admin-user-001',
        email: 'admin@fixops.dev',
        username: 'admin',
        first_name: 'System',
        last_name: 'Administrator',
        roles: ['admin', 'security_analyst', 'compliance_officer'],
        full_name: 'System Administrator'
      }
      
      setUser(mockUser)
      setIsAuthenticated(true)
      toast.success(`Welcome back, ${mockUser.first_name}!`)
      console.log('🔓 Mock login successful - Demo mode')
      return { success: true }
    }

    try {
      setIsLoading(true)
      
      const response = await api.post('/auth/login', credentials)
      const { access_token, refresh_token, user: userData } = response.data

      // Store tokens
      localStorage.setItem('access_token', access_token)
      localStorage.setItem('refresh_token', refresh_token)
      
      // Set authorization header
      api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`
      
      // Update state
      setUser(userData)
      setIsAuthenticated(true)
      
      toast.success(`Welcome back, ${userData.first_name}!`)
      
      return { success: true }
    } catch (error) {
      const errorMessage = error.response?.data?.error?.message || 'Login failed'
      toast.error(errorMessage)
      
      return { 
        success: false, 
        error: errorMessage,
        requiresMFA: error.response?.status === 401 && errorMessage.includes('MFA')
      }
    } finally {
      setIsLoading(false)
    }
  }

  const logout = async () => {
    if (bypassAuth) {
      console.log('🔓 Mock logout - Demo mode')
      toast.success('Logged out successfully')
      return
    }

    try {
      // Notify backend of logout
      await api.post('/auth/logout')
    } catch (error) {
      console.error('Logout API call failed:', error)
    } finally {
      // Clear local state regardless of API result
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      delete api.defaults.headers.common['Authorization']
      
      setUser(null)
      setIsAuthenticated(false)
      
      // Clear all cached queries
      queryClient.clear()
      
      toast.success('Logged out successfully')
    }
  }

  const refreshToken = async () => {
    const refresh_token = localStorage.getItem('refresh_token')
    
    if (!refresh_token) {
      throw new Error('No refresh token available')
    }

    try {
      const response = await api.post('/auth/refresh', { refresh_token })
      const { access_token, refresh_token: new_refresh_token } = response.data

      // Update stored tokens
      localStorage.setItem('access_token', access_token)
      localStorage.setItem('refresh_token', new_refresh_token)
      
      // Update authorization header
      api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`

      return access_token
    } catch (error) {
      // Refresh failed, logout user
      await logout()
      throw error
    }
  }

  const updateUser = (userData) => {
    setUser(prevUser => ({ ...prevUser, ...userData }))
  }

  const hasRole = (role) => {
    return user?.roles?.includes(role) || false
  }

  const hasPermission = (permission) => {
    // This would typically check against a permissions API
    // For now, we'll do basic role-based checks
    if (!user?.roles) return false
    
    const rolePermissions = {
      admin: ['*'], // Admin has all permissions
      security_analyst: [
        'incident.read', 'incident.create', 'incident.update',
        'analytics.read', 'audit.read', 'system.monitor'
      ],
      operator: [
        'incident.read', 'incident.create', 'incident.update',
        'analytics.read'
      ],
      viewer: ['incident.read', 'analytics.read'],
      compliance_officer: [
        'incident.read', 'analytics.read', 'analytics.export',
        'audit.read', 'compliance.manage'
      ]
    }
    
    for (const role of user.roles) {
      const permissions = rolePermissions[role] || []
      if (permissions.includes('*') || permissions.includes(permission)) {
        return true
      }
    }
    
    return false
  }

  const value = {
    user,
    isAuthenticated,
    isLoading,
    login,
    logout,
    refreshToken,
    updateUser,
    hasRole,
    hasPermission,
    checkAuthStatus,
    bypassAuth
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export default AuthContext