import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { 
  Shield, 
  Home, 
  AlertTriangle, 
  BarChart3, 
  Settings,
  User,
  LogOut,
  Activity
} from 'lucide-react'

function Layout({ children }) {
  const { user, logout } = useAuth()
  const location = useLocation()

  const navigation = [
    { name: 'Developer', href: '/developer', icon: Home, fullName: 'Developer Dashboard' },
    { name: 'CISO', href: '/ciso', icon: Shield, fullName: 'CISO Dashboard' },
    { name: 'Architect', href: '/architect', icon: Activity, fullName: 'Architect Dashboard' },
    { name: 'Incidents', href: '/incidents', icon: AlertTriangle, fullName: 'Incidents' },
    { name: 'Analytics', href: '/analytics', icon: BarChart3, fullName: 'Analytics' },
    { name: 'Services', href: '/services', icon: Settings, fullName: 'Services' },
  ]

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex">
              <div className="flex-shrink-0 flex items-center">
                <Shield className="h-8 w-8 text-blue-600" />
                <span className="ml-2 text-xl font-bold text-gray-900">FixOps Enterprise</span>
              </div>
              <div className="hidden sm:ml-6 sm:flex sm:space-x-4 lg:space-x-8">
                {navigation.map((item) => {
                  const Icon = item.icon
                  const isActive = location.pathname === item.href
                  return (
                    <Link
                      key={item.name}
                      to={item.href}
                      className={`inline-flex items-center px-2 lg:px-3 pt-1 border-b-2 text-xs lg:text-sm font-medium whitespace-nowrap ${
                        isActive
                          ? 'border-blue-500 text-gray-900'
                          : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
                      }`}
                      title={item.fullName}
                    >
                      <Icon className="h-4 w-4 mr-1 lg:mr-2" />
                      {item.name}
                    </Link>
                  )
                })}
              </div>
            </div>
            <div className="flex items-center">
              <div className="flex items-center space-x-4">
                <span className="text-sm text-gray-700">Welcome, {user?.full_name || 'User'}</span>
                <button
                  onClick={logout}
                  className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                  <LogOut className="h-4 w-4 mr-2" />
                  Logout
                </button>
              </div>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {children}
      </main>
    </div>
  )
}

export default Layout