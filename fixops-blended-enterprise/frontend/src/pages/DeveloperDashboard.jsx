import React, { useState, useEffect } from 'react'
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  TrendingUp,
  Code,
  Bug,
  Zap
} from 'lucide-react'
import { apiMethods } from '../utils/api'

function DeveloperDashboard() {
  const [stats, setStats] = useState({
    totalFindings: 127,
    openFindings: 34,
    criticalFindings: 8,
    fixedFindings: 93,
    hotPathLatency: 285,
    correlatedFindings: 45
  })
  const [isLoading, setIsLoading] = useState(false)

  const StatCard = ({ title, value, icon: Icon, color, subtitle }) => (
    <div className="bg-white overflow-hidden shadow rounded-lg">
      <div className="p-5">
        <div className="flex items-center">
          <div className="flex-shrink-0">
            <Icon className={`h-6 w-6 ${color}`} />
          </div>
          <div className="ml-5 w-0 flex-1">
            <dl>
              <dt className="text-sm font-medium text-gray-500 truncate">
                {title}
              </dt>
              <dd className="text-lg font-medium text-gray-900">{value}</dd>
              {subtitle && (
                <dd className="text-xs text-gray-500">{subtitle}</dd>
              )}
            </dl>
          </div>
        </div>
      </div>
    </div>
  )

  return (
    <div className="space-y-6">
      <div className="border-b border-gray-200 pb-5">
        <h3 className="text-lg leading-6 font-medium text-gray-900">
          Developer Dashboard
        </h3>
        <p className="mt-2 max-w-4xl text-sm text-gray-500">
          Security findings and performance metrics for your applications
        </p>
      </div>

      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Findings"
          value={stats.totalFindings}
          icon={Shield}
          color="text-blue-600"
        />
        <StatCard
          title="Open Findings"
          value={stats.openFindings}
          icon={AlertTriangle}
          color="text-yellow-600"
        />
        <StatCard
          title="Critical"
          value={stats.criticalFindings}
          icon={Bug}
          color="text-red-600"
        />
        <StatCard
          title="Fixed"
          value={stats.fixedFindings}
          icon={CheckCircle}
          color="text-green-600"
        />
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <div className="flex items-center">
              <Zap className="h-5 w-5 text-blue-600 mr-2" />
              <h3 className="text-lg font-medium text-gray-900">Performance Metrics</h3>
            </div>
            <div className="mt-4 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Hot Path Latency</span>
                <div className="flex items-center">
                  <span className={`text-sm font-medium ${stats.hotPathLatency <= 299 ? 'text-green-600' : 'text-red-600'}`}>
                    {stats.hotPathLatency}μs
                  </span>
                  <span className="text-xs text-gray-400 ml-2">(target: 299μs)</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Correlated Findings</span>
                <span className="text-sm font-medium text-blue-600">{stats.correlatedFindings}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Noise Reduction</span>
                <span className="text-sm font-medium text-green-600">35%</span>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <div className="flex items-center">
              <TrendingUp className="h-5 w-5 text-green-600 mr-2" />
              <h3 className="text-lg font-medium text-gray-900">Recent Activity</h3>
            </div>
            <div className="mt-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-900">SQL Injection fixed in user-service</span>
                <span className="text-xs text-gray-500">2h ago</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-900">XSS vulnerability correlated (3 findings)</span>
                <span className="text-xs text-gray-500">4h ago</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-900">Policy decision: ALLOW deployment</span>
                <span className="text-xs text-gray-500">6h ago</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">AI-Powered Insights</h3>
          <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
            <div className="flex">
              <Shield className="h-5 w-5 text-blue-400" />
              <div className="ml-3">
                <h4 className="text-sm font-medium text-blue-800">
                  Correlation Engine Active
                </h4>
                <p className="text-sm text-blue-700 mt-1">
                  Automatically correlating security findings and reducing noise by 35%. 
                  Last analysis: 45 findings correlated into 12 actionable items.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default DeveloperDashboard