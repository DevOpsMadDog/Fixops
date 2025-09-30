import React, { useState, useEffect } from 'react'
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  TrendingUp,
  Code,
  Bug,
  Zap,
  Activity,
  Target
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

  const MetricCard = ({ title, value, icon: IconComponent, color, subtitle, trend }) => (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow duration-200">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-600 mb-1">{title}</p>
          <p className="text-2xl font-bold text-gray-900 mb-1">{value}</p>
          {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}
        </div>
        <div className={`p-2 rounded-lg ${color === 'blue' ? 'bg-blue-100' : 
                                         color === 'yellow' ? 'bg-yellow-100' :
                                         color === 'red' ? 'bg-red-100' : 
                                         color === 'green' ? 'bg-green-100' : 'bg-gray-100'}`}>
          <IconComponent className={`h-5 w-5 ${color === 'blue' ? 'text-blue-600' : 
                                                color === 'yellow' ? 'text-yellow-600' :
                                                color === 'red' ? 'text-red-600' : 
                                                color === 'green' ? 'text-green-600' : 'text-gray-600'}`} />
        </div>
      </div>
    </div>
  )

  const ActivityItem = ({ icon: IconComponent, title, description, time, status }) => (
    <div className="flex items-start space-x-3 p-3 rounded-lg hover:bg-gray-50">
      <div className={`p-2 rounded-full ${status === 'success' ? 'bg-green-100' : 
                                         status === 'warning' ? 'bg-yellow-100' : 'bg-blue-100'}`}>
        <IconComponent className={`h-4 w-4 ${status === 'success' ? 'text-green-600' : 
                                              status === 'warning' ? 'text-yellow-600' : 'text-blue-600'}`} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-gray-900">{title}</p>
        <p className="text-sm text-gray-500">{description}</p>
        <p className="text-xs text-gray-400 mt-1">{time}</p>
      </div>
    </div>
  )

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Developer Dashboard</h1>
        <p className="text-gray-600">Security findings and performance metrics for your applications</p>
      </div>

      {/* Key Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <MetricCard
          title="Total Findings"
          value={stats.totalFindings}
          icon={Shield}
          color="blue"
        />
        <MetricCard
          title="Open Findings"
          value={stats.openFindings}
          icon={AlertTriangle}
          color="yellow"
        />
        <MetricCard
          title="Critical"
          value={stats.criticalFindings}
          icon={Bug}
          color="red"
        />
        <MetricCard
          title="Fixed"
          value={stats.fixedFindings}
          icon={CheckCircle}
          color="green"
        />
      </div>

      {/* Performance & Activity Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        {/* Performance Metrics */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div className="flex items-center mb-6">
            <div className="p-2 bg-purple-100 rounded-lg mr-3">
              <Zap className="h-5 w-5 text-purple-600" />
            </div>
            <h3 className="text-lg font-semibold text-gray-900">Performance Metrics</h3>
          </div>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center">
                <Target className="h-4 w-4 text-green-600 mr-2" />
                <span className="text-sm font-medium text-gray-700">Hot Path Latency</span>
              </div>
              <div className="text-right">
                <span className={`text-lg font-bold ${stats.hotPathLatency <= 299 ? 'text-green-600' : 'text-red-600'}`}>
                  {stats.hotPathLatency}μs
                </span>
                <span className="text-xs text-gray-500 block">(target: 299μs)</span>
              </div>
            </div>
            
            <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center">
                <Activity className="h-4 w-4 text-blue-600 mr-2" />
                <span className="text-sm font-medium text-gray-700">Correlated Findings</span>
              </div>
              <span className="text-lg font-bold text-blue-600">{stats.correlatedFindings}</span>
            </div>
            
            <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center">
                <TrendingUp className="h-4 w-4 text-green-600 mr-2" />
                <span className="text-sm font-medium text-gray-700">Noise Reduction</span>
              </div>
              <span className="text-lg font-bold text-green-600">35%</span>
            </div>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div className="flex items-center mb-6">
            <div className="p-2 bg-orange-100 rounded-lg mr-3">
              <Clock className="h-5 w-5 text-orange-600" />
            </div>
            <h3 className="text-lg font-semibold text-gray-900">Recent Activity</h3>
          </div>
          
          <div className="space-y-2">
            <ActivityItem
              icon={Bug}
              title="SQL Injection fixed in user-service"
              description="Critical vulnerability resolved"
              time="2h ago"
              status="success"
            />
            <ActivityItem
              icon={AlertTriangle}
              title="XSS vulnerability correlated (3 findings)"
              description="Similar issues found across services"
              time="4h ago"
              status="warning"
            />
            <ActivityItem
              icon={CheckCircle}
              title="Policy decision: ALLOW deployment"
              description="Security review completed"
              time="6h ago"
              status="success"
            />
          </div>
        </div>
      </div>

      {/* AI Insights */}
      <div className="bg-gradient-to-r from-blue-50 to-purple-50 rounded-xl border border-blue-200 p-6">
        <div className="flex items-center mb-4">
          <div className="p-2 bg-blue-100 rounded-lg mr-3">
            <Activity className="h-5 w-5 text-blue-600" />
          </div>
          <h3 className="text-lg font-semibold text-gray-900">AI-Powered Insights</h3>
        </div>
        
        <div className="bg-white rounded-lg p-4 border border-blue-100">
          <div className="flex items-start space-x-3">
            <div className="p-1 bg-green-100 rounded-full">
              <div className="w-2 h-2 bg-green-500 rounded-full"></div>
            </div>
            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-1">Correlation Engine Active</h4>
              <p className="text-sm text-gray-600">
                Automatically correlating security findings and reducing noise by 35%. 
                Last analysis: 45 findings correlated into 12 actionable items.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default DeveloperDashboard
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