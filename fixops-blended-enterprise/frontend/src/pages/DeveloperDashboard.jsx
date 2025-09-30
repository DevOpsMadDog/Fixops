import React, { useState, useEffect } from 'react'

function DeveloperDashboard() {
  const [stats, setStats] = useState({
    totalFindings: 127,
    openFindings: 34,
    criticalFindings: 8,
    fixedFindings: 93,
    hotPathLatency: 285,
    correlatedFindings: 45
  })

  const MetricCard = ({ title, value, iconBg, iconText, subtitle }) => (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow duration-200">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-600 mb-1">{title}</p>
          <p className="text-2xl font-bold text-gray-900 mb-1">{value}</p>
          {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}
        </div>
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-white font-bold ${iconBg}`}>
          {iconText}
        </div>
      </div>
    </div>
  )

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
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
            iconBg="bg-blue-500"
            iconText="🛡️"
          />
          <MetricCard
            title="Open Findings"
            value={stats.openFindings}
            iconBg="bg-yellow-500"
            iconText="⚠️"
          />
          <MetricCard
            title="Critical"
            value={stats.criticalFindings}
            iconBg="bg-red-500"
            iconText="🐛"
          />
          <MetricCard
            title="Fixed"
            value={stats.fixedFindings}
            iconBg="bg-green-500"
            iconText="✅"
          />
        </div>

        {/* Performance & Activity Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          {/* Performance Metrics */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div className="flex items-center mb-6">
              <div className="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center mr-3">
                <span className="text-purple-600 text-lg">⚡</span>
              </div>
              <h3 className="text-lg font-semibold text-gray-900">Performance Metrics</h3>
            </div>
            
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center">
                  <span className="text-green-600 text-sm mr-2">🎯</span>
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
                  <span className="text-blue-600 text-sm mr-2">📊</span>
                  <span className="text-sm font-medium text-gray-700">Correlated Findings</span>
                </div>
                <span className="text-lg font-bold text-blue-600">{stats.correlatedFindings}</span>
              </div>
              
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center">
                  <span className="text-green-600 text-sm mr-2">📈</span>
                  <span className="text-sm font-medium text-gray-700">Noise Reduction</span>
                </div>
                <span className="text-lg font-bold text-green-600">35%</span>
              </div>
            </div>
          </div>

          {/* Recent Activity */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div className="flex items-center mb-6">
              <div className="w-10 h-10 bg-orange-100 rounded-lg flex items-center justify-center mr-3">
                <span className="text-orange-600 text-lg">🕒</span>
              </div>
              <h3 className="text-lg font-semibold text-gray-900">Recent Activity</h3>
            </div>
            
            <div className="space-y-4">
              <div className="flex items-start space-x-3 p-3 rounded-lg hover:bg-gray-50">
                <div className="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center">
                  <span className="text-green-600 text-sm">🐛</span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900">SQL Injection fixed in user-service</p>
                  <p className="text-sm text-gray-500">Critical vulnerability resolved</p>
                  <p className="text-xs text-gray-400 mt-1">2h ago</p>
                </div>
              </div>
              
              <div className="flex items-start space-x-3 p-3 rounded-lg hover:bg-gray-50">
                <div className="w-8 h-8 bg-yellow-100 rounded-full flex items-center justify-center">
                  <span className="text-yellow-600 text-sm">⚠️</span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900">XSS vulnerability correlated (3 findings)</p>
                  <p className="text-sm text-gray-500">Similar issues found across services</p>
                  <p className="text-xs text-gray-400 mt-1">4h ago</p>
                </div>
              </div>
              
              <div className="flex items-start space-x-3 p-3 rounded-lg hover:bg-gray-50">
                <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                  <span className="text-blue-600 text-sm">✅</span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900">Policy decision: ALLOW deployment</p>
                  <p className="text-sm text-gray-500">Security review completed</p>
                  <p className="text-xs text-gray-400 mt-1">6h ago</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* AI Insights */}
        <div className="bg-gradient-to-r from-blue-50 to-purple-50 rounded-xl border border-blue-200 p-6">
          <div className="flex items-center mb-4">
            <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center mr-3">
              <span className="text-blue-600 text-lg">🤖</span>
            </div>
            <h3 className="text-lg font-semibold text-gray-900">AI-Powered Insights</h3>
          </div>
          
          <div className="bg-white rounded-lg p-4 border border-blue-100">
            <div className="flex items-start space-x-3">
              <div className="w-6 h-6 bg-green-100 rounded-full flex items-center justify-center">
                <span className="w-2 h-2 bg-green-500 rounded-full"></span>
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
    </div>
  )
}

export default DeveloperDashboard