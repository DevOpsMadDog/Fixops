import React from 'react'
import { Activity, Layers, Network, Database, Cloud, Cpu } from 'lucide-react'

function ArchitectDashboard() {
  const architectureMetrics = {
    services: 23,
    dependencies: 156,
    hotPaths: 12,
    dataFlows: 45,
    securityZones: 4,
    performanceScore: 'A+'
  }

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
          Architect Dashboard
        </h3>
        <p className="mt-2 max-w-4xl text-sm text-gray-500">
          System architecture overview and security design patterns
        </p>
      </div>

      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
        <StatCard
          title="Services"
          value={architectureMetrics.services}
          icon={Layers}
          color="text-blue-600"
          subtitle="microservices monitored"
        />
        <StatCard
          title="Dependencies"
          value={architectureMetrics.dependencies}
          icon={Network}
          color="text-purple-600"
          subtitle="service interactions"
        />
        <StatCard
          title="Hot Paths"
          value={architectureMetrics.hotPaths}
          icon={Activity}
          color="text-red-600"
          subtitle="performance critical routes"
        />
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Architecture Metrics</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Data Flows</span>
                <span className="text-sm font-medium text-blue-600">{architectureMetrics.dataFlows}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Security Zones</span>
                <span className="text-sm font-medium text-green-600">{architectureMetrics.securityZones}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Performance Score</span>
                <span className="text-sm font-medium text-green-600">{architectureMetrics.performanceScore}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Security Architecture</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-900">Zero Trust Implementation</span>
                <span className="text-xs bg-green-200 text-green-800 px-2 py-1 rounded">Active</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-900">Service Mesh Security</span>
                <span className="text-xs bg-green-200 text-green-800 px-2 py-1 rounded">Enabled</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-900">Network Segmentation</span>
                <span className="text-xs bg-green-200 text-green-800 px-2 py-1 rounded">Configured</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">System Design Insights</h3>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <Cpu className="h-5 w-5 text-blue-600 mr-2" />
                <h4 className="text-sm font-medium text-blue-800">Performance Optimization</h4>
              </div>
              <p className="text-xs text-blue-700">
                Hot path analysis shows 12 critical routes achieving sub-299μs latency targets.
              </p>
            </div>
            
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <Database className="h-5 w-5 text-green-600 mr-2" />
                <h4 className="text-sm font-medium text-green-800">Data Architecture</h4>
              </div>
              <p className="text-xs text-green-700">
                Distributed data patterns ensure PII compliance across 4 security zones.
              </p>
            </div>
            
            <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <Cloud className="h-5 w-5 text-purple-600 mr-2" />
                <h4 className="text-sm font-medium text-purple-800">Cloud Native Design</h4>
              </div>
              <p className="text-xs text-purple-700">
                Kubernetes-native architecture with automated security policy enforcement.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ArchitectDashboard