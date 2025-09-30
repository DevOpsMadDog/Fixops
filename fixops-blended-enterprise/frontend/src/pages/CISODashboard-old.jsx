import React from 'react'
import { Shield, TrendingDown, AlertTriangle, CheckCircle, Users, Target } from 'lucide-react'

function CISODashboard() {
  const riskMetrics = {
    overallRiskScore: 6.2,
    criticalServices: 3,
    complianceScore: 94,
    mttr: '2.4h',
    securityTeamSize: 12,
    coveragePercentage: 87
  }

  const StatCard = ({ title, value, icon: Icon, color, subtitle, trend }) => (
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
              <dd className="text-lg font-medium text-gray-900">
                {value}
                {trend && (
                  <span className={`ml-2 text-xs ${trend > 0 ? 'text-red-600' : 'text-green-600'}`}>
                    {trend > 0 ? '+' : ''}{trend}%
                  </span>
                )}
              </dd>
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
          CISO Dashboard
        </h3>
        <p className="mt-2 max-w-4xl text-sm text-gray-500">
          Executive security risk overview and compliance status
        </p>
      </div>

      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
        <StatCard
          title="Risk Score"
          value={riskMetrics.overallRiskScore}
          icon={Shield}
          color="text-yellow-600"
          subtitle="out of 10 (lower is better)"
          trend={-12}
        />
        <StatCard
          title="Critical Services"
          value={riskMetrics.criticalServices}
          icon={AlertTriangle}
          color="text-red-600"
          subtitle="requiring immediate attention"
        />
        <StatCard
          title="Compliance Score"
          value={`${riskMetrics.complianceScore}%`}
          icon={CheckCircle}
          color="text-green-600"
          subtitle="NIST SSDF & SOC2"
          trend={3}
        />
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Security Metrics</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Mean Time to Remediation</span>
                <span className="text-sm font-medium text-blue-600">{riskMetrics.mttr}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Security Team Size</span>
                <span className="text-sm font-medium text-gray-900">{riskMetrics.securityTeamSize}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Coverage Percentage</span>
                <span className="text-sm font-medium text-green-600">{riskMetrics.coveragePercentage}%</span>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Policy Automation</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Active Policies</span>
                <span className="text-sm font-medium text-blue-600">24</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Automated Decisions</span>
                <span className="text-sm font-medium text-green-600">89%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500">Policy Violations</span>
                <span className="text-sm font-medium text-red-600">3</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Risk Assessment & Compliance</h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-3">High-Risk Areas</h4>
              <div className="space-y-2">
                <div className="flex items-center justify-between p-3 bg-red-50 rounded-lg">
                  <span className="text-sm text-red-800">Payment Processing Service</span>
                  <span className="text-xs bg-red-200 text-red-800 px-2 py-1 rounded">Critical</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-yellow-50 rounded-lg">
                  <span className="text-sm text-yellow-800">User Authentication Module</span>
                  <span className="text-xs bg-yellow-200 text-yellow-800 px-2 py-1 rounded">High</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-yellow-50 rounded-lg">
                  <span className="text-sm text-yellow-800">API Gateway</span>
                  <span className="text-xs bg-yellow-200 text-yellow-800 px-2 py-1 rounded">High</span>
                </div>
              </div>
            </div>
            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-3">Compliance Status</h4>
              <div className="space-y-2">
                <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                  <span className="text-sm text-green-800">NIST SSDF</span>
                  <span className="text-xs bg-green-200 text-green-800 px-2 py-1 rounded">Compliant</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                  <span className="text-sm text-green-800">SOC2 Type II</span>
                  <span className="text-xs bg-green-200 text-green-800 px-2 py-1 rounded">Compliant</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-yellow-50 rounded-lg">
                  <span className="text-sm text-yellow-800">PCI DSS</span>
                  <span className="text-xs bg-yellow-200 text-yellow-800 px-2 py-1 rounded">Review Required</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default CISODashboard