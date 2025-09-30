import React, { useState } from 'react'
import { Plus, Search, Settings, Shield, Globe, Database, AlertTriangle } from 'lucide-react'

function ServiceManagement() {
  const [searchTerm, setSearchTerm] = useState('')
  const [services] = useState([
    {
      id: '1',
      name: 'Payment Service',
      environment: 'production',
      owner: 'payments-team@company.com',
      riskScore: 8.5,
      findings: 12,
      lastScan: '2 hours ago',
      dataClassification: ['PCI', 'PII'],
      internetFacing: true
    },
    {
      id: '2',
      name: 'User Authentication',
      environment: 'production',
      owner: 'auth-team@company.com',
      riskScore: 6.2,
      findings: 8,
      lastScan: '4 hours ago',
      dataClassification: ['PII'],
      internetFacing: true
    },
    {
      id: '3',
      name: 'Internal Analytics',
      environment: 'staging',
      owner: 'analytics-team@company.com',
      riskScore: 3.1,
      findings: 3,
      lastScan: '1 day ago',
      dataClassification: ['Internal'],
      internetFacing: false
    }
  ])

  const getRiskColor = (score) => {
    if (score >= 8) return 'text-red-600 bg-red-100'
    if (score >= 6) return 'text-yellow-600 bg-yellow-100'
    if (score >= 4) return 'text-blue-600 bg-blue-100'
    return 'text-green-600 bg-green-100'
  }

  const getEnvironmentColor = (env) => {
    switch (env) {
      case 'production': return 'text-red-700 bg-red-100'
      case 'staging': return 'text-yellow-700 bg-yellow-100'
      case 'development': return 'text-green-700 bg-green-100'
      default: return 'text-gray-700 bg-gray-100'
    }
  }

  const filteredServices = services.filter(service =>
    service.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    service.owner.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="border-b border-gray-200 pb-5">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg leading-6 font-medium text-gray-900">
              Service Management
            </h3>
            <p className="mt-2 max-w-4xl text-sm text-gray-500">
              Manage and monitor your microservices security posture
            </p>
          </div>
          <button className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
            <Plus className="h-4 w-4 mr-2" />
            Add Service
          </button>
        </div>
      </div>

      <div className="flex items-center space-x-4">
        <div className="relative flex-1 max-w-md">
          <Search className="h-5 w-5 text-gray-400 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search services..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
        </div>
      </div>

      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200">
          {filteredServices.map((service) => (
            <li key={service.id} className="px-6 py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center min-w-0 flex-1">
                  <div className="flex-shrink-0">
                    <div className="h-10 w-10 flex items-center justify-center rounded-lg bg-blue-100">
                      <Shield className="h-6 w-6 text-blue-600" />
                    </div>
                  </div>
                  <div className="ml-4 min-w-0 flex-1">
                    <div className="flex items-center space-x-3">
                      <p className="text-sm font-medium text-gray-900 truncate">
                        {service.name}
                      </p>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${getEnvironmentColor(service.environment)}`}>
                        {service.environment}
                      </span>
                      {service.internetFacing && (
                        <span className="flex items-center text-xs text-orange-600">
                          <Globe className="h-3 w-3 mr-1" />
                          Internet Facing
                        </span>
                      )}
                    </div>
                    <div className="flex items-center space-x-4 mt-2">
                      <div className="flex items-center text-xs text-gray-500">
                        <Database className="h-3 w-3 mr-1" />
                        Data: {service.dataClassification.join(', ')}
                      </div>
                      <div className="text-xs text-gray-500">
                        Owner: {service.owner}
                      </div>
                      <div className="text-xs text-gray-500">
                        Last scan: {service.lastScan}
                      </div>
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-4">
                  <div className="text-center">
                    <div className={`px-2 py-1 text-xs font-medium rounded-full ${getRiskColor(service.riskScore)}`}>
                      Risk: {service.riskScore}
                    </div>
                  </div>
                  <div className="text-center">
                    <div className="text-sm font-medium text-gray-900">{service.findings}</div>
                    <div className="text-xs text-gray-500">findings</div>
                  </div>
                  <div className="flex space-x-2">
                    <button className="text-blue-600 hover:text-blue-900">
                      <Settings className="h-4 w-4" />
                    </button>
                    <button className="text-blue-600 hover:text-blue-900">
                      <AlertTriangle className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>

      <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
        <div className="flex">
          <Shield className="h-5 w-5 text-blue-400" />
          <div className="ml-3">
            <h4 className="text-sm font-medium text-blue-800">
              Security Monitoring Active
            </h4>
            <p className="text-sm text-blue-700 mt-1">
              All services are being continuously monitored for security findings. 
              Risk scores are updated in real-time based on vulnerability assessments and policy evaluations.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ServiceManagement