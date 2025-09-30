import React, { useState } from 'react'
import { AlertTriangle, Clock, CheckCircle, User, Calendar, Filter } from 'lucide-react'

function IncidentsPage() {
  const [filter, setFilter] = useState('all')
  const [incidents] = useState([
    {
      id: '1',
      title: 'SQL Injection in Payment Service',
      severity: 'critical',
      status: 'open',
      assignee: 'Sarah Chen',
      created: '2 hours ago',
      service: 'payment-service',
      description: 'SQL injection vulnerability discovered in payment processing endpoint'
    },
    {
      id: '2',
      title: 'XSS Vulnerability Cluster',
      severity: 'high',
      status: 'investigating',
      assignee: 'Mike Johnson',
      created: '4 hours ago',
      service: 'web-app',
      description: 'Multiple XSS findings correlated across user input forms'
    },
    {
      id: '3',
      title: 'Hardcoded API Key',
      severity: 'medium',
      status: 'resolved',
      assignee: 'Alex Rodriguez',
      created: '1 day ago',
      service: 'auth-service',
      description: 'Hardcoded API key found in configuration files'
    }
  ])

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100'
      case 'high': return 'text-orange-600 bg-orange-100'
      case 'medium': return 'text-yellow-600 bg-yellow-100'
      case 'low': return 'text-blue-600 bg-blue-100'
      default: return 'text-gray-600 bg-gray-100'
    }
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 'open': return 'text-red-700 bg-red-100'
      case 'investigating': return 'text-yellow-700 bg-yellow-100'
      case 'resolved': return 'text-green-700 bg-green-100'
      default: return 'text-gray-700 bg-gray-100'
    }
  }

  const getStatusIcon = (status) => {
    switch (status) {
      case 'open': return AlertTriangle
      case 'investigating': return Clock
      case 'resolved': return CheckCircle
      default: return AlertTriangle
    }
  }

  const filteredIncidents = filter === 'all' ? incidents : incidents.filter(i => i.status === filter)

  return (
    <div className="space-y-6">
      <div className="border-b border-gray-200 pb-5">
        <h3 className="text-lg leading-6 font-medium text-gray-900">
          Security Incidents
        </h3>
        <p className="mt-2 max-w-4xl text-sm text-gray-500">
          Track and manage security incidents across your services
        </p>
      </div>

      <div className="flex items-center space-x-4">
        <Filter className="h-5 w-5 text-gray-400" />
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="all">All Incidents</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
        </select>
      </div>

      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200">
          {filteredIncidents.map((incident) => {
            const StatusIcon = getStatusIcon(incident.status)
            return (
              <li key={incident.id} className="px-6 py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center min-w-0 flex-1">
                    <div className="flex-shrink-0">
                      <StatusIcon className={`h-5 w-5 ${getSeverityColor(incident.severity).split(' ')[0]}`} />
                    </div>
                    <div className="ml-4 min-w-0 flex-1">
                      <div className="flex items-center space-x-3">
                        <p className="text-sm font-medium text-gray-900 truncate">
                          {incident.title}
                        </p>
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(incident.severity)}`}>
                          {incident.severity}
                        </span>
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(incident.status)}`}>
                          {incident.status}
                        </span>
                      </div>
                      <p className="text-sm text-gray-500 mt-1">
                        {incident.description}
                      </p>
                      <div className="flex items-center text-xs text-gray-400 mt-2 space-x-4">
                        <div className="flex items-center">
                          <User className="h-4 w-4 mr-1" />
                          {incident.assignee}
                        </div>
                        <div className="flex items-center">
                          <Calendar className="h-4 w-4 mr-1" />
                          {incident.created}
                        </div>
                        <div>
                          Service: {incident.service}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="flex-shrink-0">
                    <button className="text-blue-600 hover:text-blue-900 text-sm font-medium">
                      View Details
                    </button>
                  </div>
                </div>
              </li>
            )
          })}
        </ul>
      </div>
    </div>
  )
}

export default IncidentsPage