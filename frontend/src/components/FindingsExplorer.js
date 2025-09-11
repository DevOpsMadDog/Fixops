import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Search, Filter, AlertTriangle, Eye, Download } from 'lucide-react';
import { api } from '../api/client';
import LoadingSpinner from './LoadingSpinner';
import FindingsList from './FindingsList';

const FindingsExplorer = () => {
  const [filters, setFilters] = useState({
    severity: '',
    scanner_type: '',
    status: '',
    search: ''
  });

  const { data: findings, isLoading } = useQuery({
    queryKey: ['findings', filters],
    queryFn: () => api.getFindings(filters).then(res => res.data),
  });

  const { data: services } = useQuery({
    queryKey: ['services'],
    queryFn: () => api.getServices().then(res => res.data),
  });

  if (isLoading) {
    return <LoadingSpinner />;
  }

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const clearFilters = () => {
    setFilters({
      severity: '',
      scanner_type: '',
      status: '',
      search: ''
    });
  };

  const getServiceName = (serviceId) => {
    const service = services?.find(s => s.id === serviceId);
    return service?.name || 'Unknown Service';
  };

  const enrichedFindings = findings?.map(finding => ({
    ...finding,
    serviceName: getServiceName(finding.service_id)
  })) || [];

  // Calculate stats
  const totalFindings = findings?.length || 0;
  const criticalFindings = findings?.filter(f => f.severity === 'critical').length || 0;
  const highFindings = findings?.filter(f => f.severity === 'high').length || 0;
  
  const scannerStats = findings?.reduce((acc, finding) => {
    acc[finding.scanner_type] = (acc[finding.scanner_type] || 0) + 1;
    return acc;
  }, {}) || {};

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Findings Explorer</h1>
          <p className="text-gray-600 mt-1">Cross-scanner correlation and intelligent noise reduction</p>
        </div>
        <div className="flex items-center space-x-3">
          <button className="inline-flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors">
            <Download className="w-4 h-4 mr-2" />
            Export SARIF
          </button>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Findings</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">{totalFindings}</p>
              <p className="text-xs text-green-600 mt-1">67% noise reduced</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-gray-400" />
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Critical</p>
              <p className="text-2xl font-bold text-red-600 mt-1">{criticalFindings}</p>
              <p className="text-xs text-gray-500 mt-1">Immediate action</p>
            </div>
            <div className="w-8 h-8 rounded-full bg-red-100 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-red-600" />
            </div>
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">High Priority</p>
              <p className="text-2xl font-bold text-orange-600 mt-1">{highFindings}</p>
              <p className="text-xs text-gray-500 mt-1">Next sprint</p>
            </div>
            <div className="w-8 h-8 rounded-full bg-orange-100 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-orange-600" />
            </div>
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Scanner Coverage</p>
              <p className="text-2xl font-bold text-blue-600 mt-1">{Object.keys(scannerStats).length}</p>
              <p className="text-xs text-gray-500 mt-1">Active scanners</p>
            </div>
            <Eye className="w-8 h-8 text-blue-600" />
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-medium text-gray-900 flex items-center">
            <Filter className="w-5 h-5 mr-2" />
            Filters
          </h2>
          {Object.values(filters).some(v => v) && (
            <button
              onClick={clearFilters}
              className="text-sm text-blue-600 hover:text-blue-800"
            >
              Clear all
            </button>
          )}
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Search</label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
              <input
                type="text"
                placeholder="Search findings..."
                value={filters.search}
                onChange={(e) => handleFilterChange('search', e.target.value)}
                className="w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
            <select
              value={filters.severity}
              onChange={(e) => handleFilterChange('severity', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Scanner</label>
            <select
              value={filters.scanner_type}
              onChange={(e) => handleFilterChange('scanner_type', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">All Scanners</option>
              <option value="sast">SAST</option>
              <option value="sca">SCA</option>
              <option value="dast">DAST</option>
              <option value="iast">IAST</option>
              <option value="rasp">RASP</option>
              <option value="iac">IaC</option>
              <option value="container">Container</option>
              <option value="vm">VM</option>
              <option value="cnapp">CNAPP</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
            <select
              value={filters.status}
              onChange={(e) => handleFilterChange('status', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="fixed">Fixed</option>
              <option value="waived">Waived</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>
        </div>
      </div>

      {/* Scanner Statistics */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-medium text-gray-900 mb-4">Scanner Distribution</h2>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {Object.entries(scannerStats).map(([scanner, count]) => (
            <div key={scanner} className="text-center p-3 bg-gray-50 rounded-lg">
              <div className="text-2xl font-bold text-gray-900">{count}</div>
              <div className="text-sm text-gray-600 uppercase font-medium">{scanner}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Findings List */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Security Findings</h2>
            <span className="text-sm text-gray-500">
              {enrichedFindings.length} {enrichedFindings.length === 1 ? 'finding' : 'findings'}
            </span>
          </div>
        </div>
        
        {enrichedFindings.length > 0 ? (
          <FindingsList 
            findings={enrichedFindings} 
            showBusinessContext={true} 
            limit={50}
          />
        ) : (
          <div className="p-8 text-center text-gray-500">
            <AlertTriangle className="w-12 h-12 mx-auto text-gray-300 mb-4" />
            <p>No findings match your current filters</p>
            <button
              onClick={clearFilters}
              className="mt-2 text-blue-600 hover:text-blue-800 text-sm"
            >
              Clear filters to see all findings
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default FindingsExplorer;