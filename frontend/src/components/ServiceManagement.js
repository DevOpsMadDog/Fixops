import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Server, Plus, Edit, Globe, Lock, Database, Shield } from 'lucide-react';
import { api } from '../api/client';
import LoadingSpinner from './LoadingSpinner';

const ServiceManagement = () => {
  const [showCreateForm, setShowCreateForm] = useState(false);
  
  const { data: services, isLoading, refetch } = useQuery({
    queryKey: ['services'],
    queryFn: () => api.getServices().then(res => res.data),
  });

  const { data: findings } = useQuery({
    queryKey: ['findings'],
    queryFn: () => api.getFindings().then(res => res.data),
  });

  if (isLoading) {
    return <LoadingSpinner />;
  }

  const getServiceFindings = (serviceId) => {
    return findings?.filter(f => f.service_id === serviceId) || [];
  };

  const getDataClassificationColor = (classifications) => {
    if (classifications.includes('pci')) return 'bg-red-100 text-red-800 border-red-200';
    if (classifications.includes('pii')) return 'bg-orange-100 text-orange-800 border-orange-200';
    if (classifications.includes('phi')) return 'bg-purple-100 text-purple-800 border-purple-200';
    if (classifications.includes('confidential')) return 'bg-yellow-100 text-yellow-800 border-yellow-200';
    return 'bg-gray-100 text-gray-800 border-gray-200';
  };

  const getEnvironmentColor = (env) => {
    switch (env) {
      case 'production': return 'bg-red-100 text-red-800';
      case 'staging': return 'bg-yellow-100 text-yellow-800';
      case 'dev': return 'bg-green-100 text-green-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Service Registry</h1>
          <p className="text-gray-600 mt-1">Manage fintech services and their security context</p>
        </div>
        <button
          onClick={() => setShowCreateForm(true)}
          className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Service
        </button>
      </div>

      {/* Services Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Services</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">{services?.length || 0}</p>
            </div>
            <Server className="w-8 h-8 text-blue-600" />
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Production Services</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">
                {services?.filter(s => s.environment === 'production').length || 0}
              </p>
            </div>
            <Shield className="w-8 h-8 text-red-600" />
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">PCI Scope</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">
                {services?.filter(s => s.pci_scope).length || 0}
              </p>
            </div>
            <Lock className="w-8 h-8 text-red-600" />
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Internet-Facing</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">
                {services?.filter(s => s.internet_facing).length || 0}
              </p>
            </div>
            <Globe className="w-8 h-8 text-orange-600" />
          </div>
        </div>
      </div>

      {/* Services Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Services</h2>
          <p className="text-sm text-gray-600 mt-1">All registered services in the FixOps knowledge graph</p>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Service
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Business Capability
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Environment
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Data Classification
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Exposure
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Findings
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Owner
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {services?.map((service) => {
                const serviceFindings = getServiceFindings(service.id);
                const criticalFindings = serviceFindings.filter(f => f.severity === 'critical').length;
                const highFindings = serviceFindings.filter(f => f.severity === 'high').length;
                
                return (
                  <tr key={service.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 w-10 h-10">
                          <div className="w-10 h-10 rounded-lg bg-blue-100 flex items-center justify-center">
                            <Server className="w-5 h-5 text-blue-600" />
                          </div>
                        </div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-gray-900">{service.name}</div>
                          <div className="text-sm text-gray-500">ID: {service.id.slice(0, 8)}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900">{service.business_capability}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-center">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getEnvironmentColor(service.environment)}`}>
                        {service.environment}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-center">
                      <div className="flex flex-wrap justify-center gap-1">
                        {service.data_classification.map(classification => (
                          <span key={classification} className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full border ${getDataClassificationColor([classification])}`}>
                            {classification.toUpperCase()}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-center">
                      <div className="flex justify-center space-x-1">
                        {service.internet_facing && (
                          <Globe className="w-4 h-4 text-red-500" title="Internet-facing" />
                        )}
                        {service.pci_scope && (
                          <Lock className="w-4 h-4 text-red-600" title="PCI Scope" />
                        )}
                        {service.data_classification.includes('pii') && (
                          <Database className="w-4 h-4 text-orange-500" title="PII Data" />
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-center">
                      <div className="flex flex-col items-center">
                        <div className="text-sm font-medium text-gray-900">{serviceFindings.length}</div>
                        {(criticalFindings > 0 || highFindings > 0) && (
                          <div className="text-xs text-red-600">
                            {criticalFindings > 0 && `${criticalFindings}C`}
                            {criticalFindings > 0 && highFindings > 0 && ', '}
                            {highFindings > 0 && `${highFindings}H`}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900">{service.owner_team}</div>
                      <div className="text-sm text-gray-500">{service.owner_email}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <button className="text-blue-600 hover:text-blue-900 mr-3">
                        <Edit className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ServiceManagement;