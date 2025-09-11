import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Layers, Network, Shield, AlertTriangle, Globe, Database, Lock } from 'lucide-react';
import { api } from '../api/client';
import LoadingSpinner from './LoadingSpinner';
import MetricCard from './MetricCard';

const ArchitectDashboard = () => {
  const { data: services, isLoading: servicesLoading } = useQuery({
    queryKey: ['services'],
    queryFn: () => api.getServices().then(res => res.data),
  });

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ['findings'],
    queryFn: () => api.getFindings().then(res => res.data),
  });

  const { data: cases, isLoading: casesLoading } = useQuery({
    queryKey: ['cases'],
    queryFn: () => api.getCases().then(res => res.data),
  });

  if (servicesLoading || findingsLoading || casesLoading) {
    return <LoadingSpinner />;
  }

  // Calculate architecture metrics
  const internetFacingServices = services?.filter(s => s.internet_facing).length || 0;
  const pciServices = services?.filter(s => s.data_classification.includes('pci')).length || 0;
  const piiServices = services?.filter(s => s.data_classification.includes('pii')).length || 0;
  const prodServices = services?.filter(s => s.environment === 'production').length || 0;

  // Group services by business capability
  const servicesByCapability = services?.reduce((acc, service) => {
    const capability = service.business_capability;
    if (!acc[capability]) {
      acc[capability] = [];
    }
    acc[capability].push(service);
    return acc;
  }, {}) || {};

  // Calculate threat exposure
  const threatExposure = services?.map(service => {
    const serviceFindings = findings?.filter(f => f.service_id === service.id) || [];
    const criticalFindings = serviceFindings.filter(f => f.severity === 'critical').length;
    const highFindings = serviceFindings.filter(f => f.severity === 'high').length;
    
    const riskScore = criticalFindings * 10 + highFindings * 5;
    const dataRiskMultiplier = service.data_classification.includes('pci') ? 2 : 
                              service.data_classification.includes('pii') ? 1.5 : 1;
    const exposureMultiplier = service.internet_facing ? 2 : 1;
    
    return {
      ...service,
      riskScore: riskScore * dataRiskMultiplier * exposureMultiplier,
      findingsCount: serviceFindings.length,
      criticalFindings,
      highFindings
    };
  }).sort((a, b) => b.riskScore - a.riskScore) || [];

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
          <h1 className="text-3xl font-bold text-gray-900">Architecture Security Dashboard</h1>
          <p className="text-gray-600 mt-1">Service topology, threat modeling, and attack surface analysis</p>
        </div>
        <div className="flex items-center space-x-3">
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
            <Layers className="w-4 h-4 mr-1" />
            {services?.length || 0} Services
          </span>
        </div>
      </div>

      {/* Architecture Overview Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <MetricCard
          title="Internet-Facing Services"
          value={internetFacingServices}
          icon={Globe}
          color="red"
          subtitle="High exposure risk"
        />
        <MetricCard
          title="PCI Data Services"
          value={pciServices}
          icon={Lock}
          color="red"
          subtitle="Payment card processing"
        />
        <MetricCard
          title="PII Data Services"
          value={piiServices}
          icon={Database}
          color="yellow"
          subtitle="Personal information"
        />
        <MetricCard
          title="Production Services"
          value={prodServices}
          icon={Shield}
          color="blue"
          subtitle="Live environment"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Service Architecture Map */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center">
              <Network className="w-5 h-5 mr-2 text-blue-500" />
              Business Capability Architecture
            </h2>
            <p className="text-sm text-gray-600 mt-1">Services grouped by business capability</p>
          </div>
          <div className="p-6 space-y-4 max-h-96 overflow-y-auto">
            {Object.entries(servicesByCapability).map(([capability, capabilityServices]) => (
              <div key={capability} className="border rounded-lg p-4">
                <h3 className="font-medium text-gray-900 mb-3">{capability}</h3>
                <div className="space-y-2">
                  {capabilityServices.map((service) => (
                    <div key={service.id} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                      <div className="flex items-center space-x-2">
                        <div className="flex items-center space-x-1">
                          {service.internet_facing && <Globe className="w-4 h-4 text-red-500" />}
                          <span className="text-sm font-medium">{service.name}</span>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getEnvironmentColor(service.environment)}`}>
                          {service.environment}
                        </span>
                        {service.data_classification.length > 0 && (
                          <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getDataClassificationColor(service.data_classification)}`}>
                            {service.data_classification.join(', ').toUpperCase()}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Threat & Risk Analysis */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center">
              <AlertTriangle className="w-5 h-5 mr-2 text-red-500" />
              Threat Exposure Analysis
            </h2>
            <p className="text-sm text-gray-600 mt-1">Services ranked by risk score and attack surface</p>
          </div>
          <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
            {threatExposure.slice(0, 10).map((service) => (
              <div key={service.id} className="p-4 hover:bg-gray-50">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-2">
                      <h4 className="text-sm font-medium text-gray-900">{service.name}</h4>
                      {service.internet_facing && (
                        <Globe className="w-4 h-4 text-red-500" title="Internet-facing" />
                      )}
                      {service.pci_scope && (
                        <Lock className="w-4 h-4 text-red-600" title="PCI Scope" />
                      )}
                    </div>
                    
                    <p className="text-xs text-gray-600 mb-2">{service.business_capability}</p>
                    
                    <div className="flex items-center space-x-4 text-xs text-gray-500">
                      <span>Owner: {service.owner_team}</span>
                      <span>Findings: {service.findingsCount}</span>
                      {service.criticalFindings > 0 && (
                        <span className="text-red-600 font-medium">
                          {service.criticalFindings} Critical
                        </span>
                      )}
                    </div>
                    
                    <div className="mt-2">
                      <div className="flex flex-wrap gap-1">
                        {service.data_classification.map(classification => (
                          <span key={classification} className={`px-2 py-1 rounded-full text-xs font-medium border ${getDataClassificationColor([classification])}`}>
                            {classification.toUpperCase()}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                  
                  <div className="ml-4 text-right">
                    <div className="text-lg font-bold text-gray-900">{Math.round(service.riskScore)}</div>
                    <div className="text-xs text-gray-500">Risk Score</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Security Controls Matrix */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Security Controls Matrix</h2>
          <p className="text-sm text-gray-600 mt-1">Security coverage across business capabilities and environments</p>
        </div>
        <div className="p-6">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Business Capability
                  </th>
                  <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Services
                  </th>
                  <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Internet-Facing
                  </th>
                  <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                    PCI Scope
                  </th>
                  <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Critical Findings
                  </th>
                  <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Risk Level
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {Object.entries(servicesByCapability).map(([capability, capabilityServices]) => {
                  const internetFacing = capabilityServices.filter(s => s.internet_facing).length;
                  const pciScope = capabilityServices.filter(s => s.pci_scope).length;
                  const criticalFindings = capabilityServices.reduce((sum, service) => {
                    const serviceFindings = findings?.filter(f => f.service_id === service.id && f.severity === 'critical') || [];
                    return sum + serviceFindings.length;
                  }, 0);
                  
                  const riskLevel = criticalFindings > 0 ? 'High' : 
                                  (internetFacing > 0 || pciScope > 0) ? 'Medium' : 'Low';
                  const riskColor = riskLevel === 'High' ? 'text-red-600' : 
                                   riskLevel === 'Medium' ? 'text-yellow-600' : 'text-green-600';
                  
                  return (
                    <tr key={capability}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                        {capability}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 text-center">
                        {capabilityServices.length}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 text-center">
                        {internetFacing > 0 && (
                          <span className="text-red-600 font-medium">{internetFacing}</span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 text-center">
                        {pciScope > 0 && (
                          <span className="text-red-600 font-medium">{pciScope}</span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 text-center">
                        {criticalFindings > 0 && (
                          <span className="text-red-600 font-medium">{criticalFindings}</span>
                        )}
                      </td>
                      <td className={`px-6 py-4 whitespace-nowrap text-sm font-medium text-center ${riskColor}`}>
                        {riskLevel}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ArchitectDashboard;