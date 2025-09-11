import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Target, Clock, AlertTriangle, Code, Zap, CheckCircle } from 'lucide-react';
import { api } from '../api/client';
import LoadingSpinner from './LoadingSpinner';

const CorrelatedCases = () => {
  const { data: cases, isLoading } = useQuery({
    queryKey: ['cases'],
    queryFn: () => api.getCases().then(res => res.data),
  });

  const { data: services } = useQuery({
    queryKey: ['services'],
    queryFn: () => api.getServices().then(res => res.data),
  });

  if (isLoading) {
    return <LoadingSpinner />;
  }

  const getServiceName = (serviceId) => {
    const service = services?.find(s => s.id === serviceId);
    return service?.name || 'Unknown Service';
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low':
        return 'bg-green-100 text-green-800 border-green-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getDecisionColor = (decision) => {
    switch (decision) {
      case 'block':
        return 'bg-red-100 text-red-800';
      case 'fix':
        return 'bg-blue-100 text-blue-800';
      case 'mitigate':
        return 'bg-yellow-100 text-yellow-800';
      case 'defer':
        return 'bg-gray-100 text-gray-800';
      case 'allow':
        return 'bg-green-100 text-green-800';
      default:
        return 'bg-gray-100 text-gray-600';
    }
  };

  const getPriorityIcon = (priority) => {
    if (priority === 1) return <AlertTriangle className="w-4 h-4 text-red-500" />;
    if (priority === 2) return <Clock className="w-4 h-4 text-orange-500" />;
    return <Target className="w-4 h-4 text-blue-500" />;
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Correlated Security Cases</h1>
          <p className="text-gray-600 mt-1">Unified security findings with business context and automated decisions</p>
        </div>
        <div className="flex items-center space-x-3">
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
            <Target className="w-4 h-4 mr-1" />
            {cases?.length || 0} Active Cases
          </span>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Cases</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">{cases?.length || 0}</p>
              <p className="text-xs text-blue-600 mt-1">Root cause grouped</p>
            </div>
            <Target className="w-8 h-8 text-blue-600" />
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Blocked Releases</p>
              <p className="text-2xl font-bold text-red-600 mt-1">
                {cases?.filter(c => c.policy_decision === 'block').length || 0}
              </p>
              <p className="text-xs text-gray-500 mt-1">Policy enforcement</p>
            </div>
            <div className="w-8 h-8 rounded-full bg-red-100 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-red-600" />
            </div>
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Auto-Fix Available</p>
              <p className="text-2xl font-bold text-blue-600 mt-1">
                {cases?.filter(c => c.policy_decision === 'fix').length || 0}
              </p>
              <p className="text-xs text-gray-500 mt-1">PR generation ready</p>
            </div>
            <Code className="w-8 h-8 text-blue-600" />
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Avg Resolution</p>
              <p className="text-2xl font-bold text-green-600 mt-1">4.2d</p>
              <p className="text-xs text-gray-500 mt-1">Down from 21-28d</p>
            </div>
            <Zap className="w-8 h-8 text-green-600" />
          </div>
        </div>
      </div>

      {/* Cases List */}
      <div className="space-y-4">
        {cases?.map((case_) => (
          <div key={case_.id} className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
            <div className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-3">
                    {getPriorityIcon(case_.remediation_priority)}
                    <h3 className="text-lg font-medium text-gray-900">{case_.title}</h3>
                    <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(case_.overall_severity)}`}>
                      {case_.overall_severity}
                    </span>
                    {case_.policy_decision && (
                      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getDecisionColor(case_.policy_decision)}`}>
                        {case_.policy_decision}
                      </span>
                    )}
                  </div>
                  
                  <p className="text-gray-600 mb-3">{case_.description}</p>
                  
                  <div className="flex items-center space-x-6 text-sm text-gray-500 mb-4">
                    <span>Service: {getServiceName(case_.service_id)}</span>
                    <span>Priority: {case_.remediation_priority}</span>
                    <span>Findings: {case_.findings?.length || 0}</span>
                    {case_.estimated_effort && (
                      <span>Effort: {case_.estimated_effort}</span>
                    )}
                  </div>

                  {/* Business Impact */}
                  <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 mb-4">
                    <p className="text-sm text-yellow-800">
                      <strong>Business Impact:</strong> {case_.business_impact}
                    </p>
                  </div>

                  {/* Policy Decision Rationale */}
                  {case_.decision_rationale && (
                    <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 mb-4">
                      <p className="text-sm text-blue-800">
                        <strong>Policy Decision:</strong> {case_.decision_rationale}
                      </p>
                    </div>
                  )}

                  {/* NIST SSDF Controls */}
                  {case_.nist_ssdf_controls && case_.nist_ssdf_controls.length > 0 && (
                    <div className="mb-4">
                      <h4 className="text-sm font-medium text-gray-700 mb-2">NIST SSDF Controls:</h4>
                      <div className="flex flex-wrap gap-2">
                        {case_.nist_ssdf_controls.map(control => (
                          <span key={control} className="inline-flex items-center px-2 py-1 rounded text-xs font-mono bg-gray-100 text-gray-700 border">
                            {control}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Action Buttons */}
                  <div className="flex items-center space-x-3">
                    {case_.policy_decision === 'fix' && (
                      <button className="inline-flex items-center px-3 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 transition-colors">
                        <Code className="w-4 h-4 mr-1" />
                        Generate Fix PR
                      </button>
                    )}
                    {case_.policy_decision === 'block' && (
                      <button className="inline-flex items-center px-3 py-2 bg-red-600 text-white text-sm rounded-lg hover:bg-red-700 transition-colors">
                        <AlertTriangle className="w-4 h-4 mr-1" />
                        Request Waiver
                      </button>
                    )}
                    <button className="inline-flex items-center px-3 py-2 bg-gray-600 text-white text-sm rounded-lg hover:bg-gray-700 transition-colors">
                      View Details
                    </button>
                  </div>
                </div>
                
                <div className="ml-6 text-right">
                  <div className="text-xs text-gray-500">Created</div>
                  <div className="text-sm text-gray-900">
                    {new Date(case_.created_at).toLocaleDateString()}
                  </div>
                  <div className="text-xs text-gray-500 mt-2">Updated</div>
                  <div className="text-sm text-gray-900">
                    {new Date(case_.updated_at).toLocaleDateString()}
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {cases?.length === 0 && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-12 text-center">
          <Target className="w-16 h-16 mx-auto text-gray-300 mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No Security Cases</h3>
          <p className="text-gray-600">
            Security findings will be automatically correlated into cases when detected by scanners.
          </p>
        </div>
      )}
    </div>
  );
};

export default CorrelatedCases;