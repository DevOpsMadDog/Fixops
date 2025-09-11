import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle, Clock, Code, Zap, GitPullRequest } from 'lucide-react';
import { api } from '../api/client';
import LoadingSpinner from './LoadingSpinner';
import MetricCard from './MetricCard';
import FindingsList from './FindingsList';

const DeveloperDashboard = () => {
  const { data: metrics, isLoading: metricsLoading } = useQuery({
    queryKey: ['dashboard-metrics'],
    queryFn: () => api.getDashboardMetrics().then(res => res.data),
  });

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ['findings-developer'],
    queryFn: () => api.getFindings({ status: 'open' }).then(res => res.data),
  });

  const { data: cases, isLoading: casesLoading } = useQuery({
    queryKey: ['cases'],
    queryFn: () => api.getCases().then(res => res.data),
  });

  if (metricsLoading || findingsLoading || casesLoading) {
    return <LoadingSpinner />;
  }

  // Filter findings for developer view - prioritize actionable items
  const developerFindings = findings?.filter(f => 
    f.severity === 'critical' || f.severity === 'high'
  ).slice(0, 10) || [];

  const actionableCases = cases?.filter(c => 
    c.policy_decision === 'fix' || c.policy_decision === 'block'
  ).slice(0, 5) || [];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Developer Security Dashboard</h1>
          <p className="text-gray-600 mt-1">Actionable security findings with context and automated fixes</p>
        </div>
        <div className="flex items-center space-x-3">
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
            <CheckCircle className="w-4 h-4 mr-1" />
            67% Noise Reduced
          </span>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <MetricCard
          title="High Priority Findings"
          value={metrics?.critical_findings + metrics?.high_findings || 0}
          icon={AlertTriangle}
          color="red"
          subtitle="Require immediate attention"
        />
        <MetricCard
          title="Automated Fixes Available"
          value={actionableCases.length}
          icon={GitPullRequest}
          color="blue"
          subtitle="Ready-to-review PRs"
        />
        <MetricCard
          title="Mean Time to Fix"
          value="4.2 days"
          icon={Clock}
          color="green"
          subtitle="Down from 3-4 weeks"
        />
        <MetricCard
          title="Security Score"
          value="B+"
          icon={Zap}
          color="yellow"
          subtitle="Improving trend"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Priority Findings */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center">
              <AlertTriangle className="w-5 h-5 mr-2 text-red-500" />
              Priority Security Findings
            </h2>
            <p className="text-sm text-gray-600 mt-1">
              Context-enriched findings requiring your attention
            </p>
          </div>
          <FindingsList findings={developerFindings} showBusinessContext={true} />
        </div>

        {/* Correlated Cases */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center">
              <Code className="w-5 h-5 mr-2 text-blue-500" />
              Actionable Security Cases
            </h2>
            <p className="text-sm text-gray-600 mt-1">
              Correlated findings with automated remediation
            </p>
          </div>
          <div className="divide-y divide-gray-200">
            {actionableCases.map((case_) => (
              <div key={case_.id} className="p-6 hover:bg-gray-50 transition-colors">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <h3 className="text-sm font-medium text-gray-900">{case_.title}</h3>
                    <p className="text-sm text-gray-600 mt-1">{case_.description}</p>
                    <div className="flex items-center space-x-4 mt-3">
                      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                        case_.overall_severity === 'critical' 
                          ? 'bg-red-100 text-red-800' 
                          : 'bg-orange-100 text-orange-800'
                      }`}>
                        {case_.overall_severity}
                      </span>
                      <span className="text-xs text-gray-500">
                        Priority {case_.remediation_priority}
                      </span>
                      <span className="text-xs text-gray-500">
                        Effort: {case_.estimated_effort}
                      </span>
                    </div>
                  </div>
                  <div className="ml-4 flex-shrink-0">
                    <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                      case_.policy_decision === 'block' 
                        ? 'bg-red-100 text-red-800' 
                        : 'bg-blue-100 text-blue-800'
                    }`}>
                      {case_.policy_decision}
                    </span>
                  </div>
                </div>
                
                {/* Business Context */}
                <div className="mt-3 p-3 bg-yellow-50 rounded-lg border border-yellow-200">
                  <p className="text-xs text-yellow-800">
                    <strong>Business Impact:</strong> {case_.business_impact}
                  </p>
                </div>

                {/* NIST SSDF Controls */}
                {case_.nist_ssdf_controls?.length > 0 && (
                  <div className="mt-3">
                    <div className="flex flex-wrap gap-1">
                      {case_.nist_ssdf_controls.map(control => (
                        <span key={control} className="inline-flex items-center px-2 py-1 rounded text-xs font-mono bg-gray-100 text-gray-700">
                          {control}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* DevSec Coach Section */}
      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg border border-blue-200 p-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-blue-900">DevSec Coach</h3>
            <p className="text-blue-700 mt-1">Just-in-time security learning based on your findings</p>
          </div>
          <div className="flex items-center space-x-3">
            <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
              View Training
            </button>
          </div>
        </div>
        <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-white rounded-lg p-4 border border-blue-200">
            <h4 className="font-medium text-gray-900">SQL Injection Prevention</h4>
            <p className="text-sm text-gray-600 mt-1">Based on your payment gateway findings</p>
            <span className="text-xs text-blue-600 font-medium">5 min read</span>
          </div>
          <div className="bg-white rounded-lg p-4 border border-blue-200">
            <h4 className="font-medium text-gray-900">Secure Authentication</h4>
            <p className="text-sm text-gray-600 mt-1">Related to identity service issues</p>
            <span className="text-xs text-blue-600 font-medium">8 min read</span>
          </div>
          <div className="bg-white rounded-lg p-4 border border-blue-200">
            <h4 className="font-medium text-gray-900">PCI Compliance Basics</h4>
            <p className="text-sm text-gray-600 mt-1">For fintech payment processing</p>
            <span className="text-xs text-blue-600 font-medium">12 min read</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DeveloperDashboard;