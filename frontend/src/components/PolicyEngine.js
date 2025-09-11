import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Settings, Shield, Code, Play, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import { api } from '../api/client';
import LoadingSpinner from './LoadingSpinner';

const PolicyEngine = () => {
  const [testContext, setTestContext] = useState({
    severity: 'critical',
    data_classification: ['pci'],
    environment: 'production',
    internet_facing: true,
    hasApprovedWaiver: false
  });
  
  const [policyResult, setPolicyResult] = useState(null);
  const [isEvaluating, setIsEvaluating] = useState(false);

  const { data: metrics } = useQuery({
    queryKey: ['dashboard-metrics'],
    queryFn: () => api.getDashboardMetrics().then(res => res.data),
  });

  const evaluatePolicy = async () => {
    setIsEvaluating(true);
    try {
      const response = await api.evaluatePolicy(testContext);
      setPolicyResult(response.data);
    } catch (error) {
      console.error('Policy evaluation failed:', error);
      setPolicyResult({ error: 'Policy evaluation failed' });
    } finally {
      setIsEvaluating(false);
    }
  };

  const predefinedPolicies = [
    {
      name: "PCI Critical Vulnerability Block",
      description: "Block deployment of services with critical vulnerabilities handling PCI data",
      controls: ["PO.3.1", "PS.1.1"],
      active: true,
      example: "Critical vulnerability in PCI-scoped production service requires remediation"
    },
    {
      name: "Internet-Facing High Severity Gate",
      description: "Require approval for high severity findings in internet-facing services",
      controls: ["PW.7.1", "PW.7.2"],
      active: true,
      example: "High severity finding in internet-facing production service requires security review"
    },
    {
      name: "PII Data Classification Policy",
      description: "Enhanced monitoring and controls for services handling PII data",
      controls: ["PO.3.2", "PS.2.1"],
      active: true,
      example: "PII processing services require additional security controls"
    },
    {
      name: "Supply Chain Verification",
      description: "SBOM and provenance verification for all production deployments",
      controls: ["PW.7.2", "PS.3.1"],
      active: true,
      example: "Production deployments must include verified SBOM and signed provenance"
    }
  ];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Policy Engine</h1>
          <p className="text-gray-600 mt-1">NIST SSDF compliant policy automation and decision enforcement</p>
        </div>
        <div className="flex items-center space-x-3">
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
            <CheckCircle className="w-4 h-4 mr-1" />
            OPA/Rego Engine Active
          </span>
        </div>
      </div>

      {/* Policy Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Policies</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">{predefinedPolicies.filter(p => p.active).length}</p>
              <p className="text-xs text-green-600 mt-1">NIST SSDF aligned</p>
            </div>
            <Settings className="w-8 h-8 text-blue-600" />
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Decisions Made</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">
                {Object.values(metrics?.policy_decisions || {}).reduce((a, b) => a + b, 0)}
              </p>
              <p className="text-xs text-blue-600 mt-1">Automated</p>
            </div>
            <Shield className="w-8 h-8 text-green-600" />
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Blocked Releases</p>
              <p className="text-2xl font-bold text-red-600 mt-1">{metrics?.policy_decisions?.block || 0}</p>
              <p className="text-xs text-gray-500 mt-1">Security gates</p>
            </div>
            <XCircle className="w-8 h-8 text-red-600" />
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">SSDF Coverage</p>
              <p className="text-2xl font-bold text-blue-600 mt-1">85%</p>
              <p className="text-xs text-gray-500 mt-1">Control compliance</p>
            </div>
            <CheckCircle className="w-8 h-8 text-blue-600" />
          </div>
        </div>
      </div>

      {/* Policy Testing */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900 flex items-center">
            <Play className="w-5 h-5 mr-2 text-green-500" />
            Policy Evaluation Tester
          </h2>
          <p className="text-sm text-gray-600 mt-1">Test policy decisions with different security contexts</p>
        </div>
        
        <div className="p-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Input Context */}
            <div className="space-y-4">
              <h3 className="text-md font-medium text-gray-900">Security Context</h3>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                <select
                  value={testContext.severity}
                  onChange={(e) => setTestContext(prev => ({ ...prev, severity: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Environment</label>
                <select
                  value={testContext.environment}
                  onChange={(e) => setTestContext(prev => ({ ...prev, environment: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="dev">Development</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Data Classification</label>
                <div className="space-y-2">
                  {['pci', 'pii', 'phi', 'confidential'].map(classification => (
                    <label key={classification} className="flex items-center">
                      <input
                        type="checkbox"
                        checked={testContext.data_classification.includes(classification)}
                        onChange={(e) => {
                          const updated = e.target.checked
                            ? [...testContext.data_classification, classification]
                            : testContext.data_classification.filter(c => c !== classification);
                          setTestContext(prev => ({ ...prev, data_classification: updated }));
                        }}
                        className="mr-2"
                      />
                      <span className="text-sm text-gray-700 uppercase">{classification}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={testContext.internet_facing}
                    onChange={(e) => setTestContext(prev => ({ ...prev, internet_facing: e.target.checked }))}
                    className="mr-2"
                  />
                  <span className="text-sm text-gray-700">Internet-facing service</span>
                </label>
                
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={testContext.hasApprovedWaiver}
                    onChange={(e) => setTestContext(prev => ({ ...prev, hasApprovedWaiver: e.target.checked }))}
                    className="mr-2"
                  />
                  <span className="text-sm text-gray-700">Has approved waiver</span>
                </label>
              </div>

              <button
                onClick={evaluatePolicy}
                disabled={isEvaluating}
                className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
              >
                {isEvaluating ? 'Evaluating...' : 'Evaluate Policy'}
              </button>
            </div>

            {/* Policy Result */}
            <div className="space-y-4">
              <h3 className="text-md font-medium text-gray-900">Policy Decision</h3>
              
              {policyResult ? (
                <div className="space-y-3">
                  {policyResult.error ? (
                    <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                      <p className="text-red-800">{policyResult.error}</p>
                    </div>
                  ) : (
                    <>
                      {policyResult.decisions?.map((decision, index) => (
                        <div key={index} className={`p-4 rounded-lg border ${
                          decision.decision === 'block' ? 'bg-red-50 border-red-200' :
                          decision.decision === 'require_approval' ? 'bg-yellow-50 border-yellow-200' :
                          'bg-green-50 border-green-200'
                        }`}>
                          <div className="flex items-start">
                            <div className={`w-5 h-5 rounded-full mr-3 mt-0.5 ${
                              decision.decision === 'block' ? 'bg-red-500' :
                              decision.decision === 'require_approval' ? 'bg-yellow-500' :
                              'bg-green-500'
                            }`}></div>
                            <div className="flex-1">
                              <h4 className={`font-medium ${
                                decision.decision === 'block' ? 'text-red-900' :
                                decision.decision === 'require_approval' ? 'text-yellow-900' :
                                'text-green-900'
                              }`}>
                                {decision.rule}
                              </h4>
                              <p className={`text-sm mt-1 ${
                                decision.decision === 'block' ? 'text-red-800' :
                                decision.decision === 'require_approval' ? 'text-yellow-800' :
                                'text-green-800'
                              }`}>
                                {decision.message}
                              </p>
                              <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium mt-2 ${
                                decision.decision === 'block' ? 'bg-red-100 text-red-800' :
                                decision.decision === 'require_approval' ? 'bg-yellow-100 text-yellow-800' :
                                'bg-green-100 text-green-800'
                              }`}>
                                {decision.decision}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                      
                      {policyResult.decisions?.length === 0 && (
                        <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                          <div className="flex items-center">
                            <CheckCircle className="w-5 h-5 text-green-500 mr-2" />
                            <p className="text-green-800">No policy violations detected - deployment allowed</p>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              ) : (
                <div className="p-8 text-center text-gray-500 border-2 border-dashed border-gray-200 rounded-lg">
                  <Play className="w-12 h-12 mx-auto text-gray-300 mb-4" />
                  <p>Click "Evaluate Policy" to see the decision</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Active Policies */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Active Security Policies</h2>
          <p className="text-sm text-gray-600 mt-1">NIST SSDF aligned policies with OPA/Rego implementation</p>
        </div>
        
        <div className="divide-y divide-gray-200">
          {predefinedPolicies.map((policy, index) => (
            <div key={index} className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <h3 className="text-md font-medium text-gray-900">{policy.name}</h3>
                    <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                      policy.active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                    }`}>
                      {policy.active ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                  
                  <p className="text-sm text-gray-600 mb-3">{policy.description}</p>
                  
                  <div className="flex flex-wrap gap-2 mb-3">
                    {policy.controls.map(control => (
                      <span key={control} className="inline-flex items-center px-2 py-1 rounded text-xs font-mono bg-blue-100 text-blue-800 border border-blue-200">
                        {control}
                      </span>
                    ))}
                  </div>
                  
                  <div className="text-xs text-gray-500 bg-gray-50 p-2 rounded border">
                    <strong>Example:</strong> {policy.example}
                  </div>
                </div>
                
                <div className="ml-6 flex items-center space-x-2">
                  <button className="text-blue-600 hover:text-blue-800 text-sm">
                    <Code className="w-4 h-4" />
                  </button>
                  <button className="text-gray-600 hover:text-gray-800 text-sm">
                    <Settings className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default PolicyEngine;