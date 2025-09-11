import React from 'react';
import { AlertTriangle, Shield, Code, Database, Globe, Server } from 'lucide-react';

const FindingsList = ({ findings, showBusinessContext = false, limit = 10 }) => {
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

  const getScannerIcon = (scannerType) => {
    switch (scannerType) {
      case 'sast':
        return <Code className="w-4 h-4" />;
      case 'sca':
        return <Database className="w-4 h-4" />;
      case 'dast':
        return <Globe className="w-4 h-4" />;
      case 'iast':
        return <Shield className="w-4 h-4" />;
      case 'rasp':
        return <Shield className="w-4 h-4" />;
      case 'iac':
        return <Server className="w-4 h-4" />;
      default:
        return <AlertTriangle className="w-4 h-4" />;
    }
  };

  const displayFindings = findings?.slice(0, limit) || [];

  if (!displayFindings.length) {
    return (
      <div className="p-6 text-center text-gray-500">
        <AlertTriangle className="w-12 h-12 mx-auto text-gray-300 mb-4" />
        <p>No security findings found</p>
      </div>
    );
  }

  return (
    <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
      {displayFindings.map((finding) => (
        <div key={finding.id} className="p-4 hover:bg-gray-50 transition-colors">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center space-x-2 mb-2">
                <div className="flex items-center space-x-1">
                  {getScannerIcon(finding.scanner_type)}
                  <span className="text-xs font-medium text-gray-600 uppercase">
                    {finding.scanner_name}
                  </span>
                </div>
                <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(finding.severity)}`}>
                  {finding.severity}
                </span>
              </div>
              
              <h4 className="text-sm font-medium text-gray-900 mb-1">{finding.title}</h4>
              <p className="text-sm text-gray-600 mb-2">{finding.description}</p>
              
              <div className="flex items-center space-x-4 text-xs text-gray-500">
                {finding.cwe_id && (
                  <span className="font-mono bg-gray-100 px-2 py-1 rounded">
                    {finding.cwe_id}
                  </span>
                )}
                {finding.cvss_score && (
                  <span>CVSS: {finding.cvss_score}</span>
                )}
                {finding.epss_score && (
                  <span>EPSS: {(finding.epss_score * 100).toFixed(1)}%</span>
                )}
                {finding.exploitability_grade && (
                  <span className="font-medium text-red-600">
                    Grade: {finding.exploitability_grade}
                  </span>
                )}
              </div>

              {finding.location && (
                <div className="mt-2 text-xs text-gray-500">
                  <span className="font-mono bg-gray-100 px-2 py-1 rounded">
                    {finding.location.file}
                    {finding.location.line && `:${finding.location.line}`}
                    {finding.location.url && finding.location.url}
                    {finding.location.parameter && ` (${finding.location.parameter})`}
                  </span>
                </div>
              )}

              {showBusinessContext && finding.business_impact && (
                <div className="mt-3 p-2 bg-yellow-50 rounded border border-yellow-200">
                  <p className="text-xs text-yellow-800">
                    <strong>Business Impact:</strong> {finding.business_impact}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

export default FindingsList;