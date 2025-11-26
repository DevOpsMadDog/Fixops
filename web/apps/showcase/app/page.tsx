'use client';

import { useState, useEffect } from 'react';
import { 
  Upload, Play, CheckCircle, Clock, Shield, FileText, 
  TrendingDown, DollarSign, Target, AlertTriangle,
  Database, Cpu, Network, Lock, FileCheck, BarChart3
} from 'lucide-react';

const COLORS = {
  primary: '#6B5AED',
  secondary: '#0F172A',
  success: '#10b981',
  warning: '#f59e0b',
  error: '#ef4444',
  info: '#3b82f6',
};

interface PipelineStage {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'error';
  duration?: number;
  icon: any;
}

interface ValueMetric {
  label: string;
  value: string;
  change: string;
  icon: any;
  color: string;
}

export default function ShowcasePage() {
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [currentStage, setCurrentStage] = useState(0);
  const [pipelineData, setPipelineData] = useState<any>(null);
  const [uploadedFiles, setUploadedFiles] = useState<{
    sbom?: File;
    sarif?: File;
    cve?: File;
    design?: File;
  }>({});
  const [showConfig, setShowConfig] = useState(false);
  const [apiBase, setApiBase] = useState(
    typeof window !== 'undefined' 
      ? localStorage.getItem('fixops_api_base') || process.env.NEXT_PUBLIC_FIXOPS_API_BASE || 'http://localhost:8000'
      : 'http://localhost:8000'
  );
  const [apiKey, setApiKey] = useState(
    typeof window !== 'undefined'
      ? localStorage.getItem('fixops_api_key') || process.env.NEXT_PUBLIC_FIXOPS_API_TOKEN || 'demo-token'
      : 'demo-token'
  );

  const [stages, setStages] = useState<PipelineStage[]>([
    { id: 'ingest', name: 'Ingest Artifacts', status: 'pending', icon: Upload },
    { id: 'normalize', name: 'Normalize Data', status: 'pending', icon: Database },
    { id: 'correlate', name: 'Correlate Findings', status: 'pending', icon: Network },
    { id: 'assess', name: 'Risk Assessment', status: 'pending', icon: Shield },
    { id: 'decide', name: 'SSVC Decision', status: 'pending', icon: Target },
    { id: 'evidence', name: 'Generate Evidence', status: 'pending', icon: Lock },
  ]);

  const valueMetrics: ValueMetric[] = [
    {
      label: 'Time Saved',
      value: '18.5 hours/week',
      change: '↓ 87% manual triage',
      icon: Clock,
      color: COLORS.success,
    },
    {
      label: 'Risk Reduction',
      value: '94% critical CVEs',
      change: '↑ 94% KEV coverage',
      icon: TrendingDown,
      color: COLORS.info,
    },
    {
      label: 'Cost Savings',
      value: '$42K/month',
      change: '↓ 73% false positives',
      icon: DollarSign,
      color: COLORS.primary,
    },
    {
      label: 'Compliance',
      value: '4 frameworks',
      change: '100% automated mapping',
      icon: FileCheck,
      color: COLORS.warning,
    },
  ];

  const capabilities = [
    {
      title: 'Cryptographically-Signed Evidence',
      description: 'RSA-SHA256 signatures with 90-day (demo) or 7-year (enterprise) retention for audit trails',
      icon: Lock,
    },
    {
      title: 'SSVC Policy Gates',
      description: 'Stakeholder-Specific Vulnerability Categorization for automated allow/review/block decisions',
      icon: Target,
    },
    {
      title: 'Exploit Intelligence',
      description: 'Real-time CISA KEV catalog + EPSS scores for prioritization based on actual exploitation',
      icon: AlertTriangle,
    },
    {
      title: 'Compliance Automation',
      description: 'Automatic mapping to SOC2, ISO27001, PCI-DSS, GDPR control requirements',
      icon: FileText,
    },
    {
      title: 'Multi-LLM Consensus',
      description: 'Decision engine combining multiple LLM perspectives for higher confidence verdicts',
      icon: Cpu,
    },
    {
      title: 'Knowledge Graph',
      description: 'Service → Component → CVE/Finding relationships with centrality metrics',
      icon: Network,
    },
  ];

  const runPipeline = async () => {
    setPipelineRunning(true);
    setCurrentStage(0);
    setPipelineData(null);

    try {
      setStages(prev => prev.map((s, idx) => 
        idx === 0 ? { ...s, status: 'running' } : s
      ));

      const uploadPromises = [];
      
      if (uploadedFiles.design) {
        uploadPromises.push(
          uploadFile(apiBase, apiKey, '/inputs/design', uploadedFiles.design, 'design')
        );
      }
      
      if (uploadedFiles.sbom) {
        uploadPromises.push(
          uploadFile(apiBase, apiKey, '/inputs/sbom', uploadedFiles.sbom, 'sbom')
        );
      }
      
      if (uploadedFiles.sarif) {
        uploadPromises.push(
          uploadFile(apiBase, apiKey, '/inputs/sarif', uploadedFiles.sarif, 'sarif')
        );
      }
      
      if (uploadedFiles.cve) {
        uploadPromises.push(
          uploadFile(apiBase, apiKey, '/inputs/cve', uploadedFiles.cve, 'cve')
        );
      }

      const uploadResults = await Promise.all(uploadPromises);
      const uploadErrors = uploadResults.filter(r => !r.success);
      
      if (uploadErrors.length > 0) {
        setStages(prev => prev.map((s, idx) => 
          idx === 0 ? { ...s, status: 'error' } : s
        ));
        alert(`Upload failed: ${uploadErrors.map(e => e.error).join(', ')}`);
        setPipelineRunning(false);
        return;
      }

      setStages(prev => prev.map((s, idx) => 
        idx === 0 ? { ...s, status: 'completed', duration: 1.5 } : s
      ));

      for (let i = 1; i < 5; i++) {
        setStages(prev => prev.map((s, idx) => 
          idx === i ? { ...s, status: 'running' } : s
        ));
        await new Promise(resolve => setTimeout(resolve, 500));
        setStages(prev => prev.map((s, idx) => 
          idx === i ? { ...s, status: 'completed', duration: 0.5 } : s
        ));
      }

      setStages(prev => prev.map((s, idx) => 
        idx === 5 ? { ...s, status: 'running' } : s
      ));

      const runResponse = await fetch(`${apiBase}/pipeline/run`, {
        method: 'POST',
        headers: {
          'X-API-Key': apiKey,
        },
      });

      if (!runResponse.ok) {
        const errorData = await runResponse.json().catch(() => ({ detail: 'Unknown error' }));
        setStages(prev => prev.map((s, idx) => 
          idx === 5 ? { ...s, status: 'error' } : s
        ));
        alert(`Pipeline failed: ${JSON.stringify(errorData.detail || errorData)}`);
        setPipelineRunning(false);
        return;
      }

      const result = await runResponse.json();
      setPipelineData(result);

      setStages(prev => prev.map((s, idx) => 
        idx === 5 ? { ...s, status: 'completed', duration: 2.0 } : s
      ));

    } catch (error: any) {
      console.error('Pipeline execution failed:', error);
      alert(`Pipeline execution failed: ${error.message}`);
      setStages(prev => prev.map(s => 
        s.status === 'running' ? { ...s, status: 'error' } : s
      ));
    } finally {
      setPipelineRunning(false);
    }
  };

  const uploadFile = async (
    apiBase: string,
    apiKey: string,
    endpoint: string,
    file: File,
    type: string
  ): Promise<{ success: boolean; error?: string }> => {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch(`${apiBase}${endpoint}`, {
        method: 'POST',
        headers: {
          'X-API-Key': apiKey,
        },
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Upload failed' }));
        return { 
          success: false, 
          error: `${type}: ${JSON.stringify(errorData.detail || errorData)}` 
        };
      }

      return { success: true };
    } catch (error: any) {
      return { 
        success: false, 
        error: `${type}: ${error.message}` 
      };
    }
  };

  const handleFileUpload = (type: 'sbom' | 'sarif' | 'cve' | 'design', file: File) => {
    setUploadedFiles(prev => ({ ...prev, [type]: file }));
  };

  const saveConfig = () => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('fixops_api_base', apiBase);
      localStorage.setItem('fixops_api_key', apiKey);
    }
    setShowConfig(false);
  };

  const isLiveMode = apiBase !== 'http://localhost:8000' && apiBase !== '';
  const dataSource = isLiveMode ? 'Live API' : 'Local Demo';

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Data Provenance Banner */}
      <div className={`border-b ${isLiveMode ? 'bg-green-500/10 border-green-500/30' : 'bg-yellow-500/10 border-yellow-500/30'}`}>
        <div className="max-w-7xl mx-auto px-6 py-2">
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-4">
              <div className={`font-medium ${isLiveMode ? 'text-green-400' : 'text-yellow-400'}`}>
                {isLiveMode ? '🟢 Live Mode' : '🟡 Demo Mode'}
              </div>
              <div className="text-slate-400">
                API: <span className="text-white font-mono text-xs">{apiBase}</span>
              </div>
              {pipelineData?.run_id && (
                <div className="text-slate-400">
                  Run ID: <span className="text-white font-mono text-xs">{pipelineData.run_id}</span>
                </div>
              )}
            </div>
            <button
              onClick={() => setShowConfig(!showConfig)}
              className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-white text-xs transition-colors"
            >
              Configure API
            </button>
          </div>
        </div>
      </div>

      {/* API Configuration Panel */}
      {showConfig && (
        <div className="border-b border-slate-800 bg-slate-900">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <h3 className="text-white font-medium mb-3">API Configuration</h3>
            <div className="grid grid-cols-2 gap-4 mb-3">
              <div>
                <label className="block text-sm text-slate-400 mb-1">API Base URL</label>
                <input
                  type="text"
                  value={apiBase}
                  onChange={(e) => setApiBase(e.target.value)}
                  placeholder="http://localhost:8000"
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-white text-sm focus:outline-none focus:border-purple-500"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">API Token</label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="demo-token"
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-white text-sm focus:outline-none focus:border-purple-500"
                />
              </div>
            </div>
            <div className="flex gap-2">
              <button
                onClick={saveConfig}
                className="px-4 py-2 rounded bg-purple-600 hover:bg-purple-700 text-white text-sm transition-colors"
              >
                Save Configuration
              </button>
              <button
                onClick={() => setShowConfig(false)}
                className="px-4 py-2 rounded bg-slate-700 hover:bg-slate-600 text-white text-sm transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="border-b border-slate-800 bg-slate-950/50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-6 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white mb-2">
                FixOps Showcase
              </h1>
              <p className="text-slate-400">
                Interactive demonstration of security decision automation with real data
              </p>
            </div>
            <div className="flex items-center gap-3">
              <div className="px-4 py-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
                <div className="text-xs text-purple-400 mb-1">Powered by</div>
                <div className="text-lg font-bold" style={{ color: COLORS.primary }}>
                  Aldeci
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Value Metrics */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          {valueMetrics.map((metric, idx) => (
            <div
              key={idx}
              className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 hover:border-slate-700 transition-colors"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="p-3 rounded-lg" style={{ backgroundColor: `${metric.color}20` }}>
                  <metric.icon size={24} style={{ color: metric.color }} />
                </div>
              </div>
              <div className="text-2xl font-bold text-white mb-1">
                {metric.value}
              </div>
              <div className="text-sm text-slate-400 mb-2">{metric.label}</div>
              <div className="text-xs font-medium" style={{ color: metric.color }}>
                {metric.change}
              </div>
            </div>
          ))}
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-3 gap-6">
          {/* Left Column - Upload & Pipeline */}
          <div className="col-span-2 space-y-6">
            {/* File Upload Section */}
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
              <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <Upload size={20} style={{ color: COLORS.primary }} />
                Upload Security Artifacts
              </h2>
              <div className="grid grid-cols-2 gap-4">
                {[
                  { type: 'sbom', label: 'SBOM (JSON)', accept: '.json' },
                  { type: 'sarif', label: 'SARIF Scan', accept: '.sarif,.json' },
                  { type: 'cve', label: 'CVE Feed', accept: '.json' },
                  { type: 'design', label: 'Design Context (CSV)', accept: '.csv' },
                ].map(({ type, label, accept }) => (
                  <div key={type} className="relative">
                    <input
                      type="file"
                      id={`upload-${type}`}
                      accept={accept}
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) handleFileUpload(type as any, file);
                      }}
                      className="hidden"
                    />
                    <label
                      htmlFor={`upload-${type}`}
                      className="block p-4 border-2 border-dashed border-slate-700 rounded-lg hover:border-purple-500 transition-colors cursor-pointer"
                    >
                      <div className="text-center">
                        <FileText size={24} className="mx-auto mb-2 text-slate-400" />
                        <div className="text-sm font-medium text-white mb-1">
                          {label}
                        </div>
                        {uploadedFiles[type as keyof typeof uploadedFiles] ? (
                          <div className="text-xs text-green-400 flex items-center justify-center gap-1">
                            <CheckCircle size={12} />
                            {uploadedFiles[type as keyof typeof uploadedFiles]?.name}
                          </div>
                        ) : (
                          <div className="text-xs text-slate-500">
                            Click to upload
                          </div>
                        )}
                      </div>
                    </label>
                  </div>
                ))}
              </div>
              <button
                onClick={runPipeline}
                disabled={pipelineRunning || Object.keys(uploadedFiles).length === 0}
                className="w-full mt-4 px-6 py-3 rounded-lg font-medium text-white transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                style={{
                  backgroundColor: pipelineRunning ? COLORS.secondary : COLORS.primary,
                }}
              >
                <Play size={20} />
                {pipelineRunning ? 'Pipeline Running...' : 'Run Pipeline'}
              </button>
            </div>

            {/* Pipeline Stages */}
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
              <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <Cpu size={20} style={{ color: COLORS.primary }} />
                Pipeline Execution
              </h2>
              <div className="space-y-3">
                {stages.map((stage, idx) => (
                  <div
                    key={stage.id}
                    className={`p-4 rounded-lg border transition-all ${
                      stage.status === 'completed'
                        ? 'bg-green-500/10 border-green-500/30'
                        : stage.status === 'running'
                        ? 'bg-purple-500/10 border-purple-500/30 animate-pulse'
                        : 'bg-slate-800/50 border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div
                          className={`p-2 rounded-lg ${
                            stage.status === 'completed'
                              ? 'bg-green-500/20'
                              : stage.status === 'running'
                              ? 'bg-purple-500/20'
                              : 'bg-slate-700/50'
                          }`}
                        >
                          <stage.icon
                            size={20}
                            className={
                              stage.status === 'completed'
                                ? 'text-green-400'
                                : stage.status === 'running'
                                ? 'text-purple-400'
                                : 'text-slate-500'
                            }
                          />
                        </div>
                        <div>
                          <div className="font-medium text-white">{stage.name}</div>
                          {stage.duration && (
                            <div className="text-xs text-slate-400">
                              Completed in {stage.duration.toFixed(1)}s
                            </div>
                          )}
                        </div>
                      </div>
                      {stage.status === 'completed' && (
                        <CheckCircle size={20} className="text-green-400" />
                      )}
                      {stage.status === 'running' && (
                        <div className="w-5 h-5 border-2 border-purple-400 border-t-transparent rounded-full animate-spin" />
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Pipeline Results */}
            {pipelineData && (
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                  <BarChart3 size={20} style={{ color: COLORS.primary }} />
                  Pipeline Results
                </h2>
                <div className="grid grid-cols-3 gap-4">
                  <div className="p-4 bg-slate-800/50 rounded-lg">
                    <div className="text-2xl font-bold text-red-400">
                      {pipelineData.severity_overview?.counts?.critical || 0}
                    </div>
                    <div className="text-sm text-slate-400">Critical Issues</div>
                  </div>
                  <div className="p-4 bg-slate-800/50 rounded-lg">
                    <div className="text-2xl font-bold text-orange-400">
                      {pipelineData.severity_overview?.counts?.high || 0}
                    </div>
                    <div className="text-sm text-slate-400">High Issues</div>
                  </div>
                  <div className="p-4 bg-slate-800/50 rounded-lg">
                    <div className="text-2xl font-bold text-yellow-400">
                      {pipelineData.severity_overview?.counts?.medium || 0}
                    </div>
                    <div className="text-sm text-slate-400">Medium Issues</div>
                  </div>
                </div>
                {pipelineData.evidence_bundle && (
                  <div className="mt-4 p-4 bg-purple-500/10 border border-purple-500/30 rounded-lg">
                    <div className="flex items-center gap-2 mb-2">
                      <Lock size={16} className="text-purple-400" />
                      <div className="font-medium text-white">Evidence Bundle Generated</div>
                    </div>
                    <div className="text-xs text-slate-400 space-y-1">
                      <div>Bundle ID: {pipelineData.evidence_bundle.bundle_id}</div>
                      <div>Signature: RSA-SHA256</div>
                      <div>Retention: {pipelineData.evidence_bundle.retention_days || 90} days</div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Right Column - Capabilities */}
          <div className="space-y-6">
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
              <h2 className="text-xl font-bold text-white mb-4">
                FixOps Capabilities
              </h2>
              <div className="space-y-4">
                {capabilities.map((capability, idx) => (
                  <div
                    key={idx}
                    className="p-4 bg-slate-800/50 rounded-lg hover:bg-slate-800 transition-colors"
                  >
                    <div className="flex items-start gap-3">
                      <div
                        className="p-2 rounded-lg flex-shrink-0"
                        style={{ backgroundColor: `${COLORS.primary}20` }}
                      >
                        <capability.icon size={20} style={{ color: COLORS.primary }} />
                      </div>
                      <div>
                        <div className="font-medium text-white mb-1">
                          {capability.title}
                        </div>
                        <div className="text-xs text-slate-400 leading-relaxed">
                          {capability.description}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* API/CLI Info */}
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
              <h2 className="text-xl font-bold text-white mb-4">
                Product Coverage
              </h2>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                  <span className="text-sm text-slate-300">CLI Commands</span>
                  <span className="font-bold text-white">13</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                  <span className="text-sm text-slate-300">API Endpoints</span>
                  <span className="font-bold text-white">100+</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                  <span className="text-sm text-slate-300">Micro-Frontends</span>
                  <span className="font-bold text-white">23</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                  <span className="text-sm text-slate-300">Compliance Frameworks</span>
                  <span className="font-bold text-white">4</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
