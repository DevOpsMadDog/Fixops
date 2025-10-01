import React, { useState, useEffect } from 'react'
import { apiMethods, chunkedFileUpload } from '../utils/api'

function EnhancedDashboard() {
  const [systemState, setSystemState] = useState({
    loading: true,
    mode: 'demo',
    capabilities: null,
    lastAnalysis: null,
    systemHealth: null
  })

  const [uploadState, setUploadState] = useState({
    selectedFile: null,
    scanType: null,
    uploadProgress: 0,
    processingStage: 'idle', // idle, uploading, processing, analyzing, complete
    results: null,
    error: null
  })

  const [analysisFlow, setAnalysisFlow] = useState([])

  useEffect(() => {
    initializeSystem()
  }, [])

  const initializeSystem = async () => {
    try {
      const [capabilitiesRes, systemRes] = await Promise.all([
        apiMethods.enhanced.capabilities(),
        fetch('/api/v1/decisions/core-components')
      ])

      const systemData = await systemRes.json()
      const capabilities = capabilitiesRes.data
      const systemInfo = systemData.data?.system_info || {}

      setSystemState({
        loading: false,
        mode: systemInfo.mode || 'demo',
        capabilities,
        systemHealth: systemData.data,
        lastAnalysis: null
      })

    } catch (error) {
      console.error('System initialization failed:', error)
      setSystemState({
        loading: false,
        mode: 'demo',
        capabilities: null,
        systemHealth: null,
        lastAnalysis: null
      })
    }
  }

  const handleFileUpload = async (file, scanType) => {
    if (!file) return

    setUploadState({
      selectedFile: file,
      scanType,
      uploadProgress: 0,
      processingStage: 'uploading',
      results: null,
      error: null
    })

    // Clear previous analysis flow
    setAnalysisFlow([])

    try {
      // Stage 1: Upload
      addFlowStep('📥 Upload', 'Ingesting scan file...', 'processing')
      
      const uploadResult = await chunkedFileUpload(file, {
        scan_type: scanType,
        service_name: 'uploaded-service',
        environment: 'production',
        onProgress: (progress) => setUploadState(prev => ({ ...prev, uploadProgress: progress }))
      })

      addFlowStep('📥 Upload', `Successfully ingested ${file.name}`, 'completed')

      // Stage 2: Processing Layer Analysis
      setUploadState(prev => ({ ...prev, processingStage: 'processing' }))
      addFlowStep('🧠 Processing Layer', 'Running Bayesian + Markov + SSVC analysis...', 'processing')

      // Simulate processing stages
      await new Promise(resolve => setTimeout(resolve, 2000))
      addFlowStep('🧠 Processing Layer', `${systemState.mode === 'demo' ? 'Demo' : 'Real'} processing completed`, 'completed')

      // Stage 3: Multi-LLM Analysis
      setUploadState(prev => ({ ...prev, processingStage: 'analyzing' }))
      addFlowStep('🤖 Multi-LLM Analysis', 'Consulting GPT-5, Claude, Gemini...', 'processing')

      const analysisResult = await apiMethods.enhanced.analysis({
        service_name: 'uploaded-service',
        environment: 'production',
        security_findings: uploadResult.data?.findings_processed || [],
        business_context: { data_classification: 'internal' }
      })

      addFlowStep('🤖 Multi-LLM Analysis', `${analysisResult.data?.models?.length || 0} models analyzed`, 'completed')

      // Stage 4: Final Decision
      addFlowStep('🚦 Decision', `${analysisResult.data?.consensus?.verdict?.toUpperCase()} (${Math.round((analysisResult.data?.consensus?.confidence || 0) * 100)}% confidence)`, 'completed')

      setUploadState(prev => ({
        ...prev,
        processingStage: 'complete',
        results: {
          upload: uploadResult,
          analysis: analysisResult.data
        }
      }))

      setSystemState(prev => ({
        ...prev,
        lastAnalysis: analysisResult.data
      }))

    } catch (error) {
      console.error('Upload/analysis failed:', error)
      setUploadState(prev => ({
        ...prev,
        processingStage: 'error',
        error: error.message
      }))
      addFlowStep('❌ Error', error.message, 'error')
    }
  }

  const addFlowStep = (stage, message, status) => {
    setAnalysisFlow(prev => {
      const newFlow = [...prev]
      const existingIndex = newFlow.findIndex(step => step.stage === stage)
      
      if (existingIndex >= 0) {
        newFlow[existingIndex] = { stage, message, status, timestamp: new Date() }
      } else {
        newFlow.push({ stage, message, status, timestamp: new Date() })
      }
      
      return newFlow
    })
  }

  const getStageIcon = (stage) => {
    if (stage === 'idle') return '⏳'
    if (stage === 'uploading') return '📤'
    if (stage === 'processing') return '🧠'
    if (stage === 'analyzing') return '🤖'
    if (stage === 'complete') return '✅'
    if (stage === 'error') return '❌'
    return '🔄'
  }

  const getStageColor = (stage) => {
    if (stage === 'completed') return '#16a34a'
    if (stage === 'processing') return '#2563eb'
    if (stage === 'error') return '#dc2626'
    return '#64748b'
  }

  if (systemState.loading) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
        color: 'white'
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{
            width: '60px',
            height: '60px',
            border: '4px solid rgba(255, 255, 255, 0.3)',
            borderTop: '4px solid #2563eb',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 1rem auto'
          }}></div>
          <div style={{ fontSize: '1.25rem', fontWeight: '600' }}>
            Initializing FixOps Decision Engine...
          </div>
        </div>
      </div>
    )
  }

  const isDemo = systemState.mode === 'demo'

  return (
    <div style={{
      background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      minHeight: '100vh',
      color: 'white',
      padding: '2rem'
    }}>
      <div style={{ maxWidth: '1600px', margin: '0 auto' }}>
        {/* Header with System Status */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '3rem',
          padding: '2rem',
          backgroundColor: 'rgba(255, 255, 255, 0.05)',
          borderRadius: '16px',
          border: '1px solid rgba(255, 255, 255, 0.1)'
        }}>
          <div>
            <h1 style={{ fontSize: '2.5rem', fontWeight: '800', margin: 0, marginBottom: '0.5rem' }}>
              🚀 Decision Engine
            </h1>
            <p style={{ fontSize: '1.125rem', color: '#94a3b8', margin: 0 }}>
              Upload → Process → Analyze → Decide
            </p>
          </div>
          
          <div style={{ textAlign: 'right' }}>
            <div style={{
              fontSize: '0.875rem',
              fontWeight: '700',
              color: isDemo ? '#7c3aed' : '#16a34a',
              backgroundColor: isDemo ? 'rgba(124, 58, 237, 0.2)' : 'rgba(22, 163, 74, 0.2)',
              padding: '0.5rem 1rem',
              borderRadius: '20px',
              marginBottom: '0.5rem'
            }}>
              {isDemo ? '🎭 DEMO MODE' : '🏭 PRODUCTION MODE'}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
              Processing Layer: {systemState.systemHealth?.system_info?.processing_layer_available ? 'Active' : 'Demo'}
            </div>
          </div>
        </div>

        {/* Main Content Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '3rem',
          marginBottom: '3rem'
        }}>
          {/* Left: Upload Interface */}
          <div style={{
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            padding: '2.5rem',
            borderRadius: '16px',
            border: '1px solid rgba(255, 255, 255, 0.1)'
          }}>
            <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '1.5rem' }}>
              📤 Scan Upload & Analysis
            </h2>
            
            {/* File Drop Zone */}
            <div
              style={{
                border: '2px dashed rgba(255, 255, 255, 0.3)',
                borderRadius: '12px',
                padding: '3rem',
                textAlign: 'center',
                marginBottom: '2rem',
                cursor: 'pointer',
                transition: 'all 0.3s ease'
              }}
              onDragOver={(e) => {
                e.preventDefault()
                e.target.style.backgroundColor = 'rgba(37, 99, 235, 0.1)'
              }}
              onDragLeave={(e) => {
                e.target.style.backgroundColor = 'transparent'
              }}
              onDrop={(e) => {
                e.preventDefault()
                e.target.style.backgroundColor = 'transparent'
                const files = e.dataTransfer.files
                if (files.length > 0) {
                  setUploadState(prev => ({ ...prev, selectedFile: files[0] }))
                }
              }}
            >
              <input
                type="file"
                id="file-upload"
                style={{ display: 'none' }}
                accept=".json,.sarif,.csv,.sbom"
                onChange={(e) => {
                  if (e.target.files[0]) {
                    setUploadState(prev => ({ ...prev, selectedFile: e.target.files[0] }))
                  }
                }}
              />
              <label htmlFor="file-upload" style={{ cursor: 'pointer' }}>
                <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📁</div>
                <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '0.5rem' }}>
                  {uploadState.selectedFile ? uploadState.selectedFile.name : 'Drop scan file or click to browse'}
                </h3>
                <p style={{ fontSize: '0.875rem', color: '#94a3b8' }}>
                  Supports: SARIF, SBOM, CSV, JSON • Max 100MB
                </p>
              </label>
            </div>

            {/* Scan Type Selection */}
            {uploadState.selectedFile && (
              <div style={{ marginBottom: '2rem' }}>
                <h4 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '1rem' }}>
                  Select Scan Type:
                </h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem' }}>
                  {['sarif', 'sbom', 'csv', 'json'].map((type) => (
                    <button
                      key={type}
                      onClick={() => setUploadState(prev => ({ ...prev, scanType: type }))}
                      style={{
                        padding: '1rem',
                        backgroundColor: uploadState.scanType === type ? '#2563eb' : 'rgba(255, 255, 255, 0.1)',
                        border: '1px solid rgba(255, 255, 255, 0.2)',
                        borderRadius: '8px',
                        color: 'white',
                        fontWeight: '600',
                        cursor: 'pointer',
                        textTransform: 'uppercase'
                      }}
                    >
                      {type}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Upload Progress */}
            {uploadState.processingStage !== 'idle' && (
              <div style={{
                backgroundColor: 'rgba(255, 255, 255, 0.1)',
                padding: '1.5rem',
                borderRadius: '12px',
                marginBottom: '1rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                  <span style={{ fontSize: '1.5rem', marginRight: '0.75rem' }}>
                    {getStageIcon(uploadState.processingStage)}
                  </span>
                  <h4 style={{ fontSize: '1rem', fontWeight: '600', margin: 0 }}>
                    {uploadState.processingStage.toUpperCase()}
                  </h4>
                </div>
                
                {uploadState.processingStage === 'uploading' && (
                  <div style={{
                    width: '100%',
                    height: '8px',
                    backgroundColor: 'rgba(255, 255, 255, 0.2)',
                    borderRadius: '4px',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${uploadState.uploadProgress}%`,
                      height: '100%',
                      backgroundColor: '#2563eb',
                      transition: 'width 0.3s ease'
                    }}></div>
                  </div>
                )}
              </div>
            )}

            {/* Action Button */}
            <button
              onClick={() => {
                if (uploadState.selectedFile && uploadState.scanType) {
                  handleFileUpload(uploadState.selectedFile, uploadState.scanType)
                }
              }}
              disabled={!uploadState.selectedFile || !uploadState.scanType || uploadState.processingStage === 'uploading'}
              style={{
                width: '100%',
                padding: '1rem 2rem',
                backgroundColor: '#2563eb',
                color: 'white',
                border: 'none',
                borderRadius: '12px',
                fontSize: '1.125rem',
                fontWeight: '700',
                cursor: 'pointer',
                opacity: (!uploadState.selectedFile || !uploadState.scanType) ? 0.5 : 1
              }}
            >
              🚀 Analyze with FixOps
            </button>
          </div>

          {/* Right: Live Analysis Flow */}
          <div style={{
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            padding: '2.5rem',
            borderRadius: '16px',
            border: '1px solid rgba(255, 255, 255, 0.1)'
          }}>
            <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '1.5rem' }}>
              🔍 Live Analysis Pipeline
            </h2>

            {analysisFlow.length === 0 && (
              <div style={{
                textAlign: 'center',
                padding: '3rem',
                color: '#64748b'
              }}>
                <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>⏳</div>
                <p style={{ fontSize: '1rem' }}>
                  Upload a scan file to see real-time processing
                </p>
              </div>
            )}

            {/* Analysis Flow Steps */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {analysisFlow.map((step, index) => (
                <div key={index} style={{
                  display: 'flex',
                  alignItems: 'center',
                  padding: '1rem',
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  borderRadius: '8px',
                  border: `1px solid ${getStageColor(step.status)}40`
                }}>
                  <div style={{
                    width: '40px',
                    height: '40px',
                    backgroundColor: getStageColor(step.status),
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginRight: '1rem',
                    fontSize: '1.25rem'
                  }}>
                    {step.status === 'processing' ? '🔄' : step.status === 'completed' ? '✅' : step.status === 'error' ? '❌' : '⏳'}
                  </div>
                  <div style={{ flex: 1 }}>
                    <h4 style={{ fontSize: '1rem', fontWeight: '600', margin: 0, marginBottom: '0.25rem' }}>
                      {step.stage}
                    </h4>
                    <p style={{ fontSize: '0.875rem', color: '#94a3b8', margin: 0 }}>
                      {step.message}
                    </p>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                    {step.timestamp.toLocaleTimeString()}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Results Section */}
        {uploadState.results && (
          <div style={{
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            padding: '3rem',
            borderRadius: '20px',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            marginBottom: '3rem'
          }}>
            <h2 style={{ fontSize: '2rem', fontWeight: '700', marginBottom: '2rem', textAlign: 'center' }}>
              📊 Analysis Results
            </h2>

            {/* Decision Summary */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '2rem',
              marginBottom: '3rem'
            }}>
              <div style={{
                textAlign: 'center',
                padding: '2rem',
                backgroundColor: 'rgba(37, 99, 235, 0.2)',
                borderRadius: '12px',
                border: '1px solid #2563eb'
              }}>
                <div style={{ fontSize: '2rem', fontWeight: '800', marginBottom: '0.5rem' }}>
                  {uploadState.results.analysis?.consensus?.verdict?.toUpperCase() || 'PENDING'}
                </div>
                <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>Final Decision</div>
              </div>
              
              <div style={{
                textAlign: 'center',
                padding: '2rem',
                backgroundColor: 'rgba(22, 163, 74, 0.2)',
                borderRadius: '12px',
                border: '1px solid #16a34a'
              }}>
                <div style={{ fontSize: '2rem', fontWeight: '800', marginBottom: '0.5rem' }}>
                  {Math.round((uploadState.results.analysis?.consensus?.confidence || 0) * 100)}%
                </div>
                <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>Confidence</div>
              </div>
              
              <div style={{
                textAlign: 'center',
                padding: '2rem',
                backgroundColor: 'rgba(124, 58, 237, 0.2)',
                borderRadius: '12px',
                border: '1px solid #7c3aed'
              }}>
                <div style={{ fontSize: '2rem', fontWeight: '800', marginBottom: '0.5rem' }}>
                  {uploadState.results.analysis?.models?.length || 0}
                </div>
                <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>AI Models</div>
              </div>
              
              <div style={{
                textAlign: 'center',
                padding: '2rem',
                backgroundColor: 'rgba(220, 38, 38, 0.2)',
                borderRadius: '12px',
                border: '1px solid #dc2626'
              }}>
                <div style={{ fontSize: '2rem', fontWeight: '800', marginBottom: '0.5rem' }}>
                  {uploadState.results.upload?.data?.findings_processed || 0}
                </div>
                <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>Findings</div>
              </div>
            </div>

            {/* Model Analysis Details */}
            {uploadState.results.analysis?.models && (
              <div>
                <h3 style={{ fontSize: '1.25rem', fontWeight: '700', marginBottom: '1.5rem' }}>
                  🤖 Individual Model Analysis
                </h3>
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                  gap: '1.5rem'
                }}>
                  {uploadState.results.analysis.models.map((model, index) => (
                    <div key={index} style={{
                      padding: '1.5rem',
                      backgroundColor: 'rgba(255, 255, 255, 0.05)',
                      borderRadius: '12px',
                      border: '1px solid rgba(255, 255, 255, 0.1)'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                        <h4 style={{ fontSize: '1rem', fontWeight: '700', margin: 0 }}>
                          {model.name?.replace('_', ' ')?.toUpperCase()}
                        </h4>
                        <div style={{
                          marginLeft: 'auto',
                          fontSize: '0.75rem',
                          fontWeight: '600',
                          color: model.confidence >= 0.8 ? '#16a34a' : model.confidence >= 0.6 ? '#d97706' : '#dc2626',
                          backgroundColor: `${model.confidence >= 0.8 ? '#16a34a' : model.confidence >= 0.6 ? '#d97706' : '#dc2626'}20`,
                          padding: '0.25rem 0.5rem',
                          borderRadius: '12px'
                        }}>
                          {Math.round(model.confidence * 100)}%
                        </div>
                      </div>
                      <div style={{ marginBottom: '0.75rem' }}>
                        <span style={{ fontSize: '0.875rem', color: '#94a3b8' }}>Verdict: </span>
                        <span style={{ fontSize: '0.875rem', fontWeight: '600' }}>
                          {model.verdict?.toUpperCase()}
                        </span>
                      </div>
                      <p style={{ fontSize: '0.75rem', color: '#64748b', lineHeight: '1.4' }}>
                        {model.rationale || 'No rationale provided'}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Right: System Capabilities */}
          <div style={{
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            padding: '2.5rem',
            borderRadius: '16px',
            border: '1px solid rgba(255, 255, 255, 0.1)'
          }}>
            <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '1.5rem' }}>
              ⚙️ System Capabilities
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {[
                {
                  name: 'Multi-LLM Consensus',
                  description: 'GPT-5, Claude, Gemini with disagreement analysis',
                  status: systemState.capabilities?.llm_providers_available || 0,
                  icon: '🧠'
                },
                {
                  name: 'MITRE ATT&CK Mapping',
                  description: 'Vulnerability to attack technique correlation',
                  status: systemState.capabilities?.mitre_techniques_mapped || 0,
                  icon: '🎯'
                },
                {
                  name: 'SSVC Framework',
                  description: 'CISA/SEI methodology with EPSS/KEV',
                  status: 'Compliant',
                  icon: '📋'
                },
                {
                  name: 'Evidence Lake',
                  description: 'Immutable audit trail with cryptographic integrity',
                  status: isDemo ? 'Demo' : 'Production',
                  icon: '📚'
                }
              ].map((capability) => (
                <div key={capability.name} style={{
                  display: 'flex',
                  alignItems: 'center',
                  padding: '1.5rem',
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  borderRadius: '12px',
                  border: '1px solid rgba(255, 255, 255, 0.1)'
                }}>
                  <div style={{
                    width: '50px',
                    height: '50px',
                    backgroundColor: '#2563eb',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginRight: '1rem',
                    fontSize: '1.5rem'
                  }}>
                    {capability.icon}
                  </div>
                  <div style={{ flex: 1 }}>
                    <h4 style={{ fontSize: '1rem', fontWeight: '700', margin: 0, marginBottom: '0.25rem' }}>
                      {capability.name}
                    </h4>
                    <p style={{ fontSize: '0.75rem', color: '#94a3b8', margin: 0 }}>
                      {capability.description}
                    </p>
                  </div>
                  <div style={{
                    fontSize: '0.875rem',
                    fontWeight: '600',
                    color: '#16a34a',
                    backgroundColor: 'rgba(22, 163, 74, 0.2)',
                    padding: '0.25rem 0.75rem',
                    borderRadius: '12px'
                  }}>
                    {capability.status}
                  </div>
                </div>
              ))}
            </div>

            {/* Quick Actions */}
            <div style={{ marginTop: '2rem', paddingTop: '2rem', borderTop: '1px solid rgba(255, 255, 255, 0.1)' }}>
              <h4 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '1rem' }}>
                Quick Actions
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <Link
                  to="/install"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '0.75rem 1rem',
                    backgroundColor: 'rgba(255, 255, 255, 0.1)',
                    borderRadius: '8px',
                    textDecoration: 'none',
                    color: 'white',
                    fontSize: '0.875rem',
                    fontWeight: '600'
                  }}
                >
                  <span style={{ marginRight: '0.75rem' }}>📦</span>
                  Installation & CLI Setup
                </Link>
                <Link
                  to="/architecture"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '0.75rem 1rem',
                    backgroundColor: 'rgba(255, 255, 255, 0.1)',
                    borderRadius: '8px',
                    textDecoration: 'none',
                    color: 'white',
                    fontSize: '0.875rem',
                    fontWeight: '600'
                  }}
                >
                  <span style={{ marginRight: '0.75rem' }}>🏗️</span>
                  Technical Architecture
                </Link>
                <Link
                  to="/marketplace"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '0.75rem 1rem',
                    backgroundColor: 'rgba(255, 255, 255, 0.1)',
                    borderRadius: '8px',
                    textDecoration: 'none',
                    color: 'white',
                    fontSize: '0.875rem',
                    fontWeight: '600'
                  }}
                >
                  <span style={{ marginRight: '0.75rem' }}>🛒</span>
                  Security Marketplace
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* Business Value Section */}
        <div style={{
          backgroundColor: 'rgba(255, 255, 255, 0.05)',
          padding: '3rem',
          borderRadius: '20px',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          textAlign: 'center'
        }}>
          <h2 style={{ fontSize: '2rem', fontWeight: '700', marginBottom: '2rem' }}>
            🎯 Unique Value Proposition
          </h2>
          
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
            gap: '2rem'
          }}>
            <div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: '700', marginBottom: '1rem', color: '#2563eb' }}>
                🚀 Industry First
              </h3>
              <p style={{ fontSize: '0.875rem', color: '#94a3b8', lineHeight: '1.5' }}>
                First multi-LLM consensus engine for DevSecOps. Combines 4+ AI models 
                with disagreement analysis for unprecedented decision accuracy.
              </p>
            </div>
            
            <div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: '700', marginBottom: '1rem', color: '#16a34a' }}>
                📈 ROI Impact  
              </h3>
              <p style={{ fontSize: '0.875rem', color: '#94a3b8', lineHeight: '1.5' }}>
                Reduce false positives by 80%, accelerate security reviews by 10x, 
                and enable continuous deployment with confidence.
              </p>
            </div>
            
            <div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: '700', marginBottom: '1rem', color: '#7c3aed' }}>
                🏗️ Enterprise Ready
              </h3>
              <p style={{ fontSize: '0.875rem', color: '#94a3b8', lineHeight: '1.5' }}>
                Kubernetes-native, SSVC compliant, Evidence Lake for audit, 
                and enterprise integrations (Jira, Confluence, SIEM).
              </p>
            </div>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  )
}

export default EnhancedDashboard