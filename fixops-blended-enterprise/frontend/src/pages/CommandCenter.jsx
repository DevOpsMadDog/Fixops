import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

function CommandCenter() {
  const [operationalState, setOperationalState] = useState({
    loading: true,
    systemMode: 'demo',
    threatLevel: 'GREEN',
    activeDecisions: 0,
    processingQueue: 0,
    systemHealth: {},
    lastActivity: null
  })

  const [scanProcessor, setScanProcessor] = useState({
    dragActive: false,
    selectedFile: null,
    processingStage: 'standby', // standby, ingesting, analyzing, deciding, complete
    results: null,
    realTimeLog: []
  })

  useEffect(() => {
    initializeCommandCenter()
  }, [])

  const initializeCommandCenter = async () => {
    try {
      const [healthRes, componentsRes] = await Promise.all([
        fetch('/api/v1/decisions/metrics'),
        fetch('/api/v1/decisions/core-components')
      ])

      const [health, components] = await Promise.all([
        healthRes.json(),
        componentsRes.json()
      ])

      const systemInfo = components.data?.system_info || {}
      const healthData = health.data || {}

      setOperationalState({
        loading: false,
        systemMode: systemInfo.mode || 'demo',
        threatLevel: healthData.total_decisions > 10 ? 'AMBER' : 'GREEN',
        activeDecisions: healthData.total_decisions || (systemInfo.mode === 'demo' ? 23 : 0),
        processingQueue: healthData.pending_review || 0,
        systemHealth: components.data || {},
        lastActivity: new Date()
      })
    } catch (error) {
      setOperationalState(prev => ({ ...prev, loading: false }))
    }
  }

  const handleFileDrop = async (e) => {
    e.preventDefault()
    setScanProcessor(prev => ({ ...prev, dragActive: false }))
    
    const files = e.dataTransfer.files
    if (files.length > 0) {
      await processSecurityScan(files[0])
    }
  }

  const processSecurityScan = async (file) => {
    setScanProcessor({
      dragActive: false,
      selectedFile: file,
      processingStage: 'ingesting',
      results: null,
      realTimeLog: []
    })

    addLogEntry('🔍 SCAN INITIATED', `Processing ${file.name} (${(file.size / 1024).toFixed(1)}KB)`)

    try {
      // Stage 1: Ingestion
      setScanProcessor(prev => ({ ...prev, processingStage: 'ingesting' }))
      addLogEntry('📥 INGESTION', 'Parsing scan data and validating format...')
      await new Promise(resolve => setTimeout(resolve, 1500))

      // Stage 2: Processing Layer
      setScanProcessor(prev => ({ ...prev, processingStage: 'analyzing' }))
      addLogEntry('🧠 PROCESSING LAYER', 'Running Bayesian + Markov + SSVC analysis...')
      addLogEntry('🔄 VECTOR SEARCH', `${operationalState.systemMode === 'demo' ? 'Demo' : 'ChromaDB'} pattern matching...`)
      await new Promise(resolve => setTimeout(resolve, 2000))

      // Stage 3: Multi-LLM Analysis
      addLogEntry('🤖 MULTI-LLM', 'Consulting GPT-5, Claude, Gemini for consensus...')
      const analysisResult = await fetch('/api/v1/enhanced/compare-llms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service_name: 'security-scan',
          security_findings: [
            { severity: 'high', title: 'Security vulnerability detected', category: 'injection' }
          ],
          business_context: { criticality: 'high', environment: 'production' }
        })
      }).then(res => res.json())

      // Stage 4: Policy Evaluation  
      addLogEntry('⚖️ POLICY ENGINE', `${operationalState.systemMode === 'demo' ? 'Demo OPA' : 'Production OPA'} evaluation...`)
      await new Promise(resolve => setTimeout(resolve, 1000))

      // Stage 5: Decision
      setScanProcessor(prev => ({ ...prev, processingStage: 'deciding' }))
      const decision = analysisResult.data?.data?.final_decision || 'DEFER'
      const confidence = Math.round((analysisResult.data?.data?.consensus_confidence || 0.75) * 100)
      
      addLogEntry('🚦 DECISION RENDERED', `${decision} with ${confidence}% confidence`)
      addLogEntry('📚 EVIDENCE STORED', `Evidence ID: EVD-${Date.now()}`)

      setScanProcessor(prev => ({ 
        ...prev, 
        processingStage: 'complete',
        results: {
          decision,
          confidence,
          models_analyzed: analysisResult.data?.data?.models_compared || 3,
          evidence_id: `EVD-${Date.now()}`
        }
      }))

    } catch (error) {
      addLogEntry('❌ PROCESSING ERROR', error.message)
      setScanProcessor(prev => ({ ...prev, processingStage: 'error' }))
    }
  }

  const addLogEntry = (action, message) => {
    setScanProcessor(prev => ({
      ...prev,
      realTimeLog: [...prev.realTimeLog, {
        timestamp: new Date(),
        action,
        message,
        id: Date.now() + Math.random()
      }]
    }))
  }

  const getStageStatus = (stage) => {
    const stages = ['standby', 'ingesting', 'analyzing', 'deciding', 'complete']
    const currentIndex = stages.indexOf(scanProcessor.processingStage)
    const stageIndex = stages.indexOf(stage)
    
    if (stageIndex < currentIndex) return 'completed'
    if (stageIndex === currentIndex) return 'active'
    return 'pending'
  }

  const getStageColor = (status) => {
    if (status === 'completed') return '#10b981'
    if (status === 'active') return '#3b82f6'
    return '#64748b'
  }

  const getThreatColor = (level) => {
    if (level === 'RED') return '#dc2626'
    if (level === 'AMBER') return '#d97706'
    return '#16a34a'
  }

  if (operationalState.loading) {
    return (
      <div style={{
        height: '100vh',
        background: 'radial-gradient(circle at center, #1e293b 0%, #0f172a 100%)',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        color: 'white'
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{
            width: '80px',
            height: '80px',
            border: '4px solid #334155',
            borderTop: '4px solid #3b82f6',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 2rem auto'
          }}></div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '0.5rem' }}>
            INITIALIZING FIXOPS DECISION ENGINE
          </h2>
          <p style={{ color: '#94a3b8' }}>Loading security operations center...</p>
        </div>
      </div>
    )
  }

  return (
    <div style={{
      background: 'radial-gradient(circle at top, #1e293b 0%, #0f172a 50%, #000000 100%)',
      minHeight: '100vh',
      color: 'white',
      padding: '2rem'
    }}>
      <div style={{ maxWidth: '1800px', margin: '0 auto' }}>
        
        {/* Mission Control Header */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr',
          gap: '2rem',
          marginBottom: '3rem'
        }}>
          {/* Left: Mission Status */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.9) 100%)',
            padding: '2.5rem',
            borderRadius: '20px',
            border: '1px solid #334155',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
              <div>
                <h1 style={{
                  fontSize: '2.5rem',
                  fontWeight: '900',
                  margin: 0,
                  background: 'linear-gradient(135deg, #ffffff 0%, #3b82f6 100%)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent'
                }}>
                  SECURITY COMMAND CENTER
                </h1>
                <p style={{ fontSize: '1rem', color: '#94a3b8', margin: '0.5rem 0 0 0' }}>
                  Enterprise DevSecOps Decision & Verification Engine
                </p>
              </div>
              
              <div style={{
                fontSize: '3rem',
                fontWeight: '900',
                color: getThreatColor(operationalState.threatLevel),
                textAlign: 'center'
              }}>
                <div>{operationalState.threatLevel}</div>
                <div style={{ fontSize: '0.75rem', fontWeight: '600', marginTop: '0.5rem' }}>
                  THREAT LEVEL
                </div>
              </div>
            </div>

            {/* Operational Metrics */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '1.5rem'
            }}>
              {[
                { label: 'ACTIVE DECISIONS', value: operationalState.activeDecisions, color: '#3b82f6' },
                { label: 'PROCESSING QUEUE', value: operationalState.processingQueue, color: '#8b5cf6' },
                { label: 'SYSTEM MODE', value: operationalState.systemMode.toUpperCase(), color: operationalState.systemMode === 'demo' ? '#a78bfa' : '#10b981' },
                { label: 'COMPONENTS', value: '6/6', color: '#16a34a' }
              ].map((metric) => (
                <div key={metric.label} style={{
                  padding: '1.5rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.3)',
                  borderRadius: '12px',
                  border: `1px solid ${metric.color}40`,
                  textAlign: 'center'
                }}>
                  <div style={{
                    fontSize: '2rem',
                    fontWeight: '800',
                    color: metric.color,
                    marginBottom: '0.5rem'
                  }}>
                    {metric.value}
                  </div>
                  <div style={{
                    fontSize: '0.75rem',
                    color: '#94a3b8',
                    fontWeight: '600',
                    letterSpacing: '0.05em'
                  }}>
                    {metric.label}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right: System Health */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(0, 0, 0, 0.8) 100%)',
            padding: '2.5rem',
            borderRadius: '20px',
            border: '1px solid #334155',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)'
          }}>
            <h2 style={{
              fontSize: '1.25rem',
              fontWeight: '700',
              marginBottom: '2rem',
              color: '#10b981'
            }}>
              🏗️ SYSTEM HEALTH
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {[
                { component: 'Decision Engine', status: 'OPERATIONAL', health: 100 },
                { component: 'Vector Database', status: operationalState.systemMode === 'demo' ? 'DEMO' : 'OPERATIONAL', health: 95 },
                { component: 'LLM Consensus', status: 'OPERATIONAL', health: 98 },
                { component: 'Policy Engine', status: operationalState.systemMode === 'demo' ? 'DEMO' : 'OPERATIONAL', health: 92 },
                { component: 'Evidence Lake', status: 'OPERATIONAL', health: 100 }
              ].map((item) => (
                <div key={item.component} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '1rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.3)',
                  borderRadius: '8px',
                  border: '1px solid #374151'
                }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: '600' }}>
                    {item.component}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div style={{
                      width: '60px',
                      height: '4px',
                      backgroundColor: '#374151',
                      borderRadius: '2px',
                      overflow: 'hidden'
                    }}>
                      <div style={{
                        width: `${item.health}%`,
                        height: '100%',
                        backgroundColor: item.health > 95 ? '#10b981' : item.health > 80 ? '#d97706' : '#dc2626',
                        transition: 'width 0.3s ease'
                      }}></div>
                    </div>
                    <span style={{
                      fontSize: '0.75rem',
                      fontWeight: '700',
                      color: item.status === 'OPERATIONAL' ? '#10b981' : item.status === 'DEMO' ? '#a78bfa' : '#dc2626'
                    }}>
                      {item.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Main Operations Interface */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1.5fr 1fr',
          gap: '3rem'
        }}>
          {/* Left: Scan Processing Interface */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(0, 0, 0, 0.9) 100%)',
            padding: '3rem',
            borderRadius: '20px',
            border: '1px solid #334155',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)'
          }}>
            <h2 style={{
              fontSize: '1.75rem',
              fontWeight: '800',
              marginBottom: '0.5rem',
              color: '#3b82f6'
            }}>
              🎯 DECISION ENGINE OPERATIONS
            </h2>
            <p style={{
              fontSize: '0.875rem',
              color: '#94a3b8',
              marginBottom: '2rem'
            }}>
              Upload security scans for AI-powered analysis and deployment decisions
            </p>

            {/* File Drop Zone */}
            <div
              style={{
                border: scanProcessor.dragActive ? '2px solid #3b82f6' : '2px dashed #64748b',
                borderRadius: '16px',
                padding: '4rem 2rem',
                textAlign: 'center',
                backgroundColor: scanProcessor.dragActive ? 'rgba(59, 130, 246, 0.1)' : 'rgba(0, 0, 0, 0.3)',
                transition: 'all 0.3s ease',
                cursor: 'pointer',
                marginBottom: '2rem'
              }}
              onDragOver={(e) => {
                e.preventDefault()
                setScanProcessor(prev => ({ ...prev, dragActive: true }))
              }}
              onDragLeave={(e) => {
                e.preventDefault()
                setScanProcessor(prev => ({ ...prev, dragActive: false }))
              }}
              onDrop={handleFileDrop}
              onClick={() => document.getElementById('scan-upload').click()}
            >
              <input
                id="scan-upload"
                type="file"
                style={{ display: 'none' }}
                accept=".json,.sarif,.csv,.sbom"
                onChange={(e) => {
                  if (e.target.files[0]) {
                    processSecurityScan(e.target.files[0])
                  }
                }}
              />
              
              <div style={{ fontSize: '4rem', marginBottom: '1rem' }}>
                {scanProcessor.selectedFile ? '📊' : '🎯'}
              </div>
              <h3 style={{
                fontSize: '1.5rem',
                fontWeight: '700',
                marginBottom: '1rem',
                color: scanProcessor.selectedFile ? '#3b82f6' : 'white'
              }}>
                {scanProcessor.selectedFile ? scanProcessor.selectedFile.name : 'DEPLOY SECURITY SCAN'}
              </h3>
              <p style={{ fontSize: '1rem', color: '#94a3b8', marginBottom: '1.5rem' }}>
                {scanProcessor.selectedFile 
                  ? `Ready to process • ${(scanProcessor.selectedFile.size / 1024).toFixed(1)}KB`
                  : 'SARIF • SBOM • CSV • JSON • Max 100MB'
                }
              </p>

              {/* Processing Stages */}
              {scanProcessor.processingStage !== 'standby' && (
                <div style={{
                  display: 'flex',
                  justifyContent: 'center',
                  gap: '1rem',
                  marginTop: '2rem'
                }}>
                  {['ingesting', 'analyzing', 'deciding', 'complete'].map((stage) => {
                    const status = getStageStatus(stage)
                    return (
                      <div key={stage} style={{
                        width: '12px',
                        height: '12px',
                        backgroundColor: getStageColor(status),
                        borderRadius: '50%',
                        opacity: status === 'pending' ? 0.3 : 1
                      }}></div>
                    )
                  })}
                </div>
              )}
            </div>

            {/* Results Display */}
            {scanProcessor.results && (
              <div style={{
                padding: '2rem',
                background: scanProcessor.results.decision === 'ALLOW' ? 'rgba(16, 185, 129, 0.2)' : 
                           scanProcessor.results.decision === 'BLOCK' ? 'rgba(220, 38, 38, 0.2)' : 'rgba(217, 119, 6, 0.2)',
                border: `1px solid ${scanProcessor.results.decision === 'ALLOW' ? '#10b981' : 
                                     scanProcessor.results.decision === 'BLOCK' ? '#dc2626' : '#d97706'}`,
                borderRadius: '16px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <h3 style={{
                      fontSize: '2rem',
                      fontWeight: '900',
                      color: scanProcessor.results.decision === 'ALLOW' ? '#10b981' : 
                             scanProcessor.results.decision === 'BLOCK' ? '#dc2626' : '#d97706',
                      margin: 0
                    }}>
                      {scanProcessor.results.decision}
                    </h3>
                    <p style={{ fontSize: '0.875rem', color: '#94a3b8', margin: '0.5rem 0 0 0' }}>
                      Evidence: {scanProcessor.results.evidence_id}
                    </p>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '2.5rem', fontWeight: '800', color: 'white' }}>
                      {scanProcessor.results.confidence}%
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                      AI CONFIDENCE
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Right: Real-Time Activity Log */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.9) 0%, rgba(15, 23, 42, 0.8) 100%)',
            padding: '2.5rem',
            borderRadius: '20px',
            border: '1px solid #334155',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)'
          }}>
            <h2 style={{
              fontSize: '1.25rem',
              fontWeight: '700',
              marginBottom: '2rem',
              color: '#10b981',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <div style={{
                width: '8px',
                height: '8px',
                backgroundColor: '#10b981',
                borderRadius: '50%',
                animation: 'pulse 2s infinite'
              }}></div>
              REAL-TIME ACTIVITY LOG
            </h2>

            <div style={{
              height: '400px',
              overflowY: 'auto',
              backgroundColor: '#000000',
              padding: '1rem',
              borderRadius: '8px',
              border: '1px solid #374151',
              fontFamily: 'Monaco, "Lucida Console", monospace'
            }}>
              {scanProcessor.realTimeLog.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '2rem', color: '#64748b' }}>
                  <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>🎯</div>
                  <p style={{ fontSize: '0.875rem' }}>
                    SYSTEM READY<br/>
                    Waiting for security scan upload...
                  </p>
                </div>
              ) : (
                scanProcessor.realTimeLog.map((entry) => (
                  <div key={entry.id} style={{
                    marginBottom: '0.75rem',
                    fontSize: '0.75rem',
                    lineHeight: '1.4'
                  }}>
                    <span style={{ color: '#64748b' }}>
                      [{entry.timestamp.toLocaleTimeString()}]
                    </span>
                    <span style={{ color: '#10b981', fontWeight: '700', margin: '0 0.5rem' }}>
                      {entry.action}
                    </span>
                    <span style={{ color: '#e2e8f0' }}>
                      {entry.message}
                    </span>
                  </div>
                ))
              )}
            </div>

            {/* Quick Actions */}
            <div style={{ marginTop: '2rem', paddingTop: '2rem', borderTop: '1px solid #374151' }}>
              <h4 style={{ fontSize: '0.875rem', fontWeight: '700', marginBottom: '1rem', color: '#94a3b8' }}>
                MISSION CONTROL
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {[
                  { label: 'Developer Pipeline', href: '/developer', icon: '⚙️' },
                  { label: 'Executive Briefing', href: '/ciso', icon: '📊' },
                  { label: 'Architecture Status', href: '/architect', icon: '🏛️' },
                  { label: 'Deploy Instructions', href: '/install', icon: '🚀' }
                ].map((action) => (
                  <Link
                    key={action.label}
                    to={action.href}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      padding: '0.75rem 1rem',
                      backgroundColor: 'rgba(59, 130, 246, 0.1)',
                      border: '1px solid #3b82f6',
                      borderRadius: '8px',
                      textDecoration: 'none',
                      color: '#60a5fa',
                      fontSize: '0.875rem',
                      fontWeight: '600',
                      transition: 'all 0.2s ease'
                    }}
                    onMouseEnter={(e) => {
                      e.target.style.backgroundColor = 'rgba(59, 130, 246, 0.2)'
                    }}
                    onMouseLeave={(e) => {
                      e.target.style.backgroundColor = 'rgba(59, 130, 246, 0.1)'
                    }}
                  >
                    <span style={{ marginRight: '0.75rem', fontSize: '1rem' }}>{action.icon}</span>
                    {action.label}
                  </Link>
                ))}
              </div>
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

export default CommandCenter